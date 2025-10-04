use crate::config::AnalysisConfig;
use crate::qemu::QemuDetector;
use anyhow::{anyhow, Result};
use log::{info, warn, debug};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct VmManager {
    config: Arc<AnalysisConfig>,
    qemu_path: PathBuf,
    vm_process: Option<Child>,
    monitor_socket: Option<PathBuf>,
}

impl VmManager {
    pub fn new(config: AnalysisConfig) -> Result<Self> {
        let qemu_path = QemuDetector::find_qemu()?;
        info!("Found QEMU at: {}", qemu_path.display());
        
        let version = QemuDetector::verify_qemu(&qemu_path)?;
        info!("QEMU version: {}", version);

        Ok(VmManager {
            config: Arc::new(config),
            qemu_path,
            vm_process: None,
            monitor_socket: None,
        })
    }

    pub async fn start_vm(&mut self) -> Result<()> {
        info!("Starting VM with configuration: {:?}", self.config.vm);

        // Create output directory
        std::fs::create_dir_all(&self.config.logging.output_dir)?;

        // Build QEMU command
        let mut cmd = Command::new(&self.qemu_path);
        
        // Add basic VM configuration
        self.add_basic_args(&mut cmd)?;
        
        // Add disk configuration
        self.add_disk_args(&mut cmd)?;
        
        // Add network configuration
        self.add_network_args(&mut cmd)?;
        
        // Add monitoring and control
        self.add_monitor_args(&mut cmd)?;
        
        // Add acceleration if available
        let accel_args = QemuDetector::get_acceleration_args();
        for arg in accel_args {
            cmd.arg(arg);
        }

        debug!("QEMU command: {:?}", cmd);

        // Start the VM process
        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to start QEMU: {}", e))?;

        self.vm_process = Some(child);
        info!("VM started successfully");
        
        Ok(())
    }

    pub async fn stop_vm(&mut self) -> Result<()> {
        if let Some(mut process) = self.vm_process.take() {
            info!("Stopping VM...");
            
            // Try graceful shutdown via monitor first
            if let Some(monitor_path) = &self.monitor_socket {
                if let Err(e) = self.send_monitor_command("system_powerdown").await {
                    warn!("Failed to send powerdown command: {}", e);
                }
                
                // Wait for graceful shutdown
                for _ in 0..30 {
                    match process.try_wait() {
                        Ok(Some(_)) => {
                            info!("VM shutdown gracefully");
                            return Ok(());
                        }
                        Ok(None) => {
                            sleep(Duration::from_secs(1)).await;
                        }
                        Err(e) => {
                            warn!("Error checking VM status: {}", e);
                            break;
                        }
                    }
                }
            }
            
            // Force kill if graceful shutdown failed
            warn!("Forcing VM termination");
            process.kill().map_err(|e| anyhow!("Failed to kill VM process: {}", e))?;
            process.wait().map_err(|e| anyhow!("Failed to wait for VM process: {}", e))?;
        }
        
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut process) = self.vm_process {
            match process.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn add_basic_args(&self, cmd: &mut Command) -> Result<()> {
        cmd.args(&[
            "-machine", &self.config.vm.machine,
            "-m", &self.config.vm.ram_mb.to_string(),
            "-smp", &self.config.vm.cpus.to_string(),
            "-boot", &self.config.vm.boot,
            "-display", "none", // Headless mode
            "-nographic",
        ]);
        
        Ok(())
    }

    fn add_disk_args(&self, cmd: &mut Command) -> Result<()> {
        for (index, drive) in self.config.disks.drives.iter().enumerate() {
            let drive_arg = format!(
                "file={},format={},if={},index={}",
                drive.path.display(),
                drive.format,
                drive.interface,
                index
            );
            cmd.args(&["-drive", &drive_arg]);
        }
        
        Ok(())
    }

    fn add_network_args(&self, cmd: &mut Command) -> Result<()> {
        if !self.config.network.enabled {
            cmd.args(&["-netdev", "none"]);
            return Ok(());
        }

        match self.config.network.mode.as_str() {
            "user" => {
                let mut netdev_arg = "user,id=net0".to_string();
                
                // Add port forwards
                for forward in &self.config.network.forwards {
                    netdev_arg.push_str(&format!(
                        ",hostfwd={}::{}-:{}",
                        forward.protocol,
                        forward.host_port,
                        forward.guest_port
                    ));
                }
                
                cmd.args(&["-netdev", &netdev_arg]);
                cmd.args(&["-device", "virtio-net-pci,netdev=net0"]);
            }
            "bridge" => {
                // Bridge mode requires additional setup
                cmd.args(&["-netdev", "bridge,id=net0,br=br0"]);
                cmd.args(&["-device", "virtio-net-pci,netdev=net0"]);
            }
            "tap" => {
                // TAP mode for advanced networking
                cmd.args(&["-netdev", "tap,id=net0,ifname=tap0,script=no,downscript=no"]);
                cmd.args(&["-device", "virtio-net-pci,netdev=net0"]);
            }
            _ => {
                return Err(anyhow!("Unsupported network mode: {}", self.config.network.mode));
            }
        }
        
        Ok(())
    }

    fn add_monitor_args(&mut self, cmd: &mut Command) -> Result<()> {
        let socket_path = self.config.logging.output_dir.join("monitor.sock");
        self.monitor_socket = Some(socket_path.clone());
        
        let monitor_arg = format!("unix:{},server,nowait", socket_path.display());
        cmd.args(&["-monitor", &monitor_arg]);
        
        Ok(())
    }

    async fn send_monitor_command(&self, command: &str) -> Result<String> {
        // This would require implementing a QEMU monitor protocol client
        // For now, we'll return a placeholder
        warn!("Monitor command '{}' not implemented yet", command);
        Ok(String::new())
    }

    pub async fn run_analysis(&mut self) -> Result<()> {
        info!("Starting VM analysis for {} seconds", self.config.analysis.runtime_seconds);
        
        self.start_vm().await?;
        
        if self.config.analysis.runtime_seconds > 0 {
            sleep(Duration::from_secs(self.config.analysis.runtime_seconds)).await;
        } else {
            // Run indefinitely until manually stopped
            info!("VM running indefinitely. Press Ctrl+C to stop.");
            loop {
                if !self.is_running() {
                    info!("VM has stopped");
                    break;
                }
                sleep(Duration::from_secs(5)).await;
            }
        }
        
        self.stop_vm().await?;
        info!("VM analysis completed");
        
        Ok(())
    }
}

impl Drop for VmManager {
    fn drop(&mut self) {
        if self.is_running() {
            warn!("VM still running during drop, attempting to stop");
            if let Some(mut process) = self.vm_process.take() {
                let _ = process.kill();
                let _ = process.wait();
            }
        }
    }
}