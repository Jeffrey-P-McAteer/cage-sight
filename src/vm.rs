use crate::config::AnalysisConfig;
use crate::qemu::QemuDetector;
use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::io::Read;
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

    pub async fn start_vm(&mut self, network_monitor: Option<&crate::network::NetworkMonitor>, display_config: Option<&crate::config::DisplayConfig>) -> Result<()> {
        info!("Starting VM with configuration: {:?}", self.config.vm);

        // Create output directory
        std::fs::create_dir_all(&self.config.logging.output_dir)?;

        // Build QEMU command
        let mut cmd = Command::new(&self.qemu_path);
        
        // Add basic VM configuration
        self.add_basic_args(&mut cmd)?;
        
        // Add disk configuration
        self.add_disk_args(&mut cmd)?;
        
        // Add network configuration with monitoring
        self.add_network_args(&mut cmd, network_monitor)?;
        
        // Add display configuration
        self.add_display_args(&mut cmd, display_config)?;
        
        // Add monitoring and control
        self.add_monitor_args(&mut cmd)?;
        
        // Add acceleration if available
        let accel_args = QemuDetector::get_acceleration_args();
        for arg in accel_args {
            cmd.arg(arg);
        }

        info!("QEMU command: {}", self.format_qemu_command(&cmd));
        debug!("Full QEMU command: {:?}", cmd);

        // Start the VM process with proper error handling
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to start QEMU process: {}", e))?;

        // Give QEMU a moment to start and check if it crashes immediately
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                // QEMU exited immediately - capture error output
                let mut stderr_output = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut stderr_output);
                }
                
                let mut stdout_output = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut stdout_output);
                }
                
                let error_msg = format!(
                    "QEMU failed to start (exit code: {})\nSTDERR: {}\nSTDOUT: {}",
                    exit_status, stderr_output, stdout_output
                );
                
                return Err(anyhow!(error_msg));
            }
            Ok(None) => {
                // QEMU is still running - good!
                info!("QEMU process started successfully (PID: {})", child.id());
            }
            Err(e) => {
                return Err(anyhow!("Failed to check QEMU process status: {}", e));
            }
        }

        self.vm_process = Some(child);
        
        // Log success message with display info
        if let Some(display) = display_config {
            if display.gui_enabled {
                info!("VM started successfully with GUI display (no administrative privileges required)");
                info!("🖥️  Interactive GUI window should now be visible");
                info!("You can directly interact with the VM using mouse and keyboard");
                
                if let Some(vnc_port) = display.vnc_port {
                    info!("Note: VNC was also requested but GUI takes priority");
                    info!("Use 'cage-sight run --vnc {} config.toml' for VNC-only mode", vnc_port);
                }
            } else if let Some(vnc_port) = display.vnc_port {
                info!("VM started successfully with VNC display on port {} (no administrative privileges required)", vnc_port);
                info!("🌐 Connect with VNC client to localhost:{}", vnc_port);
                info!("Example: vncviewer localhost:{}", vnc_port);
            } else {
                info!("VM started successfully in headless mode (no administrative privileges required)");
            }
        } else {
            info!("VM started successfully in headless mode (no administrative privileges required)");
        }
        
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
        ]);
        
        Ok(())
    }

    fn add_display_args(&self, cmd: &mut Command, display_config: Option<&crate::config::DisplayConfig>) -> Result<()> {
        if let Some(display) = display_config {
            if display.gui_enabled {
                // Enable GUI display - ALWAYS try to show a local window
                info!("Enabling GUI display for interactive VM access");
                
                let display_backend = self.select_gui_backend()?;
                info!("Using {} display backend for local GUI", display_backend);
                cmd.args(&["-display", &display_backend]);
                
                // Add VNC as secondary option if requested
                if let Some(vnc_port) = display.vnc_port {
                    info!("Also enabling VNC on port {} for remote access", vnc_port);
                    // Note: QEMU doesn't support multiple -display options easily
                    // We'll prioritize local GUI and mention VNC option
                    warn!("VNC port specified but GUI takes priority. Use VNC-only mode if needed.");
                }
            } else if let Some(vnc_port) = display.vnc_port {
                // VNC only mode
                info!("Enabling VNC display on port {}", vnc_port);
                cmd.args(&["-display", &format!("vnc=:{}", vnc_port - 5900)]);
            } else {
                // Headless mode
                info!("Running in headless mode (no display)");
                cmd.args(&["-display", "none", "-nographic"]);
            }
        } else {
            // Default to headless mode
            info!("Running in headless mode (no display)");
            cmd.args(&["-display", "none", "-nographic"]);
        }
        
        Ok(())
    }

    fn select_gui_backend(&self) -> Result<String> {
        // Platform-specific GUI backend selection with SDL prioritized
        
        #[cfg(target_os = "linux")]
        {
            // On Linux: Try SDL first, then GTK, then fail with clear error
            if self.is_display_available() {
                // Check for SDL support first (most reliable for GUI)
                if self.check_qemu_display_support("sdl") {
                    return Ok("sdl".to_string());
                }
                // Fallback to GTK if available
                if self.check_qemu_display_support("gtk") {
                    return Ok("gtk".to_string());
                }
                // Last resort: try default X11
                return Ok("default".to_string());
            } else {
                return Err(anyhow!("No display environment available. Set DISPLAY or WAYLAND_DISPLAY, or use --vnc instead of --gui"));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows: SDL is usually the best option
            if self.check_qemu_display_support("sdl") {
                return Ok("sdl".to_string());
            }
            // Fallback to default Windows display
            return Ok("default".to_string());
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS: Try SDL first, then Cocoa
            if self.check_qemu_display_support("sdl") {
                return Ok("sdl".to_string());
            }
            if self.check_qemu_display_support("cocoa") {
                return Ok("cocoa".to_string());
            }
            return Ok("default".to_string());
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            // Other platforms: try SDL
            if self.check_qemu_display_support("sdl") {
                return Ok("sdl".to_string());
            }
            return Ok("default".to_string());
        }
    }

    fn is_display_available(&self) -> bool {
        // Check if we have a display environment
        std::env::var("DISPLAY").is_ok() || 
        std::env::var("WAYLAND_DISPLAY").is_ok() ||
        cfg!(target_os = "windows") ||
        cfg!(target_os = "macos")
    }

    fn check_qemu_display_support(&self, backend: &str) -> bool {
        // Query QEMU for supported display backends
        match Command::new(&self.qemu_path)
            .args(&["-display", "help"])
            .output()
        {
            Ok(output) => {
                let help_text = String::from_utf8_lossy(&output.stdout);
                help_text.contains(backend)
            }
            Err(_) => {
                // If we can't query QEMU, assume common backends are available
                match backend {
                    "sdl" | "gtk" | "cocoa" | "default" => true,
                    _ => false,
                }
            }
        }
    }

    fn format_qemu_command(&self, cmd: &Command) -> String {
        // Create a readable version of the QEMU command for logging
        let program = cmd.get_program().to_string_lossy();
        let args: Vec<String> = cmd.get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        
        format!("{} {}", program, args.join(" "))
    }

    fn add_disk_args(&self, cmd: &mut Command) -> Result<()> {
        let mut ahci_added = false;
        
        for (index, drive) in self.config.disks.drives.iter().enumerate() {
            let interface = self.normalize_disk_interface(&drive.interface)?;
            
            if interface == "ahci" && !ahci_added {
                // Add AHCI controller for SATA-like drives
                cmd.args(&["-device", "ahci,id=ahci"]);
                ahci_added = true;
            }
            
            let drive_arg = if interface == "ahci" {
                format!(
                    "file={},format={},if=none,id=drive{}",
                    drive.path.display(),
                    drive.format,
                    index
                )
            } else {
                format!(
                    "file={},format={},if={},index={}",
                    drive.path.display(),
                    drive.format,
                    interface,
                    index
                )
            };
            
            cmd.args(&["-drive", &drive_arg]);
            
            // Connect AHCI drives to the controller
            if interface == "ahci" {
                let device_arg = format!("ide-hd,drive=drive{},bus=ahci.{}", index, index);
                cmd.args(&["-device", &device_arg]);
            }
        }
        
        Ok(())
    }
    
    fn normalize_disk_interface(&self, interface: &str) -> Result<String> {
        match interface.to_lowercase().as_str() {
            "sata" => Ok("ahci".to_string()), // Convert SATA to AHCI
            "ide" | "scsi" | "virtio" | "nvme" | "ahci" => Ok(interface.to_lowercase()),
            _ => Err(anyhow!("Unsupported disk interface: '{}'. Supported interfaces: ide, sata, scsi, virtio, nvme", interface))
        }
    }

    fn add_network_args(&self, cmd: &mut Command, network_monitor: Option<&crate::network::NetworkMonitor>) -> Result<()> {
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
                
                // Add network monitoring arguments if available
                if let Some(monitor) = network_monitor {
                    let monitor_args = monitor.get_qemu_monitor_args();
                    for arg in monitor_args {
                        cmd.arg(arg);
                    }
                }
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

    pub async fn run_analysis(&mut self, network_monitor: Option<&crate::network::NetworkMonitor>, display_config: Option<&crate::config::DisplayConfig>) -> Result<()> {
        info!("Starting VM analysis for {} seconds", self.config.analysis.runtime_seconds);
        
        self.start_vm(network_monitor, display_config).await?;
        
        if self.config.analysis.runtime_seconds > 0 {
            // Run for specified time with health checks
            let mut elapsed = 0;
            let check_interval = 5;
            
            while elapsed < self.config.analysis.runtime_seconds {
                if !self.is_running() {
                    // VM died unexpectedly
                    self.handle_vm_death().await?;
                    return Err(anyhow!("VM stopped unexpectedly after {} seconds", elapsed));
                }
                
                let sleep_time = std::cmp::min(check_interval, self.config.analysis.runtime_seconds - elapsed);
                sleep(Duration::from_secs(sleep_time)).await;
                elapsed += sleep_time;
            }
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

    async fn handle_vm_death(&mut self) -> Result<()> {
        if let Some(mut process) = self.vm_process.take() {
            warn!("VM process died unexpectedly, capturing error output...");
            
            // Try to read any remaining output
            let mut stderr_output = String::new();
            let mut stdout_output = String::new();
            
            if let Some(mut stderr) = process.stderr.take() {
                let _ = stderr.read_to_string(&mut stderr_output);
            }
            
            if let Some(mut stdout) = process.stdout.take() {
                let _ = stdout.read_to_string(&mut stdout_output);
            }
            
            // Wait for the process to ensure we don't leave a zombie
            match process.wait() {
                Ok(exit_status) => {
                    error!("VM exited with status: {}", exit_status);
                }
                Err(e) => {
                    error!("Failed to wait for VM process: {}", e);
                }
            }
            
            if !stderr_output.is_empty() {
                error!("VM STDERR: {}", stderr_output);
            }
            
            if !stdout_output.is_empty() {
                info!("VM STDOUT: {}", stdout_output);
            }
        }
        
        Ok(())
    }
}

impl Drop for VmManager {
    fn drop(&mut self) {
        if let Some(mut process) = self.vm_process.take() {
            if self.is_running() {
                warn!("VM still running during drop, attempting to stop gracefully");
                let _ = process.kill();
            }
            
            // Always wait for the process to prevent zombies
            match process.wait() {
                Ok(exit_status) => {
                    debug!("VM process cleanup completed with status: {}", exit_status);
                }
                Err(e) => {
                    warn!("Failed to wait for VM process during cleanup: {}", e);
                }
            }
        }
    }
}