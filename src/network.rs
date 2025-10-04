use crate::config::LoggingConfig;
use anyhow::{anyhow, Result};
use log::{info, debug, error};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use tokio::time::{sleep, Duration};
use tokio::sync::mpsc;
use tokio::task;
use tokio::fs;
use std::process::{Command, Stdio};

pub struct NetworkMonitor {
    config: Arc<LoggingConfig>,
    capture_file: Option<PathBuf>,
    is_running: Arc<AtomicBool>,
    dump_file: Option<PathBuf>,
    monitor_socket: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: std::time::SystemTime,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub size: usize,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct NetworkStats {
    pub total_packets: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub dns_queries: u64,
    pub http_requests: u64,
    pub connections: HashMap<String, u64>,
}

impl NetworkMonitor {
    pub fn new(config: LoggingConfig) -> Result<Self> {
        let capture_file = if config.capture_network {
            Some(config.output_dir.join(format!("capture.{}", config.pcap_format)))
        } else {
            None
        };

        let dump_file = if config.capture_network {
            Some(config.output_dir.join("network_dump.pcap"))
        } else {
            None
        };

        let monitor_socket = Some(config.output_dir.join("network_monitor.sock"));

        Ok(NetworkMonitor {
            config: Arc::new(config),
            capture_file,
            is_running: Arc::new(AtomicBool::new(false)),
            dump_file,
            monitor_socket,
        })
    }

    /// Get QEMU arguments for network monitoring (no privileges required)
    pub fn get_qemu_monitor_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        
        if let Some(ref dump_file) = self.dump_file {
            // Use QEMU's built-in network dump (no root required)
            args.push("-object".to_string());
            args.push(format!("filter-dump,id=netdump,netdev=net0,file={}", dump_file.display()));
        }

        if let Some(ref monitor_sock) = self.monitor_socket {
            // Add monitor socket for network statistics
            args.push("-monitor".to_string());
            args.push(format!("unix:{},server,nowait", monitor_sock.display()));
        }

        args
    }

    /// Get the dump file path for VM configuration
    pub fn get_dump_file(&self) -> Option<&Path> {
        self.dump_file.as_deref()
    }

    /// Get the monitor socket path for VM configuration  
    pub fn get_monitor_socket(&self) -> Option<&Path> {
        self.monitor_socket.as_deref()
    }

    pub async fn start_capture(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(anyhow!("Network capture already running"));
        }

        info!("Starting network monitoring (using QEMU network dump - no privileges required)");
        self.is_running.store(true, Ordering::Relaxed);

        // Note: The actual network capture will be handled by QEMU via the filter-dump object
        // We just need to monitor the dump file and extract statistics
        
        if let Some(ref dump_file) = self.dump_file {
            info!("Network packets will be captured to: {}", dump_file.display());
            
            // Start monitoring task that will read from QEMU's dump file
            let dump_path = dump_file.clone();
            let is_running = Arc::clone(&self.is_running);
            let config = Arc::clone(&self.config);
            
            let _monitor_task = task::spawn(async move {
                Self::monitor_network_dump(dump_path, is_running, config).await;
            });
        }

        Ok(())
    }

    /// Monitor QEMU's network dump file for packets (runs in background)
    async fn monitor_network_dump(
        dump_file: PathBuf, 
        is_running: Arc<AtomicBool>,
        _config: Arc<LoggingConfig>
    ) {
        let mut stats = NetworkStats::new();
        let mut last_size = 0u64;
        
        info!("Monitoring QEMU network dump at: {}", dump_file.display());
        
        while is_running.load(Ordering::Relaxed) {
            // Check if dump file exists and has grown
            if let Ok(metadata) = fs::metadata(&dump_file).await {
                let current_size = metadata.len();
                if current_size > last_size {
                    let new_data = current_size - last_size;
                    debug!("Network dump file grew by {} bytes", new_data);
                    
                    // Estimate packet count (rough approximation)
                    stats.total_packets += (new_data / 64) as u64; // Assume ~64 bytes average packet
                    last_size = current_size;
                }
            }
            
            // Sleep for a short interval
            sleep(Duration::from_millis(100)).await;
        }
        
        info!("Network monitoring stopped. Estimated stats: {:?}", stats);
    }

    pub fn stop_capture(&mut self) {
        info!("Stopping network capture");
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Process the QEMU network dump file after VM completes
    pub async fn process_dump_file(&self) -> Result<NetworkStats> {
        let mut stats = NetworkStats::new();
        
        if let Some(ref dump_file) = self.dump_file {
            if dump_file.exists() {
                match self.analyze_pcap_file(dump_file).await {
                    Ok(file_stats) => {
                        info!("Processed network dump: {} total packets", file_stats.total_packets);
                        stats = file_stats;
                    }
                    Err(e) => {
                        error!("Failed to process network dump: {}", e);
                        // Return basic stats based on file size
                        if let Ok(metadata) = std::fs::metadata(dump_file) {
                            stats.total_packets = (metadata.len() / 64) as u64;
                        }
                    }
                }
            } else {
                info!("No network dump file found - VM may not have generated network traffic");
            }
        }
        
        Ok(stats)
    }

    /// Analyze PCAP file created by QEMU
    async fn analyze_pcap_file(&self, pcap_file: &Path) -> Result<NetworkStats> {
        use std::fs::File;
        use std::io::BufReader;
        
        let mut stats = NetworkStats::new();
        
        info!("Analyzing PCAP file: {}", pcap_file.display());
        
        // For now, just count file size as a proxy for packets
        // In a full implementation, we would parse the PCAP file here
        let metadata = std::fs::metadata(pcap_file)?;
        let file_size = metadata.len();
        
        // Rough estimation: average packet size in PCAP is ~80 bytes including headers
        stats.total_packets = (file_size / 80).max(1) as u64;
        
        info!("Estimated {} packets from {} byte PCAP file", stats.total_packets, file_size);
        
        Ok(stats)
    }

    /// Get network statistics from QEMU monitor if available
    pub async fn get_monitor_stats(&self) -> Option<NetworkStats> {
        if let Some(ref monitor_sock) = self.monitor_socket {
            // Try to connect to QEMU monitor and get network info
            match self.query_qemu_monitor(monitor_sock).await {
                Ok(stats) => Some(stats),
                Err(e) => {
                    debug!("Failed to query QEMU monitor: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Query QEMU monitor for network statistics
    async fn query_qemu_monitor(&self, monitor_path: &Path) -> Result<NetworkStats> {
        // This would implement QEMU Monitor Protocol (QMP) communication
        // For now, return basic stats
        let mut stats = NetworkStats::new();
        
        info!("Querying QEMU monitor at: {}", monitor_path.display());
        
        // In a full implementation, we would:
        // 1. Connect to the QEMU monitor socket
        // 2. Send QMP commands to get network statistics
        // 3. Parse the JSON responses
        
        // For now, just return empty stats with a note
        debug!("QEMU monitor integration not fully implemented yet");
        
        Ok(stats)
    }

    pub fn get_capture_file(&self) -> Option<&Path> {
        self.capture_file.as_deref()
    }
}

impl NetworkStats {
    fn new() -> Self {
        NetworkStats {
            total_packets: 0,
            tcp_packets: 0,
            udp_packets: 0,
            dns_queries: 0,
            http_requests: 0,
            connections: HashMap::new(),
        }
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.stop_capture();
    }
}