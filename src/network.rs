use crate::config::LoggingConfig;
use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};
use pcap::{Capture, Device, Savefile, PacketCodec};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tokio::task;

pub struct NetworkMonitor {
    config: Arc<LoggingConfig>,
    capture_file: Option<PathBuf>,
    is_running: Arc<AtomicBool>,
    packet_tx: Option<mpsc::UnboundedSender<PacketInfo>>,
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

        Ok(NetworkMonitor {
            config: Arc::new(config),
            capture_file,
            is_running: Arc::new(AtomicBool::new(false)),
            packet_tx: None,
        })
    }

    pub async fn start_capture(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(anyhow!("Network capture already running"));
        }

        info!("Starting network packet capture");
        
        // Create packet processing channel
        let (tx, mut rx) = mpsc::unbounded_channel::<PacketInfo>();
        self.packet_tx = Some(tx);

        // Find suitable network interface
        let device = self.find_capture_interface()?;
        info!("Using network interface: {}", device.name);

        // Open capture
        let mut capture = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        // Set up packet capture file if enabled
        let mut savefile = if let Some(ref capture_path) = self.capture_file {
            info!("Saving packets to: {}", capture_path.display());
            Some(capture.savefile(capture_path)?)
        } else {
            None
        };

        self.is_running.store(true, Ordering::Relaxed);
        let is_running = Arc::clone(&self.is_running);
        let config = Arc::clone(&self.config);

        // Start packet capture task
        let capture_task = task::spawn_blocking(move || {
            let mut stats = NetworkStats::new();
            
            while is_running.load(Ordering::Relaxed) {
                match capture.next_packet() {
                    Ok(packet) => {
                        stats.total_packets += 1;
                        
                        // Save to file if configured
                        if let Some(ref mut sf) = savefile {
                            sf.write(&packet);
                        }

                        // Parse and analyze packet
                        if let Some(packet_info) = Self::parse_packet(&packet.data) {
                            Self::update_stats(&mut stats, &packet_info);
                            
                            // Send to analysis if channel is available
                            // Note: In a real implementation, we'd send via the channel
                            debug!("Captured packet: {} -> {} ({})", 
                                packet_info.src_ip, packet_info.dst_ip, packet_info.protocol);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal timeout, continue
                        continue;
                    }
                    Err(e) => {
                        error!("Packet capture error: {}", e);
                        break;
                    }
                }
            }
            
            info!("Packet capture stopped. Final stats: {:?}", stats);
        });

        // Start packet analysis task
        let analysis_task = task::spawn(async move {
            while let Some(packet) = rx.recv().await {
                // Process packet for specific analysis
                Self::analyze_packet(&packet).await;
            }
        });

        // Store task handles for cleanup
        // In a real implementation, you'd store these for proper cleanup

        Ok(())
    }

    pub fn stop_capture(&mut self) {
        info!("Stopping network capture");
        self.is_running.store(false, Ordering::Relaxed);
    }

    fn find_capture_interface(&self) -> Result<Device> {
        let devices = Device::list()?;
        
        // Look for the default interface first
        for device in &devices {
            if device.name.contains("eth") || device.name.contains("ens") || 
               device.name.contains("enp") || device.name == "any" {
                return Ok(device.clone());
            }
        }

        // Fallback to first available device
        devices.into_iter()
            .find(|d| !d.name.starts_with("lo"))
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
        let eth_packet = EthernetPacket::new(data)?;
        
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(eth_packet.payload())?;
                let src_ip = ipv4_packet.get_source().to_string();
                let dst_ip = ipv4_packet.get_destination().to_string();
                
                let (src_port, dst_port, protocol) = match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            (Some(tcp_packet.get_source()), 
                             Some(tcp_packet.get_destination()), 
                             "TCP".to_string())
                        } else {
                            (None, None, "TCP".to_string())
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                            (Some(udp_packet.get_source()), 
                             Some(udp_packet.get_destination()), 
                             "UDP".to_string())
                        } else {
                            (None, None, "UDP".to_string())
                        }
                    }
                    IpNextHeaderProtocols::Icmp => {
                        (None, None, "ICMP".to_string())
                    }
                    _ => {
                        (None, None, "OTHER".to_string())
                    }
                };

                Some(PacketInfo {
                    timestamp: std::time::SystemTime::now(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    size: data.len(),
                    data: data.to_vec(),
                })
            }
            _ => None
        }
    }

    fn update_stats(stats: &mut NetworkStats, packet: &PacketInfo) {
        match packet.protocol.as_str() {
            "TCP" => stats.tcp_packets += 1,
            "UDP" => {
                stats.udp_packets += 1;
                // Check for DNS (port 53)
                if packet.dst_port == Some(53) || packet.src_port == Some(53) {
                    stats.dns_queries += 1;
                }
            }
            _ => {}
        }

        // Track connections
        let connection_key = format!("{}:{} -> {}:{}", 
            packet.src_ip, packet.src_port.unwrap_or(0),
            packet.dst_ip, packet.dst_port.unwrap_or(0));
        
        *stats.connections.entry(connection_key).or_insert(0) += 1;

        // Check for HTTP traffic
        if packet.dst_port == Some(80) || packet.dst_port == Some(443) ||
           packet.src_port == Some(80) || packet.src_port == Some(443) {
            stats.http_requests += 1;
        }
    }

    async fn analyze_packet(packet: &PacketInfo) {
        // This would contain more sophisticated analysis
        debug!("Analyzing packet from {} to {}", packet.src_ip, packet.dst_ip);
        
        // Example: detect suspicious patterns
        if packet.size > 1500 {
            debug!("Large packet detected: {} bytes", packet.size);
        }
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