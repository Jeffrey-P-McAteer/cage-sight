mod config;
mod qemu;
mod vm;
mod network;
mod dns;
mod disk;
mod error;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{info, error};
use std::path::PathBuf;
use tokio::signal;

#[derive(Parser)]
#[command(name = "cage-sight")]
#[command(about = "A VM analysis tool for security research and malware analysis")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, help = "Configuration file path")]
    config: Option<PathBuf>,
    
    #[arg(short, long, help = "Enable verbose logging")]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full VM analysis session
    Run {
        #[arg(help = "Analysis configuration file")]
        config_file: PathBuf,
    },
    /// Inspect disk images without running VM
    Inspect {
        #[arg(help = "Analysis configuration file")]
        config_file: PathBuf,
    },
    /// Validate configuration file
    Validate {
        #[arg(help = "Configuration file to validate")]
        config_file: PathBuf,
    },
    /// Generate example configuration
    GenerateConfig {
        #[arg(help = "Output path for example config")]
        output: PathBuf,
    },
    /// Show system information and requirements
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();

    info!("Starting Cage-Sight VM Analysis Tool");

    match cli.command {
        Commands::Run { config_file } => {
            run_analysis(config_file).await?;
        }
        Commands::Inspect { config_file } => {
            inspect_disks(config_file).await?;
        }
        Commands::Validate { config_file } => {
            validate_config(config_file).await?;
        }
        Commands::GenerateConfig { output } => {
            generate_config(output).await?;
        }
        Commands::Info => {
            show_system_info().await?;
        }
    }

    Ok(())
}

async fn run_analysis(config_file: PathBuf) -> Result<()> {
    info!("Loading configuration from: {}", config_file.display());
    let config = config::AnalysisConfig::from_file(&config_file)?;
    config.validate()?;

    info!("Starting full VM analysis");
    
    // Create output directory
    std::fs::create_dir_all(&config.logging.output_dir)?;

    // Initialize components
    let mut vm_manager = vm::VmManager::new(config.clone())?;
    let mut network_monitor = network::NetworkMonitor::new(config.logging.clone())?;
    let dns_monitor = dns::DnsMonitor::new(&config.logging.output_dir)?;
    let disk_inspector = disk::DiskInspector::new(
        config.disks.drives.clone(),
        config.logging.output_dir.clone(),
    );

    // Take before-boot snapshots
    if config.analysis.inspect_changes {
        info!("Taking before-boot disk snapshots");
        disk_inspector.take_before_snapshot().await?;
    }

    // Start network monitoring
    if config.logging.capture_network {
        info!("Starting network monitoring");
        network_monitor.start_capture().await?;
    }

    // Set up signal handling for graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal");
    };

    // Run VM analysis
    tokio::select! {
        result = vm_manager.run_analysis() => {
            match result {
                Ok(()) => info!("VM analysis completed successfully"),
                Err(e) => error!("VM analysis failed: {}", e),
            }
        }
        _ = shutdown_signal => {
            info!("Shutting down due to signal");
        }
    }

    // Stop network monitoring
    network_monitor.stop_capture();

    // Take after-boot snapshots
    if config.analysis.inspect_changes {
        info!("Taking after-boot disk snapshots");
        disk_inspector.take_after_snapshot().await?;
    }

    // Generate final reports
    info!("Generating analysis reports");
    let disk_analyses = disk_inspector.inspect_all_drives().await?;
    disk_inspector.export_analysis(&disk_analyses)?;

    // Export DNS statistics
    let dns_stats_path = config.logging.output_dir.join("dns_stats.json");
    dns_monitor.export_stats(&dns_stats_path)?;
    dns_monitor.print_summary();

    info!("Analysis complete. Results saved to: {}", config.logging.output_dir.display());
    Ok(())
}

async fn inspect_disks(config_file: PathBuf) -> Result<()> {
    info!("Loading configuration from: {}", config_file.display());
    let config = config::AnalysisConfig::from_file(&config_file)?;
    config.validate()?;

    info!("Inspecting disk images without running VM");
    
    // Create output directory
    std::fs::create_dir_all(&config.logging.output_dir)?;

    let disk_inspector = disk::DiskInspector::new(
        config.disks.drives.clone(),
        config.logging.output_dir.clone(),
    );

    let analyses = disk_inspector.inspect_all_drives().await?;
    disk_inspector.export_analysis(&analyses)?;

    info!("Disk inspection complete. Results saved to: {}", config.logging.output_dir.display());
    Ok(())
}

async fn validate_config(config_file: PathBuf) -> Result<()> {
    info!("Validating configuration file: {}", config_file.display());
    
    match config::AnalysisConfig::from_file(&config_file) {
        Ok(config) => {
            match config.validate() {
                Ok(()) => {
                    info!("✓ Configuration is valid");
                    
                    // Show summary
                    info!("Configuration Summary:");
                    info!("  VM: {} MB RAM, {} CPUs", config.vm.ram_mb, config.vm.cpus);
                    info!("  Disks: {} drive(s)", config.disks.drives.len());
                    info!("  Network: {} ({})", 
                        if config.network.enabled { "enabled" } else { "disabled" },
                        config.network.mode);
                    info!("  Output: {}", config.logging.output_dir.display());
                }
                Err(e) => {
                    error!("✗ Configuration validation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("✗ Failed to parse configuration: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn generate_config(output: PathBuf) -> Result<()> {
    info!("Generating example configuration at: {}", output.display());
    
    let example_config = include_str!("../analysis.toml.example");
    std::fs::write(&output, example_config)?;
    
    info!("✓ Example configuration generated");
    info!("Edit the file and adjust paths, VM settings, and analysis options as needed");
    
    Ok(())
}

async fn show_system_info() -> Result<()> {
    info!("=== Cage-Sight System Information ===");
    
    // Check QEMU installation
    match qemu::QemuDetector::find_qemu() {
        Ok(qemu_path) => {
            info!("✓ QEMU found at: {}", qemu_path.display());
            match qemu::QemuDetector::verify_qemu(&qemu_path) {
                Ok(version) => info!("  Version: {}", version.lines().next().unwrap_or("unknown")),
                Err(e) => info!("  Warning: {}", e),
            }
        }
        Err(e) => {
            error!("✗ QEMU not found: {}", e);
        }
    }

    // Check acceleration support
    if qemu::QemuDetector::check_kvm_support() {
        info!("✓ KVM acceleration available");
    } else {
        info!("! KVM acceleration not available");
    }

    // libguestfs integration not yet implemented
    info!("! libguestfs support not implemented (basic inspection only)");

    // Check network capture capabilities
    match network::NetworkMonitor::new(Default::default()) {
        Ok(_) => info!("✓ Network capture capabilities available"),
        Err(e) => info!("! Network capture may have issues: {}", e),
    }

    info!("=== Requirements ===");
    info!("- QEMU/KVM for VM execution");
    info!("- libpcap-dev for network capture");
    info!("- libguestfs for advanced disk inspection (optional)");
    info!("- Sufficient disk space for VM images and logs");
    info!("- Network interface access for packet capture");

    Ok(())
}

impl Default for config::LoggingConfig {
    fn default() -> Self {
        Self {
            capture_network: true,
            output_dir: PathBuf::from("./analysis_output"),
            log_dns: true,
            log_http: true,
            pcap_format: "pcap".to_string(),
        }
    }
}
