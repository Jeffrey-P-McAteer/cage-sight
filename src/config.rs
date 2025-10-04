use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisConfig {
    pub vm: VmConfig,
    pub disks: DisksConfig,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub analysis: AnalysisConfig_,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VmConfig {
    pub ram_mb: u32,
    pub cpus: u32,
    #[serde(default = "default_machine")]
    pub machine: String,
    #[serde(default = "default_boot")]
    pub boot: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DisksConfig {
    pub drives: Vec<DriveConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DriveConfig {
    pub name: String,
    pub path: PathBuf,
    pub format: String,
    pub interface: String,
    #[serde(default)]
    pub inspect: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_network_mode")]
    pub mode: String,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortForward {
    pub host_port: u16,
    pub guest_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_true")]
    pub capture_network: bool,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_true")]
    pub log_dns: bool,
    #[serde(default = "default_true")]
    pub log_http: bool,
    #[serde(default = "default_pcap_format")]
    pub pcap_format: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisConfig_ {
    #[serde(default = "default_runtime")]
    pub runtime_seconds: u64,
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval_seconds: u64,
    #[serde(default = "default_true")]
    pub inspect_changes: bool,
}

// Default value functions
fn default_machine() -> String {
    "q35".to_string()
}

fn default_boot() -> String {
    "c".to_string()
}

fn default_true() -> bool {
    true
}

fn default_network_mode() -> String {
    "user".to_string()
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("./analysis_output")
}

fn default_pcap_format() -> String {
    "pcap".to_string()
}

fn default_runtime() -> u64 {
    300
}

fn default_snapshot_interval() -> u64 {
    60
}

impl AnalysisConfig {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: AnalysisConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate RAM is reasonable
        if self.vm.ram_mb < 64 || self.vm.ram_mb > 32768 {
            anyhow::bail!("RAM must be between 64MB and 32GB");
        }

        // Validate CPU count
        if self.vm.cpus == 0 || self.vm.cpus > 64 {
            anyhow::bail!("CPU count must be between 1 and 64");
        }

        // Validate disk files exist
        for drive in &self.disks.drives {
            if !drive.path.exists() {
                anyhow::bail!("Disk file does not exist: {}", drive.path.display());
            }
        }

        // Validate output directory
        if let Some(parent) = self.logging.output_dir.parent() {
            if !parent.exists() {
                anyhow::bail!("Output directory parent does not exist: {}", parent.display());
            }
        }

        Ok(())
    }
}