use crate::config::DriveConfig;
use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};

// libguestfs integration would go here when available
// #[cfg(feature = "qcow2-inspection")]
// use libguestfs::Guestfs;

pub struct DiskInspector {
    drives: Vec<DriveConfig>,
    output_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiskAnalysis {
    pub drive_name: String,
    pub file_path: PathBuf,
    pub file_size: u64,
    pub partitions: Vec<PartitionInfo>,
    pub filesystems: Vec<FilesystemInfo>,
    pub file_listing: HashMap<String, Vec<FileEntry>>,
    pub suspicious_files: Vec<SuspiciousFile>,
    pub before_boot: Option<DiskSnapshot>,
    pub after_boot: Option<DiskSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub device: String,
    pub partition_type: String,
    pub size: u64,
    pub start_sector: u64,
    pub bootable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub device: String,
    pub filesystem_type: String,
    pub size: u64,
    pub used: u64,
    pub available: u64,
    pub mount_point: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub file_type: String,
    pub permissions: String,
    pub modified: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: String,
    pub severity: String,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiskSnapshot {
    pub timestamp: std::time::SystemTime,
    pub file_count: u64,
    pub total_size: u64,
    pub file_checksums: HashMap<String, String>,
}

impl DiskInspector {
    pub fn new(drives: Vec<DriveConfig>, output_dir: PathBuf) -> Self {
        DiskInspector {
            drives,
            output_dir,
        }
    }

    pub async fn inspect_all_drives(&self) -> Result<Vec<DiskAnalysis>> {
        info!("Starting disk inspection for {} drives", self.drives.len());
        let mut analyses = Vec::new();

        for drive in &self.drives {
            if drive.inspect {
                match self.inspect_drive(drive).await {
                    Ok(analysis) => {
                        info!("Successfully inspected drive: {}", drive.name);
                        analyses.push(analysis);
                    }
                    Err(e) => {
                        error!("Failed to inspect drive {}: {}", drive.name, e);
                    }
                }
            } else {
                info!("Skipping inspection for drive: {} (disabled)", drive.name);
            }
        }

        Ok(analyses)
    }

    pub async fn take_before_snapshot(&self) -> Result<()> {
        info!("Taking before-boot disk snapshots");
        for drive in &self.drives {
            if drive.inspect {
                let snapshot = self.create_snapshot(&drive.path).await?;
                let snapshot_path = self.output_dir.join(format!("{}_before.json", drive.name));
                self.save_snapshot(&snapshot, &snapshot_path)?;
            }
        }
        Ok(())
    }

    pub async fn take_after_snapshot(&self) -> Result<()> {
        info!("Taking after-boot disk snapshots");
        for drive in &self.drives {
            if drive.inspect {
                let snapshot = self.create_snapshot(&drive.path).await?;
                let snapshot_path = self.output_dir.join(format!("{}_after.json", drive.name));
                self.save_snapshot(&snapshot, &snapshot_path)?;
            }
        }
        Ok(())
    }

    async fn inspect_drive(&self, drive: &DriveConfig) -> Result<DiskAnalysis> {
        info!("Inspecting drive: {} at {}", drive.name, drive.path.display());

        // Get basic file information
        let metadata = std::fs::metadata(&drive.path)?;
        let file_size = metadata.len();

        // Use qemu-img for basic qcow2 information
        let qemu_info = self.get_qemu_img_info(&drive.path)?;
        debug!("QEMU image info: {}", qemu_info);

        let mut analysis = DiskAnalysis {
            drive_name: drive.name.clone(),
            file_path: drive.path.clone(),
            file_size,
            partitions: Vec::new(),
            filesystems: Vec::new(),
            file_listing: HashMap::new(),
            suspicious_files: Vec::new(),
            before_boot: None,
            after_boot: None,
        };

        // Use basic inspection for now (libguestfs integration would go here)
        warn!("Using basic inspection (libguestfs integration not implemented)");
        self.basic_inspection(&mut analysis, drive).await?;

        // Load before/after snapshots if they exist
        analysis.before_boot = self.load_snapshot(&format!("{}_before.json", drive.name)).ok();
        analysis.after_boot = self.load_snapshot(&format!("{}_after.json", drive.name)).ok();

        Ok(analysis)
    }

    // libguestfs integration would be implemented here
    // This would provide detailed filesystem inspection capabilities

    async fn basic_inspection(&self, analysis: &mut DiskAnalysis, drive: &DriveConfig) -> Result<()> {
        info!("Using basic inspection (without libguestfs) for {}", drive.name);
        
        // Use qemu-nbd to mount the image and inspect it
        // This is a more limited approach but doesn't require libguestfs
        warn!("Basic inspection not fully implemented - this would use qemu-nbd or similar tools");
        
        Ok(())
    }

    fn get_qemu_img_info(&self, path: &Path) -> Result<String> {
        let output = Command::new("qemu-img")
            .args(&["info", "--output=json"])
            .arg(path)
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    Ok(String::from_utf8_lossy(&output.stdout).to_string())
                } else {
                    Err(anyhow!("qemu-img failed: {}", String::from_utf8_lossy(&output.stderr)))
                }
            }
            Err(e) => {
                warn!("qemu-img not available: {}", e);
                Ok("qemu-img not available".to_string())
            }
        }
    }

    async fn create_snapshot(&self, disk_path: &Path) -> Result<DiskSnapshot> {
        // For now, just create a basic snapshot with file metadata
        // In a real implementation, this would use libguestfs to create comprehensive snapshots
        
        let metadata = std::fs::metadata(disk_path)?;
        
        Ok(DiskSnapshot {
            timestamp: std::time::SystemTime::now(),
            file_count: 1, // Just the disk file itself for basic implementation
            total_size: metadata.len(),
            file_checksums: HashMap::new(),
        })
    }

    fn save_snapshot(&self, snapshot: &DiskSnapshot, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(snapshot)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    fn load_snapshot(&self, filename: &str) -> Result<DiskSnapshot> {
        let path = self.output_dir.join(filename);
        let json = std::fs::read_to_string(path)?;
        let snapshot = serde_json::from_str(&json)?;
        Ok(snapshot)
    }

    fn get_file_type(&self, mode: u32) -> String {
        if mode & 0o040000 != 0 { "directory".to_string() }
        else if mode & 0o100000 != 0 { "file".to_string() }
        else if mode & 0o120000 != 0 { "symlink".to_string() }
        else if mode & 0o020000 != 0 { "chardev".to_string() }
        else if mode & 0o060000 != 0 { "blockdev".to_string() }
        else if mode & 0o010000 != 0 { "fifo".to_string() }
        else if mode & 0o140000 != 0 { "socket".to_string() }
        else { "unknown".to_string() }
    }

    fn check_suspicious_file(&self, file: &FileEntry) -> Option<SuspiciousFile> {
        // Example suspicious file detection rules
        let suspicious_patterns = [
            ("/tmp/", "Temporary file"),
            ("/var/tmp/", "Temporary file"),
            ("/.ssh/", "SSH configuration"),
            ("/etc/passwd", "Password file"),
            ("/etc/shadow", "Shadow file"),
            (".exe", "Executable file"),
            (".bat", "Batch file"),
            (".ps1", "PowerShell script"),
        ];

        for (pattern, reason) in &suspicious_patterns {
            if file.path.contains(pattern) {
                return Some(SuspiciousFile {
                    path: file.path.clone(),
                    reason: reason.to_string(),
                    severity: "medium".to_string(),
                    details: format!("File matches suspicious pattern: {}", pattern),
                });
            }
        }

        // Check for very large files
        if file.size > 100_000_000 { // 100MB
            return Some(SuspiciousFile {
                path: file.path.clone(),
                reason: "Large file".to_string(),
                severity: "low".to_string(),
                details: format!("File size: {} bytes", file.size),
            });
        }

        // Check for executable files in unusual locations
        if file.permissions.chars().nth(2) == Some('x') && 
           (file.path.contains("/tmp/") || file.path.contains("/var/tmp/")) {
            return Some(SuspiciousFile {
                path: file.path.clone(),
                reason: "Executable in temp directory".to_string(),
                severity: "high".to_string(),
                details: "Executable files in temporary directories are often suspicious".to_string(),
            });
        }

        None
    }

    pub fn export_analysis(&self, analyses: &[DiskAnalysis]) -> Result<()> {
        for analysis in analyses {
            let output_path = self.output_dir.join(format!("{}_analysis.json", analysis.drive_name));
            let json = serde_json::to_string_pretty(analysis)?;
            std::fs::write(&output_path, json)?;
            info!("Exported disk analysis to: {}", output_path.display());
        }
        Ok(())
    }
}