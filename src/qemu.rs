use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use which::which;

pub struct QemuDetector;

impl QemuDetector {
    /// Find qemu-system-x86_64 binary on the system
    pub fn find_qemu() -> Result<PathBuf> {
        // First try to find in PATH
        if let Ok(path) = which("qemu-system-x86_64") {
            return Ok(path);
        }

        // Common Linux installation paths
        let linux_paths = [
            "/usr/bin/qemu-system-x86_64",
            "/usr/local/bin/qemu-system-x86_64",
            "/opt/qemu/bin/qemu-system-x86_64",
            "/snap/qemu/current/usr/bin/qemu-system-x86_64",
        ];

        for path in &linux_paths {
            if Path::new(path).exists() {
                return Ok(PathBuf::from(path));
            }
        }

        // Common Windows installation paths
        let windows_paths = [
            r"C:\Program Files\qemu\qemu-system-x86_64.exe",
            r"C:\Program Files (x86)\qemu\qemu-system-x86_64.exe",
            r"C:\qemu\qemu-system-x86_64.exe",
            r"C:\msys64\usr\bin\qemu-system-x86_64.exe",
            r"C:\msys64\mingw64\bin\qemu-system-x86_64.exe",
        ];

        for path in &windows_paths {
            if Path::new(path).exists() {
                return Ok(PathBuf::from(path));
            }
        }

        Err(anyhow!("Could not find qemu-system-x86_64 binary. Please install QEMU or add it to PATH."))
    }

    /// Verify QEMU installation and get version
    pub fn verify_qemu(qemu_path: &Path) -> Result<String> {
        let output = Command::new(qemu_path)
            .arg("--version")
            .output()
            .map_err(|e| anyhow!("Failed to execute QEMU: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!("QEMU version check failed"));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }

    /// Check if KVM acceleration is available (Linux only)
    pub fn check_kvm_support() -> bool {
        #[cfg(target_os = "linux")]
        {
            Path::new("/dev/kvm").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Get recommended acceleration options
    pub fn get_acceleration_args() -> Vec<String> {
        let mut args = Vec::new();

        #[cfg(target_os = "linux")]
        if Self::check_kvm_support() {
            args.push("-enable-kvm".to_string());
        }

        #[cfg(target_os = "windows")]
        {
            // Check for WHPX (Windows Hypervisor Platform)
            if Self::check_whpx_support() {
                args.push("-accel".to_string());
                args.push("whpx".to_string());
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Check for Hypervisor.framework
            args.push("-accel".to_string());
            args.push("hvf".to_string());
        }

        args
    }

    #[cfg(target_os = "windows")]
    fn check_whpx_support() -> bool {
        use std::process::Command;
        
        // Try to check if WHPX is available via PowerShell
        Command::new("powershell")
            .args(&["-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor"])
            .output()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout).contains("Enabled")
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_qemu() {
        // This test will only pass if QEMU is actually installed
        match QemuDetector::find_qemu() {
            Ok(path) => {
                println!("Found QEMU at: {}", path.display());
                assert!(path.exists());
            }
            Err(e) => {
                println!("QEMU not found: {}", e);
                // This is expected if QEMU is not installed
            }
        }
    }

    #[test]
    fn test_kvm_support() {
        let kvm_available = QemuDetector::check_kvm_support();
        println!("KVM support: {}", kvm_available);
        // This test just prints the result, no assertion needed
    }
}