# Cage-Sight

A comprehensive VM analysis tool for security research and malware analysis. Cage-Sight provides automated VM execution with comprehensive network monitoring, DNS logging, and disk inspection capabilities.

## Features

- **VM Management**: Automated QEMU/KVM virtual machine execution with configurable resources
- **Network Monitoring**: Complete packet capture and analysis of all VM network traffic
- **DNS Logging**: Detailed DNS query and response tracking with domain resolution mapping
- **Disk Inspection**: Deep analysis of qcow2 disk images before and after VM execution
- **Cross-Platform**: Supports Linux, Windows, and macOS with automatic QEMU detection
- **Flexible Configuration**: TOML-based configuration system for easy customization

## Installation

### Prerequisites

#### Required
- **QEMU**: For VM execution
  - Linux: `sudo apt install qemu-system-x86` or `sudo yum install qemu-kvm`
  - Windows: Download from [QEMU website](https://www.qemu.org/download/)
  - macOS: `brew install qemu`

- **No special privileges**: Network capture uses QEMU's built-in capabilities
  - No root/administrator access required
  - No libpcap or raw socket access needed

#### Optional
- **libguestfs**: For advanced disk inspection (recommended)
  - Linux: `sudo apt install libguestfs-dev` or `sudo yum install libguestfs-devel`
  - Windows: Not available (basic inspection only)
  - macOS: `brew install libguestfs`

- **KVM**: For hardware acceleration (Linux only)
  - `sudo apt install qemu-kvm` and ensure `/dev/kvm` exists

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd cage-sight

# Build with default features (includes libguestfs if available)
cargo build --release

# Build without libguestfs support
cargo build --release --no-default-features

# Install system-wide
cargo install --path .
```

## Quick Start

1. **Generate example configuration**:
   ```bash
   cage-sight generate-config analysis.toml
   ```

2. **Edit the configuration** to match your setup:
   ```bash
   nano analysis.toml
   ```

3. **Validate your configuration**:
   ```bash
   cage-sight validate analysis.toml
   ```

4. **Run VM analysis** (no root/admin privileges required):
   ```bash
   # Headless mode (default)
   cage-sight run analysis.toml
   
   # With GUI for interactive access
   cage-sight run --gui analysis.toml
   
   # With VNC server for remote access
   cage-sight run --vnc 5901 analysis.toml
   ```

5. **Check results** in the output directory specified in your config.

## Configuration

Cage-Sight uses TOML configuration files. Here's a minimal example:

```toml
[vm]
ram_mb = 2048
cpus = 2
machine = "q35"

[[disks.drives]]
name = "primary"
path = "/path/to/disk.qcow2"
format = "qcow2"
interface = "virtio"
inspect = true

[network]
enabled = true
mode = "user"

[logging]
capture_network = true
output_dir = "./analysis_output"
log_dns = true
```

See `analysis.toml.example` for a complete configuration with all options.

### Configuration Sections

#### `[vm]`
- `ram_mb`: RAM allocation in megabytes (64-32768)
- `cpus`: Number of CPU cores (1-64)
- `machine`: QEMU machine type (e.g., "pc", "q35")
- `boot`: Boot order ("c" for disk, "d" for CD-ROM)

#### `[[disks.drives]]`
- `name`: Friendly name for the drive
- `path`: Path to qcow2/raw disk image
- `format`: Disk format ("qcow2", "raw", "vmdk")
- `interface`: Disk interface (see supported interfaces below)
- `inspect`: Enable deep disk inspection

**Supported Disk Interfaces:**
- `virtio`: Modern paravirtualized driver (best performance, requires VirtIO drivers)
- `ide`: Legacy IDE/PATA interface (universally supported, slower performance)  
- `sata`: SATA interface via AHCI controller (widely supported, good performance)
- `scsi`: SCSI interface (good for enterprise systems, requires SCSI drivers)
- `nvme`: NVMe SSD interface (fastest, requires modern OS with NVMe support)

**Guest OS Compatibility:**
- **Windows 10/11**: All interfaces supported (VirtIO requires driver installation)
- **Windows 7/8**: IDE, SATA, SCSI supported (VirtIO requires drivers)
- **Linux (modern)**: All interfaces supported natively
- **Linux (legacy)**: IDE, SATA, SCSI supported (VirtIO may need kernel modules)
- **BSD systems**: IDE, SATA, SCSI, VirtIO supported
- **Legacy/DOS systems**: IDE only

**Recommendations:**
- **General use**: `virtio` (best performance with driver support)
- **Legacy compatibility**: `ide` (slowest but universally compatible)
- **Modern without drivers**: `sata` (good balance of speed and compatibility)
- **Enterprise/server**: `scsi` (robust, good for multiple drives)
- **High performance**: `nvme` (requires modern guest OS)

#### `[network]`
- `enabled`: Enable/disable networking
- `mode`: Network mode ("user", "bridge", "tap")
- `forwards`: Port forwarding rules (optional)

#### `[logging]`
- `capture_network`: Enable packet capture
- `output_dir`: Directory for analysis results
- `log_dns`: Enable DNS query logging
- `log_http`: Enable HTTP request logging
- `pcap_format`: Packet capture format ("pcap", "pcapng")

#### `[analysis]`
- `runtime_seconds`: VM execution time (0 = indefinite)
- `snapshot_interval_seconds`: Disk snapshot interval
- `inspect_changes`: Compare before/after disk states

## Display Modes

Cage-Sight supports multiple display modes for VM interaction:

### Headless Mode (Default)
```bash
cage-sight run analysis.toml
```
- No display output
- Fully automated analysis
- Minimal resource usage
- Ideal for batch processing

### GUI Mode
```bash
cage-sight run --gui analysis.toml
```
- **Local interactive GUI window** (SDL/GTK/platform-native)
- Direct mouse/keyboard access to VM
- Real-time VM interaction and control
- **Always prioritizes local display** over remote access
- Automatically selects best display backend (SDL preferred)
- Requires graphical environment (X11/Wayland/Windows/macOS)

### VNC Mode
```bash
cage-sight run --vnc 5901 analysis.toml
```
- Remote access via VNC protocol
- Works over network connections
- No local display required
- Connect with any VNC client to `localhost:5901`

### Combined Mode
```bash
cage-sight run --gui --vnc 5902 analysis.toml
```
- GUI takes priority (local display)
- VNC ignored when GUI is enabled
- Use separate commands for different modes

### Force SDL Display
```bash
export SDL_VIDEODRIVER=x11    # Force SDL backend
cage-sight run --gui analysis.toml
```
- Ensures SDL display backend is used
- Most reliable for local GUI windows
- Works across platforms

## Usage Examples

### Basic Malware Analysis
```bash
# Create configuration for malware sample
cage-sight generate-config malware-analysis.toml

# Edit to point to your malware VM image
# Run automated analysis for 5 minutes
cage-sight run malware-analysis.toml
```

### Interactive Malware Analysis
```bash
# Run with GUI for manual interaction
cage-sight run --gui malware-analysis.toml

# Or use VNC for remote analysis
cage-sight run --vnc 5900 malware-analysis.toml
# Then connect with: vncviewer localhost:5900
```

### Network Traffic Analysis Only
```bash
# Inspect existing VM disk without running
cage-sight inspect analysis.toml

# Run VM with focus on network monitoring
cage-sight run --gui network-focused.toml
```

### System Information Check
```bash
# Verify system requirements and capabilities
cage-sight info
```

## Output and Results

Cage-Sight generates comprehensive analysis results:

### Files Created
- `capture.pcap`: Raw packet capture
- `dns_queries.log`: Detailed DNS query/response log
- `dns_stats.json`: DNS statistics and metrics
- `*_analysis.json`: Disk inspection results
- `*_before.json`/`*_after.json`: Disk snapshots
- `monitor.sock`: QEMU monitor socket (during execution)

### Analysis Reports
- **Network Statistics**: Packet counts, protocols, connections
- **DNS Analysis**: Queried domains, resolved IPs, query types
- **Disk Changes**: File system modifications, new/deleted files
- **Suspicious Indicators**: Potentially malicious files or behaviors

## Security Considerations

- **No Elevated Privileges**: Runs entirely as regular user with no special access requirements
- **Network Isolation**: VM network traffic is contained within QEMU's user-mode networking
- **Disk Snapshots**: Always work with copies of original disk images
- **Output Security**: Analysis results may contain sensitive information

## Troubleshooting

### Common Issues

**QEMU not found**:
```bash
# Check if QEMU is installed and in PATH
cage-sight info
which qemu-system-x86_64
```

**No permission issues**: Cage-sight uses QEMU's built-in network monitoring, which requires no special privileges:
```bash
# Works as regular user - no sudo needed
cage-sight run analysis.toml
```

**GUI mode not showing window**:
```bash
# Check if you have a graphical environment
echo $DISPLAY          # Should show something like :0
echo $WAYLAND_DISPLAY   # For Wayland sessions

# Check QEMU display backends available
qemu-system-x86_64 -display help

# Force specific display backend
export SDL_VIDEODRIVER=x11    # Force SDL to use X11
cage-sight run --gui analysis.toml

# Try VNC instead if GUI completely fails
cage-sight run --vnc 5900 analysis.toml
```

**VNC connection issues**:
```bash
# Check if port is available
netstat -ln | grep 5900

# Connect with VNC viewer
vncviewer localhost:5900
# Or use any VNC client with address: localhost:5900
```

**libguestfs errors**:
```bash
# Build without libguestfs if problematic
cargo build --release --no-default-features
```

**VM won't start**:
- Check disk image paths in configuration
- Verify QEMU arguments with `-v` flag
- Ensure sufficient system resources

### Debug Mode
```bash
# Enable verbose logging
cage-sight -v run analysis.toml

# Check system capabilities
cage-sight info
```

## Development

### Project Structure
```
src/
├── main.rs          # CLI interface and main application logic
├── config.rs        # Configuration parsing and validation
├── qemu.rs          # QEMU detection and management
├── vm.rs            # Virtual machine execution logic
├── network.rs       # Network packet capture and analysis
├── dns.rs           # DNS query parsing and logging
├── disk.rs          # Disk image inspection utilities
└── error.rs         # Error types and handling
```

### Building and Testing
```bash
# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy lints
cargo clippy -- -D warnings

# Build documentation
cargo doc --open
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This tool is intended for legitimate security research, malware analysis, and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.