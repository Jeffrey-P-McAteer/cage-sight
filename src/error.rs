use thiserror::Error;

#[derive(Error, Debug)]
pub enum CageSightError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("QEMU error: {0}")]
    Qemu(#[from] QemuError),

    #[error("Network monitoring error: {0}")]
    Network(#[from] NetworkError),

    #[error("DNS monitoring error: {0}")]
    Dns(#[from] DnsError),

    #[error("Disk inspection error: {0}")]
    Disk(#[from] DiskError),

    #[error("VM execution error: {0}")]
    VmExecution(#[from] VmError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    TomlParsing(#[from] toml::de::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Operation timed out: {0}")]
    Timeout(String),

    #[error("System requirements not met: {0}")]
    SystemRequirements(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid configuration file: {0}")]
    InvalidFile(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for {field}: {value} (reason: {reason})")]
    InvalidValue {
        field: String,
        value: String,
        reason: String,
    },

    #[error("File path does not exist: {0}")]
    PathNotFound(String),

    #[error("Disk file validation failed: {0}")]
    DiskValidation(String),
}

#[derive(Error, Debug)]
pub enum QemuError {
    #[error("QEMU binary not found")]
    NotFound,

    #[error("QEMU version check failed: {0}")]
    VersionCheck(String),

    #[error("QEMU execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Unsupported QEMU version: {version} (minimum required: {min_version})")]
    UnsupportedVersion { version: String, min_version: String },

    #[error("Hardware acceleration not available: {0}")]
    NoAcceleration(String),

    #[error("Invalid QEMU arguments: {0}")]
    InvalidArguments(String),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Packet capture initialization failed: {0}")]
    CaptureInit(String),

    #[error("Packet parsing error: {0}")]
    PacketParsing(String),

    #[error("Network permissions insufficient: {0}")]
    InsufficientPermissions(String),

    #[error("Capture file write error: {0}")]
    CaptureFileError(String),

    #[error("Network device busy: {0}")]
    DeviceBusy(String),
}

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS packet parsing failed: {0}")]
    PacketParsing(String),

    #[error("DNS log file error: {0}")]
    LogFile(String),

    #[error("Invalid DNS message format: {0}")]
    InvalidFormat(String),

    #[error("DNS statistics export failed: {0}")]
    StatsExport(String),
}

#[derive(Error, Debug)]
pub enum DiskError {
    #[error("Disk image not accessible: {path} (reason: {reason})")]
    NotAccessible { path: String, reason: String },

    #[error("Unsupported disk format: {0}")]
    UnsupportedFormat(String),

    #[error("libguestfs error: {0}")]
    LibGuestFs(String),

    #[error("Filesystem mount failed: {device} (reason: {reason})")]
    MountFailed { device: String, reason: String },

    #[error("File inspection failed: {0}")]
    InspectionFailed(String),

    #[error("Snapshot creation failed: {0}")]
    SnapshotFailed(String),

    #[error("Checksum calculation failed: {0}")]
    ChecksumFailed(String),
}

#[derive(Error, Debug)]
pub enum VmError {
    #[error("VM startup failed: {0}")]
    StartupFailed(String),

    #[error("VM shutdown failed: {0}")]
    ShutdownFailed(String),

    #[error("VM process crashed: {0}")]
    ProcessCrashed(String),

    #[error("VM monitor communication failed: {0}")]
    MonitorFailed(String),

    #[error("VM resource allocation failed: {resource} (requested: {requested}, available: {available})")]
    ResourceAllocation {
        resource: String,
        requested: String,
        available: String,
    },

    #[error("VM timeout: operation '{operation}' exceeded {timeout_secs} seconds")]
    Timeout {
        operation: String,
        timeout_secs: u64,
    },
}

pub type Result<T> = std::result::Result<T, CageSightError>;

// Helper functions for creating specific errors
impl CageSightError {
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    pub fn system_requirements(msg: impl Into<String>) -> Self {
        Self::SystemRequirements(msg.into())
    }
}

impl ConfigError {
    pub fn invalid_value(field: impl Into<String>, value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidValue {
            field: field.into(),
            value: value.into(),
            reason: reason.into(),
        }
    }
}

impl QemuError {
    pub fn unsupported_version(version: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self::UnsupportedVersion {
            version: version.into(),
            min_version: min_version.into(),
        }
    }
}

impl NetworkError {
    pub fn insufficient_permissions(msg: impl Into<String>) -> Self {
        Self::InsufficientPermissions(msg.into())
    }
}

impl DiskError {
    pub fn not_accessible(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::NotAccessible {
            path: path.into(),
            reason: reason.into(),
        }
    }

    pub fn mount_failed(device: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::MountFailed {
            device: device.into(),
            reason: reason.into(),
        }
    }
}

impl VmError {
    pub fn resource_allocation(resource: impl Into<String>, requested: impl Into<String>, available: impl Into<String>) -> Self {
        Self::ResourceAllocation {
            resource: resource.into(),
            requested: requested.into(),
            available: available.into(),
        }
    }

    pub fn timeout(operation: impl Into<String>, timeout_secs: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            timeout_secs,
        }
    }
}