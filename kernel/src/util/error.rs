#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelError {
    OutOfMemory,
    InvalidAddress,
    NotFound,
    PermissionDenied,
    Again,
    Io,
    BadFd,
    NoSys,
    Fault,
}

impl From<KernelError> for i64 {
    fn from(e: KernelError) -> Self {
        match e {
            KernelError::NotFound => -2,
            KernelError::Again => -35,
            KernelError::BadFd => -9,
            KernelError::OutOfMemory => -12,
            KernelError::PermissionDenied => -1,
            KernelError::Fault => -14,
            KernelError::Io => -5,
            KernelError::InvalidAddress => -22,
            KernelError::NoSys => -78,
        }
    }
}
