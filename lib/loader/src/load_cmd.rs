//! Typed Mach-O load command structs used by the image parser.

/// Linkedit range used by code-signature and chained-fixup commands.
#[derive(Clone, Copy, Debug)]
pub struct LinkeditRange {
    /// File offset of the data within `__LINKEDIT`.
    pub offset: u32,
    /// Size of the data in bytes.
    pub size: u32,
}

/// Chained-fixup chain location from `LC_DYLD_CHAINED_FIXUPS`.
#[derive(Clone, Copy, Debug)]
pub struct ChainedFixupsInfo {
    /// File offset of the `dyld_chained_fixups_header` blob.
    pub dataoff: u32,
    /// Size of the blob in bytes.
    pub datasize: u32,
}

/// Rebase/bind offsets from `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`.
#[derive(Clone, Copy, Debug)]
pub struct DyldInfoCmd {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Platform and SDK version from `LC_BUILD_VERSION`.
#[derive(Clone, Copy, Debug)]
pub struct BuildVersionInfo {
    /// Platform identifier (e.g. 1 = macOS, 2 = iOS).
    pub platform: u32,
    /// Minimum OS version (packed BCD: major<<16 | minor<<8 | patch).
    pub minos: u32,
    /// SDK version (same encoding as `minos`).
    pub sdk: u32,
}

/// A dylib name + version info from `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`,
/// or `LC_ID_DYLIB`.
#[derive(Clone, Copy, Debug)]
pub struct DylibRef<'data> {
    /// Null-terminated install name from the binary (e.g. `/usr/lib/libSystem.B.dylib`).
    pub name: &'data str,
    pub timestamp: u32,
    pub current_version: u32,
    pub compat_version: u32,
}

/// Parse a null-terminated UTF-8 string out of `cmd_bytes` starting at `offset`.
///
/// Returns an empty string on any parse failure.
///
/// # Safety
///
/// `cmd_bytes` must be a slice of at least `cmdsize` bytes from a valid Mach-O
/// load command with `'data` lifetime.
pub(crate) unsafe fn parse_lc_str<'data>(cmd_bytes: &'data [u8], offset: u32) -> &'data str {
    let start = offset as usize;
    let tail = match cmd_bytes.get(start..) {
        Some(s) => s,
        None => return "",
    };
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    core::str::from_utf8(&tail[..end]).unwrap_or("")
}
