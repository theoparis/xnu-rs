//! `UserImage`, `Segment`, and `Section` types produced by the Mach-O parser.

use alloc::vec::Vec;

use crate::load_cmd::{BuildVersionInfo, ChainedFixupsInfo, DyldInfoCmd, DylibRef, LinkeditRange};

// ── Section ───────────────────────────────────────────────────────────────────

/// A Mach-O section within a segment.
#[derive(Clone, Debug)]
pub struct Section {
    /// Section name (e.g. `__text`), null-padded to 16 bytes.
    pub sectname: [u8; 16],
    /// Parent segment name (e.g. `__TEXT`), null-padded to 16 bytes.
    pub segname: [u8; 16],
    /// Virtual address of the section.
    pub addr: u64,
    /// Size of the section in bytes.
    pub size: u64,
    /// File offset of the section data (0 for zerofill sections).
    pub fileoff: u32,
    /// Section type and attribute flags.
    pub flags: u32,
}

impl Section {
    /// Return the section name as a UTF-8 string slice, trimming trailing NULs.
    #[must_use]
    pub fn name_str(&self) -> &str {
        let end = self
            .sectname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.sectname.len());
        core::str::from_utf8(&self.sectname[..end]).unwrap_or("")
    }

    /// Return the segment name as a UTF-8 string slice, trimming trailing NULs.
    #[must_use]
    pub fn segname_str(&self) -> &str {
        let end = self
            .segname
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.segname.len());
        core::str::from_utf8(&self.segname[..end]).unwrap_or("")
    }
}

// ── Segment ───────────────────────────────────────────────────────────────────

/// A loadable `LC_SEGMENT_64` segment.
#[derive(Debug)]
pub struct Segment<'data> {
    /// Segment name (e.g. `__TEXT`), null-padded to 16 bytes.
    pub name: [u8; 16],
    /// Virtual address at link time.
    pub vmaddr: u64,
    /// Virtual size (may exceed `filesize` for zero-fill).
    pub vmsize: u64,
    /// File offset of segment data.
    pub fileoff: u64,
    /// File size of segment data.
    pub filesize: u64,
    /// Maximum VM protection.
    pub maxprot: u32,
    /// Initial VM protection.
    pub initprot: u32,
    /// Raw file bytes for this segment (zero-length for BSS-only segments).
    pub data: &'data [u8],
    /// Sections within this segment.
    pub sections: Vec<Section>,
}

impl<'data> Segment<'data> {
    /// Return the segment name as a UTF-8 string slice, trimming trailing NULs.
    #[must_use]
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

// ── EntryPoint ────────────────────────────────────────────────────────────────

/// Where the image's first instruction is.
#[derive(Clone, Copy, Debug)]
pub enum EntryPoint {
    /// `LC_MAIN` — file offset relative to the start of the binary.
    ///
    /// Call [`UserImage::entry_va`] to convert to a virtual address.
    FileOffset(u64),
    /// `LC_UNIXTHREAD` — virtual address directly.
    VirtualAddress(u64),
}

// ── UserImage ─────────────────────────────────────────────────────────────────

/// A parsed, loadable Mach-O 64-bit executable or dylib.
///
/// Produced by [`crate::parse`].
#[must_use]
#[derive(Debug)]
pub struct UserImage<'data> {
    /// All loadable segments in file order, excluding `__PAGEZERO`.
    pub segments: Vec<Segment<'data>>,
    /// Entry point (file offset or VA; use [`UserImage::entry_va`] to resolve).
    pub entry: EntryPoint,
    /// Lowest `vmaddr` across all segments — the image's link base.
    pub link_base: u64,

    /// Required dylib dependencies (`LC_LOAD_DYLIB`).
    pub dylib_deps: Vec<DylibRef<'data>>,
    /// Weakly-linked dylib dependencies (`LC_LOAD_WEAK_DYLIB`).
    pub weak_dylib_deps: Vec<DylibRef<'data>>,
    /// The dylib's own identity (`LC_ID_DYLIB`), if present.
    pub dylib_id: Option<DylibRef<'data>>,
    /// Run-path search entries (`LC_RPATH`).
    pub rpaths: Vec<&'data str>,
    /// Binary UUID from `LC_UUID`, if present.
    pub uuid: Option<[u8; 16]>,
    /// Chained-fixup chain location from `LC_DYLD_CHAINED_FIXUPS`, if present.
    pub chained_fixups: Option<ChainedFixupsInfo>,
    /// Rebase/bind table from `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`, if present.
    pub dyld_info: Option<DyldInfoCmd>,
    /// Code signature location from `LC_CODE_SIGNATURE`, if present.
    pub code_signature: Option<LinkeditRange>,
    /// Platform/SDK version from `LC_BUILD_VERSION`, if present.
    pub build_version: Option<BuildVersionInfo>,
    /// Encryption info from `LC_ENCRYPTION_INFO_64`, if present.
    pub encryption_info: Option<LinkeditRange>,
}

impl<'data> UserImage<'data> {
    /// Resolve the entry point to a virtual address.
    ///
    /// `FileOffset` entries are converted using the `__TEXT` segment.
    /// Returns `None` if no `__TEXT` segment exists (unexpected for valid binaries).
    #[must_use]
    pub fn entry_va(&self) -> Option<u64> {
        match self.entry {
            EntryPoint::VirtualAddress(va) => Some(va),
            EntryPoint::FileOffset(off) => {
                let text = self.segments.iter().find(|s| s.name_str() == "__TEXT")?;
                Some(text.vmaddr + off.saturating_sub(text.fileoff))
            }
        }
    }

    /// Virtual extent of all segments: `max(vmaddr + vmsize) - link_base`.
    #[must_use]
    pub fn image_span(&self) -> u64 {
        let end = self
            .segments
            .iter()
            .map(|s| s.vmaddr.saturating_add(s.vmsize))
            .max()
            .unwrap_or(self.link_base);
        end.saturating_sub(self.link_base)
    }

    /// Slide applied when loading at `load_base`: `load_base - link_base`.
    #[must_use]
    pub fn slide_for(&self, load_base: u64) -> u64 {
        load_base.wrapping_sub(self.link_base)
    }
}
