#[allow(clippy::wildcard_imports)]
use ::liballoc::vec::Vec;

use object::{
    LittleEndian, Object, ObjectSegment,
    macho::CPU_TYPE_ARM64,
    read::macho::{FatArch, MachOFatFile32, MachOFatFile64, MachOFile64},
};

use crate::arch::aarch64::uart;

/// A parsed, loadable segment from a Mach-O image.
pub struct Segment {
    /// Virtual address the segment expects to be mapped at.
    pub vmaddr: u64,
    /// Virtual size of the segment (may be larger than `data`).
    pub vmsize: u64,
    /// Raw file bytes for this segment (may be empty for BSS-only segments).
    pub data: Vec<u8>,
}

/// A parsed Mach-O executable ready for loading.
#[must_use]
pub struct UserImage {
    /// All loadable segments in file order.
    pub segments: Vec<Segment>,
    /// Virtual address of the program entry point.
    pub entry_va: u64,
    /// Lowest `vmaddr` across all segments — the image's link base.
    pub link_base: u64,
}

/// Extract the arm64/arm64e slice from a (possibly FAT) binary.
///
/// Returns a subslice of `bytes` for the arm64 Mach-O, or `bytes` itself if
/// it is already a thin binary.
#[must_use]
pub fn arm64_slice(bytes: &[u8]) -> Option<&[u8]> {
    // Try FAT (64-bit arch entries) first.
    if let Ok(fat) = MachOFatFile64::parse(bytes) {
        for arch in fat.arches() {
            if arch.cputype() == CPU_TYPE_ARM64 {
                return arch.data(bytes).ok();
            }
        }
    }

    // Try FAT (32-bit arch entries) — some toolchains emit 32-bit fat headers.
    if let Ok(fat) = MachOFatFile32::parse(bytes) {
        for arch in fat.arches() {
            if arch.cputype() == CPU_TYPE_ARM64 {
                return arch.data(bytes).ok();
            }
        }
    }

    // Assume thin binary — verify with magic.
    if MachOFile64::<LittleEndian>::parse(bytes).is_ok() {
        return Some(bytes);
    }

    None
}

/// Compute the entry-point virtual address.
///
/// The object crate's `entry()` returns raw `entryoff` for `LC_MAIN` (a file
/// offset) or already a VA from `LC_UNIXTHREAD`.  We convert the `LC_MAIN`
/// case by looking up the `__TEXT` segment.
fn compute_entry_va(macho: &MachOFile64<'_, object::NativeEndian>, _slice: &[u8]) -> Option<u64> {
    use object::LittleEndian;
    use object::macho::{LC_MAIN, LC_UNIXTHREAD};

    let mut commands = macho.macho_load_commands().ok()?;
    while let Ok(Some(cmd)) = commands.next() {
        let cmd_id = cmd.cmd();
        if cmd_id == LC_MAIN {
            let entry = cmd.entry_point().ok()??;
            let entryoff = entry.entryoff.get(LittleEndian);

            // Find the __TEXT segment to convert file offset → VA.
            let text = macho
                .segments()
                .find(|s| s.name().ok().flatten() == Some("__TEXT"))?;
            let (text_fileoff, _) = text.file_range();
            let text_vmaddr = text.address();
            return Some(text_vmaddr + (entryoff.saturating_sub(text_fileoff)));
        }
        if cmd_id == LC_UNIXTHREAD {
            // The object crate's `entry()` already handles this, but for
            // completeness we use its result.
            return Some(macho.entry());
        }
    }

    None
}

/// Parse a raw Mach-O 64-bit binary (or FAT containing arm64/arm64e) and
/// extract segments and entry point.
///
/// Returns `None` if the binary is not a recognisable arm64 Mach-O or is
/// missing a loadable segment and a known entry-point command.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<UserImage> {
    let slice = arm64_slice(bytes)?;
    let macho = MachOFile64::parse(slice).ok()?;

    // Compute entry VA.  object::entry() returns the raw entryoff (file
    // offset) for LC_MAIN, or the PC from LC_UNIXTHREAD (already a VA).
    // We need to convert file offset to VA: find __TEXT and compute
    //   entry_va = text_vmaddr + (entryoff - text_fileoff)
    let Some(entry_va) = compute_entry_va(&macho, slice) else {
        uart::write_str("xnu-rs: Mach-O missing entry point\n");
        return None;
    };

    // Collect loadable segments.
    let mut segments: Vec<Segment> = Vec::new();
    let mut link_base = u64::MAX;

    for seg in macho.segments() {
        let vmsize = seg.size();
        if vmsize == 0 {
            continue;
        }

        // __PAGEZERO is a virtual-only 4 GiB guard mapping with no file
        // data; including it inflates link_base and image_span to ~4 GiB.
        if let Ok(Some(name)) = seg.name()
            && name == "__PAGEZERO"
        {
            continue;
        }

        let vmaddr = seg.address();
        let data = seg.data().map_or_else(|_| Vec::new(), <[u8]>::to_vec);

        if vmaddr < link_base {
            link_base = vmaddr;
        }

        segments.push(Segment {
            vmaddr,
            vmsize,
            data,
        });
    }

    if segments.is_empty() {
        uart::write_str("xnu-rs: Mach-O has no loadable segments\n");
        return None;
    }
    if link_base == u64::MAX {
        link_base = 0;
    }

    Some(UserImage {
        segments,
        entry_va,
        link_base,
    })
}
