#[allow(clippy::wildcard_imports)]
use ::liballoc::vec::Vec;

use goblin::mach::{MachO, load_command::LC_MAIN};

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
    /// Virtual address of the program entry point (computed from `LC_MAIN`).
    pub entry_va: u64,
    /// Lowest `vmaddr` across all segments — the image's link base.
    pub link_base: u64,
}

/// Parse a raw Mach-O 64-bit binary and extract segments and entry point.
///
/// Returns `None` if the bytes are not a valid `AArch64` Mach-O executable or
/// if they are missing a loadable segment or an `LC_MAIN` command.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<UserImage> {
    let macho = MachO::parse(bytes, 0).ok()?;

    // Collect loadable segments.
    let mut segments: Vec<Segment> = Vec::new();
    let mut link_base = u64::MAX;

    for seg in &macho.segments {
        if seg.vmsize == 0 {
            continue;
        }
        let data = seg.data.to_vec();
        if seg.vmaddr < link_base {
            link_base = seg.vmaddr;
        }
        segments.push(Segment {
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            data,
        });
    }

    if segments.is_empty() {
        uart::write_str("xnu-rs: Mach-O has no loadable segments\n");
        return None;
    }

    // Find LC_MAIN to compute the entry VA.
    let mut entry_va: Option<u64> = None;
    for cmd in &macho.load_commands {
        if cmd.command.cmd() == LC_MAIN {
            if let goblin::mach::load_command::CommandVariant::Main(main) = cmd.command {
                let text_seg = macho
                    .segments
                    .iter()
                    .find(|s| s.name().ok() == Some("__TEXT"));
                if let Some(text) = text_seg {
                    // entry_va = text.vmaddr + (entryoff - text.fileoff)
                    let entry_offset = main.entryoff.saturating_sub(text.fileoff);
                    entry_va = Some(text.vmaddr + entry_offset);
                }
            }
            break;
        }
    }

    let Some(entry_va) = entry_va else {
        uart::write_str("xnu-rs: Mach-O missing LC_MAIN\n");
        return None;
    };

    Some(UserImage {
        segments,
        entry_va,
        link_base,
    })
}
