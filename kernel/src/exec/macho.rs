#[allow(clippy::wildcard_imports)]
use ::liballoc::vec::Vec;

use goblin::mach::{
    Mach, MachO,
    load_command::{LC_MAIN, LC_UNIXTHREAD},
};

use crate::arch::aarch64::uart;

const CPU_TYPE_ARM64: u32 = 0x0100_000C;

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
    match Mach::parse(bytes).ok()? {
        Mach::Binary(_) => Some(bytes),
        Mach::Fat(fat) => {
            let arch = fat.find_cputype(CPU_TYPE_ARM64).ok()??;
            let start = arch.offset as usize;
            let end = start + arch.size as usize;
            bytes.get(start..end)
        }
    }
}

/// Read the PC from an `LC_UNIXTHREAD` arm64 load command.
///
/// Layout from `cmd_offset` in `bytes`:
/// ```text
/// cmd(4) + cmdsize(4) + flavor(4) + count(4)
/// + x[0..29](232) + fp(8) + lr(8) + sp(8) + pc(8) + cpsr(4)
/// ```
/// PC is at offset 4+4+4+4 + 29×8 + 8+8+8 = 272 from the start of the LC.
fn unixthread_pc(bytes: &[u8], cmd_offset: usize) -> Option<u64> {
    const PC_OFF: usize = 4 + 4 + 4 + 4 + 29 * 8 + 8 + 8 + 8;
    let b = bytes.get(cmd_offset + PC_OFF..cmd_offset + PC_OFF + 8)?;
    Some(u64::from_le_bytes(b.try_into().ok()?))
}

/// Parse a raw Mach-O 64-bit binary (or FAT containing arm64/arm64e) and
/// extract segments and entry point.
///
/// Supports `LC_MAIN` and `LC_UNIXTHREAD` entry-point commands.
///
/// Returns `None` if the binary is not a recognisable arm64 Mach-O or is
/// missing a loadable segment and a known entry-point command.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<UserImage> {
    let slice = arm64_slice(bytes)?;
    let macho = MachO::parse(slice, 0).ok()?;

    // Collect loadable segments.
    let mut segments: Vec<Segment> = Vec::new();
    let mut link_base = u64::MAX;

    for seg in &macho.segments {
        if seg.vmsize == 0 {
            continue;
        }
        // __PAGEZERO is a virtual-only 4 GiB guard mapping with no file
        // data; including it inflates link_base and image_span to ~4 GiB.
        if seg.name().ok() == Some("__PAGEZERO") {
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
    if link_base == u64::MAX {
        link_base = 0;
    }

    // Find entry point: prefer LC_MAIN, fall back to LC_UNIXTHREAD.
    let mut entry_va: Option<u64> = None;

    for cmd in &macho.load_commands {
        match cmd.command.cmd() {
            LC_MAIN => {
                if let goblin::mach::load_command::CommandVariant::Main(main) = cmd.command {
                    let text_seg = macho
                        .segments
                        .iter()
                        .find(|s| s.name().ok() == Some("__TEXT"));
                    if let Some(text) = text_seg {
                        let entry_offset = main.entryoff.saturating_sub(text.fileoff);
                        entry_va = Some(text.vmaddr + entry_offset);
                    }
                }
                break;
            }
            LC_UNIXTHREAD => {
                if let Some(pc) = unixthread_pc(slice, cmd.offset) {
                    // pc is an absolute VA in the binary's virtual address space.
                    entry_va = Some(pc);
                }
                // Don't break; LC_MAIN takes priority if it appears later.
            }
            _ => {}
        }
    }

    let Some(entry_va) = entry_va else {
        uart::write_str("xnu-rs: Mach-O missing LC_MAIN / LC_UNIXTHREAD\n");
        return None;
    };

    Some(UserImage {
        segments,
        entry_va,
        link_base,
    })
}
