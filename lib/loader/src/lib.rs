//! Mach-O 64-bit parser for arm64/arm64e binaries.
//!
//! Handles FAT and thin binaries, extracts all loadable segments with their
//! sections, and parses the load commands most relevant for dynamic linking:
//! `LC_LOAD_DYLIB`, `LC_RPATH`, `LC_UUID`, `LC_BUILD_VERSION`,
//! `LC_DYLD_CHAINED_FIXUPS`, `LC_DYLD_INFO_ONLY`, `LC_CODE_SIGNATURE`, and
//! `LC_ENCRYPTION_INFO_64`.

#![no_std]

extern crate alloc;

pub mod fat;
pub mod fixup;
pub mod image;
pub mod load_cmd;

pub use image::{EntryPoint, Section, Segment, UserImage};
pub use load_cmd::{BuildVersionInfo, ChainedFixupsInfo, DyldInfoCmd, DylibRef, LinkeditRange};

use alloc::vec::Vec;
use object::{
    LittleEndian as LE, Object, ObjectSection, ObjectSegment, SectionFlags, SegmentFlags,
    macho::{
        LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_INFO,
        LC_DYLD_INFO_ONLY, LC_ENCRYPTION_INFO_64, LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
        LC_MAIN, LC_RPATH, LC_UNIXTHREAD, LC_UUID,
    },
    read::macho::MachOFile64,
};

/// Parse a raw Mach-O 64-bit binary (or FAT containing arm64/arm64e) into a
/// [`UserImage`].
///
/// Returns `None` if:
/// - No arm64 architecture is found in the binary.
/// - The binary has no loadable segments.
/// - No recognisable entry-point command (`LC_MAIN` / `LC_UNIXTHREAD`) is present.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<UserImage<'_>> {
    let slice = fat::arm64_slice(bytes)?;
    let macho = MachOFile64::<LE>::parse(slice).ok()?;

    // ── Segments ──────────────────────────────────────────────────────────────
    let mut segments: Vec<Segment<'_>> = Vec::new();
    let mut link_base = u64::MAX;

    for seg in macho.segments() {
        let vmsize = seg.size();
        if vmsize == 0 {
            continue;
        }
        if let Ok(Some("__PAGEZERO")) = seg.name() {
            continue;
        }

        let vmaddr = seg.address();
        let (fileoff, filesize) = seg.file_range();
        let data = seg.data().unwrap_or(&[]);
        let (maxprot, initprot) = match seg.flags() {
            SegmentFlags::MachO {
                maxprot, initprot, ..
            } => (maxprot, initprot),
            _ => (0, 0),
        };

        let mut name = [0u8; 16];
        if let Ok(Some(n)) = seg.name() {
            let copy = n.len().min(16);
            name[..copy].copy_from_slice(n.as_bytes().get(..copy).unwrap_or(&[]));
        }

        if vmaddr < link_base {
            link_base = vmaddr;
        }

        segments.push(Segment {
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            data,
            sections: Vec::new(), // filled in below
        });
    }

    if segments.is_empty() {
        return None;
    }
    if link_base == u64::MAX {
        link_base = 0;
    }

    // ── Sections (matched to segments by name) ────────────────────────────────
    for sect in macho.sections() {
        let seg_name = sect.segment_name().ok().flatten().unwrap_or("");
        let Some(seg) = segments.iter_mut().find(|s| s.name_str() == seg_name) else {
            continue;
        };

        let mut sectname = [0u8; 16];
        if let Ok(name_str) = sect.name() {
            let copy = name_str.len().min(16);
            sectname[..copy].copy_from_slice(name_str.as_bytes().get(..copy).unwrap_or(&[]));
        }
        let flags = match sect.flags() {
            SectionFlags::MachO { flags } => flags,
            _ => 0,
        };

        seg.sections.push(image::Section {
            sectname,
            segname: seg.name,
            addr: sect.address(),
            size: sect.size(),
            fileoff: sect.file_range().map_or(0, |(off, _)| off as u32),
            flags,
        });
    }

    // ── Load commands ─────────────────────────────────────────────────────────
    let mut entry = None::<EntryPoint>;
    let mut dylib_deps: Vec<DylibRef<'_>> = Vec::new();
    let mut weak_dylib_deps: Vec<DylibRef<'_>> = Vec::new();
    let mut dylib_id: Option<DylibRef<'_>> = None;
    let mut rpaths: Vec<&str> = Vec::new();
    let mut uuid: Option<[u8; 16]> = None;
    let mut chained_fixups: Option<ChainedFixupsInfo> = None;
    let mut dyld_info: Option<DyldInfoCmd> = None;
    let mut code_signature: Option<LinkeditRange> = None;
    let mut build_version: Option<BuildVersionInfo> = None;
    let mut encryption_info: Option<LinkeditRange> = None;

    let Ok(mut cmds) = macho.macho_load_commands() else {
        return None;
    };

    while let Ok(Some(cmd)) = cmds.next() {
        match cmd.cmd() {
            LC_MAIN => {
                if let Ok(lc) = cmd.data::<object::macho::EntryPointCommand<LE>>() {
                    entry.get_or_insert_with(|| EntryPoint::FileOffset(lc.entryoff.get(LE)));
                }
            }
            LC_UNIXTHREAD => {
                entry.get_or_insert_with(|| EntryPoint::VirtualAddress(macho.entry()));
            }
            LC_LOAD_DYLIB => {
                if let Some(r) = parse_dylib_ref(cmd) {
                    dylib_deps.push(r);
                }
            }
            LC_LOAD_WEAK_DYLIB => {
                if let Some(r) = parse_dylib_ref(cmd) {
                    weak_dylib_deps.push(r);
                }
            }
            LC_ID_DYLIB => {
                if dylib_id.is_none() {
                    dylib_id = parse_dylib_ref(cmd);
                }
            }
            LC_RPATH => {
                if let Ok(lc) = cmd.data::<object::macho::RpathCommand<LE>>() {
                    let raw = lc_raw_bytes(lc, lc.cmdsize.get(LE));
                    // SAFETY: raw is a valid slice of the binary's bytes
                    // derived from a LoadCommandData reference with 'data lifetime.
                    let path = unsafe { load_cmd::parse_lc_str(raw, lc.path.offset.get(LE)) };
                    if !path.is_empty() {
                        rpaths.push(path);
                    }
                }
            }
            LC_UUID => {
                if let Ok(lc) = cmd.data::<object::macho::UuidCommand<LE>>() {
                    uuid = Some(lc.uuid);
                }
            }
            LC_DYLD_CHAINED_FIXUPS => {
                if let Ok(lc) = cmd.data::<object::macho::LinkeditDataCommand<LE>>() {
                    chained_fixups = Some(ChainedFixupsInfo {
                        dataoff: lc.dataoff.get(LE),
                        datasize: lc.datasize.get(LE),
                    });
                }
            }
            lc if lc == LC_DYLD_INFO || lc == LC_DYLD_INFO_ONLY => {
                if let Ok(lc) = cmd.data::<object::macho::DyldInfoCommand<LE>>() {
                    dyld_info = Some(DyldInfoCmd {
                        rebase_off: lc.rebase_off.get(LE),
                        rebase_size: lc.rebase_size.get(LE),
                        bind_off: lc.bind_off.get(LE),
                        bind_size: lc.bind_size.get(LE),
                        lazy_bind_off: lc.lazy_bind_off.get(LE),
                        lazy_bind_size: lc.lazy_bind_size.get(LE),
                        export_off: lc.export_off.get(LE),
                        export_size: lc.export_size.get(LE),
                    });
                }
            }
            LC_CODE_SIGNATURE => {
                if let Ok(lc) = cmd.data::<object::macho::LinkeditDataCommand<LE>>() {
                    code_signature = Some(LinkeditRange {
                        offset: lc.dataoff.get(LE),
                        size: lc.datasize.get(LE),
                    });
                }
            }
            LC_BUILD_VERSION => {
                if let Ok(lc) = cmd.data::<object::macho::BuildVersionCommand<LE>>() {
                    build_version = Some(BuildVersionInfo {
                        platform: lc.platform.get(LE),
                        minos: lc.minos.get(LE),
                        sdk: lc.sdk.get(LE),
                    });
                }
            }
            LC_ENCRYPTION_INFO_64 => {
                if let Ok(lc) = cmd.data::<object::macho::EncryptionInfoCommand64<LE>>() {
                    encryption_info = Some(LinkeditRange {
                        offset: lc.cryptoff.get(LE),
                        size: lc.cryptsize.get(LE),
                    });
                }
            }
            _ => {}
        }
    }

    Some(UserImage {
        segments,
        entry: entry?,
        link_base,
        dylib_deps,
        weak_dylib_deps,
        dylib_id,
        rpaths,
        uuid,
        chained_fixups,
        dyld_info,
        code_signature,
        build_version,
        encryption_info,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a dylib reference from an `LC_LOAD_DYLIB`-family load command.
fn parse_dylib_ref(cmd: object::read::macho::LoadCommandData<'_, LE>) -> Option<DylibRef<'_>> {
    let lc = cmd.data::<object::macho::DylibCommand<LE>>().ok()?;
    let raw = lc_raw_bytes(lc, lc.cmdsize.get(LE));
    // SAFETY: raw is a valid slice of the binary's bytes derived from a
    // LoadCommandData reference; the lifetime is tied to the binary slice.
    let name = unsafe { load_cmd::parse_lc_str(raw, lc.dylib.name.offset.get(LE)) };
    if name.is_empty() {
        return None;
    }
    Some(DylibRef {
        name,
        timestamp: lc.dylib.timestamp.get(LE),
        current_version: lc.dylib.current_version.get(LE),
        compat_version: lc.dylib.compatibility_version.get(LE),
    })
}

/// Reconstruct the full load command bytes from a reference to its parsed header.
///
/// `t` must be a `&T` returned by `LoadCommandData::data::<T>()`, whose backing
/// buffer has at least `cmdsize` bytes.  This gives us access to variable-length
/// data (e.g. dylib name strings) that follows the fixed-size header struct.
fn lc_raw_bytes<T>(t: &T, cmdsize: u32) -> &[u8] {
    // SAFETY: `t` points into the parsed Mach-O binary bytes.  The buffer is at
    // least `cmdsize` bytes long (guaranteed by the object crate's cmdsize check).
    // Casting `*const T → *const u8` is always valid (u8 has alignment 1).
    unsafe { core::slice::from_raw_parts(core::ptr::from_ref(t).cast::<u8>(), cmdsize as usize) }
}
