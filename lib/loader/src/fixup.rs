//! Chained fixup application for `DYLD_CHAINED_PTR_ARM64E_USERLAND` (format 12).
//!
//! This module reads the `LC_DYLD_CHAINED_FIXUPS` blob from a loaded image and
//! rewrites every rebase pointer with the applied slide.  Bind entries are
//! skipped (they are resolved by dyld, not the kernel).
//!
//! # Chain pointer format 12 encoding
//!
//! Each 8-byte slot is:
//! ```text
//! bit 63   auth   (0 = plain, 1 = authenticated PAC pointer)
//! bit 62   bind   (1 = import entry — skip)
//! bits 62:51 next  stride (×8 bytes to next fixup; 0 = end of chain)
//!
//! Plain rebase  (auth=0, bind=0):
//!   bits 31:0   target32
//!   bits 39:32  high8
//!   new_value = slide + target32 + (high8 << 56)
//!
//! Auth rebase   (auth=1, bind=0):
//!   bits 31:0   target32
//!   new_value = slide + target32  (PAC auth disabled in SCTLR_EL1)
//! ```

/// Apply ARM64e chained fixup chains to a freshly loaded Mach-O image.
///
/// Walks every chain described in the `LC_DYLD_CHAINED_FIXUPS` blob and
/// applies the slide to each plain or authenticated rebase entry.
///
/// Does nothing if `file_bytes` has no `LC_DYLD_CHAINED_FIXUPS` command or if
/// the format is not 12.
///
/// # Safety
///
/// * `[load_base, …)` must be valid, writable, identity-mapped RAM containing
///   the already-loaded image segments.
/// * `file_bytes` must be the raw arm64/arm64e Mach-O slice used to produce
///   the loaded image (its `LC_DYLD_CHAINED_FIXUPS` offset is read, then the
///   chain data is accessed from `load_base + that_offset`).
pub unsafe fn apply_arm64e_userland(file_bytes: &[u8], load_base: u64, slide: u64) {
    use object::{LittleEndian as LE, macho::LC_DYLD_CHAINED_FIXUPS, read::macho::MachOFile64};

    let Ok(macho) = MachOFile64::<LE>::parse(file_bytes) else {
        return;
    };

    // Locate LC_DYLD_CHAINED_FIXUPS to get the file offset of the header.
    let mut fixup_dataoff: Option<u32> = None;
    let Ok(mut cmds) = macho.macho_load_commands() else {
        return;
    };
    while let Ok(Some(cmd)) = cmds.next() {
        if cmd.cmd() == LC_DYLD_CHAINED_FIXUPS {
            if let Ok(lc) = cmd.data::<object::macho::LinkeditDataCommand<LE>>() {
                fixup_dataoff = Some(lc.dataoff.get(LE));
            }
            break;
        }
    }
    let Some(foff) = fixup_dataoff else { return };

    // The fixup blob lives in __LINKEDIT which was loaded at load_base + vmaddr.
    // For dyld (links at 0) the file offset equals the runtime address minus load_base.
    let fixup_runtime = load_base + u64::from(foff);

    // dyld_chained_fixups_header:
    //   u32 fixups_version
    //   u32 starts_offset   ← offset from header start to dyld_chained_starts_in_image
    // SAFETY: fixup_runtime is in loaded RAM.
    let starts_offset = unsafe { core::ptr::read_volatile((fixup_runtime + 4) as *const u32) };
    let starts_base = fixup_runtime + u64::from(starts_offset);

    // dyld_chained_starts_in_image: { u32 seg_count, u32 seg_info_offset[seg_count] }
    // SAFETY: starts_base is in loaded RAM.
    let seg_count = unsafe { core::ptr::read_volatile(starts_base as *const u32) } as usize;

    for seg_idx in 0..seg_count {
        let off_ptr = (starts_base + 4 + (seg_idx as u64) * 4) as *const u32;
        // SAFETY: within loaded RAM.
        let seg_info_off = unsafe { core::ptr::read_volatile(off_ptr) };
        if seg_info_off == 0 {
            continue;
        }

        let seg_info = starts_base + u64::from(seg_info_off);
        // dyld_chained_starts_in_segment:
        //   +0  u32 size
        //   +4  u16 page_size
        //   +6  u16 pointer_format
        //   +8  u64 segment_offset
        //   +16 u32 max_valid_pointer
        //   +20 u16 page_count
        //   +22 u16 page_start[page_count]
        // SAFETY: All reads below are within the loaded-RAM region guaranteed by
        // the caller.  Addresses are derived from `starts_base` which was
        // computed from the fixup blob at `load_base + dataoff`.
        let page_size = u64::from(
            // SAFETY: seg_info+4 is within loaded RAM; value is 2 bytes.
            unsafe { core::ptr::read_volatile((seg_info + 4) as *const u16) },
        );
        // SAFETY: seg_info+6 is within loaded RAM; value is 2 bytes.
        let ptr_format = unsafe { core::ptr::read_volatile((seg_info + 6) as *const u16) };
        // SAFETY: seg_info+8 is within loaded RAM; value is 8 bytes.
        let segment_offset = unsafe { core::ptr::read_volatile((seg_info + 8) as *const u64) };
        let page_count = u64::from(
            // SAFETY: seg_info+20 is within loaded RAM; value is 2 bytes.
            unsafe { core::ptr::read_volatile((seg_info + 20) as *const u16) },
        );

        // Only format 12 (DYLD_CHAINED_PTR_ARM64E_USERLAND) is handled.
        if ptr_format != 12 {
            continue;
        }

        for page_idx in 0..page_count {
            let start_off_ptr = (seg_info + 22 + page_idx * 2) as *const u16;
            // SAFETY: within loaded RAM.
            let page_start = unsafe { core::ptr::read_volatile(start_off_ptr) };
            if page_start == 0xFFFF {
                continue; // no fixups on this page
            }

            let page_addr = load_base + segment_offset + page_idx * page_size;
            let mut ptr_addr = page_addr + u64::from(page_start);

            loop {
                // SAFETY: ptr_addr is in loaded RAM.
                let val = unsafe { core::ptr::read_volatile(ptr_addr as *const u64) };

                let auth = (val >> 63) & 1;
                let bind = (val >> 62) & 1;

                let next = if bind != 0 {
                    (val >> 51) & 0x7FF // bind entry — skip, just advance
                } else if auth != 0 {
                    let target32 = val & 0xFFFF_FFFF;
                    let next = (val >> 51) & 0x7FF;
                    let new_val = slide + target32;
                    // SAFETY: ptr_addr is writable loaded RAM.
                    unsafe { core::ptr::write_volatile(ptr_addr as *mut u64, new_val) };
                    next
                } else {
                    let target32 = val & 0xFFFF_FFFF;
                    let high8 = (val >> 32) & 0xFF;
                    let next = (val >> 51) & 0x7FF;
                    let new_val = slide + target32 + (high8 << 56);
                    // SAFETY: ptr_addr is writable loaded RAM.
                    unsafe { core::ptr::write_volatile(ptr_addr as *mut u64, new_val) };
                    next
                };

                if next == 0 {
                    break;
                }
                ptr_addr += next * 8;
            }
        }
    }
}
