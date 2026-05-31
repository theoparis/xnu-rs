//! Fixup application for loaded Mach-O images.
//!
//! Two formats are supported:
//!
//! * **`LC_DYLD_CHAINED_FIXUPS`** (macOS 13+ / format 12): chain-pointer walk.
//! * **`LC_DYLD_INFO_ONLY`** (pre-macOS 13): rebase opcode byte stream.
//!
//! Bind entries are skipped in both cases — symbol resolution from dylibs is
//! not yet implemented.
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

// ── LC_DYLD_INFO_ONLY rebase opcode interpreter ───────────────────────────────

/// Apply the `LC_DYLD_INFO_ONLY` rebase opcode stream to a freshly loaded image.
///
/// Reads the segment table from the raw Mach-O (including `__PAGEZERO`, so
/// segment indices in the opcode stream match what dyld expects) and slides
/// every pointer-typed rebase target.
///
/// # Safety
///
/// * `[load_base, …)` must be valid, writable, identity-mapped RAM containing
///   the loaded image.
/// * `file_bytes` must be the raw arm64 Mach-O slice that was parsed to produce
///   the loaded image; the rebase opcodes are read from its `__LINKEDIT`.
pub unsafe fn apply_dyld_info_rebase(
    file_bytes: &[u8],
    load_base: u64,
    link_base: u64,
    slide: u64,
) {
    use alloc::vec::Vec;
    use object::{
        LittleEndian as LE, Object, ObjectSegment, macho::LC_DYLD_INFO_ONLY,
        read::macho::MachOFile64,
    };

    let Ok(macho) = MachOFile64::<LE>::parse(file_bytes) else {
        return;
    };

    // Locate the rebase opcode stream offset/size from LC_DYLD_INFO_ONLY.
    let mut rebase_off: u32 = 0;
    let mut rebase_size: u32 = 0;
    let Ok(mut cmds) = macho.macho_load_commands() else {
        return;
    };
    while let Ok(Some(cmd)) = cmds.next() {
        let lc = cmd.cmd();
        if lc == LC_DYLD_INFO_ONLY || lc == object::macho::LC_DYLD_INFO {
            if let Ok(c) = cmd.data::<object::macho::DyldInfoCommand<LE>>() {
                rebase_off = c.rebase_off.get(LE);
                rebase_size = c.rebase_size.get(LE);
            }
            break;
        }
    }
    if rebase_size == 0 {
        return;
    }
    let Some(opcodes) =
        file_bytes.get(rebase_off as usize..rebase_off as usize + rebase_size as usize)
    else {
        return;
    };

    // Build a segment runtime-address table in Mach-O load-command order.
    // This MUST include __PAGEZERO (index 0) so the rebase stream indices match.
    let mut seg_runtime: Vec<u64> = Vec::new();
    for seg in macho.segments() {
        let vmaddr = seg.address();
        // __PAGEZERO has vmaddr == 0; runtime address is not meaningful for rebase.
        let runtime = if vmaddr == 0 {
            0
        } else {
            load_base.wrapping_add(vmaddr.wrapping_sub(link_base))
        };
        seg_runtime.push(runtime);
    }

    // Interpret the opcode stream.
    const POINTER_SIZE: u64 = 8;
    let mut seg_index: usize = 0;
    let mut seg_offset: u64 = 0;
    let mut i: usize = 0;

    while i < opcodes.len() {
        let byte = opcodes[i];
        i += 1;
        let opcode = byte & 0xF0;
        let imm = u64::from(byte & 0x0F);

        match opcode {
            // REBASE_OPCODE_DONE
            0x00 => break,
            // REBASE_OPCODE_SET_TYPE_IMM — type 1 = pointer; we always treat as pointer
            0x10 => {}
            // REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            0x20 => {
                seg_index = imm as usize;
                let (val, n) = read_uleb128(&opcodes[i..]);
                i += n;
                seg_offset = val;
            }
            // REBASE_OPCODE_ADD_ADDR_ULEB
            0x30 => {
                let (val, n) = read_uleb128(&opcodes[i..]);
                i += n;
                seg_offset = seg_offset.wrapping_add(val);
            }
            // REBASE_OPCODE_ADD_ADDR_IMM_SCALED
            0x40 => {
                seg_offset = seg_offset.wrapping_add(imm.wrapping_mul(POINTER_SIZE));
            }
            // REBASE_OPCODE_DO_REBASE_IMM_TIMES
            0x50 => {
                for _ in 0..imm {
                    // SAFETY: within the loaded image's writable RAM.
                    unsafe { rebase_ptr(&seg_runtime, seg_index, seg_offset, slide) };
                    seg_offset = seg_offset.wrapping_add(POINTER_SIZE);
                }
            }
            // REBASE_OPCODE_DO_REBASE_ULEB_TIMES
            0x60 => {
                let (count, n) = read_uleb128(&opcodes[i..]);
                i += n;
                for _ in 0..count {
                    // SAFETY: within the loaded image's writable RAM.
                    unsafe { rebase_ptr(&seg_runtime, seg_index, seg_offset, slide) };
                    seg_offset = seg_offset.wrapping_add(POINTER_SIZE);
                }
            }
            // REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
            0x70 => {
                // SAFETY: within the loaded image's writable RAM.
                unsafe { rebase_ptr(&seg_runtime, seg_index, seg_offset, slide) };
                let (val, n) = read_uleb128(&opcodes[i..]);
                i += n;
                seg_offset = seg_offset.wrapping_add(val).wrapping_add(POINTER_SIZE);
            }
            // REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
            0x80 => {
                let (count, n) = read_uleb128(&opcodes[i..]);
                i += n;
                let (skip, n2) = read_uleb128(&opcodes[i..]);
                i += n2;
                for _ in 0..count {
                    // SAFETY: within the loaded image's writable RAM.
                    unsafe { rebase_ptr(&seg_runtime, seg_index, seg_offset, slide) };
                    seg_offset = seg_offset.wrapping_add(skip).wrapping_add(POINTER_SIZE);
                }
            }
            _ => {} // unknown opcode — skip
        }
    }
}

/// Slide the 8-byte pointer at `seg_runtime[seg_index] + seg_offset`.
///
/// # Safety
///
/// The computed address must be valid writable RAM (within the loaded image).
unsafe fn rebase_ptr(seg_runtime: &[u64], seg_index: usize, seg_offset: u64, slide: u64) {
    let Some(&base) = seg_runtime.get(seg_index) else {
        return;
    };
    if base == 0 {
        return; // __PAGEZERO — never rebased
    }
    let addr = base.wrapping_add(seg_offset);
    // SAFETY: caller guarantees addr is in loaded RAM.
    let val = unsafe { core::ptr::read_volatile(addr as *const u64) };
    // SAFETY: writable loaded RAM.
    unsafe { core::ptr::write_volatile(addr as *mut u64, val.wrapping_add(slide)) };
}

/// Decode one ULEB128 value from `bytes`. Returns `(value, bytes_consumed)`.
fn read_uleb128(bytes: &[u8]) -> (u64, usize) {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    let mut i: usize = 0;
    loop {
        let Some(&byte) = bytes.get(i) else { break };
        i += 1;
        val |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 || shift >= 64 {
            break;
        }
    }
    (val, i)
}
