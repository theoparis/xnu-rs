use crate::arch::aarch64::{context::TrapFrame, exception, uart};

use super::macho;

/// Load a bare-metal Mach-O binary into physical memory and jump to EL0.
///
/// `load_base` is the first free physical address where segments will be
/// copied.  Segments are laid out contiguously relative to their virtual
/// addresses starting from `UserImage::link_base`.
///
/// A 64 KiB user stack is placed immediately after the last segment.
///
/// # Safety
///
/// * `load_base` must point to valid, writable, identity-mapped RAM of at
///   least `image_size + STACK_SIZE` bytes that is not used by the kernel.
/// * This function never returns.
pub unsafe fn load_and_run(bytes: &[u8], load_base: u64) -> ! {
    const STACK_SIZE: u64 = 64 * 1024;
    const PAGE_SIZE: u64 = 4096;

    let Some(image) = macho::parse(bytes) else {
        uart::write_str("xnu-rs: failed to parse user Mach-O\n");
        loop {
            core::hint::spin_loop();
        }
    };

    // Compute the total span of virtual addresses covered by the image.
    let mut image_end = 0_u64;
    for seg in &image.segments {
        let end = seg.vmaddr.saturating_add(seg.vmsize);
        if end > image_end {
            image_end = end;
        }
    }
    let image_span = image_end.saturating_sub(image.link_base);

    uart::write_str("xnu-rs: loading user image link_base=0x");
    uart::write_hex_u64(image.link_base);
    uart::write_str(" span=0x");
    uart::write_hex_u64(image_span);
    uart::write_str(" load_base=0x");
    uart::write_hex_u64(load_base);
    uart::write_str("\n");

    // Zero the destination region to handle BSS gaps between segments.
    let dst = load_base as *mut u8;
    // SAFETY: Caller guarantees [load_base, load_base+image_span) is valid RAM.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        core::ptr::write_bytes(dst, 0, image_span as usize);
    }

    // Copy each segment's data.
    for seg in &image.segments {
        let offset = seg.vmaddr - image.link_base;
        let seg_dst = (load_base + offset) as *mut u8;
        #[allow(clippy::cast_possible_truncation)]
        let copy_len = seg.data.len().min(seg.vmsize as usize);
        // SAFETY: Within the zeroed region allocated above.
        unsafe {
            core::ptr::copy_nonoverlapping(seg.data.as_ptr(), seg_dst, copy_len);
        }
    }

    // Flush D-cache and invalidate I-cache for the loaded region.
    // SAFETY: Cache maintenance for the freshly written range.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        flush_dcache_invalidate_icache(load_base, image_span as usize);
    }

    // Entry point physical address = load_base + (entry_va - link_base).
    let entry_phys = load_base + (image.entry_va - image.link_base);

    // Place the user stack after the image, aligned to a page boundary.
    let stack_base = align_up(load_base + image_span, PAGE_SIZE);
    let stack_top = stack_base + STACK_SIZE;

    uart::write_str("xnu-rs: entry_phys=0x");
    uart::write_hex_u64(entry_phys);
    uart::write_str(" stack_top=0x");
    uart::write_hex_u64(stack_top);
    uart::write_str("\n");

    let frame = TrapFrame::new_user(entry_phys, stack_top);

    uart::write_str("xnu-rs: ERET to EL0\n");

    // SAFETY: Installs the vector table before ERET; all preconditions met.
    unsafe { exception::install_vectors() };
    // SAFETY: `frame` has a valid EL0 entry, valid stack, and pstate=0.
    unsafe { crate::arch::aarch64::context::user_enter(&raw const frame) }
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Clean D-cache to `PoU` and invalidate I-cache for `[base, base+len)`.
///
/// # Safety
///
/// `base` and `len` must describe a valid memory range that was just written.
unsafe fn flush_dcache_invalidate_icache(base: u64, len: usize) {
    const CACHE_LINE: u64 = 64;
    let end = base + len as u64;
    let mut addr = base & !(CACHE_LINE - 1);
    while addr < end {
        // SAFETY: `DC CVAU` cache maintenance on a valid address.
        unsafe {
            core::arch::asm!("dc cvau, {a}", a = in(reg) addr, options(nostack, preserves_flags));
        }
        addr += CACHE_LINE;
    }
    // SAFETY: `DSB ISH` ensures all DC operations complete before IC invalidation.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };

    addr = base & !(CACHE_LINE - 1);
    while addr < end {
        // SAFETY: `IC IVAU` invalidates the I-cache by VA.
        unsafe {
            core::arch::asm!("ic ivau, {a}", a = in(reg) addr, options(nostack, preserves_flags));
        }
        addr += CACHE_LINE;
    }
    // SAFETY: `DSB ISH` + `ISB` complete IC invalidation before next fetch.
    unsafe {
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}
