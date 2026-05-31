use crate::arch::aarch64::{context::TrapFrame, exception, uart};

use super::macho;

// Exported so dyld.rs can share the same helpers without duplicating them.
pub(super) const PAGE_SIZE: u64 = 4096;
pub(super) const STACK_SIZE: u64 = 64 * 1024;

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
    let Some(image) = macho::parse(bytes) else {
        uart::write_str("xnu-rs: failed to parse user Mach-O\n");
        loop {
            core::hint::spin_loop();
        }
    };

    let image_span = image.image_span();

    uart::write_str("xnu-rs: loading user image link_base=0x");
    uart::write_hex_u64(image.link_base);
    uart::write_str(" span=0x");
    uart::write_hex_u64(image_span);
    uart::write_str(" load_base=0x");
    uart::write_hex_u64(load_base);
    uart::write_str("\n");

    // SAFETY: Caller guarantees [load_base, load_base+image_span) is valid RAM.
    unsafe { load_image(&image, load_base) };

    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: Cache maintenance for the freshly written range.
    unsafe {
        flush_dcache_invalidate_icache(load_base, image_span as usize);
    }

    let entry_phys = load_base + (image.entry_va().unwrap_or(0) - image.link_base);
    let stack_base = align_up(load_base + image_span, PAGE_SIZE);
    let stack_top = stack_base + STACK_SIZE;

    uart::write_str("xnu-rs: entry_phys=0x");
    uart::write_hex_u64(entry_phys);
    uart::write_str(" stack_top=0x");
    uart::write_hex_u64(stack_top);
    uart::write_str("\n");

    let frame = TrapFrame::new_user(entry_phys, stack_top);

    uart::write_str("xnu-rs: ERET to EL0\n");

    // SAFETY: Writing to a system register via inline asm; value is a valid
    // reserved identity-mapped physical address for the commpage.
    unsafe {
        core::arch::asm!("msr tpidrro_el0, {}", in(reg) 0x0000_000F_FFFF_0000u64);
    }

    // SAFETY: Installs the vector table before ERET; all preconditions met.
    unsafe { exception::install_vectors() };
    // SAFETY: `frame` has a valid EL0 entry, valid stack, and pstate=0.
    unsafe { crate::arch::aarch64::context::user_enter(&raw const frame) }
}

// ── Shared helpers (pub(super) so dyld.rs can use them) ────────────────────

/// Zero the image span then copy each segment's file data into place.
///
/// # Safety
///
/// `load_base` must be valid, writable RAM of at least `image.image_span()`
/// bytes.
pub(super) unsafe fn load_image(image: &macho::UserImage<'_>, load_base: u64) {
    let span = image.image_span();
    // SAFETY: load_base is valid writable RAM; zeroing before copying handles BSS.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        core::ptr::write_bytes(load_base as *mut u8, 0, span as usize);
    }
    for seg in &image.segments {
        let offset = seg.vmaddr - image.link_base;
        let dst = (load_base + offset) as *mut u8;
        #[allow(clippy::cast_possible_truncation)]
        let copy_len = seg.data.len().min(seg.vmsize as usize);
        // SAFETY: dst is within the zeroed region.
        unsafe {
            core::ptr::copy_nonoverlapping(seg.data.as_ptr(), dst, copy_len);
        }
    }
}

/// Write a Darwin exec stack layout below `stack_top` and return the new SP.
///
/// Layout (SP points to mach_header slot):
/// ```text
/// [sp+0]   mach_header pointer (= load_base, the __TEXT base)
/// [sp+8]   argc = 1
/// [sp+16]  argv[0] -> app_path string
/// [sp+24]  NULL (end of argv)
/// [sp+32]  NULL (end of envp)
/// [sp+40]  apple[0] -> exe_path string
/// [sp+48]  NULL (end of apple)
///          strings ...
/// ```
///
/// # Safety
///
/// `stack_top` must be the top of a valid, writable, zero-initialised
/// 64 KiB stack region in identity-mapped RAM.
pub(super) unsafe fn setup_darwin_stack(
    stack_top: u64,
    mach_header: u64,
    app_path: &[u8],
    exe_path: &[u8],
) -> u64 {
    // Place strings near the top of the stack (growing downward).
    let str1_addr = stack_top - app_path.len() as u64;
    let str2_addr = align_down(str1_addr - exe_path.len() as u64, 8);

    // SAFETY: stack region is valid writable identity-mapped RAM.
    unsafe {
        core::ptr::copy_nonoverlapping(
            app_path.as_ptr(),
            str1_addr as *mut u8,
            app_path.len(),
        );
        core::ptr::copy_nonoverlapping(
            exe_path.as_ptr(),
            str2_addr as *mut u8,
            exe_path.len(),
        );
    }

    // Table: mh(8) + argc(8) + argv[0](8) + null(8) + null(8) + apple[0](8) + null(8)
    let table_size: u64 = 7 * 8;
    let sp = align_down(str2_addr - table_size, 16);

    // SAFETY: sp..sp+table_size is within the allocated stack region.
    unsafe {
        let p = sp as *mut u64;
        p.write(mach_header);  // mh
        p.add(1).write(1);     // argc
        p.add(2).write(str1_addr); // argv[0]
        p.add(3).write(0);     // argv end
        p.add(4).write(0);     // envp end
        p.add(5).write(str2_addr); // apple[0]
        p.add(6).write(0);     // apple end
    }

    sp
}

pub(super) const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

pub(super) const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Clean D-cache to `PoU` and invalidate I-cache for `[base, base+len)`.
///
/// # Safety
///
/// `base` and `len` must describe a valid memory range that was just written.
pub(super) unsafe fn flush_dcache_invalidate_icache(base: u64, len: usize) {
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
