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

    let image_span = image.image_span();

    uart::write_str("xnu-rs: loading user image link_base=0x");
    uart::write_hex_u64(image.link_base);
    uart::write_str(" span=0x");
    uart::write_hex_u64(image_span);
    uart::write_str(" load_base=0x");
    uart::write_hex_u64(load_base);
    uart::write_str("\n");

    let dst = load_base as *mut u8;
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: Caller guarantees [load_base, load_base+image_span) is valid RAM.
    unsafe {
        core::ptr::write_bytes(dst, 0, image_span as usize);
    }

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

    // Set TPIDRRO_EL0 to point to the start of the user-accessible commpage.
    // This provides a valid, zero-filled page at offset 8 (and indeed the first 16 KiB),
    // which prevents dyld's early TLS checks from null-pointer dereferencing.
    // SAFETY: Writing to a system register via inline asm; the value is a valid,
    // reserved, identity-mapped physical address in the VM space.
    unsafe {
        core::arch::asm!("msr tpidrro_el0, {}", in(reg) 0x0000_000F_FFFF_0000u64);
    }

    // SAFETY: Installs the vector table before ERET; all preconditions met.
    unsafe { exception::install_vectors() };
    // SAFETY: `frame` has a valid EL0 entry, valid stack, and pstate=0.
    unsafe { crate::arch::aarch64::context::user_enter(&raw const frame) }
}

/// Load dyld and a main executable (zsh) from the rootfs disk, set up a
/// Darwin-compatible execution environment, and ERET to dyld's entry.
///
/// Memory layout after loading (all identity-mapped):
/// ```text
/// load_base              : dyld segments
/// load_base + dyld_span  : zsh segments
/// ...                    : 64 KiB user stack with argc/argv/apple[]
/// ```
///
/// # Safety
///
/// `load_base` must be valid, writable, identity-mapped RAM with at least
/// `dyld_span + zsh_span + 64 KiB` bytes available.
pub unsafe fn load_dyld_and_run(load_base: u64) -> ! {
    use crate::fs::xnrsfs;

    const PAGE_SIZE: u64 = 4096;
    const STACK_SIZE: u64 = 64 * 1024;

    // ── Read binaries from rootfs ──────────────────────────────────────────
    let Some(dyld_bytes) = xnrsfs::read_file("/usr/lib/dyld") else {
        uart::write_str("xnu-rs: dyld not found on rootfs\n");
        loop {
            core::hint::spin_loop();
        }
    };
    let Some(zsh_bytes) = xnrsfs::read_file("/bin/zsh") else {
        uart::write_str("xnu-rs: zsh not found on rootfs\n");
        loop {
            core::hint::spin_loop();
        }
    };

    uart::write_str("xnu-rs: dyld read (");
    uart::write_hex_u64(dyld_bytes.len() as u64);
    uart::write_str(" bytes), zsh read (");
    uart::write_hex_u64(zsh_bytes.len() as u64);
    uart::write_str(" bytes)\n");

    // ── Parse Mach-O images ────────────────────────────────────────────────
    let Some(dyld) = macho::parse(&dyld_bytes) else {
        uart::write_str("xnu-rs: failed to parse dyld\n");
        loop {
            core::hint::spin_loop();
        }
    };
    let Some(zsh) = macho::parse(&zsh_bytes) else {
        uart::write_str("xnu-rs: failed to parse zsh\n");
        loop {
            core::hint::spin_loop();
        }
    };

    // ── Log dependencies ───────────────────────────────────────────────────
    super::dyld::log_deps(&dyld, "dyld");
    super::dyld::log_deps(&zsh, "zsh");

    // ── Load dyld ──────────────────────────────────────────────────────────
    let dyld_span = dyld.image_span();
    load_image(&dyld, load_base);

    // Compute the slide applied to dyld (link_base → load_base).
    // dyld links at vmaddr=0, so slide = load_base.
    let dyld_slide = load_base.wrapping_sub(dyld.link_base);
    let dyld_entry = load_base + (dyld.entry_va().unwrap_or(0) - dyld.link_base);

    // NOTE: We do NOT apply chained fixups here. dyld is designed to
    // self-rebase via its own `rebaseDyld()` during `__dyld_start`.
    // Pre-rebasing would cause a double-slide bug.

    uart::write_str("xnu-rs: dyld loaded at 0x");
    uart::write_hex_u64(load_base);
    uart::write_str(" slide=0x");
    uart::write_hex_u64(dyld_slide);
    uart::write_str(" entry=0x");
    uart::write_hex_u64(dyld_entry);
    uart::write_str("\n");

    // ── Load zsh ───────────────────────────────────────────────────────────
    let zsh_load_base = align_up(load_base + dyld_span, PAGE_SIZE * 2);
    let zsh_span = zsh.image_span();
    load_image(&zsh, zsh_load_base);

    let zsh_header_pa = zsh_load_base;
    let zsh_slide = zsh_load_base.wrapping_sub(zsh.link_base);

    uart::write_str("xnu-rs: zsh loaded at 0x");
    uart::write_hex_u64(zsh_load_base);
    uart::write_str(" slide=0x");
    uart::write_hex_u64(zsh_slide);
    uart::write_str("\n");

    // ── Set up stack with Darwin exec layout ───────────────────────────────
    //
    // Stack (sp points to argc):
    //   [sp+0]  argc = 1
    //   [sp+8]  argv[0] -> "/bin/zsh\0"
    //   [sp+16] NULL (end of argv[])
    //   [sp+24] NULL (end of envp[])
    //   [sp+32] apple[0] -> "executable_path=/bin/zsh\0"
    //   [sp+40] NULL (end of apple[])
    //   strings follow...
    let stack_pa = align_up(zsh_load_base + zsh_span, PAGE_SIZE);
    let stack_top = stack_pa + STACK_SIZE;

    // Write strings at the top of the stack region.
    let zsh_path = b"/bin/zsh\0";
    let exe_path = b"executable_path=/bin/zsh\0";

    // Place strings below stack_top (growing down from top).
    let str1_addr = stack_top - zsh_path.len() as u64;
    let str2_addr = str1_addr - exe_path.len() as u64;
    let str2_addr = align_down(str2_addr, 8);

    // SAFETY: stack region is valid writable identity-mapped RAM.
    unsafe {
        core::ptr::copy_nonoverlapping(zsh_path.as_ptr(), str1_addr as *mut u8, zsh_path.len());
        core::ptr::copy_nonoverlapping(exe_path.as_ptr(), str2_addr as *mut u8, exe_path.len());
    }

    // Place the argv/envp/apple[] table below the strings.
    // On macOS ARM64, the stack layout starts with the main executable's mach_header at [sp+0],
    // followed by argc, argv, envp, and apple.
    // Each entry is a u64 pointer.
    let table_size: u64 = 7 * 8; // mh(8) + argc(8) + argv[0](8) + null(8) + null(8) + apple[0](8) + null(8)
    let sp = align_down(str2_addr - table_size, 16);

    // SAFETY: sp..sp+table_size is within the allocated stack region.
    unsafe {
        let p = sp as *mut u64;
        p.write(zsh_header_pa); // mh (main executable mach_header)
        p.add(1).write(1); // argc
        p.add(2).write(str1_addr); // argv[0] = "/bin/zsh"
        p.add(3).write(0); // end of argv
        p.add(4).write(0); // end of envp
        p.add(5).write(str2_addr); // apple[0] = "executable_path=/bin/zsh"
        p.add(6).write(0); // end of apple
    }

    uart::write_str("xnu-rs: sp=0x");
    uart::write_hex_u64(sp);
    uart::write_str(" zsh_header=0x");
    uart::write_hex_u64(zsh_header_pa);
    uart::write_str("\n");

    // ── Flush caches ───────────────────────────────────────────────────────
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: Loaded regions are valid RAM.
    unsafe {
        flush_dcache_invalidate_icache(load_base, dyld_span as usize);
        flush_dcache_invalidate_icache(zsh_load_base, zsh_span as usize);
    }

    // ── Build trap frame ───────────────────────────────────────────────────
    // x0 = pointer to main executable's mach_header (Darwin convention).
    let mut frame = TrapFrame::new_user(dyld_entry, sp);
    frame.x[0] = zsh_header_pa;

    uart::write_str("xnu-rs: ERET to dyld entry 0x");
    uart::write_hex_u64(dyld_entry);
    uart::write_str("\n");

    // Set TPIDRRO_EL0 to point to the start of the user-accessible commpage.
    // This provides a valid, zero-filled page at offset 8 (and indeed the first 16 KiB),
    // which prevents dyld's early TLS checks from null-pointer dereferencing.
    // SAFETY: Writing to a system register via inline asm; the value is a valid,
    // reserved, identity-mapped physical address in the VM space.
    unsafe {
        core::arch::asm!("msr tpidrro_el0, {}", in(reg) 0x0000_000F_FFFF_0000u64);
    }

    // SAFETY: Vectors must be installed before ERET.
    unsafe { exception::install_vectors() };
    // SAFETY: frame has valid EL0 pc/sp/pstate.
    unsafe { crate::arch::aarch64::context::user_enter(&raw const frame) }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn load_image(image: &macho::UserImage<'_>, load_base: u64) {
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

const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
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
