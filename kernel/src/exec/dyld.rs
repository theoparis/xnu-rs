//! Kernel-resident minimal dynamic linker.
//!
//! Loads a Mach-O executable (with `LC_MAIN`) into physical memory, applies
//! any chained-fixup rebase entries, sets up a Darwin-compatible user stack,
//! and ERTs to the entry point at EL0.  No Apple dyld binary is required.
//!
//! Bind entries (references to external dylib symbols) are left zeroed — the
//! demo binary (`userspace/hello`) has none.  Full symbol resolution will be
//! added as dylib support grows.

use crate::arch::aarch64::{
    context::{TrapFrame, user_enter},
    exception::install_vectors,
    uart,
};

use super::loader::{
    PAGE_SIZE, STACK_SIZE, align_up, flush_dcache_invalidate_icache, load_image,
    setup_darwin_stack,
};
use super::macho::UserImage;

/// Load a Mach-O `image` at `load_base`, apply fixups, and ERET to `LC_MAIN`
/// entry at EL0 with a Darwin-compatible stack layout.
///
/// # Safety
///
/// * `load_base` must be valid, writable, identity-mapped RAM with at least
///   `image.image_span() + STACK_SIZE` bytes available past the kernel.
/// * `file_bytes` must be the raw Mach-O slice that was parsed to produce
///   `image` — needed for the fixup walk.
/// * This function never returns.
pub unsafe fn load_and_run(image: &UserImage<'_>, file_bytes: &[u8], load_base: u64) -> ! {
    uart::write_str("xnu-rs: dyld: loading image link_base=0x");
    uart::write_hex_u64(image.link_base);
    uart::write_str(" span=0x");
    uart::write_hex_u64(image.image_span());
    uart::write_str(" load_base=0x");
    uart::write_hex_u64(load_base);
    uart::write_str("\n");

    // 1. Copy segments into RAM (zeroes first, then overlays file data).
    // SAFETY: load_base is valid RAM per caller contract; load_image handles alignment.
    unsafe { load_image(image, load_base) };

    // 2. Apply chained fixups (rebase pass) if the binary has them.
    //    LC_DYLD_CHAINED_FIXUPS is the newer format (macOS 13+, format 12).
    //    LC_DYLD_INFO_ONLY (older format) is not currently interpreted — for
    //    our no_std hello binary the rebase table is empty so this is fine.
    let slide = image.slide_for(load_base);
    if image.chained_fixups.is_some() {
        uart::write_str("xnu-rs: dyld: applying chained fixups slide=0x");
        uart::write_hex_u64(slide);
        uart::write_str("\n");
        // SAFETY: image segments are loaded at load_base in valid RAM;
        // file_bytes is the source Mach-O with the fixup chain data.
        unsafe { ::loader::fixup::apply_arm64e_userland(file_bytes, load_base, slide) };
    }

    // 3. Flush D-cache and invalidate I-cache for the loaded region.
    // SAFETY: [load_base, load_base + image_span) is the freshly written range.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        flush_dcache_invalidate_icache(load_base, image.image_span() as usize);
    }

    // 4. Compute physical entry address.
    let entry_va = image.entry_va().unwrap_or(0);
    let entry_phys = load_base + (entry_va - image.link_base);
    uart::write_str("xnu-rs: dyld: entry_va=0x");
    uart::write_hex_u64(entry_va);
    uart::write_str(" entry_phys=0x");
    uart::write_hex_u64(entry_phys);
    uart::write_str("\n");

    // 5. Set up Darwin stack layout just above the image span.
    let stack_base = align_up(load_base + image.image_span(), PAGE_SIZE);
    let stack_top = stack_base + STACK_SIZE;
    // SAFETY: stack region is valid writable identity-mapped RAM.
    let sp = unsafe {
        setup_darwin_stack(
            stack_top,
            load_base,
            b"/bin/hello\0",
            b"executable_path=/bin/hello\0",
        )
    };

    // 6. Build trap frame: x0 = mach_header (Darwin ABI convention for LC_MAIN).
    let mut frame = TrapFrame::new_user(entry_phys, sp);
    frame.x[0] = load_base; // mach_header is at load_base (__TEXT base)

    // 7. Set commpage pointer so any early TLS/commpage reads don't fault.
    // SAFETY: Writing TPIDRRO_EL0 via asm; value is a valid, reserved PA.
    unsafe {
        core::arch::asm!(
            "msr tpidrro_el0, {}",
            in(reg) 0x0000_000F_FFFF_0000u64,
        );
    }

    uart::write_str("xnu-rs: dyld: ERET to EL0\n");

    // SAFETY: Installs the exception vector table before ERET.
    unsafe { install_vectors() };
    // SAFETY: frame has valid EL0 entry_phys, sp, and pstate=0.
    unsafe { user_enter(&raw const frame) }
}

/// Log the dylib dependencies and rpaths of `image` over UART.
pub fn log_deps(image: &UserImage<'_>, name: &str) {
    uart::write_str("xnu-rs: deps for ");
    uart::write_str(name);
    uart::write_str(":\n");
    for dep in &image.dylib_deps {
        uart::write_str("  LOAD   ");
        uart::write_str(dep.name);
        uart::write_str("\n");
    }
    for dep in &image.weak_dylib_deps {
        uart::write_str("  WEAK   ");
        uart::write_str(dep.name);
        uart::write_str("\n");
    }
    for rpath in &image.rpaths {
        uart::write_str("  RPATH  ");
        uart::write_str(rpath);
        uart::write_str("\n");
    }
    if let Some(uuid) = image.uuid {
        uart::write_str("  UUID   ");
        uart::write_uuid(&uuid);
        uart::write_str("\n");
    }
}

