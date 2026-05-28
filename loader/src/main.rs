#![no_std]
#![no_main]

extern crate alloc;

mod boot_args;
mod device_tree;

use alloc::vec::Vec;
use core::{
    arch::asm,
    convert::Infallible,
    panic::PanicInfo,
    ptr::{copy_nonoverlapping, write_bytes},
};

use boot_args::BootArgs;
use goblin::mach::MachO;
use loader::MachOImage;
use uefi::{
    boot::{self, AllocateType, MemoryType, PAGE_SIZE},
    cstr16, entry,
    fs::FileSystem,
    mem::memory_map::MemoryMap,
    prelude::*,
    println,
};

#[entry]
fn main() -> Status {
    match load_and_jump_to_kernel() {
        Ok(never) => match never {},
        Err(status) => status,
    }
}

fn load_and_jump_to_kernel() -> Result<Infallible, Status> {
    uefi::helpers::init().map_err(|err| err.status())?;
    log::set_max_level(log::LevelFilter::Info);
    println!("loader: opening ESP filesystem");

    let proto = boot::get_image_file_system(boot::image_handle()).map_err(|err| err.status())?;
    let mut fs = FileSystem::new(proto);
    let kernel_bytes = fs
        .read(cstr16!("\\KERNEL"))
        .map_err(|_| Status::NOT_FOUND)?;

    println!(
        "loader: parsing kernel Mach-O ({} bytes)",
        kernel_bytes.len()
    );
    let macho = MachOImage::new(&kernel_bytes)
        .parse()
        .map_err(|_| Status::LOAD_ERROR)?;

    allocate_load_ranges(&macho)?;
    load_segments(&macho)?;
    sync_loaded_image(&macho)?;

    let top_of_kernel_data = kernel_top(&macho)?;
    let apple_dt = device_tree::build_apple_device_tree()?;
    let boot_args_ptr = allocate_boot_args_page()?;
    let stack_top = allocate_kernel_stack()?;

    println!(
        "loader: prepared kernel entry {:#x}, stack {:#x}; exiting boot services",
        macho.entry, stack_top
    );
    // SAFETY: We intentionally exit boot services after all protocol/file allocations are done.
    let memory_map = unsafe { boot::exit_boot_services(None) };
    fill_boot_args(boot_args_ptr, &memory_map, top_of_kernel_data, &apple_dt)?;

    // SAFETY: At this point boot services are gone and all handoff state is in loader-owned
    // memory. Do not return through the UEFI entry wrapper; branch directly to the kernel.
    unsafe {
        jump_to_entry(KernelHandOff {
            entry: macho.entry,
            boot_args: boot_args_ptr.cast_const(),
            stack_top,
        });
    }
}

fn allocate_load_ranges(macho: &MachO<'_>) -> Result<(), Status> {
    let mut ranges = load_ranges(macho)?;
    ranges.sort_unstable_by_key(|range| range.start);

    let mut merged: Vec<LoadRange> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }

    for range in merged {
        // Allocate one page at a time so each request stays within a single
        // memory-map entry. A multi-page AllocateType::Address call fails when
        // the range spans entry boundaries (seen with -cpu max / OVMF).
        let mut cursor = range.start;
        while cursor < range.end {
            let next = cursor + PAGE_SIZE as u64;
            boot::allocate_pages(AllocateType::Address(cursor), MemoryType::LOADER_CODE, 1)
                .map_err(|err| err.status())?;
            let ptr = cursor as *mut u8;
            // SAFETY: The page at `cursor` was just allocated by UEFI above.
            unsafe { write_bytes(ptr, 0, PAGE_SIZE) };
            cursor = next;
        }
    }

    Ok(())
}

fn load_ranges(macho: &MachO<'_>) -> Result<Vec<LoadRange>, Status> {
    let mut ranges = Vec::new();

    for segment in &macho.segments {
        if segment.vmsize == 0 {
            continue;
        }

        let start = align_down(segment.vmaddr, PAGE_SIZE as u64);
        let end = align_up(
            segment
                .vmaddr
                .checked_add(segment.vmsize)
                .ok_or(Status::LOAD_ERROR)?,
            PAGE_SIZE as u64,
        )?;
        ranges.push(LoadRange { start, end });
    }

    Ok(ranges)
}

fn load_segments(macho: &MachO<'_>) -> Result<(), Status> {
    for segment in &macho.segments {
        if segment.filesize == 0 {
            continue;
        }

        let dst = usize::try_from(segment.vmaddr).map_err(|_| Status::LOAD_ERROR)? as *mut u8;
        // SAFETY: The destination virtual address lies within the pages allocated from the
        // Mach-O segment ranges, and `segment.data` points to the segment bytes in the file.
        unsafe { copy_nonoverlapping(segment.data.as_ptr(), dst, segment.data.len()) };
    }

    Ok(())
}

fn sync_loaded_image(macho: &MachO<'_>) -> Result<(), Status> {
    for segment in &macho.segments {
        if segment.vmsize == 0 {
            continue;
        }
        let start = segment.vmaddr;
        let len = usize::try_from(segment.vmsize).map_err(|_| Status::LOAD_ERROR)?;
        // SAFETY: The loader just copied/zeroed the loaded image into this memory range.
        unsafe { clean_dcache_invalidate_icache(start, len) };
    }
    Ok(())
}

unsafe fn clean_dcache_invalidate_icache(start: u64, len: usize) {
    const CACHE_LINE: u64 = 64;
    let end = start.saturating_add(len as u64);
    let mut addr = start & !(CACHE_LINE - 1);
    while addr < end {
        // SAFETY: Performs AArch64 cache maintenance for the virtual address in `addr`.
        unsafe { asm!("dc cvau, {addr}", addr = in(reg) addr, options(nostack, preserves_flags)) };
        addr = addr.saturating_add(CACHE_LINE);
    }
    // SAFETY: Orders data cache clean before instruction cache invalidation.
    unsafe { asm!("dsb ish", options(nostack, preserves_flags)) };

    let mut addr = start & !(CACHE_LINE - 1);
    while addr < end {
        // SAFETY: Invalidates the instruction cache line for the virtual address in `addr`.
        unsafe { asm!("ic ivau, {addr}", addr = in(reg) addr, options(nostack, preserves_flags)) };
        addr = addr.saturating_add(CACHE_LINE);
    }
    // SAFETY: Completes instruction cache invalidation before executing loaded code.
    unsafe {
        asm!("dsb ish", options(nostack, preserves_flags));
        asm!("isb", options(nostack, preserves_flags));
    }
}

fn kernel_top(macho: &MachO<'_>) -> Result<u64, Status> {
    let mut top = 0_u64;
    for segment in &macho.segments {
        let end = segment
            .vmaddr
            .checked_add(segment.vmsize)
            .ok_or(Status::LOAD_ERROR)?;
        if end > top {
            top = end;
        }
    }
    Ok(top)
}

fn allocate_kernel_stack() -> Result<u64, Status> {
    const STACK_PAGES: usize = 16;
    let ptr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, STACK_PAGES)
        .map_err(|err| err.status())?;
    let stack_bytes = u64::try_from(STACK_PAGES * PAGE_SIZE).map_err(|_| Status::LOAD_ERROR)?;
    (ptr.as_ptr() as usize as u64)
        .checked_add(stack_bytes)
        .ok_or(Status::LOAD_ERROR)
}

#[allow(clippy::cast_ptr_alignment)]
fn allocate_boot_args_page() -> Result<*mut BootArgs, Status> {
    let pages = 1;
    let ptr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| err.status())?;
    Ok(ptr.as_ptr().cast::<BootArgs>())
}

fn fill_boot_args(
    boot_args_ptr: *mut BootArgs,
    memory_map: &impl MemoryMap,
    top_of_kernel_data: u64,
    apple_dt: &device_tree::AppleDeviceTree,
) -> Result<(), Status> {
    let (phys_base, mem_size_actual) = memory_extent(memory_map)?;

    let mut boot_args = BootArgs::zeroed();
    boot_args.phys_base = phys_base;
    boot_args.mem_size = mem_size_actual;
    boot_args.mem_size_actual = mem_size_actual;
    boot_args.top_of_kernel_data = top_of_kernel_data;
    boot_args.device_tree_p = apple_dt.ptr;
    boot_args.device_tree_length = apple_dt.len;

    // SAFETY: `boot_args_ptr` points to a dedicated page we allocated for boot args.
    unsafe { *boot_args_ptr = boot_args };
    Ok(())
}

fn memory_extent(memory_map: &impl MemoryMap) -> Result<(u64, u64), Status> {
    let mut min = u64::MAX;
    let mut max = 0_u64;

    for desc in memory_map.entries() {
        let start = desc.phys_start;
        let size = desc
            .page_count
            .checked_mul(PAGE_SIZE as u64)
            .ok_or(Status::LOAD_ERROR)?;
        let end = start.checked_add(size).ok_or(Status::LOAD_ERROR)?;

        if start < min {
            min = start;
        }
        if end > max {
            max = end;
        }
    }

    if min == u64::MAX || max <= min {
        return Err(Status::LOAD_ERROR);
    }

    Ok((min, max - min))
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> Result<u64, Status> {
    value
        .checked_add(align - 1)
        .map(|value| align_down(value, align))
        .ok_or(Status::LOAD_ERROR)
}

unsafe fn jump_to_entry(hand_off: KernelHandOff) -> ! {
    let entry = usize::try_from(hand_off.entry).unwrap_or_else(|_| panic!("invalid kernel entry"));
    let stack_top =
        usize::try_from(hand_off.stack_top).unwrap_or_else(|_| panic!("invalid kernel stack"));
    // SAFETY: The loader validated and populated the kernel image at `entry`. We switch to a
    // loader-allocated stack that survives `exit_boot_services` before branching to Rust code.
    unsafe {
        asm!(
            "mov sp, {stack_top}",
            "mov x0, {boot_args}",
            "br {entry}",
            stack_top = in(reg) stack_top,
            boot_args = in(reg) hand_off.boot_args,
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}

#[derive(Clone, Copy)]
struct KernelHandOff {
    entry: u64,
    boot_args: *const BootArgs,
    stack_top: u64,
}

struct LoadRange {
    start: u64,
    end: u64,
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
