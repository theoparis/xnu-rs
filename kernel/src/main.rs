#![no_std]
#![no_main]

extern crate kernel;

mod boot_args;
mod device_tree;

use boot_args::BootArgs;
use core::{panic::PanicInfo, ptr, slice};
use kernel::arch::aarch64::{boot, gic, mmu, smp, uart};
use kernel::mm;
use kernel::sched;

const BOOT_ARGS_REVISION2: u16 = 2;
const BOOT_ARGS_VERSION2: u16 = 2;

static mut BOOT_ARGS_PTR: *const BootArgs = ptr::null();

#[unsafe(no_mangle)]
pub extern "C" fn _start(boot_args: *const BootArgs) -> ! {
    // Drop from EL2 to EL1 if UEFI left us at EL2 (QEMU `virtualization=on`).
    // SAFETY: First thing in _start; no EL1 system registers touched yet.
    unsafe { boot::drop_to_el1_if_needed() };

    // SAFETY: Single-core bring-up path sets this once during early boot.
    unsafe {
        BOOT_ARGS_PTR = boot_args;
    }

    uart::write_str("xnu-rs: entered kernel _start\n");
    let args = validate_boot_args(boot_args);

    // Initialise the physical frame allocator.
    // Use phys_base/mem_size from boot args when available; fall back to
    // conservative defaults that cover QEMU virt RAM at 0x40000000 (256 MiB).
    let (phys_base, mem_size, kernel_end) = args.map_or(
        (0x4000_0000u64, 256 * 1024 * 1024u64, 0x4020_0000u64 + 4 * 1024 * 1024),
        |a| (a.phys_base, a.mem_size, a.top_of_kernel_data),
    );
    mm::frame::init(phys_base, mem_size, 0x4020_0000, kernel_end);

    // Enable the MMU with a TTBR0 identity map covering all RAM and MMIO.
    // SAFETY: Frame allocator is initialised; page tables are static BSS.
    unsafe { mmu::init_kernel_tables() };
    uart::write_str("xnu-rs: mmu enabled\n");

    // Compute load address for the test user binary: just past kernel data.
    let load_base = args.map_or_else(
        || align_up_2m(0x4000_0000 + 64 * 1024 * 1024),
        |a| align_up_2m(a.top_of_kernel_data),
    );

    uart::write_str("xnu-rs: launching test user binary at load_base=0x");
    uart::write_hex_u64(load_base);
    uart::write_str("\n");

    // Initialise the cooperative scheduler and task table.
    sched::init_runqueue();
    sched::init_task_table();
    uart::write_str("xnu-rs: scheduler init\n");

    // Initialize GIC distributor (CPU0 only).
    // SAFETY: Single-core early boot; no secondary CPUs running yet.
    unsafe { gic::init_distributor() };
    // Initialize GIC CPU interface for CPU0.
    // SAFETY: Called once during CPU0 bring-up.
    unsafe { gic::init_cpu_interface() };
    uart::write_str("xnu-rs: gic init\n");

    // Initialize virtio-blk driver.
    kernel::drivers::virtio::init_blk();

    // Boot secondary CPUs via PSCI.
    // SAFETY: GIC distributor is initialized; called from CPU0.
    unsafe { smp::boot_secondaries(4) };

    // SAFETY: `load_base` is aligned, past the kernel, and in valid RAM.
    // The exception vectors will be installed inside `load_and_run`.
    unsafe {
        kernel::exec::loader::load_and_run(TEST_USER_MACHO, load_base);
    }
}

const fn align_up_2m(v: u64) -> u64 {
    const ALIGN: u64 = 2 * 1024 * 1024;
    (v + ALIGN - 1) & !(ALIGN - 1)
}

fn validate_boot_args(boot_args: *const BootArgs) -> Option<&'static BootArgs> {
    if boot_args.is_null() {
        uart::write_str("xnu-rs: boot_args=NULL\n");
        return None;
    }

    // SAFETY: Loader passes a valid pointer to loader-owned BootArgs.
    let args = unsafe { &*boot_args };
    uart::write_str("xnu-rs: revision=");
    uart::write_hex_u64(u64::from(args.revision));
    uart::write_str(" version=");
    uart::write_hex_u64(u64::from(args.version));
    uart::write_str(" phys_base=0x");
    uart::write_hex_u64(args.phys_base);
    uart::write_str(" mem_size=0x");
    uart::write_hex_u64(args.mem_size);
    uart::write_str(" top_of_kernel_data=0x");
    uart::write_hex_u64(args.top_of_kernel_data);
    uart::write_str("\n");

    if args.revision != BOOT_ARGS_REVISION2 || args.version != BOOT_ARGS_VERSION2 {
        uart::write_str("xnu-rs: unsupported boot_args revision/version\n");
        return None;
    }

    dump_apple_device_tree(args);
    Some(args)
}

fn dump_apple_device_tree(args: &BootArgs) {
    if args.device_tree_p.is_null() || args.device_tree_length < 8 {
        return;
    }
    let len = args.device_tree_length as usize;
    // SAFETY: Loader allocated and populated `device_tree_length` bytes at `device_tree_p`.
    let bytes = unsafe { slice::from_raw_parts(args.device_tree_p.cast::<u8>(), len) };
    device_tree::dump(bytes);
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    uart::write_str("xnu-rs: kernel panic\n");
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Minimal test user binary (ARM64 Mach-O, no libc, no dyld)
//
// The program calls:
//   write(1, "Hello from EL0!\n", 16)  → Darwin BSD SVC #0x80 with x16=4
//   exit(42)                            → Darwin BSD SVC #0x80 with x16=1
//
// Machine code (12 instructions = 32 bytes) followed by the message string:
//
//   adr  x1, #32      ; x1 = address of msg (32 bytes from this instruction)
//   movz x0, #1       ; fd = stdout
//   movz x2, #16      ; len = 16
//   movz x16, #4      ; SYS_write
//   svc  #0x80
//   movz x0, #42      ; exit code
//   movz x16, #1      ; SYS_exit
//   svc  #0x80
//   msg: "Hello from EL0!\n"
//
// The Mach-O has one LC_SEGMENT_64 (__TEXT, vmaddr=0x100000000) and LC_MAIN.
// ---------------------------------------------------------------------------

/// A minimal static `AArch64` Mach-O binary for testing EL0 bring-up.
static TEST_USER_MACHO: &[u8] = &make_test_macho();

const fn make_test_macho() -> [u8; 0x1030] {
    let mut buf = [0u8; 0x1030];

    // --- mach_header_64 (32 bytes) ---
    // magic = MH_MAGIC_64 = 0xFEEDFACF
    buf[0] = 0xCF;
    buf[1] = 0xFA;
    buf[2] = 0xED;
    buf[3] = 0xFE;
    // cputype = CPU_TYPE_ARM64 = 0x0100000C
    buf[4] = 0x0C;
    buf[5] = 0x00;
    buf[6] = 0x00;
    buf[7] = 0x01;
    // cpusubtype = 0
    // filetype = MH_EXECUTE = 2
    buf[12] = 0x02;
    // ncmds = 2
    buf[16] = 0x02;
    // sizeofcmds = 96 = 0x60
    buf[20] = 0x60;
    // flags = 0; reserved = 0

    // --- LC_SEGMENT_64 for __TEXT (72 bytes, offset 0x20) ---
    // cmd = LC_SEGMENT_64 = 0x19
    buf[32] = 0x19;
    // cmdsize = 72 = 0x48
    buf[36] = 0x48;
    // segname = "__TEXT\0\0\0\0\0\0\0\0\0\0"
    buf[40] = b'_';
    buf[41] = b'_';
    buf[42] = b'T';
    buf[43] = b'E';
    buf[44] = b'X';
    buf[45] = b'T';
    // vmaddr = 0x100000000 (little-endian u64)
    buf[56] = 0x00;
    buf[57] = 0x00;
    buf[58] = 0x00;
    buf[59] = 0x00;
    buf[60] = 0x01;
    buf[61] = 0x00;
    buf[62] = 0x00;
    buf[63] = 0x00;
    // vmsize = 0x1000
    buf[64] = 0x00;
    buf[65] = 0x10;
    // fileoff = 0x1000
    buf[72] = 0x00;
    buf[73] = 0x10;
    // filesize = 0x30 = 48
    buf[80] = 0x30;
    // maxprot = 5 (R+X)
    buf[88] = 0x05;
    // initprot = 5
    buf[92] = 0x05;
    // nsects = 0; flags = 0

    // --- LC_MAIN (24 bytes, offset 0x68 = 104) ---
    // cmd = LC_MAIN = 0x80000028
    buf[104] = 0x28;
    buf[105] = 0x00;
    buf[106] = 0x00;
    buf[107] = 0x80;
    // cmdsize = 24 = 0x18
    buf[108] = 0x18;
    // entryoff = 0x1000 (file offset of entry = start of __TEXT data)
    buf[112] = 0x00;
    buf[113] = 0x10;
    // stacksize = 0

    // --- Code at file offset 0x1000 ---
    // adr x1, #32  → 0x10000101
    buf[0x1000] = 0x01;
    buf[0x1001] = 0x01;
    buf[0x1002] = 0x00;
    buf[0x1003] = 0x10;
    // movz x0, #1  → 0xD2800020
    buf[0x1004] = 0x20;
    buf[0x1005] = 0x00;
    buf[0x1006] = 0x80;
    buf[0x1007] = 0xD2;
    // movz x2, #16 → 0xD2800202
    buf[0x1008] = 0x02;
    buf[0x1009] = 0x02;
    buf[0x100A] = 0x80;
    buf[0x100B] = 0xD2;
    // movz x16, #4 → 0xD2800090
    buf[0x100C] = 0x90;
    buf[0x100D] = 0x00;
    buf[0x100E] = 0x80;
    buf[0x100F] = 0xD2;
    // svc #0x80    → 0xD4001001
    buf[0x1010] = 0x01;
    buf[0x1011] = 0x10;
    buf[0x1012] = 0x00;
    buf[0x1013] = 0xD4;
    // movz x0, #42 → 0xD2800540
    buf[0x1014] = 0x40;
    buf[0x1015] = 0x05;
    buf[0x1016] = 0x80;
    buf[0x1017] = 0xD2;
    // movz x16, #1 → 0xD2800030
    buf[0x1018] = 0x30;
    buf[0x1019] = 0x00;
    buf[0x101A] = 0x80;
    buf[0x101B] = 0xD2;
    // svc #0x80    → 0xD4001001
    buf[0x101C] = 0x01;
    buf[0x101D] = 0x10;
    buf[0x101E] = 0x00;
    buf[0x101F] = 0xD4;
    // "Hello from EL0!\n"
    buf[0x1020] = b'H';
    buf[0x1021] = b'e';
    buf[0x1022] = b'l';
    buf[0x1023] = b'l';
    buf[0x1024] = b'o';
    buf[0x1025] = b' ';
    buf[0x1026] = b'f';
    buf[0x1027] = b'r';
    buf[0x1028] = b'o';
    buf[0x1029] = b'm';
    buf[0x102A] = b' ';
    buf[0x102B] = b'E';
    buf[0x102C] = b'L';
    buf[0x102D] = b'0';
    buf[0x102E] = b'!';
    buf[0x102F] = b'\n';

    buf
}
