#![no_std]
#![no_main]

mod boot_args;
mod device_tree;

use boot_args::BootArgs;
use core::{panic::PanicInfo, ptr, slice};
use kernel::arch::aarch64::uart;

const BOOT_ARGS_REVISION2: u16 = 2;
const BOOT_ARGS_VERSION2: u16 = 2;

static mut BOOT_ARGS_PTR: *const BootArgs = ptr::null();

#[unsafe(no_mangle)]
pub extern "C" fn _start(boot_args: *const BootArgs) -> ! {
    // SAFETY: Single-core bring-up path sets this once during early boot.
    unsafe {
        BOOT_ARGS_PTR = boot_args;
    }

    uart::write_str("xnu-rs: entered kernel _start via Mach-O loader\n");
    validate_boot_args(boot_args);

    loop {
        core::hint::spin_loop();
    }
}

fn validate_boot_args(boot_args: *const BootArgs) {
    if boot_args.is_null() {
        uart::write_str("xnu-rs: boot_args=NULL\n");
        return;
    }

    // SAFETY: The loader passes a valid pointer to a loader-owned `BootArgs` page.
    let args = unsafe { &*boot_args };
    uart::write_str("xnu-rs: boot_args revision=");
    uart::write_hex_u64(u64::from(args.revision));
    uart::write_str(" version=");
    uart::write_hex_u64(u64::from(args.version));
    uart::write_str("\n");

    if args.revision != BOOT_ARGS_REVISION2 || args.version != BOOT_ARGS_VERSION2 {
        uart::write_str("xnu-rs: unsupported boot_args revision/version\n");
    }

    uart::write_str("xnu-rs: phys_base=");
    uart::write_hex_u64(args.phys_base);
    uart::write_str(" mem_size=");
    uart::write_hex_u64(args.mem_size);
    uart::write_str(" top_of_kernel_data=");
    uart::write_hex_u64(args.top_of_kernel_data);
    uart::write_str("\n");

    uart::write_str("xnu-rs: device_tree_p=");
    uart::write_hex_usize(args.device_tree_p.addr());
    uart::write_str(" length=");
    uart::write_hex_u64(u64::from(args.device_tree_length));
    uart::write_str("\n");

    dump_apple_device_tree(args);
}

fn dump_apple_device_tree(args: &BootArgs) {
    if args.device_tree_p.is_null() || args.device_tree_length < 8 {
        uart::write_str("xnu-rs: no Apple device tree\n");
        return;
    }

    let len = args.device_tree_length as usize;
    // SAFETY: The loader allocated and populated `device_tree_length` bytes at `device_tree_p`.
    let bytes = unsafe { slice::from_raw_parts(args.device_tree_p.cast::<u8>(), len) };
    let Some(properties) = read_le_u32(bytes, 0) else {
        uart::write_str("xnu-rs: malformed Apple device tree\n");
        return;
    };
    let Some(children) = read_le_u32(bytes, 4) else {
        uart::write_str("xnu-rs: malformed Apple device tree\n");
        return;
    };

    uart::write_str("xnu-rs: adt root properties=");
    uart::write_hex_u64(u64::from(properties));
    uart::write_str(" children=");
    uart::write_hex_u64(u64::from(children));
    uart::write_str("\n");
    device_tree::dump(bytes);
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let data = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    uart::write_str("xnu-rs: kernel panic\n");
    loop {
        core::hint::spin_loop();
    }
}
