#![no_std]
#![feature(alloc_error_handler)]

// Bring in the alloc crate; use `::alloc::` to disambiguate from our `alloc` module.
extern crate alloc as liballoc;

pub mod alloc;
pub mod arch;
pub mod drivers;
pub mod exec;
pub mod fs;
pub mod ipc;
pub mod mach;
pub mod mm;
pub mod sched;
pub mod util;

#[alloc_error_handler]
fn handle_alloc_error(_layout: core::alloc::Layout) -> ! {
    crate::arch::aarch64::uart::write_str("xnu-rs: out of memory\n");
    loop {
        core::hint::spin_loop();
    }
}
