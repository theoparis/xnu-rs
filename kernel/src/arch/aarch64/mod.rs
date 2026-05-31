pub mod boot;
pub mod context;
pub mod cpu;
pub mod exception;
pub mod gic;
pub mod mmu;
pub mod smp;
pub mod uart;

pub fn time_ticks() -> u64 {
    let t: u64;
    // SAFETY: `cntvct_el0` is a read-only counter register accessible from
    // EL1; reading it has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) t, options(nostack, preserves_flags))
    };
    t
}

/// Write the EL0 read-only thread-ID register from EL1.
pub fn thread_register_set(val: u64) {
    // SAFETY: `tpidrro_el0` is the EL0 read-only thread-ID register; writing
    // it from EL1 is always permitted and has no architectural side effects.
    unsafe {
        core::arch::asm!("msr tpidrro_el0, {}", in(reg) val, options(nostack, preserves_flags))
    };
}

pub fn thread_register_get() -> u64 {
    let val: u64;
    // SAFETY: Reading `tpidrro_el0` from EL1 is always permitted.
    unsafe {
        core::arch::asm!("mrs {}, tpidrro_el0", out(reg) val, options(nostack, preserves_flags))
    };
    val
}
