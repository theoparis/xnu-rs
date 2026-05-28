/// SMP bring-up for `AArch64` using PSCI via SMC.
use super::{gic, uart};

/// PSCI `CPU_ON` function ID (SMC64 calling convention).
const PSCI_CPU_ON: u64 = 0x8400_0003;

/// Invoke a PSCI function via SMC (traps to EL3 where QEMU implements PSCI).
///
/// With `virtualization=on` QEMU exposes real EL2 hardware. UEFI runs at EL2
/// and leaves its own EL2 vector table which does not handle PSCI HVC calls.
/// PSCI must therefore be invoked via SMC which always reaches EL3.
///
/// Returns 0 on success, negative on error.
///
/// # Safety
///
/// Caller must ensure `func`, `arg1`, `arg2`, `arg3` are valid PSCI arguments.
unsafe fn psci_call(func: u64, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    let ret: i64;
    // SAFETY: SMC #0 invokes EL3 (PSCI) with the given register values.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") func => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            options(nostack),
        );
    }
    ret
}

/// Return the current CPU ID from `MPIDR_EL1` bits [7:0] (Aff0).
#[must_use]
pub fn this_cpu() -> u32 {
    let mpidr: u64;
    // SAFETY: MPIDR_EL1 is a read-only architectural register, always accessible at EL1.
    unsafe {
        core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nostack, preserves_flags));
    }
    (mpidr & 0xFF) as u32
}

/// Per-CPU stacks for secondary CPUs (64 KiB each).
// SAFETY: Each stack is only accessed by its corresponding secondary CPU after
// PSCI CPU_ON, before secondary_main returns (it never returns).
static mut CPU1_STACK: [u8; 65536] = [0; 65536];
static mut CPU2_STACK: [u8; 65536] = [0; 65536];
static mut CPU3_STACK: [u8; 65536] = [0; 65536];

/// Boot secondary CPUs 1..(count-1) via PSCI `CPU_ON`.
///
/// # Safety
///
/// Must be called from CPU0 after the GIC distributor has been initialized.
/// `count` must be ≤ 4 (QEMU virt default).
pub unsafe fn boot_secondaries(count: u32) {
    unsafe extern "C" {
        fn secondary_entry();
    }

    for cpu in 1..count.min(4) {
        // SAFETY: Each CPU's stack is exclusively owned by that CPU; we only
        // compute a pointer to its top here, before the CPU starts running.
        let stack_top: u64 = unsafe {
            match cpu {
                1 => (&raw const CPU1_STACK).cast::<u8>().add(65536) as u64,
                2 => (&raw const CPU2_STACK).cast::<u8>().add(65536) as u64,
                3 => (&raw const CPU3_STACK).cast::<u8>().add(65536) as u64,
                _ => continue,
            }
        };

        // SAFETY: PSCI CPU_ON call; entry point and stack are valid.
        let ret = unsafe {
            psci_call(
                PSCI_CPU_ON,
                u64::from(cpu),
                secondary_entry as *const () as u64,
                stack_top,
            )
        };

        uart::write_str("xnu-rs: cpu");
        uart::write_hex_u64(u64::from(cpu));
        if ret == 0 {
            uart::write_str(" online\n");
        } else {
            uart::write_str(" psci_call failed ret=");
            uart::write_hex_u64(ret.cast_unsigned());
            uart::write_str("\n");
        }
    }
}

// ---------------------------------------------------------------------------
// Secondary CPU entry point (assembly) and Rust main
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
    .global secondary_entry
secondary_entry:
    // x0 = context_id = stack top (passed by PSCI as context_id argument)
    mov sp, x0
    // Drop to EL1 if secondary CPU started at EL2
    bl drop_to_el1_if_needed
    // Call into Rust
    bl secondary_main
    // Should not return; spin in WFI
1:
    wfi
    b 1b
"#
);

/// Rust entry point for secondary CPUs.
///
/// # Safety
///
/// Called from the `secondary_entry` assembly stub; the stack and EL are
/// already set up. Must not return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn secondary_main() -> ! {
    // Initialize GIC CPU interface for this CPU.
    // SAFETY: Called once per secondary CPU during its bring-up.
    unsafe { gic::init_cpu_interface() };

    let cpu = this_cpu();
    uart::write_str("xnu-rs: cpu");
    uart::write_hex_u64(u64::from(cpu));
    uart::write_str(" secondary_main\n");

    // Install EL1 exception vectors for this CPU.
    // SAFETY: Called once during secondary CPU bring-up before enabling IRQs.
    unsafe { crate::arch::aarch64::exception::install_vectors() };

    // Spin in WFI loop — idle until woken by an IPI or interrupt.
    loop {
        // SAFETY: WFI is a no-op hint that suspends the CPU until an interrupt.
        unsafe { core::arch::asm!("wfi", options(nostack)) };
    }
}
