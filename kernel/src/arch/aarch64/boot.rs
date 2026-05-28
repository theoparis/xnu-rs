/// Drop from EL2 to EL1 if we are currently running at EL2.
///
/// QEMU `virt` with `virtualization=on` keeps the firmware (and therefore
/// the boot-loader entry point) at EL2.  All of our kernel code expects to
/// run at EL1, so we perform the transition here before touching any
/// EL1-specific system registers.
///
/// If the CPU is already at EL1 this function is a no-op.
///
/// # Safety
///
/// Must be the very first thing called in `_start`, before any code that
/// reads or writes EL1 system registers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn drop_to_el1_if_needed() {
    // `CurrentEL` bits [3:2] encode the current exception level.
    let current_el: u64;
    // SAFETY: `CurrentEL` is a read-only architectural register.
    unsafe {
        core::arch::asm!(
            "mrs {el}, CurrentEL",
            "lsr {el}, {el}, #2",
            el = out(reg) current_el,
            options(nostack, preserves_flags),
        );
    }

    if current_el != 2 {
        return; // Already at EL1 (or EL3 — unsupported, leave as-is).
    }

    // Transition from EL2 → EL1 entirely inside one inline-asm block so that
    // the ERET and its continuation `2:` are both visible to the assembler.
    //
    // SAFETY:
    // * We confirmed `current_el == 2` above.
    // * SP_EL1 is set to the current EL2 stack so the Rust frame stays valid.
    // * HCR_EL2.RW = 1 ensures EL1 runs as AArch64.
    // * HCR_EL2.TGE is cleared: UEFI sets TGE=1 to route EL1/EL0 traps to
    //   EL2; with TGE=1 an ERET targeting EL1 is illegal (PSTATE.IL set).
    // * ISB after HCR_EL2 write is required to synchronise the change before
    //   SPSR/ELR writes that depend on RW.
    unsafe {
        core::arch::asm!(
            // Configure HCR_EL2: set RW=1 (EL1 is AArch64), clear TGE (bit 27).
            "mrs x0, hcr_el2",
            "orr x0, x0, #(1 << 31)",   // RW=1
            "movz x1, #0x800, lsl #16",  // x1 = 1<<27 (TGE bit)
            "bic x0, x0, x1",            // TGE=0
            "msr hcr_el2, x0",
            "isb",                       // synchronise before SPSR/ELR writes

            // Copy current EL2 stack → SP_EL1 so our frame remains valid.
            "mov x0, sp",
            "msr sp_el1, x0",

            // SPSR_EL2 = 0x3C5: EL1h, DAIF all masked.
            //   M[3:0] = 0b0101 = EL1h, M[4] = 0 = AArch64, DAIF[9:6] = 1111
            "mov x0, #0x3C5",
            "msr spsr_el2, x0",

            // ELR_EL2 = address just after the `eret`.
            "adr x0, 2f",
            "msr elr_el2, x0",

            "eret",     // drop to EL1; continues at `2:` below
            "2:",

            out("x0") _,   // scratch
            out("x1") _,   // scratch (TGE mask)
            options(nostack),
        );
    }
}
