use core::arch::global_asm;

use super::context::TrapFrame;
use super::gic;
use super::syscall;
use super::uart;

// TrapFrame is 34 × 8 = 272 bytes.  The assembly below must stay in sync with
// the field order defined in `context.rs`.
const _: () = assert!(272 == core::mem::size_of::<TrapFrame>());

/// Install the `AArch64` EL1 exception vector table.
///
/// # Safety
///
/// Must be called exactly once during early kernel bring-up, before any
/// code that could take an exception (including ERET to EL0).
pub unsafe fn install_vectors() {
    unsafe extern "C" {
        static _vector_table: u8;
    }
    // SAFETY: `_vector_table` is the 2 KiB-aligned assembly symbol defined
    // by `global_asm!` in this module.  Writing `VBAR_EL1` followed by ISB
    // makes the new table take effect before the next instruction fetch.
    let vbar = core::ptr::addr_of!(_vector_table) as u64;
    // SAFETY: Single-core early-boot path; no concurrent writes to VBAR_EL1.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {addr}",
            "isb",
            addr = in(reg) vbar,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Rust exception handlers called from assembly trampolines
// ---------------------------------------------------------------------------

/// Synchronous exception from lower EL (`AArch64`) — handles SVC from user space.
///
/// # Safety
///
/// Called exclusively by the `_lower_el_sync` assembly trampoline with a
/// valid `TrapFrame` on the kernel stack.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exception_lower_el_sync(frame: &mut TrapFrame) {
    // ESR_EL1.EC field (bits [31:26]) identifies the exception class.
    let esr: u64;
    // SAFETY: `ESR_EL1` is a read-only system register accessible at EL1.
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, preserves_flags)) };
    let ec = (esr >> 26) & 0x3f;

    if ec == 0x15 {
        // EC = 0b010101: SVC64 — syscall from `AArch64` EL0.
        // SAFETY: Caller guarantees `frame` is a valid EL0 trap frame.
        unsafe { syscall::dispatch(frame) };
    } else {
        uart::write_str("xnu-rs: unexpected lower-EL sync exception EC=0x");
        uart::write_hex_u64(ec);
        uart::write_str(" ESR=0x");
        uart::write_hex_u64(esr);
        uart::write_str(" FAR=0x");
        let far: u64;
        // SAFETY: `FAR_EL1` is a read-only system register accessible at EL1.
        unsafe {
            core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, preserves_flags));
        }
        uart::write_hex_u64(far);
        uart::write_str(" ELR=0x");
        uart::write_hex_u64(frame.pc);
        uart::write_str("\n");
        // Decode Data Abort details (EC=0x24 from lower EL, EC=0x25 from current EL).
        if ec == 0x24 || ec == 0x25 {
            let dfsc = esr & 0x3F;
            let wnr = (esr >> 6) & 1;
            uart::write_str("  ");
            if wnr != 0 {
                uart::write_str("WRITE");
            } else {
                uart::write_str("READ");
            }
            uart::write_str(" fault, DFSC=0x");
            uart::write_hex_u64(dfsc);
            uart::write_str(" (");
            match dfsc {
                0x04 => uart::write_str("translation L0"),
                0x05 => uart::write_str("translation L1"),
                0x06 => uart::write_str("translation L2"),
                0x07 => uart::write_str("translation L3"),
                0x09 => uart::write_str("access flag L1"),
                0x0A => uart::write_str("access flag L2"),
                0x0B => uart::write_str("access flag L3"),
                0x0D => uart::write_str("permission L1"),
                0x0E => uart::write_str("permission L2"),
                0x0F => uart::write_str("permission L3"),
                0x10 => uart::write_str("external sync"),
                0x21 => uart::write_str("alignment"),
                _ => uart::write_str("other"),
            }
            uart::write_str(")\n");
        }
        // Print registers
        for i in 0..31 {
            uart::write_str(" x");
            // Simple decimal formatting for registers
            if i < 10 {
                uart::write_byte(b'0' + u8::try_from(i).unwrap_or(0));
            } else {
                uart::write_byte(b'0' + u8::try_from(i / 10).unwrap_or(0));
                uart::write_byte(b'0' + u8::try_from(i % 10).unwrap_or(0));
            }
            uart::write_str("=0x");
            uart::write_hex_u64(frame.x[i]);
            if i % 4 == 3 {
                uart::write_str("\n");
            }
        }
        uart::write_str("\n sp=0x");
        uart::write_hex_u64(frame.sp);
        uart::write_str("\n");
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Synchronous exception from current EL (kernel fault) — fatal.
#[unsafe(no_mangle)]
pub extern "C" fn exception_el1_sync(frame: &TrapFrame) {
    let esr: u64;
    // SAFETY: `ESR_EL1` is a read-only system register accessible at EL1.
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, preserves_flags)) };
    uart::write_str("xnu-rs: kernel sync exception ESR=0x");
    uart::write_hex_u64(esr);
    uart::write_str(" ELR=0x");
    uart::write_hex_u64(frame.pc);
    uart::write_str("\n");
    loop {
        core::hint::spin_loop();
    }
}

/// IRQ from current EL — dispatch via GIC.
#[unsafe(no_mangle)]
pub extern "C" fn exception_el1_irq(_frame: &TrapFrame) {
    gic::handle_irq();
}

/// IRQ from lower EL — dispatch via GIC.
#[unsafe(no_mangle)]
pub extern "C" fn exception_lower_el_irq(_frame: &TrapFrame) {
    gic::handle_irq();
}

// ---------------------------------------------------------------------------
// Assembly: vector table + save/restore trampolines + user_enter
// ---------------------------------------------------------------------------

global_asm!(
    // -----------------------------------------------------------------------
    // Macro: allocate and fill one 128-byte vector slot.
    // -----------------------------------------------------------------------
    ".macro ventry label",
    "    .align 7", // 128-byte alignment within the table
    "    b \\label",
    ".endm",
    // -----------------------------------------------------------------------
    // Exception vector table — must be 2 KiB aligned (VBAR_EL1 requirement).
    // -----------------------------------------------------------------------
    ".global _vector_table",
    ".align 11",
    "_vector_table:",
    // Group 1: Current EL, SP0
    "ventry _el1_sp0_sync",
    "ventry _el1_sp0_irq",
    "ventry _el1_sp0_fiq",
    "ventry _el1_sp0_serror",
    // Group 2: Current EL, SPx (kernel uses SPx)
    "ventry _el1_spx_sync",
    "ventry _el1_spx_irq",
    "ventry _el1_spx_fiq",
    "ventry _el1_spx_serror",
    // Group 3: Lower EL, AArch64
    "ventry _lower_el_sync",
    "ventry _lower_el_irq",
    "ventry _lower_el_fiq",
    "ventry _lower_el_serror",
    // Group 4: Lower EL, AArch32 (not supported)
    "ventry _lower_el_aarch32_sync",
    "ventry _lower_el_aarch32_irq",
    "ventry _lower_el_aarch32_fiq",
    "ventry _lower_el_aarch32_serror",
    // -----------------------------------------------------------------------
    // Macro: save TrapFrame onto kernel stack, call `handler`, restore, ERET.
    // The full expansion is ~44 instructions so it must live outside the
    // 128-byte vector slot — each slot contains only `b <label>`.
    // -----------------------------------------------------------------------
    ".macro save_restore_eret handler",
    "    sub sp, sp, #272", // allocate TrapFrame (34 × 8)
    // x0–x30
    "    stp x0,  x1,  [sp, #0]",
    "    stp x2,  x3,  [sp, #16]",
    "    stp x4,  x5,  [sp, #32]",
    "    stp x6,  x7,  [sp, #48]",
    "    stp x8,  x9,  [sp, #64]",
    "    stp x10, x11, [sp, #80]",
    "    stp x12, x13, [sp, #96]",
    "    stp x14, x15, [sp, #112]",
    "    stp x16, x17, [sp, #128]",
    "    stp x18, x19, [sp, #144]",
    "    stp x20, x21, [sp, #160]",
    "    stp x22, x23, [sp, #176]",
    "    stp x24, x25, [sp, #192]",
    "    stp x26, x27, [sp, #208]",
    "    stp x28, x29, [sp, #224]",
    "    str x30,       [sp, #240]",
    // SP_EL0, ELR_EL1, SPSR_EL1
    "    mrs x0, sp_el0",
    "    str x0,        [sp, #248]",
    "    mrs x0, elr_el1",
    "    str x0,        [sp, #256]",
    "    mrs x0, spsr_el1",
    "    str x0,        [sp, #264]",
    "    mov x0, sp", // arg0: &mut TrapFrame
    "    bl \\handler",
    // Restore system registers
    "    ldr x0,        [sp, #264]",
    "    msr spsr_el1, x0",
    "    ldr x0,        [sp, #256]",
    "    msr elr_el1, x0",
    "    ldr x0,        [sp, #248]",
    "    msr sp_el0, x0",
    // Restore x0–x30
    "    ldp x28, x29, [sp, #224]",
    "    ldr x30,       [sp, #240]",
    "    ldp x26, x27, [sp, #208]",
    "    ldp x24, x25, [sp, #192]",
    "    ldp x22, x23, [sp, #176]",
    "    ldp x20, x21, [sp, #160]",
    "    ldp x18, x19, [sp, #144]",
    "    ldp x16, x17, [sp, #128]",
    "    ldp x14, x15, [sp, #112]",
    "    ldp x12, x13, [sp, #96]",
    "    ldp x10, x11, [sp, #80]",
    "    ldp x8,  x9,  [sp, #64]",
    "    ldp x6,  x7,  [sp, #48]",
    "    ldp x4,  x5,  [sp, #32]",
    "    ldp x2,  x3,  [sp, #16]",
    "    ldp x0,  x1,  [sp, #0]",
    "    add sp, sp, #272",
    "    eret",
    ".endm",
    // -----------------------------------------------------------------------
    // EL1 / SP0 stubs (unused but required for a complete table)
    // -----------------------------------------------------------------------
    "_el1_sp0_sync:",
    "    b _el1_sp0_sync",
    "_el1_sp0_irq:",
    "    b _el1_sp0_irq",
    "_el1_sp0_fiq:",
    "    b _el1_sp0_fiq",
    "_el1_sp0_serror:",
    "    b _el1_sp0_serror",
    // -----------------------------------------------------------------------
    // EL1 / SPx — kernel faults
    // -----------------------------------------------------------------------
    "_el1_spx_sync:",
    "    save_restore_eret exception_el1_sync",
    "_el1_spx_irq:",
    "    save_restore_eret exception_el1_irq",
    "_el1_spx_fiq:",
    "    b _el1_spx_fiq",
    "_el1_spx_serror:",
    "    b _el1_spx_serror",
    // -----------------------------------------------------------------------
    // Lower EL (user) AArch64 exceptions
    // -----------------------------------------------------------------------
    "_lower_el_sync:",
    "    save_restore_eret exception_lower_el_sync",
    "_lower_el_irq:",
    "    save_restore_eret exception_lower_el_irq",
    "_lower_el_fiq:",
    "    b _lower_el_fiq",
    "_lower_el_serror:",
    "    b _lower_el_serror",
    // -----------------------------------------------------------------------
    // Lower EL AArch32 — not supported
    // -----------------------------------------------------------------------
    "_lower_el_aarch32_sync:",
    "    b _lower_el_aarch32_sync",
    "_lower_el_aarch32_irq:",
    "    b _lower_el_aarch32_irq",
    "_lower_el_aarch32_fiq:",
    "    b _lower_el_aarch32_fiq",
    "_lower_el_aarch32_serror:",
    "    b _lower_el_aarch32_serror",
    // -----------------------------------------------------------------------
    // user_enter(frame: *const TrapFrame) -> !
    //
    // Loads all registers from the TrapFrame pointed to by x0, then ERETs to
    // EL0.  Must be called with the exception vector table already installed.
    // -----------------------------------------------------------------------
    ".global user_enter",
    "user_enter:",
    // Load system registers before clobbering x0/x1.
    "    ldr x1,  [x0, #248]", // sp_el0
    "    msr sp_el0, x1",
    "    ldr x1,  [x0, #256]", // elr_el1 = pc
    "    msr elr_el1, x1",
    "    ldr x1,  [x0, #264]", // spsr_el1 = pstate
    "    msr spsr_el1, x1",
    // Load x2–x30
    "    ldp x2,  x3,  [x0, #16]",
    "    ldp x4,  x5,  [x0, #32]",
    "    ldp x6,  x7,  [x0, #48]",
    "    ldp x8,  x9,  [x0, #64]",
    "    ldp x10, x11, [x0, #80]",
    "    ldp x12, x13, [x0, #96]",
    "    ldp x14, x15, [x0, #112]",
    "    ldp x16, x17, [x0, #128]",
    "    ldp x18, x19, [x0, #144]",
    "    ldp x20, x21, [x0, #160]",
    "    ldp x22, x23, [x0, #176]",
    "    ldp x24, x25, [x0, #192]",
    "    ldp x26, x27, [x0, #208]",
    "    ldp x28, x29, [x0, #224]",
    "    ldr x30,       [x0, #240]",
    // Load x0 and x1 last (this clobbers the frame pointer).
    "    ldp x0,  x1,  [x0, #0]",
    "    eret",
);
