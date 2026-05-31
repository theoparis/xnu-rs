use core::arch::global_asm;

use super::thread::KernelContext;

// Assembly context-switch routine.
//
// `switch_to(from, to)`:
//   x0 = *mut KernelContext  (current thread — save here)
//   x1 = *const KernelContext (next thread — load from here)
//
// The offsets below must match the field layout of `KernelContext` exactly:
//   offset  0: x19
//   offset  8: x20
//   offset 16: x21
//   offset 24: x22
//   offset 32: x23
//   offset 40: x24
//   offset 48: x25
//   offset 56: x26
//   offset 64: x27
//   offset 72: x28
//   offset 80: x29 (fp)
//   offset 88: lr  (x30)
//   offset 96: sp
global_asm!(
    ".global switch_to",
    "switch_to:",
    // ---- save current thread ----
    "stp x19, x20, [x0, #0]",
    "stp x21, x22, [x0, #16]",
    "stp x23, x24, [x0, #32]",
    "stp x25, x26, [x0, #48]",
    "stp x27, x28, [x0, #64]",
    "stp x29, x30, [x0, #80]",
    "mov x2, sp",
    "str x2,  [x0, #96]",
    // ---- restore next thread ----
    "ldp x19, x20, [x1, #0]",
    "ldp x21, x22, [x1, #16]",
    "ldp x23, x24, [x1, #32]",
    "ldp x25, x26, [x1, #48]",
    "ldp x27, x28, [x1, #64]",
    "ldp x29, x30, [x1, #80]",
    "ldr x2,  [x1, #96]",
    "mov sp,  x2",
    "ret",
);

unsafe extern "C" {
    /// Low-level context switch: save callee-saved registers into `*from`,
    /// then restore them from `*to` and return to `to.lr`.
    ///
    /// # Safety
    ///
    /// Both `from` and `to` must be non-null and correctly initialised
    /// `KernelContext` values.  The `sp` field of `to` must point to a valid
    /// kernel stack.  This function must not be called from an interrupt
    /// handler or with interrupts disabled across a long-running switch.
    pub fn switch_to(from: *mut KernelContext, to: *const KernelContext);
}

/// Voluntarily yield the CPU to the next ready thread.
///
/// This reads the current thread's `KernelContext` from `TPIDR_EL1` and
/// delegates to `schedule()`, which picks the next thread and calls
/// `switch_to`.
pub fn yield_now() {
    super::runqueue::schedule();
}
