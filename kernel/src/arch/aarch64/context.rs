/// Saved CPU state for an exception or context switch.
///
/// Layout is fixed by the assembly in `exception.rs`; do not reorder fields.
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers x0–x30.
    pub x: [u64; 31],
    /// EL0 stack pointer (`SP_EL0`).
    pub sp: u64,
    /// Exception return address (`ELR_EL1`).
    pub pc: u64,
    /// Saved processor state (`SPSR_EL1`).
    pub pstate: u64,
}

impl TrapFrame {
    /// Returns a zeroed frame for a new user task at `entry` with stack `sp`.
    ///
    /// `pstate = 0` means EL0 / `AArch64` / all interrupts unmasked.
    #[must_use]
    pub const fn new_user(entry: u64, sp: u64) -> Self {
        Self {
            x: [0; 31],
            sp,
            pc: entry,
            pstate: 0,
        }
    }
}

unsafe extern "C" {
    /// Transfer control to user space by loading `frame` and executing `ERET`.
    ///
    /// # Safety
    ///
    /// `frame` must describe a valid EL0 execution context: `pc` must point to
    /// mapped executable user memory, `sp` must point to a valid user stack, and
    /// `pstate` must encode EL0 (`M[3:0] = 0b0000`).  The caller must have
    /// installed the exception vector table before invoking this function.
    pub fn user_enter(frame: *const TrapFrame) -> !;
}
