use crate::arch::aarch64::context::TrapFrame;

/// Callee-saved register set for kernel-side context switches.
/// Matches the `AArch64` AAPCS64 callee-saved registers.
#[repr(C)]
pub struct KernelContext {
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64, // frame pointer
    pub lr: u64,  // x30 — return address
    pub sp: u64,
}

impl KernelContext {
    /// Returns a zeroed `KernelContext`.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            lr: 0,
            sp: 0,
        }
    }
}

/// State of a scheduler thread.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Dead,
}

/// A kernel thread with both user-mode trap frame and kernel-mode callee-saved state.
pub struct Thread {
    pub tid: u32,
    /// User-mode register state, restored on `eret`.
    pub trap_frame: TrapFrame,
    /// Kernel-mode callee-saved state, used by `switch_to`.
    pub kernel_ctx: KernelContext,
    /// Top of this thread's kernel stack (stack grows down).
    pub kernel_stack_top: u64,
    pub state: ThreadState,
}

impl Thread {
    /// Create a new user thread that will enter EL0 at `entry` with stack `user_sp`.
    #[must_use]
    pub const fn new_user(tid: u32, entry: u64, user_sp: u64, kernel_stack_top: u64) -> Self {
        Self {
            tid,
            trap_frame: TrapFrame::new_user(entry, user_sp),
            kernel_ctx: KernelContext::zeroed(),
            kernel_stack_top,
            state: ThreadState::Ready,
        }
    }

    /// Create the idle thread.  Its `TrapFrame` is unused; `kernel_ctx.lr` is set
    /// to the `idle_loop` address so that the first `switch_to` resumes there.
    #[must_use]
    pub fn new_idle(tid: u32, kernel_stack_top: u64) -> Self {
        // The idle loop entry address — resolved at link time via a function pointer.
        let lr = idle_loop as *const () as u64;
        let mut ctx = KernelContext::zeroed();
        ctx.lr = lr;
        ctx.sp = kernel_stack_top;
        Self {
            tid,
            trap_frame: TrapFrame::new_user(0, 0),
            kernel_ctx: ctx,
            kernel_stack_top,
            state: ThreadState::Ready,
        }
    }
}

/// Idle loop: spins with `wfi` forever, consuming minimal power.
pub fn idle_loop() -> ! {
    loop {
        // SAFETY: `wfi` is a no-op from an ABI perspective; it only halts the
        // pipeline until an interrupt arrives and is safe to call at any privilege.
        unsafe { core::arch::asm!("wfi", options(nostack)) };
    }
}
