mod bsd;
mod mach;
mod platform;

pub(crate) static MMAP_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub(crate) const MMAP_REGION_START: u64 = 0x6000_0000;
pub(crate) const MMAP_REGION_END: u64 = 0xBF00_0000;

/// Arch-neutral syscall context passed through dispatch.
///
/// Populated from the trap frame by the arch exception handler; results are
/// written back to the frame after dispatch returns.
pub struct SyscallContext {
    nr: u64,
    args: [u64; 8],
    ret: u64,
    carry: bool, // Darwin PSTATE.C error flag
}

impl SyscallContext {
    pub const fn new(nr: u64, args: [u64; 8]) -> Self {
        Self {
            nr,
            args,
            ret: 0,
            carry: false,
        }
    }

    pub const fn nr(&self) -> u64 {
        self.nr
    }

    pub const fn arg(&self, i: usize) -> u64 {
        self.args[i]
    }

    pub const fn set_return(&mut self, val: u64) {
        self.ret = val;
    }

    pub const fn return_val(&self) -> u64 {
        self.ret
    }

    /// Set an errno return and raise the Darwin carry error flag.
    pub const fn set_error(&mut self, errno: u64) {
        self.ret = errno;
        self.carry = true;
    }

    pub const fn has_error(&self) -> bool {
        self.carry
    }
}

pub fn dispatch(ctx: &mut SyscallContext) {
    let nr = ctx.nr();
    if nr as u32 == 0x8000_0000 {
        platform::dispatch(ctx);
    } else if (nr as u32) >= 0x8000_0000 {
        // Sign-extend the 32-bit Mach trap number to 64-bit so matching works.
        let mach_nr = (nr as i32) as u64;
        mach::dispatch(ctx, mach_nr);
    } else {
        bsd::dispatch(ctx, nr);
    }
}
