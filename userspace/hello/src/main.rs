#![no_std]
#![no_main]

// Darwin BSD syscall numbers (SVC #0x80; syscall number in x16).
const SYS_WRITE: u64 = 4;
const SYS_EXIT: u64 = 1;

/// LC_MAIN entry point — called by our kernel dyld stub after applying fixups.
/// Signature matches what the Darwin ABI passes: argc and argv from the stack.
///
/// # Safety
///
/// Called by the kernel at EL0 after ERET; the stack and registers must
/// conform to the Darwin ABI calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    let msg = b"xnu-rs: hello from userspace!\n";
    // SAFETY: Darwin write(fd=1, buf, len) syscall via SVC #0x80.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") SYS_WRITE,
            in("x0") 1u64,
            in("x1") msg.as_ptr(),
            in("x2") msg.len() as u64,
            options(nostack),
        );
        core::arch::asm!(
            "svc #0x80",
            in("x16") SYS_EXIT,
            in("x0") 0u64,
            options(nostack, noreturn),
        );
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: exit(1) — best-effort on panic since we have no unwinding.
    unsafe {
        core::arch::asm!(
            "svc #0x80",
            in("x16") SYS_EXIT,
            in("x0") 1u64,
            options(nostack, noreturn),
        );
    }
}
