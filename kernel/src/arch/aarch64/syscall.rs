use super::context::TrapFrame;
use super::uart;

// Darwin BSD syscall numbers used by bare-metal user code.
const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 4;

/// Dispatch a Darwin BSD syscall from a user `SVC #0x80` instruction.
///
/// Convention: `frame.x[16]` = syscall number, `frame.x[0..7]` = arguments.
/// On return the frame is restored to EL0 by the exception trampoline.
///
/// # Safety
///
/// Must only be called from `exception_lower_el_sync` with a valid
/// `TrapFrame` saved from EL0 by the assembly trampoline.
pub unsafe fn dispatch(frame: &mut TrapFrame) {
    let nr = frame.x[16];
    match nr {
        SYS_EXIT => {
            let code = frame.x[0];
            uart::write_str("xnu-rs: user exit(");
            uart::write_hex_u64(code);
            uart::write_str(")\n");
            loop {
                core::hint::spin_loop();
            }
        }
        SYS_WRITE => {
            let fd = frame.x[0];
            let buf_ptr = frame.x[1] as *const u8;
            let raw_len = frame.x[2];
            // Only handle stdout/stderr; clamp len to a sane max.
            if (fd == 1 || fd == 2) && !buf_ptr.is_null() && raw_len <= 65536 {
                #[allow(clippy::cast_possible_truncation)]
                let len = raw_len as usize;
                // SAFETY: User passed a pointer+len; bare-metal demo without
                // separate address spaces — we trust the call is in-bounds.
                let bytes = unsafe { core::slice::from_raw_parts(buf_ptr, len) };
                for &b in bytes {
                    uart::write_byte(b);
                }
                frame.x[0] = raw_len; // return bytes written
            } else {
                frame.x[0] = u64::MAX; // -1 error
            }
        }
        _ => {
            uart::write_str("xnu-rs: unimplemented syscall x16=0x");
            uart::write_hex_u64(nr);
            uart::write_str("\n");
            frame.x[0] = u64::MAX; // -1 (ENOSYS)
        }
    }
}
