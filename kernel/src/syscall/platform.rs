use crate::arch::uart;

use super::SyscallContext;

pub(super) fn dispatch(ctx: &mut SyscallContext) {
    let code = ctx.arg(3) as u32;
    match code {
        0 | 1 => {
            // Cache flush (I-Cache or D-Cache). Success.
            ctx.set_return(0);
        }
        2 => {
            // set cthread self: value is in x0
            crate::arch::thread_register_set(ctx.arg(0));
            ctx.set_return(0);
        }
        3 => {
            // get cthread self
            ctx.set_return(crate::arch::thread_register_get());
        }
        _ => {
            uart::write_str("xnu-rs: unknown platform syscall code=");
            uart::write_hex_u64(u64::from(code));
            uart::write_str("\n");
            ctx.set_return(u64::MAX);
        }
    }
}
