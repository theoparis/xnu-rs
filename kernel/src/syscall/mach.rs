#![allow(clippy::cast_possible_truncation, clippy::undocumented_unsafe_blocks)]

use crate::arch::uart;
use crate::ipc::mach_msg::{MACH_RCV_MSG, MACH_SEND_MSG};
use crate::ipc::mach_port::{NAMESPACE, Port};
use crate::ipc::rights::RightKind;

use liballoc::sync::Arc;
use spin::Mutex;

use super::SyscallContext;

// ── Mach trap numbers (u64 wrapping of negative i32) ──────────────────────
const MACH_ABSOLUTE_TIME: u64 = 0xFFFF_FFFF_FFFF_FFFD; // -3
const MACH_TIMEBASE_INFO: u64 = 0xFFFF_FFFF_FFFF_FFFC; // -4
const KERNELRPC_MACH_VM_ALLOCATE_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFF6; // -10
const KERNELRPC_MACH_VM_DEALLOCATE_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFF4; // -12
const KERNELRPC_MACH_VM_PROTECT_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFF2; // -14
const KERNELRPC_MACH_VM_MAP_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFF1; // -15
const TASK_SELF_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE4; // -28
const THREAD_SELF_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE5; // -27
const HOST_SELF_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFEC; // -20
const MACH_REPLY_PORT: u64 = 0xFFFF_FFFF_FFFF_FFE6; // -26
const MACH_MSG_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE1; // -31
const MACH_MSG2_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE0; // -32
const KERNELRPC_MACH_PORT_ALLOCATE: u64 = 0xFFFF_FFFF_FFFF_FFF0; // -16
const KERNELRPC_MACH_PORT_DEALLOCATE: u64 = 0xFFFF_FFFF_FFFF_FFEE; // -18
const KERNELRPC_MACH_PORT_MOD_REFS: u64 = 0xFFFF_FFFF_FFFF_FFED; // -19
const KERNELRPC_MACH_PORT_INSERT_RIGHT: u64 = 0xFFFF_FFFF_FFFF_FFE9; // -23
const KERNELRPC_MACH_PORT_CONSTRUCT: u64 = 0xFFFF_FFFF_FFFF_FFE7; // -25
const KERNELRPC_MACH_PORT_DESTRUCT: u64 = 0xFFFF_FFFF_FFFF_FFE8; // -24
const SEMAPHORE_SIGNAL_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE3; // -29
const SEMAPHORE_WAIT_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFE2; // -30
const SWTCH_PRI_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFFB; // -5
const SWTCH_TRAP: u64 = 0xFFFF_FFFF_FFFF_FFFA; // -6

pub(super) fn dispatch(ctx: &mut SyscallContext, nr: u64) {
    match nr {
        MACH_ABSOLUTE_TIME => {
            ctx.set_return(crate::arch::time_ticks());
        }
        MACH_TIMEBASE_INFO => {
            let p = ctx.arg(0) as *mut u32;
            if !p.is_null() {
                unsafe {
                    p.write(1);
                    p.add(1).write(1);
                }
            }
            ctx.set_return(0);
        }

        // ── Well-known port names ─────────────────────────────────────────
        TASK_SELF_TRAP => {
            ctx.set_return(u64::from(crate::mach::task::TASK_SELF_NAME));
        }
        THREAD_SELF_TRAP => {
            ctx.set_return(u64::from(crate::mach::task::THREAD_SELF_NAME));
        }
        HOST_SELF_TRAP => {
            ctx.set_return(u64::from(crate::mach::task::HOST_SELF_NAME));
        }

        // ── Port allocation ───────────────────────────────────────────────
        MACH_REPLY_PORT => {
            let port = Arc::new(Mutex::new(Port::new()));
            let name = NAMESPACE.lock().insert(port, RightKind::Receive);
            ctx.set_return(u64::from(name));
        }
        KERNELRPC_MACH_PORT_ALLOCATE => {
            // x0 = task (ignored), x1 = right kind, x2 = *mach_port_name_t out
            let out_ptr = ctx.arg(2) as *mut u32;
            let port = Arc::new(Mutex::new(Port::new()));
            let name = NAMESPACE.lock().insert(port, RightKind::Receive);
            if !out_ptr.is_null() {
                unsafe { out_ptr.write(name) };
            }
            ctx.set_return(0); // KERN_SUCCESS
        }
        KERNELRPC_MACH_PORT_DEALLOCATE => {
            // x0 = task (ignored), x1 = port name
            let name = ctx.arg(1) as u32;
            NAMESPACE.lock().deallocate(name);
            ctx.set_return(0);
        }
        KERNELRPC_MACH_PORT_INSERT_RIGHT => {
            // x0 = task, x1 = name, x2 = poly (ignored), x3 = right_type
            // Look up the existing port for `name` and add a Send right.
            let name = ctx.arg(1) as u32;
            let port_arc = NAMESPACE.lock().lookup(name).map(|e| Arc::clone(&e.port));
            if let Some(port) = port_arc {
                let send_name = NAMESPACE.lock().insert(port, RightKind::Send);
                ctx.set_return(u64::from(send_name));
            } else {
                ctx.set_return(0);
            }
        }

        // ── Mach message ──────────────────────────────────────────────────
        MACH_MSG_TRAP | MACH_MSG2_TRAP => {
            // mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify)
            // x0=msg_addr x1=option x2=send_size x3=rcv_size x4=rcv_name
            let msg_addr = ctx.arg(0) as usize;
            let option = ctx.arg(1) as u32;
            let send_size = ctx.arg(2) as u32;
            let rcv_size = ctx.arg(3) as u32;
            let rcv_name = ctx.arg(4) as u32;

            let mut result = crate::ipc::mach_msg::MACH_MSG_SUCCESS;

            if option & MACH_SEND_MSG != 0 {
                // SAFETY: msg_addr is a user pointer; send() validates size.
                result = unsafe {
                    crate::ipc::mach_msg::send(&mut NAMESPACE.lock(), msg_addr, send_size)
                };
            }

            if result == crate::ipc::mach_msg::MACH_MSG_SUCCESS && option & MACH_RCV_MSG != 0 {
                // SAFETY: msg_addr is a user pointer; recv() validates size.
                result = unsafe {
                    crate::ipc::mach_msg::recv(&NAMESPACE.lock(), rcv_name, msg_addr, rcv_size)
                };
            }

            ctx.set_return(u64::from(result));
        }

        // ── VM allocation ─────────────────────────────────────────────────
        KERNELRPC_MACH_VM_ALLOCATE_TRAP => {
            let addr_ptr = ctx.arg(1) as *mut u64;
            let size = ctx.arg(2);
            let aligned = (size + 0xFFF) & !0xFFF;
            uart::write_str("xnu-rs: vm_allocate size=0x");
            uart::write_hex_u64(size);
            let base = super::MMAP_BASE.load(core::sync::atomic::Ordering::Relaxed);
            let start = if base == 0 {
                super::MMAP_REGION_START
            } else {
                base
            };
            if start + aligned <= super::MMAP_REGION_END {
                super::MMAP_BASE.store(start + aligned, core::sync::atomic::Ordering::Relaxed);
                unsafe { core::ptr::write_bytes(start as *mut u8, 0, aligned as usize) };
                if !addr_ptr.is_null() {
                    unsafe { addr_ptr.write(start) };
                }
                uart::write_str(" -> 0x");
                uart::write_hex_u64(start);
                uart::write_str("\n");
                ctx.set_return(0);
            } else {
                uart::write_str(" -> KERN_NO_SPACE\n");
                ctx.set_return(3);
            }
        }
        KERNELRPC_MACH_VM_MAP_TRAP => {
            let addr_ptr = ctx.arg(1) as *mut u64;
            let size = ctx.arg(2);
            let aligned = (size + 0xFFF) & !0xFFF;
            uart::write_str("xnu-rs: vm_map size=0x");
            uart::write_hex_u64(size);
            let base = super::MMAP_BASE.load(core::sync::atomic::Ordering::Relaxed);
            let start = if base == 0 {
                super::MMAP_REGION_START
            } else {
                base
            };
            if start + aligned <= super::MMAP_REGION_END {
                super::MMAP_BASE.store(start + aligned, core::sync::atomic::Ordering::Relaxed);
                unsafe { core::ptr::write_bytes(start as *mut u8, 0, aligned as usize) };
                if !addr_ptr.is_null() {
                    unsafe { addr_ptr.write(start) };
                }
                uart::write_str(" -> 0x");
                uart::write_hex_u64(start);
                uart::write_str("\n");
                ctx.set_return(0);
            } else {
                uart::write_str(" -> KERN_NO_SPACE\n");
                ctx.set_return(3);
            }
        }
        KERNELRPC_MACH_VM_DEALLOCATE_TRAP => {
            ctx.set_return(0);
        }

        // ── No-ops ────────────────────────────────────────────────────────
        KERNELRPC_MACH_PORT_MOD_REFS
        | KERNELRPC_MACH_PORT_CONSTRUCT
        | KERNELRPC_MACH_PORT_DESTRUCT
        | SEMAPHORE_SIGNAL_TRAP
        | SEMAPHORE_WAIT_TRAP
        | KERNELRPC_MACH_VM_PROTECT_TRAP
        | SWTCH_PRI_TRAP
        | SWTCH_TRAP => {
            ctx.set_return(0);
        }

        _ => {
            uart::write_str("xnu-rs: mach x16=");
            uart::write_hex_u64(nr);
            uart::write_str("\n");
            ctx.set_return(u64::MAX);
        }
    }
}
