#![allow(clippy::cast_possible_truncation, clippy::undocumented_unsafe_blocks)]

use core::sync::atomic::AtomicU32;

use crate::arch::uart;

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

static PORT_COUNTER: AtomicU32 = AtomicU32::new(10);

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
        TASK_SELF_TRAP => {
            ctx.set_return(1);
        }
        THREAD_SELF_TRAP => {
            ctx.set_return(2);
        }
        HOST_SELF_TRAP => {
            ctx.set_return(3);
        }
        MACH_REPLY_PORT => {
            ctx.set_return(u64::from(
                PORT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            ));
        }
        KERNELRPC_MACH_PORT_ALLOCATE => {
            let p = ctx.arg(2) as *mut u32;
            let name = PORT_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if !p.is_null() {
                unsafe { p.write(name) };
            }
            ctx.set_return(0);
        }
        KERNELRPC_MACH_VM_ALLOCATE_TRAP => {
            // x0 = task (ignored), x1 = *mach_vm_address_t out, x2 = size, x3 = flags
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
                ctx.set_return(0); // KERN_SUCCESS
            } else {
                uart::write_str(" -> KERN_NO_SPACE\n");
                ctx.set_return(3); // KERN_NO_SPACE
            }
        }
        KERNELRPC_MACH_VM_MAP_TRAP => {
            // x0 = task (ignored), x1 = *mach_vm_address_t in/out, x2 = size
            // x3 = mask, x4 = flags, x5 = cur_prot
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
                ctx.set_return(0); // KERN_SUCCESS
            } else {
                uart::write_str(" -> KERN_NO_SPACE\n");
                ctx.set_return(3); // KERN_NO_SPACE
            }
        }
        KERNELRPC_MACH_VM_DEALLOCATE_TRAP => {
            ctx.set_return(0); // KERN_SUCCESS (no-op; no real VM tracking)
        }
        MACH_MSG_TRAP
        | MACH_MSG2_TRAP
        | KERNELRPC_MACH_PORT_DEALLOCATE
        | KERNELRPC_MACH_PORT_MOD_REFS
        | KERNELRPC_MACH_PORT_INSERT_RIGHT
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
