//! Minimal Mach message send/receive (inline data only, no OOL descriptors).

use core::slice;

use super::mach_port::{Port, PortNamespace};
use super::rights::RightKind;
use liballoc::{sync::Arc, vec};
use spin::Mutex;

// ── Mach message return codes ─────────────────────────────────────────────────

pub const MACH_MSG_SUCCESS: u32 = 0;
pub const MACH_SEND_INVALID_DEST: u32 = 0x1000_0003;
pub const MACH_RCV_TIMED_OUT: u32 = 0x1000_4003;
pub const MACH_RCV_TOO_LARGE: u32 = 0x1000_4004;

// ── mach_msg option bits ──────────────────────────────────────────────────────

pub const MACH_SEND_MSG: u32 = 0x00000001;
pub const MACH_RCV_MSG: u32 = 0x00000002;

// ── MachMsgHeader ─────────────────────────────────────────────────────────────

/// C-compatible Mach message header (matches `mach_msg_header_t`).
#[repr(C)]
pub struct MachMsgHeader {
    pub msgh_bits: u32,
    pub msgh_size: u32,
    pub msgh_remote_port: u32,
    pub msgh_local_port: u32,
    pub msgh_voucher_port: u32,
    pub msgh_id: i32,
}

// ── send ──────────────────────────────────────────────────────────────────────

/// Copy `msgh_size` bytes from user address `header_addr`, look up the remote
/// port from `ns`, and enqueue the raw bytes on that port's message queue.
///
/// Returns `MACH_MSG_SUCCESS` or `MACH_SEND_INVALID_DEST`.
///
/// # Safety
///
/// `header_addr` must be a valid user-space pointer to at least `msgh_size`
/// readable bytes for the duration of this call.
pub unsafe fn send(ns: &mut PortNamespace, header_addr: usize, size: u32) -> u32 {
    if size < core::mem::size_of::<MachMsgHeader>() as u32 {
        return MACH_SEND_INVALID_DEST;
    }

    // SAFETY: Caller guarantees `header_addr` points to `size` valid bytes.
    let bytes = unsafe { slice::from_raw_parts(header_addr as *const u8, size as usize) };
    // Parse remote port from the header (bytes 8..12).
    let remote_port = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

    let port_arc: Arc<Mutex<Port>> = match ns.lookup(remote_port) {
        Some(e) if e.kind == RightKind::Send || e.kind == RightKind::SendOnce => {
            Arc::clone(&e.port)
        }
        // Sending to a null port (name=0) or non-send right is silently
        // discarded — matches Darwin behaviour for bootstrap messages.
        _ if remote_port == 0 => return MACH_MSG_SUCCESS,
        _ => return MACH_SEND_INVALID_DEST,
    };

    port_arc.lock().messages.push_back(vec::Vec::from(bytes));
    MACH_MSG_SUCCESS
}

// ── recv ──────────────────────────────────────────────────────────────────────

/// Dequeue the oldest message from `local_port` and write it to the user
/// buffer at `rcv_addr` (up to `rcv_size` bytes).
///
/// Returns `MACH_MSG_SUCCESS`, `MACH_RCV_TIMED_OUT` (empty queue), or
/// `MACH_RCV_TOO_LARGE`.
///
/// # Safety
///
/// `rcv_addr` must be a valid user-space pointer to at least `rcv_size`
/// writable bytes.
pub unsafe fn recv(ns: &PortNamespace, local_port: u32, rcv_addr: usize, rcv_size: u32) -> u32 {
    let port_arc = match ns.lookup(local_port) {
        Some(e) if e.kind == RightKind::Receive => Arc::clone(&e.port),
        _ => return MACH_RCV_TIMED_OUT,
    };

    let msg = match port_arc.lock().messages.pop_front() {
        Some(m) => m,
        None => return MACH_RCV_TIMED_OUT,
    };

    if msg.len() > rcv_size as usize {
        // Put it back and report the overflow.
        port_arc.lock().messages.push_front(msg);
        return MACH_RCV_TOO_LARGE;
    }

    // SAFETY: Caller guarantees `rcv_addr` is writable for `rcv_size` bytes.
    let out = unsafe { slice::from_raw_parts_mut(rcv_addr as *mut u8, msg.len()) };
    out.copy_from_slice(&msg);
    MACH_MSG_SUCCESS
}
