use super::transport::{QUEUE_SIZE, VirtioMmio};
use crate::arch::aarch64::uart;
use core::sync::atomic::{Ordering, fence};
use spin::Once;

const BLK_T_IN: u32 = 0; // read
const BLK_T_OUT: u32 = 1; // write

// Virtq descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
struct BlkReq {
    type_: u32,
    reserved: u32,
    sector: u64,
}

// Static buffers avoid stack addresses crossing page boundaries during DMA.
// SAFETY: Access is serialized by the `Mutex<VirtioBlk>` wrapper.
static mut BLK_REQ: BlkReq = BlkReq {
    type_: 0,
    reserved: 0,
    sector: 0,
};
static mut BLK_STATUS: u8 = 0;

pub struct VirtioBlk {
    mmio: VirtioMmio,
}

impl VirtioBlk {
    /// Read one 512-byte sector into `buf`. Returns `true` on success.
    pub fn read_block(&mut self, sector: u64, buf: &mut [u8; 512]) -> bool {
        // SAFETY: `BLK_REQ`/`BLK_STATUS` access is serialized by `Mutex<VirtioBlk>`.
        unsafe { self.do_request(BLK_T_IN, sector, buf.as_mut_ptr(), true) }
    }

    /// Write one 512-byte sector from `buf`. Returns `true` on success.
    pub fn write_block(&mut self, sector: u64, buf: &[u8; 512]) -> bool {
        // SAFETY: `BLK_REQ`/`BLK_STATUS` access is serialized by `Mutex<VirtioBlk>`.
        unsafe { self.do_request(BLK_T_OUT, sector, buf.as_ptr().cast_mut(), false) }
    }

    /// Build and submit a 3-descriptor virtio-blk request, then poll for completion.
    ///
    /// # Safety
    /// `BLK_REQ` and `BLK_STATUS` must not be concurrently accessed.
    unsafe fn do_request(
        &mut self,
        req_type: u32,
        sector: u64,
        data_ptr: *mut u8,
        data_write: bool,
    ) -> bool {
        // Fill request header.
        // SAFETY: Exclusive access via `Mutex<VirtioBlk>`.
        unsafe {
            BLK_REQ = BlkReq {
                type_: req_type,
                reserved: 0,
                sector,
            };
            BLK_STATUS = 0xFF; // sentinel: device must overwrite with 0 on success
        }

        // `addr_of!` does not create a reference; safe inside the surrounding unsafe fn.
        let req_pa = core::ptr::addr_of!(BLK_REQ) as u64;
        let status_pa = core::ptr::addr_of!(BLK_STATUS) as u64;

        // Allocate 3 descriptors from the free list via a raw pointer so that
        // we don't hold a mutable borrow on `self.mmio` when calling notify/poll_used.
        // SAFETY: `q_ptr` is valid for the lifetime of this call; no concurrent access.
        let q_ptr = &raw mut self.mmio.queue;

        // SAFETY: `q_ptr` is valid; free_head is always a valid index after init.
        let d0 = unsafe { (*q_ptr).free_head as usize };
        // SAFETY: `d0` is a valid index into the descriptor table (free list is never empty
        // after init; QUEUE_SIZE = 16 descriptors are pre-linked).
        let d1 = unsafe { (*(*q_ptr).desc.add(d0)).next as usize };
        // SAFETY: Same as above for `d1`.
        let d2 = unsafe { (*(*q_ptr).desc.add(d1)).next as usize };
        // SAFETY: Advance free head past the three descriptors we are about to use.
        unsafe { (*q_ptr).free_head = (*(*q_ptr).desc.add(d2)).next };

        // Desc 0: `BlkReq` header (device-readable, has NEXT).
        // SAFETY: `d0` is a valid descriptor index within the pre-allocated table.
        unsafe {
            let d = (*q_ptr).desc.add(d0);
            (*d).addr = req_pa;
            #[allow(clippy::cast_possible_truncation)] // BlkReq is 16 bytes; fits in u32
            {
                (*d).len = core::mem::size_of::<BlkReq>() as u32;
            }
            (*d).flags = VIRTQ_DESC_F_NEXT;
            #[allow(clippy::cast_possible_truncation)] // d1 ≤ QUEUE_SIZE (16)
            {
                (*d).next = d1 as u16;
            }
        }

        // Desc 1: data buffer (device-writable for READ, device-readable for WRITE, has NEXT).
        // SAFETY: `d1` is a valid descriptor index.
        unsafe {
            let d = (*q_ptr).desc.add(d1);
            (*d).addr = data_ptr as u64;
            (*d).len = 512;
            (*d).flags = VIRTQ_DESC_F_NEXT | if data_write { VIRTQ_DESC_F_WRITE } else { 0 };
            #[allow(clippy::cast_possible_truncation)] // d2 ≤ QUEUE_SIZE (16)
            {
                (*d).next = d2 as u16;
            }
        }

        // Desc 2: status byte (device-writable, no NEXT).
        // SAFETY: `d2` is a valid descriptor index.
        unsafe {
            let d = (*q_ptr).desc.add(d2);
            (*d).addr = status_pa;
            (*d).len = 1;
            (*d).flags = VIRTQ_DESC_F_WRITE;
            (*d).next = 0;
        }

        // Publish to available ring.
        // SAFETY: `avail` ring is valid; `idx` wraps naturally by u16 arithmetic.
        unsafe {
            let avail = (*q_ptr).avail;
            let avail_idx = core::ptr::read_volatile(&raw const (*avail).idx);
            let slot = (avail_idx as usize) % QUEUE_SIZE;
            #[allow(clippy::cast_possible_truncation)] // d0 ≤ QUEUE_SIZE (16)
            core::ptr::write_volatile(&raw mut (*avail).ring[slot], d0 as u16);
            fence(Ordering::Release);
            core::ptr::write_volatile(&raw mut (*avail).idx, avail_idx.wrapping_add(1));
        }

        // Kick the device.
        // SAFETY: Device is initialized; `notify` writes to the MMIO notify register.
        unsafe { self.mmio.notify(0) };

        // Poll for completion.
        // SAFETY: A request is in flight; `poll_used` spins on the used ring.
        unsafe { self.mmio.poll_used() };

        // Return all three descriptors to the free list.
        // SAFETY: `q_ptr` is still valid; no concurrent access.
        unsafe {
            (*(*q_ptr).desc.add(d2)).next = (*q_ptr).free_head;
            #[allow(clippy::cast_possible_truncation)] // d0 ≤ QUEUE_SIZE (16)
            {
                (*q_ptr).free_head = d0 as u16;
            }
        }

        fence(Ordering::Acquire);

        // Check status byte written by device (0 = OK, 1 = IOERR, 2 = UNSUPP).
        // SAFETY: `BLK_STATUS` was written by the device before `poll_used` returned.
        unsafe { BLK_STATUS == 0 }
    }
}

pub static VIRTIO_BLK: Once<spin::Mutex<VirtioBlk>> = Once::new();

/// Initialize virtio-blk. Call from kernel main after MMU setup.
pub fn init() {
    for slot in 0..32_usize {
        // SAFETY: MMIO region is identity-mapped by `mmu::init_kernel_tables()`.
        if let Some(mmio) = unsafe { VirtioMmio::probe(slot, 2) } {
            uart::write_str("xnu-rs: virtio-blk found at slot 0x");
            uart::write_hex_u64(slot as u64);
            uart::write_str("\n");
            VIRTIO_BLK.call_once(|| spin::Mutex::new(VirtioBlk { mmio }));
            return;
        }
    }
    uart::write_str("xnu-rs: no virtio-blk found\n");
}
