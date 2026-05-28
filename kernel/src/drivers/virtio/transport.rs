use core::sync::atomic::{Ordering, fence};

const MMIO_BASE: u64 = 0x0A00_0000;
const MMIO_STRIDE: u64 = 0x200;
const MAGIC: u32 = 0x7472_6976;
pub const QUEUE_SIZE: usize = 16;

// MMIO register offsets
const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_HOST_FEATURES: u64 = 0x010;
const REG_GUEST_FEATURES: u64 = 0x020;
const REG_GUEST_PAGE_SIZE: u64 = 0x028;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_ALIGN: u64 = 0x03C;
const REG_QUEUE_PFN: u64 = 0x040;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_STATUS: u64 = 0x070;

// Device status flags
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;

// Queue layout (QUEUE_SIZE = 16):
//   Offset 0    : descriptor table  = 16 * 16 = 256 bytes
//   Offset 256  : available ring    = 6 + 16*2 + 2 = 40 bytes
//   Offset 4096 : used ring         = 6 + 16*8 + 2 = 136 bytes  (page-aligned per spec)
// Total: 8192 bytes (2 pages) fits in QueueMem below.

#[repr(align(4096))]
#[allow(dead_code)] // field accessed via raw pointer
struct QueueMem([u8; 8192]);

// SAFETY: Protected by Once<Mutex<VirtioBlk>>; only one driver accesses this.
static mut QUEUE_MEM: QueueMem = QueueMem([0u8; 8192]);

#[repr(C)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

#[repr(C)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

pub struct VirtQueue {
    pub base_pa: u64,
    pub desc: *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used: *const VirtqUsed,
    pub last_used_idx: u16,
    pub free_head: u16,
}

// SAFETY: `VirtQueue` contains raw pointers into static DMA memory. Access is always
// serialized via the `Mutex<VirtioBlk>` wrapper, so Send + Sync are sound.
unsafe impl Send for VirtQueue {}
// SAFETY: see above.
unsafe impl Sync for VirtQueue {}

pub struct VirtioMmio {
    pub base: u64,
    pub queue: VirtQueue,
}

// SAFETY: `VirtioMmio` wraps a `VirtQueue` (see above) and a base MMIO address.
// Both are safe to transfer between threads when protected by a Mutex.
unsafe impl Send for VirtioMmio {}
// SAFETY: see above.
unsafe impl Sync for VirtioMmio {}

impl VirtioMmio {
    /// Probe the given MMIO slot.
    ///
    /// Returns `None` if not a valid virtio device or wrong `device_id`.
    ///
    /// # Safety
    /// Caller must ensure the MMIO region is mapped and accessible.
    #[must_use]
    pub unsafe fn probe(slot: usize, expected_device_id: u32) -> Option<Self> {
        let base = MMIO_BASE + (slot as u64) * MMIO_STRIDE;

        // SAFETY: Caller guarantees MMIO is identity-mapped.
        let magic = unsafe { Self::read_reg_raw(base, REG_MAGIC) };
        if magic != MAGIC {
            return None;
        }

        // SAFETY: Caller guarantees MMIO is identity-mapped.
        let version = unsafe { Self::read_reg_raw(base, REG_VERSION) };
        // SAFETY: Caller guarantees MMIO is identity-mapped.
        let device_id = unsafe { Self::read_reg_raw(base, REG_DEVICE_ID) };

        // Support both legacy (v1) and modern (v2) transports.
        if version != 1 && version != 2 {
            return None;
        }

        if device_id != expected_device_id {
            return None;
        }

        let mut dev = Self {
            base,
            queue: VirtQueue {
                base_pa: 0,
                desc: core::ptr::null_mut(),
                avail: core::ptr::null_mut(),
                used: core::ptr::null(),
                last_used_idx: 0,
                free_head: 0,
            },
        };

        // SAFETY: Device is confirmed present; single-threaded init path.
        if unsafe { dev.init_queue() } {
            Some(dev)
        } else {
            None
        }
    }

    /// Initialize the virtqueue (legacy mode).
    ///
    /// # Safety
    /// Must be called once during device initialization while no other code
    /// accesses `QUEUE_MEM` or the MMIO registers.
    unsafe fn init_queue(&mut self) -> bool {
        // SAFETY: Exclusive access to this MMIO device during single-threaded init.
        unsafe {
            // Reset device.
            self.write_reg(REG_STATUS, 0);

            // Acknowledge + driver.
            self.write_reg(REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

            // Accept all features (legacy: no negotiation needed).
            let _features = self.read_reg(REG_HOST_FEATURES);
            self.write_reg(REG_GUEST_FEATURES, 0);

            // Set page size = 4096.
            self.write_reg(REG_GUEST_PAGE_SIZE, 4096);

            // Select queue 0.
            self.write_reg(REG_QUEUE_SEL, 0);
        }

        // SAFETY: MMIO register read.
        let queue_num_max = unsafe { self.read_reg(REG_QUEUE_NUM_MAX) };
        if queue_num_max == 0 || (queue_num_max as usize) < QUEUE_SIZE {
            return false;
        }

        // SAFETY: Single-threaded init writes.
        unsafe {
            // Set queue size.
            // SAFETY: QUEUE_SIZE = 16; fits in u32.
            #[allow(clippy::cast_possible_truncation)]
            self.write_reg(REG_QUEUE_NUM, QUEUE_SIZE as u32);
            // Set queue alignment.
            self.write_reg(REG_QUEUE_ALIGN, 4096);
        }

        // Compute pointers into static queue memory.
        // SAFETY: `addr_of_mut!` on a static does not create a reference.
        // `QUEUE_MEM` is exclusively owned during init (protected by `Once<Mutex>`).
        let mem_ptr: *mut u8 = core::ptr::addr_of_mut!(QUEUE_MEM).cast::<u8>();
        let mem_pa = mem_ptr as u64;

        // Descriptor table at offset 0 (QUEUE_SIZE * 16 = 256 bytes).
        // mem_ptr is 4096-byte aligned (repr(align(4096))); VirtqDesc requires 8-byte
        // alignment. 4096 % 8 == 0, so the cast is valid.
        // clippy::cast_ptr_alignment: alignment is guaranteed by the repr above.
        #[allow(clippy::cast_ptr_alignment)]
        let desc_ptr: *mut VirtqDesc = mem_ptr.cast::<VirtqDesc>();

        // Available ring at offset 256; VirtqAvail requires 2-byte alignment; 256 % 2 == 0.
        // SAFETY: offset 256 is within the 8192-byte allocation; alignment verified above.
        let avail_ptr: *mut VirtqAvail = unsafe {
            #[allow(clippy::cast_ptr_alignment)] // alignment verified above
            mem_ptr.add(256).cast::<VirtqAvail>()
        };

        // Used ring at offset 4096 (page-aligned per QueueAlign = 4096).
        // VirtqUsed requires 4-byte alignment; 4096 % 4 == 0.
        // SAFETY: offset 4096 is within the 8192-byte allocation; alignment verified above.
        let used_ptr: *const VirtqUsed = unsafe {
            #[allow(clippy::cast_ptr_alignment)] // alignment verified above
            mem_ptr.add(4096).cast::<VirtqUsed>()
        };

        self.queue = VirtQueue {
            base_pa: mem_pa,
            desc: desc_ptr,
            avail: avail_ptr,
            used: used_ptr,
            last_used_idx: 0,
            free_head: 0,
        };

        // Zero-init the queue memory.
        // SAFETY: mem_ptr is valid for 8192 bytes; we own the buffer.
        unsafe { core::ptr::write_bytes(mem_ptr, 0, 8192) };

        // Initialize descriptor free list.
        for i in 0..QUEUE_SIZE {
            // SAFETY: `i` is within [0, QUEUE_SIZE); desc table covers all indices.
            unsafe {
                #[allow(clippy::cast_possible_truncation)] // i + 1 ≤ 16; fits in u16
                let next = (i + 1) as u16;
                (*desc_ptr.add(i)).next = next;
            }
        }

        // Set `QueuePFN` (page frame number = phys_addr / 4096).
        // SAFETY: MMIO write; pfn fits in u32 for all RAM addresses in QEMU virt.
        unsafe {
            #[allow(clippy::cast_possible_truncation)] // phys addr < 4 GiB on QEMU virt
            self.write_reg(REG_QUEUE_PFN, (mem_pa / 4096) as u32);
        }

        // Mark driver OK.
        // SAFETY: MMIO write finalizing initialization.
        unsafe {
            self.write_reg(
                REG_STATUS,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
            );
        }

        true
    }

    /// Write a 32-bit MMIO register.
    ///
    /// # Safety
    /// Caller must ensure `offset` is a valid register for this device.
    pub unsafe fn write_reg(&self, offset: u64, val: u32) {
        // SAFETY: base is a valid MMIO address; volatile write is required for MMIO.
        unsafe {
            core::ptr::write_volatile((self.base + offset) as *mut u32, val);
        }
    }

    /// Read a 32-bit MMIO register.
    ///
    /// # Safety
    /// Caller must ensure `offset` is a valid register for this device.
    #[must_use]
    pub unsafe fn read_reg(&self, offset: u64) -> u32 {
        // SAFETY: base is a valid MMIO address; volatile read is required for MMIO.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Read a 32-bit MMIO register without a `self` receiver (used during probe).
    ///
    /// # Safety
    /// Caller must ensure `base + offset` is a valid MMIO address.
    unsafe fn read_reg_raw(base: u64, offset: u64) -> u32 {
        // SAFETY: Caller guarantees validity.
        unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
    }

    /// Notify device of new available descriptor.
    ///
    /// # Safety
    /// Queue must be initialized and descriptor chain must be published.
    pub unsafe fn notify(&self, queue_idx: u32) {
        fence(Ordering::Release);
        // SAFETY: MMIO write to notify register; device is initialized.
        unsafe { self.write_reg(REG_QUEUE_NOTIFY, queue_idx) };
    }

    /// Poll until device has consumed at least one descriptor since `last_used_idx`.
    ///
    /// Returns the used element id.
    ///
    /// # Safety
    /// Queue must be initialized and a request must be in flight.
    pub unsafe fn poll_used(&mut self) -> u32 {
        loop {
            fence(Ordering::Acquire);
            // SAFETY: `used` points to valid initialized shared memory; volatile read required.
            let used_idx = unsafe { core::ptr::read_volatile(&raw const (*self.queue.used).idx) };
            if used_idx != self.queue.last_used_idx {
                // SAFETY: `ring` index is masked to [0, QUEUE_SIZE).
                let elem_id = unsafe {
                    let slot = (self.queue.last_used_idx as usize) % QUEUE_SIZE;
                    core::ptr::read_volatile(&raw const (*self.queue.used).ring[slot].id)
                };
                self.queue.last_used_idx = self.queue.last_used_idx.wrapping_add(1);
                return elem_id;
            }
            core::hint::spin_loop();
        }
    }
}
