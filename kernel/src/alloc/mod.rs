pub mod buddy;
pub mod slab;

use spin::{LazyLock, Mutex};
use zs_alloc::ZsStore;

/// Kernel-wide compressed object store.
///
/// Use this for caching data that benefits from transparent LZ4 compression
/// (e.g., file-system block caches, page-out staging).  General kernel heap
/// allocations go through the [`KernelAllocator`] below.
pub static ZS: LazyLock<Mutex<ZsStore>> = LazyLock::new(|| Mutex::new(ZsStore::new()));

use core::{
    alloc::{GlobalAlloc, Layout},
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

const HEAP_SIZE: usize = 64 * 1024 * 1024;

/// Maximum number of disjoint free regions tracked simultaneously.
///
/// Each `dealloc` consumes one slot; coalescing merges adjacent regions to
/// keep the list compact.  256 is generous for a single-image kernel.
const MAX_FREE_REGIONS: usize = 256;

#[repr(align(16))]
struct HeapStorage([MaybeUninit<u8>; HEAP_SIZE]);

// SAFETY: The `Mutex<FreeList>` inside `KernelAllocator` serialises all
// access; `HeapStorage` is treated as raw bytes only.
static mut HEAP: HeapStorage = HeapStorage([MaybeUninit::uninit(); HEAP_SIZE]);

/// Returns the base address of the heap backing store.
fn heap_base() -> usize {
    // SAFETY: We only form a raw usize from the static's address, never
    // create a Rust reference to its contents.
    unsafe { ptr::addr_of!(HEAP.0) as usize }
}

// ── Free-region list ──────────────────────────────────────────────────────

/// One contiguous free span on the heap.  `size == 0` marks an empty slot.
#[derive(Clone, Copy)]
struct Region {
    addr: usize,
    size: usize,
}

/// Free list stored entirely in BSS — no pointer embedding into freed memory.
struct FreeList {
    regions: [Region; MAX_FREE_REGIONS],
    len: usize,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            regions: [Region { addr: 0, size: 0 }; MAX_FREE_REGIONS],
            len: 0,
        }
    }

    fn init(&mut self) {
        self.regions[0] = Region {
            addr: heap_base(),
            size: HEAP_SIZE,
        };
        self.len = 1;
    }

    /// First-fit allocation with optional splitting.
    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        for i in 0..self.len {
            let r = self.regions[i];
            let aligned = r.addr.wrapping_add(align - 1) & !(align - 1);
            let end = match aligned.checked_add(size) {
                Some(e) if e <= r.addr + r.size => e,
                _ => continue,
            };

            // Consume or shrink the region.
            let leftover_before = aligned - r.addr;
            let leftover_after = (r.addr + r.size) - end;

            if leftover_before == 0 {
                // Aligned to the start: shrink or remove.
                if leftover_after > 0 {
                    self.regions[i] = Region {
                        addr: end,
                        size: leftover_after,
                    };
                } else {
                    self.remove(i);
                }
            } else {
                // Trim the region to the prefix; add an after-region if any.
                self.regions[i] = Region {
                    addr: r.addr,
                    size: leftover_before,
                };
                if leftover_after > 0 {
                    self.push(Region {
                        addr: end,
                        size: leftover_after,
                    });
                }
            }

            // SAFETY: `aligned` is within the static `HEAP` array, properly
            // aligned, and exclusively owned until freed.
            return aligned as *mut u8;
        }

        ptr::null_mut() // OOM
    }

    /// Return a span to the free list, coalescing with adjacent regions.
    fn dealloc(&mut self, addr: usize, size: usize) {
        // Try to merge with an existing adjacent region.
        for i in 0..self.len {
            let r = &mut self.regions[i];
            if r.addr + r.size == addr {
                // `[r][freed]` → extend right.
                r.size += size;
                // Check if the next region now abuts this one.
                let merged_end = r.addr + r.size;
                let merged_addr = r.addr;
                let merged_size = r.size;
                for j in 0..self.len {
                    if j != i && self.regions[j].addr == merged_end {
                        let extra = self.regions[j].size;
                        self.regions[i] = Region {
                            addr: merged_addr,
                            size: merged_size + extra,
                        };
                        self.remove(j);
                        return;
                    }
                }
                return;
            }
            if addr + size == r.addr {
                // `[freed][r]` → extend left.
                r.addr = addr;
                r.size += size;
                return;
            }
        }

        // No neighbour — add a new region.
        self.push(Region { addr, size });
    }

    fn push(&mut self, r: Region) {
        if self.len < MAX_FREE_REGIONS {
            self.regions[self.len] = r;
            self.len += 1;
        }
        // Silently drop if table is full; the memory becomes permanently lost.
        // With MAX_FREE_REGIONS=256 and coalescing this should never occur in
        // normal kernel operation.
    }

    fn remove(&mut self, i: usize) {
        if i + 1 < self.len {
            self.regions[i] = self.regions[self.len - 1];
        }
        self.len -= 1;
    }
}

// ── Global allocator ──────────────────────────────────────────────────────

struct KernelAllocator {
    free_list: Mutex<FreeList>,
    ready: AtomicBool,
}

// SAFETY: All heap access is serialised through `Mutex<FreeList>`.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut fl = self.free_list.lock();
        if !self.ready.load(Ordering::Relaxed) {
            fl.init();
            self.ready.store(true, Ordering::Relaxed);
        }
        fl.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.free_list.lock().dealloc(ptr as usize, layout.size());
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator {
    free_list: Mutex::new(FreeList::new()),
    ready: AtomicBool::new(false),
};
