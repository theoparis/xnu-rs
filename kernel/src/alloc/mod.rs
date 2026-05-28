pub mod buddy;
pub mod slab;

use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};

const HEAP_SIZE: usize = 4 * 1024 * 1024;

#[repr(align(16))]
struct Heap([u8; HEAP_SIZE]);

static HEAP: Heap = Heap([0; HEAP_SIZE]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

// SAFETY: `BumpAllocator` bumps an atomic offset into a static backing array.
// All pointers returned are within `HEAP` and will not be freed.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = HEAP.0.as_ptr() as usize;
        loop {
            let old = HEAP_NEXT.load(Ordering::Relaxed);
            let align = layout.align();
            let aligned = old.wrapping_add(align - 1) & !(align - 1);
            let new = match aligned.checked_add(layout.size()) {
                Some(n) if n <= HEAP_SIZE => n,
                _ => return core::ptr::null_mut(),
            };
            if HEAP_NEXT
                .compare_exchange(old, new, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: `aligned` is within `HEAP` (checked above) and properly aligned.
                return (base + aligned) as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator — allocations are never freed.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;
