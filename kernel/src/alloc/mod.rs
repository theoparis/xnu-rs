pub mod buddy;
pub mod slab;

use core::{
    alloc::{GlobalAlloc, Layout},
    mem::MaybeUninit,
    sync::atomic::{AtomicUsize, Ordering},
};

const HEAP_SIZE: usize = 64 * 1024 * 1024;

#[repr(align(16))]
struct Heap([MaybeUninit<u8>; HEAP_SIZE]);

// SAFETY: Zero-initialized via MaybeUninit; treated as raw bytes by the allocator.
static mut HEAP: Heap = Heap([MaybeUninit::uninit(); HEAP_SIZE]);
static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);

struct BumpAllocator;

// SAFETY: `BumpAllocator` bumps an atomic offset into a static backing array.
// All pointers returned are within `HEAP` and will not be freed.
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: We only form a raw pointer to the array, never a reference.
        let base = unsafe { core::ptr::addr_of!(HEAP.0) as usize };
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
