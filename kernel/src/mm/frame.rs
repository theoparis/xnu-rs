use core::sync::atomic::{AtomicU64, Ordering};

const PAGE_SIZE: u64 = 4096;
const MAX_FRAMES: usize = 65536; // 256 MiB / 4 KiB
const WORDS: usize = MAX_FRAMES / 64;

// 1 = free, 0 = used. Starts as all-zeros (BSS); init() sets free bits.
static BITMAP: [AtomicU64; WORDS] = {
    let mut arr = [const { AtomicU64::new(0) }; WORDS];
    // Convince the compiler this is the same as const-init all-zero.
    // The loop is zero-iteration at const-eval time; value is already 0.
    let mut i = 0;
    while i < WORDS {
        arr[i] = AtomicU64::new(0);
        i += 1;
    }
    arr
};

static PHYS_BASE: AtomicU64 = AtomicU64::new(0);
static FRAME_COUNT: AtomicU64 = AtomicU64::new(0);

/// Initialize the frame allocator.
///
/// Marks all frames in `[phys_base, phys_base + mem_size)` as free, then
/// marks the kernel's own frames as used so they are never handed out.
pub fn init(phys_base: u64, mem_size: u64, kernel_start: u64, kernel_end: u64) {
    PHYS_BASE.store(phys_base, Ordering::Relaxed);

    let total_frames = (mem_size / PAGE_SIZE) as usize;
    let clamped = if total_frames > MAX_FRAMES {
        MAX_FRAMES
    } else {
        total_frames
    };
    FRAME_COUNT.store(clamped as u64, Ordering::Relaxed);

    // Mark all frames in the usable range as free.
    for i in 0..clamped {
        set_bit(i, true);
    }

    // Reserve the frames occupied by the kernel.
    if kernel_end > kernel_start {
        let ks = frame_index(phys_base, kernel_start);
        let ke = frame_index_ceil(phys_base, kernel_end);
        for i in ks..ke {
            if i < clamped {
                set_bit(i, false);
            }
        }
    }
}

/// Allocate one free 4 KiB physical frame.  Returns its physical address.
pub fn alloc_frame() -> Option<u64> {
    #[allow(clippy::cast_possible_truncation)]
    let count = FRAME_COUNT.load(Ordering::Relaxed) as usize;
    let words = count.div_ceil(64);
    for (w, bitmap_word) in BITMAP.iter().enumerate().take(words) {
        let mut val = bitmap_word.load(Ordering::Relaxed);
        while val != 0 {
            let bit = val.trailing_zeros() as usize;
            let new_val = val & !(1u64 << bit);
            match bitmap_word.compare_exchange(val, new_val, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => {
                    let frame = w * 64 + bit;
                    if frame < count {
                        #[allow(clippy::cast_possible_truncation)]
                        let pa = PHYS_BASE.load(Ordering::Relaxed) + (frame as u64) * PAGE_SIZE;
                        return Some(pa);
                    }
                    // Frame index out of range — put it back and stop.
                    set_bit(frame, true);
                    return None;
                }
                Err(current) => val = current,
            }
        }
    }
    None
}

/// Free the frame that contains physical address `pa`.
pub fn free_frame(pa: u64) {
    let base = PHYS_BASE.load(Ordering::Relaxed);
    if pa < base {
        return;
    }
    let idx = ((pa - base) / PAGE_SIZE) as usize;
    #[allow(clippy::cast_possible_truncation)]
    let count = FRAME_COUNT.load(Ordering::Relaxed) as usize;
    if idx < count {
        set_bit(idx, true);
    }
}

const fn frame_index(base: u64, pa: u64) -> usize {
    if pa <= base {
        0
    } else {
        #[allow(clippy::cast_possible_truncation)]
        { ((pa - base) / PAGE_SIZE) as usize }
    }
}

const fn frame_index_ceil(base: u64, pa: u64) -> usize {
    if pa <= base {
        0
    } else {
        #[allow(clippy::cast_possible_truncation)]
        { ((pa - base).div_ceil(PAGE_SIZE)) as usize }
    }
}

fn set_bit(index: usize, free: bool) {
    let word = index / 64;
    let bit = index % 64;
    if word >= WORDS {
        return;
    }
    if free {
        BITMAP[word].fetch_or(1u64 << bit, Ordering::Relaxed);
    } else {
        BITMAP[word].fetch_and(!(1u64 << bit), Ordering::Relaxed);
    }
}
