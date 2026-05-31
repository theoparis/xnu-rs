/// Describes the slot geometry for one size class.
pub(crate) struct SizeClass {
    /// Total bytes per slot, header included.
    pub(crate) slot_size: usize,
    /// Maximum payload bytes that fit in one slot (`slot_size` − `SLOT_HEADER`).
    pub(crate) max_payload: usize,
    /// Number of slots per 4096-byte page.
    pub(crate) slots_per_page: usize,
}

/// Bytes consumed by the per-slot header: `[original_len: u16 LE][stored_len: u16 LE]`.
pub(crate) const SLOT_HEADER: usize = 4;

/// Power-of-two slot sizes, each dividing 4096 evenly (zero intra-page waste).
///
/// The payload limits are `slot_size − SLOT_HEADER`.
pub(crate) const SIZE_CLASSES: &[SizeClass] = &[
    SizeClass {
        slot_size: 32,
        max_payload: 28,
        slots_per_page: 128,
    },
    SizeClass {
        slot_size: 64,
        max_payload: 60,
        slots_per_page: 64,
    },
    SizeClass {
        slot_size: 128,
        max_payload: 124,
        slots_per_page: 32,
    },
    SizeClass {
        slot_size: 256,
        max_payload: 252,
        slots_per_page: 16,
    },
    SizeClass {
        slot_size: 512,
        max_payload: 508,
        slots_per_page: 8,
    },
    SizeClass {
        slot_size: 1024,
        max_payload: 1020,
        slots_per_page: 4,
    },
    SizeClass {
        slot_size: 2048,
        max_payload: 2044,
        slots_per_page: 2,
    },
    SizeClass {
        slot_size: 4096,
        max_payload: 4092,
        slots_per_page: 1,
    },
];

pub(crate) const NUM_CLASSES: usize = SIZE_CLASSES.len();

/// Return the index of the smallest size class whose `max_payload` is ≥ `n`.
pub(crate) fn class_for_size(n: usize) -> Option<usize> {
    SIZE_CLASSES.iter().position(|c| c.max_payload >= n)
}
