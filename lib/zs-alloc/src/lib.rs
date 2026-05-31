//! LZ4-compressed object store inspired by Linux zsmalloc.
//!
//! [`ZsStore`] compresses objects with LZ4 block format and packs them into
//! 4 KiB pages, using size-class-aligned slots to minimise fragmentation —
//! the same key idea as Linux's `zsmalloc` allocator.
//!
//! # Size classes
//!
//! Eight power-of-two slot sizes, all dividing 4096 evenly:
//!
//! | Slot | Max payload | Slots/page |
//! |-----:|------------:|-----------:|
//! |   32 |          28 |        128 |
//! |   64 |          60 |         64 |
//! |  128 |         124 |         32 |
//! |  256 |         252 |         16 |
//! |  512 |         508 |          8 |
//! | 1024 |        1020 |          4 |
//! | 2048 |        2044 |          2 |
//! | 4096 |        4092 |          1 |
//!
//! A 4-byte per-slot header stores the original and stored lengths, allowing
//! transparent decompression on [`ZsStore::load`].  If LZ4 does not reduce
//! an object's size the object is stored verbatim.

#![no_std]
#![feature(const_option_ops)]
#![feature(const_trait_impl)]

extern crate alloc;

mod class;
mod page;

use alloc::vec::Vec;

use class::{NUM_CLASSES, class_for_size};
use page::{PAGE_SIZE, SlotError, ZsPage};

/// Maximum uncompressed object size accepted by [`ZsStore::store`].
pub const MAX_OBJECT_SIZE: usize = 4092;

// ── Handle ────────────────────────────────────────────────────────────────

/// Opaque handle to a stored object.
///
/// Valid only for the [`ZsStore`] that produced it.  Do not mix handles
/// across different store instances.
///
/// # Encoding (u64, little-endian field layout)
///
/// | Bits    | Field       | Range         |
/// |---------|-------------|---------------|
/// | 63 – 48 | (reserved)  | 0             |
/// | 47 – 16 | page index  | 0 .. u32::MAX |
/// |  15 – 8 | class index | 0 .. 7        |
/// |   7 – 0 | slot index  | 0 .. 127      |
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handle(u64);

impl Handle {
    const fn encode(page_idx: u32, class_idx: u8, slot_idx: u8) -> Self {
        Self(((page_idx as u64) << 16) | ((class_idx as u64) << 8) | (slot_idx as u64))
    }

    const fn decode(self) -> (u32, usize, usize) {
        let page_idx = (self.0 >> 16) as u32;
        let class_idx = ((self.0 >> 8) & 0xFF) as usize;
        let slot_idx = (self.0 & 0xFF) as usize;
        (page_idx, class_idx, slot_idx)
    }
}

// ── Stats ─────────────────────────────────────────────────────────────────

/// Statistics snapshot from a [`ZsStore`].
#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    /// Number of live objects currently in the store.
    pub objects_stored: u64,
    /// Total uncompressed bytes across all live objects.
    pub original_bytes: u64,
    /// Total bytes actually written to pages (post-compression).
    pub stored_bytes: u64,
    /// Total 4 KiB pages allocated (pages are never freed to the system).
    pub pages_allocated: usize,
}

impl Stats {
    /// Stored bytes per 100 original bytes (`stored / original × 100`).
    ///
    /// Returns `100` when nothing has been stored yet.
    #[must_use]
    pub const fn compression_percent(&self) -> u64 {
        (100 * self.stored_bytes)
            .checked_div(self.original_bytes)
            .unwrap_or(100)
    }

    /// Total RAM consumed by page backing storage, in bytes.
    #[must_use]
    pub const fn backing_bytes(&self) -> usize {
        self.pages_allocated * PAGE_SIZE
    }
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors from [`ZsStore::store`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// `data.len()` exceeds [`MAX_OBJECT_SIZE`].
    ObjectTooLarge,
    /// Page index overflowed `u32::MAX` (> 16 TiB stored).
    TooManyPages,
}

/// Errors from [`ZsStore::load`] and [`ZsStore::free`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// The handle refers to a page that does not exist.
    InvalidPage,
    /// The handle refers to a slot that is not allocated.
    InvalidSlot,
    /// The output buffer is shorter than the stored object.
    ///
    /// Use [`ZsStore::query_size`] to obtain the required length.
    BufferTooSmall {
        /// Minimum number of bytes required.
        need: usize,
    },
    /// LZ4 decompression failed (corrupted store state).
    DecompressFailed,
}

impl From<SlotError> for LoadError {
    fn from(e: SlotError) -> Self {
        match e {
            SlotError::InvalidSlot | SlotError::SlotFree => Self::InvalidSlot,
            SlotError::BufferTooSmall { need } => Self::BufferTooSmall { need },
            SlotError::DecompressFailed => Self::DecompressFailed,
        }
    }
}

// ── Per-class tracking ────────────────────────────────────────────────────

/// Page lists for one size class, split by fullness.
///
/// This mirrors zsmalloc's per-class fullness grouping: pages with at least
/// one free slot go into `partial`; full pages are implicitly tracked by
/// absence.  When a full page regains a free slot (via `free`), it is pushed
/// back to `partial`.
struct ClassState {
    /// Indices into `ZsStore::pages` with at least one free slot.
    partial: Vec<usize>,
}

impl ClassState {
    const fn new() -> Self {
        Self {
            partial: Vec::new(),
        }
    }
}

// ── ZsStore ───────────────────────────────────────────────────────────────

/// LZ4-compressed object store with zsmalloc-style size-class packing.
///
/// # Example
///
/// ```rust,no_run
/// # extern crate alloc;
/// use zs_alloc::ZsStore;
///
/// let mut store = ZsStore::new();
/// let handle = store.store(b"hello, kernel").unwrap();
///
/// let size = store.query_size(handle).unwrap();
/// let mut buf = alloc::vec![0u8; size];
/// store.load(handle, &mut buf).unwrap();
/// assert_eq!(&buf, b"hello, kernel");
///
/// store.free(handle).unwrap();
/// ```
pub struct ZsStore {
    /// All pages ever allocated, indexed by page index.
    pages: Vec<ZsPage>,
    /// Per size-class partial-page lists.
    classes: [ClassState; NUM_CLASSES],
    stats: Stats,
}

impl ZsStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pages: Vec::new(),
            classes: core::array::from_fn(|_| ClassState::new()),
            stats: Stats::default(),
        }
    }

    /// Compress `data` with LZ4 and store it.  Returns an opaque [`Handle`].
    ///
    /// If LZ4 does not reduce the size the object is stored verbatim.
    ///
    /// # Errors
    ///
    /// - [`StoreError::ObjectTooLarge`] — `data.len() > MAX_OBJECT_SIZE`.
    /// - [`StoreError::TooManyPages`] — more than `u32::MAX` pages allocated.
    pub fn store(&mut self, data: &[u8]) -> Result<Handle, StoreError> {
        if data.len() > MAX_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        let original_len = data.len();

        // Attempt LZ4 compression into a temporary heap buffer.
        let max_compressed = lz4_flex::block::get_maximum_output_size(original_len);
        let mut tmp = alloc::vec![0u8; max_compressed];
        let (payload, stored_len) = match lz4_flex::block::compress_into(data, &mut tmp) {
            Ok(n) if n < original_len => (&tmp[..n], n),
            _ => (data, original_len),
        };

        let class_idx = class_for_size(stored_len).unwrap_or(NUM_CLASSES - 1); // stored_len ≤ original_len ≤ MAX_OBJECT_SIZE = 4092 ≤ max_payload of last class

        // Find or allocate a page with a free slot.
        let (page_idx_usize, page_idx_u32) = match self.classes[class_idx].partial.last().copied() {
            Some(pi) => {
                let pu = u32::try_from(pi).map_err(|_| StoreError::TooManyPages)?;
                (pi, pu)
            }
            None => {
                let pi = self.pages.len();
                let pu = u32::try_from(pi).map_err(|_| StoreError::TooManyPages)?;
                self.pages.push(ZsPage::new(class_idx));
                self.classes[class_idx].partial.push(pi);
                self.stats.pages_allocated += 1;
                (pi, pu)
            }
        };

        // original_len ≤ MAX_OBJECT_SIZE = 4092 < u16::MAX.
        let original_len_u16 = original_len as u16;

        let (slot_idx, now_full) = {
            let page = self
                .pages
                .get_mut(page_idx_usize)
                .unwrap_or_else(|| unreachable!("page_idx_usize is a freshly verified index"));
            let s = page
                .alloc_slot(original_len_u16, payload)
                .unwrap_or_else(|| unreachable!("page was taken from partial list"));
            let full = page.is_full();
            (s, full)
        };

        if now_full {
            self.classes[class_idx].partial.pop();
        }

        self.stats.objects_stored += 1;
        self.stats.original_bytes += original_len as u64;
        self.stats.stored_bytes += stored_len as u64;

        // class_idx ≤ NUM_CLASSES − 1 = 7 < u8::MAX; slot_idx ≤ 127 < u8::MAX.
        Ok(Handle::encode(
            page_idx_u32,
            class_idx as u8,
            slot_idx as u8,
        ))
    }

    /// Return the uncompressed byte length of the object identified by `handle`.
    ///
    /// Returns `None` if `handle` is invalid.
    #[must_use]
    pub fn query_size(&self, handle: Handle) -> Option<usize> {
        let (page_idx, _, slot_idx) = handle.decode();
        self.pages
            .get(page_idx as usize)?
            .slot_original_len(slot_idx)
    }

    /// Decompress and write the object identified by `handle` into `out`.
    ///
    /// Returns the number of bytes written.  Use [`ZsStore::query_size`] to
    /// size `out` correctly before calling.
    ///
    /// # Errors
    ///
    /// - [`LoadError::InvalidPage`] — `handle` does not name a valid page.
    /// - [`LoadError::InvalidSlot`] — the slot is free or out of range.
    /// - [`LoadError::BufferTooSmall`] — `out` is too short.
    /// - [`LoadError::DecompressFailed`] — LZ4 decompression error.
    pub fn load(&self, handle: Handle, out: &mut [u8]) -> Result<usize, LoadError> {
        let (page_idx, _, slot_idx) = handle.decode();
        let page = self
            .pages
            .get(page_idx as usize)
            .ok_or(LoadError::InvalidPage)?;
        page.read_slot(slot_idx, out).map_err(LoadError::from)
    }

    /// Release the object identified by `handle`, returning its slot to the
    /// free pool.
    ///
    /// The backing page is not freed; it may be reused for future objects of
    /// the same size class.
    ///
    /// # Errors
    ///
    /// - [`LoadError::InvalidPage`] — `handle` does not name a valid page.
    /// - [`LoadError::InvalidSlot`] — the slot is already free.
    pub fn free(&mut self, handle: Handle) -> Result<(), LoadError> {
        let (page_idx, class_idx, slot_idx) = handle.decode();
        let pi = page_idx as usize;
        let page = self.pages.get_mut(pi).ok_or(LoadError::InvalidPage)?;
        let was_full = page.is_full();
        if !page.free_slot(slot_idx) {
            return Err(LoadError::InvalidSlot);
        }
        if was_full {
            self.classes[class_idx].partial.push(pi);
        }
        self.stats.objects_stored = self.stats.objects_stored.saturating_sub(1);
        Ok(())
    }

    /// Return a statistics snapshot.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Number of 4 KiB pages currently allocated.
    #[must_use]
    pub const fn page_count(&self) -> usize {
        self.pages.len()
    }
}

impl Default for ZsStore {
    fn default() -> Self {
        Self::new()
    }
}
