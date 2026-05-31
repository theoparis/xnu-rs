extern crate alloc;

use alloc::vec;

use crate::class::{SIZE_CLASSES, SLOT_HEADER};

pub(crate) const PAGE_SIZE: usize = 4096;

/// One 4 KiB page of slot storage.
///
/// Slots are packed end-to-end from offset 0.  Each slot begins with a 4-byte
/// header `[original_len: u16 LE][stored_len: u16 LE]` followed by the
/// (possibly compressed) payload.  Free slots are tracked with a 128-bit
/// bitmap: bit *N* set means slot *N* is available.
pub(crate) struct ZsPage {
    /// Raw backing storage — always exactly `PAGE_SIZE` bytes.
    data: alloc::boxed::Box<[u8]>,
    /// Bit N = 1 → slot N is free.
    free_bitmap: u128,
    /// Index into `crate::class::SIZE_CLASSES`.
    pub(crate) class_idx: usize,
}

impl ZsPage {
    pub(crate) fn new(class_idx: usize) -> Self {
        let slots = SIZE_CLASSES[class_idx].slots_per_page;
        // All slots start free.
        let free_bitmap = full_mask(slots);
        Self {
            data: vec![0u8; PAGE_SIZE].into_boxed_slice(),
            free_bitmap,
            class_idx,
        }
    }

    pub(crate) const fn is_full(&self) -> bool {
        self.free_bitmap == 0
    }

    // pub(crate) fn is_empty(&self) -> bool {
    //     let slots = SIZE_CLASSES[self.class_idx].slots_per_page;
    //     self.free_bitmap == full_mask(slots)
    // }

    /// Write `payload` into the lowest free slot, recording `original_len`.
    ///
    /// Returns the slot index, or `None` if the page is full or `payload`
    /// exceeds `max_payload` for this class.
    pub(crate) fn alloc_slot(&mut self, original_len: u16, payload: &[u8]) -> Option<usize> {
        let sc = &SIZE_CLASSES[self.class_idx];
        if payload.len() > sc.max_payload {
            return None;
        }
        let slot = self.free_bitmap.trailing_zeros() as usize;
        if slot >= sc.slots_per_page {
            return None;
        }
        self.free_bitmap &= !(1u128 << slot);

        let off = slot * sc.slot_size;
        // payload.len() ≤ max_payload ≤ 4092 < u16::MAX, cast is safe.
        let stored_len = payload.len() as u16;
        self.data[off..off + 2].copy_from_slice(&original_len.to_le_bytes());
        self.data[off + 2..off + 4].copy_from_slice(&stored_len.to_le_bytes());
        self.data[off + SLOT_HEADER..off + SLOT_HEADER + payload.len()].copy_from_slice(payload);
        Some(slot)
    }

    /// Decompress (or copy) the payload at `slot_idx` into `out`.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// See [`SlotError`].
    pub(crate) fn read_slot(&self, slot_idx: usize, out: &mut [u8]) -> Result<usize, SlotError> {
        let sc = &SIZE_CLASSES[self.class_idx];
        if slot_idx >= sc.slots_per_page {
            return Err(SlotError::InvalidSlot);
        }
        if self.free_bitmap & (1u128 << slot_idx) != 0 {
            return Err(SlotError::SlotFree);
        }
        let off = slot_idx * sc.slot_size;
        let original_len = usize::from(u16::from_le_bytes([self.data[off], self.data[off + 1]]));
        let stored_len = usize::from(u16::from_le_bytes([self.data[off + 2], self.data[off + 3]]));

        if out.len() < original_len {
            return Err(SlotError::BufferTooSmall { need: original_len });
        }
        let payload = &self.data[off + SLOT_HEADER..off + SLOT_HEADER + stored_len];
        if stored_len == original_len {
            // Stored uncompressed.
            out[..original_len].copy_from_slice(payload);
            Ok(original_len)
        } else {
            lz4_flex::block::decompress_into(payload, &mut out[..original_len])
                .map_err(|_| SlotError::DecompressFailed)
        }
    }

    /// Return the uncompressed byte count stored at `slot_idx`, or `None` if
    /// the slot is free or the index is out of range.
    pub(crate) fn slot_original_len(&self, slot_idx: usize) -> Option<usize> {
        let sc = &SIZE_CLASSES[self.class_idx];
        if slot_idx >= sc.slots_per_page {
            return None;
        }
        if self.free_bitmap & (1u128 << slot_idx) != 0 {
            return None;
        }
        let off = slot_idx * sc.slot_size;
        Some(usize::from(u16::from_le_bytes([
            self.data[off],
            self.data[off + 1],
        ])))
    }

    /// Mark `slot_idx` as free.  Returns `false` if the slot was already free
    /// or the index is out of range.
    pub(crate) fn free_slot(&mut self, slot_idx: usize) -> bool {
        let sc = &SIZE_CLASSES[self.class_idx];
        if slot_idx >= sc.slots_per_page {
            return false;
        }
        if self.free_bitmap & (1u128 << slot_idx) != 0 {
            return false;
        }
        self.free_bitmap |= 1u128 << slot_idx;
        true
    }
}

/// Error type for slot-level operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    InvalidSlot,
    SlotFree,
    BufferTooSmall { need: usize },
    DecompressFailed,
}

/// Compute the bitmap value where the low `slots` bits are set.
///
/// `slots` must be in `1..=128`.
const fn full_mask(slots: usize) -> u128 {
    if slots == 128 {
        u128::MAX
    } else {
        (1u128 << slots) - 1
    }
}
