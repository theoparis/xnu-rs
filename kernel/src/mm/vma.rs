use liballoc::vec::Vec;

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

#[derive(Clone, Copy)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
}

pub struct VmaList(Vec<Vma>);

impl Default for VmaList {
    fn default() -> Self {
        Self::new()
    }
}

impl VmaList {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn insert(&mut self, vma: Vma) {
        self.0.push(vma);
        // Keep sorted by start address for O(log n) lookup later.
        self.0.sort_unstable_by_key(|v| v.start);
    }

    #[must_use]
    pub fn find(&self, va: u64) -> Option<&Vma> {
        // Binary search for the last entry whose start ≤ va.
        let idx = self.0.partition_point(|v| v.start <= va);
        if idx == 0 {
            return None;
        }
        let vma = &self.0[idx - 1];
        if va < vma.end { Some(vma) } else { None }
    }

    pub fn remove_range(&mut self, start: u64, end: u64) {
        self.0.retain(|v| v.end <= start || v.start >= end);
    }
}
