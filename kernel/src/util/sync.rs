pub use spin::{Mutex, MutexGuard, RwLockReadGuard, RwLockWriteGuard};

pub type SpinLock<T> = spin::Mutex<T>;
pub type RwLock<T> = spin::RwLock<T>;

pub struct OnceLock<T> {
    inner: spin::Once<T>,
}

impl<T> OnceLock<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: spin::Once::new(),
        }
    }

    pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        self.inner.call_once(f)
    }

    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}
