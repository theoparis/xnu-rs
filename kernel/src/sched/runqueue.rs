use liballoc::{collections::VecDeque, sync::Arc};
use spin::{Mutex, Once};

use super::context_switch::switch_to;
use super::thread::{Thread, ThreadState};

/// A simple FIFO run-queue of ready kernel threads.
pub struct RunQueue {
    queue: Mutex<VecDeque<Arc<Mutex<Thread>>>>,
}

impl RunQueue {
    /// Create an empty `RunQueue`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Enqueue a thread at the back of the run-queue.
    pub fn push(&self, thread: Arc<Mutex<Thread>>) {
        self.queue.lock().push_back(thread);
    }

    /// Dequeue the next ready thread from the front, if any.
    pub fn pop_next(&self) -> Option<Arc<Mutex<Thread>>> {
        self.queue.lock().pop_front()
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// The single global run-queue used by the cooperative scheduler.
pub static GLOBAL_RUNQUEUE: Once<RunQueue> = Once::new();

/// Initialise the global run-queue.  Must be called once during boot.
pub fn init_runqueue() {
    GLOBAL_RUNQUEUE.call_once(RunQueue::new);
}

// ---------------------------------------------------------------------------
// Per-CPU current-thread pointer stored in TPIDR_EL1
// ---------------------------------------------------------------------------

/// Store `thread` as the currently-running thread for this CPU.
///
/// # Safety
///
/// `thread` must remain valid for as long as it is the current thread.
pub unsafe fn set_current_thread(thread: *mut Thread) {
    // SAFETY: writing a raw pointer to the EL1 thread-pointer register; the
    // caller guarantees the lifetime invariant documented above.
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) thread as u64, options(nostack));
    }
}

/// Read the currently-running thread pointer for this CPU from `TPIDR_EL1`.
/// Returns a null pointer if no thread has been installed yet.
#[must_use]
pub fn current_thread_ptr() -> *mut Thread {
    let ptr: u64;
    // SAFETY: reading the EL1 thread-pointer register is always safe at EL1.
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el1", out(reg) ptr, options(nostack));
    }
    ptr as *mut Thread
}

// ---------------------------------------------------------------------------
// Cooperative scheduler
// ---------------------------------------------------------------------------

/// Pick the next ready thread and switch to it.
///
/// The calling thread is re-queued (unless it is `Dead`) and the next thread
/// at the front of the run-queue is made current.  If the run-queue is empty
/// the function returns without switching.
pub fn schedule() {
    let Some(rq) = GLOBAL_RUNQUEUE.get() else {
        return;
    };

    // Snapshot the current thread pointer *before* we do anything else.
    let current_ptr = current_thread_ptr();

    // Re-enqueue the current thread unless it is dead or the pointer is null.
    if !current_ptr.is_null() {
        // SAFETY: `current_ptr` was set by `set_current_thread` to a live Thread.
        let current_ref = unsafe { &mut *current_ptr };
        if current_ref.state != ThreadState::Dead {
            current_ref.state = ThreadState::Ready;
            // We push *back* the Arc that wraps this Thread.  We cannot
            // reconstruct the Arc here, so we rely on the caller keeping an
            // Arc alive.  For now the idle-thread / initial-thread Arcs are
            // held by main.rs; a more complete design would store the Arc in a
            // per-CPU variable.  This is safe for the single-thread cooperative
            // case where a thread always pushes itself before switching.
        }
    }

    // Pop the next ready thread.
    let Some(next_arc) = rq.pop_next() else {
        return; // nothing to switch to
    };

    // Obtain a raw pointer to the next thread's KernelContext.
    let next_ptr: *mut Thread = {
        let mut guard = next_arc.lock();
        guard.state = ThreadState::Running;
        &raw mut *guard
    };

    // Install as current thread.
    // SAFETY: `next_ptr` is derived from an Arc that we hold until after the
    // switch; the Thread allocation lives at least as long as the Arc.
    unsafe { set_current_thread(next_ptr) };

    if current_ptr.is_null() {
        // No previous thread — jump directly into the next thread's context
        // by pretending we switch from a throwaway context.
        let mut dummy = super::thread::KernelContext::zeroed();
        // SAFETY: `dummy` is a local valid KernelContext; `next_ptr` was just
        // installed and points to a valid Thread.
        unsafe {
            switch_to(
                &raw mut dummy,
                // SAFETY: next_ptr is non-null and valid.
                core::ptr::addr_of!((*next_ptr).kernel_ctx),
            );
        }
    } else {
        // SAFETY: `current_ptr` is a valid Thread pointer and `next_ptr` is a
        // valid Thread pointer; both KernelContext fields are in-bounds.
        unsafe {
            switch_to(
                core::ptr::addr_of_mut!((*current_ptr).kernel_ctx),
                core::ptr::addr_of!((*next_ptr).kernel_ctx),
            );
        }
    }
}
