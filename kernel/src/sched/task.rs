use core::sync::atomic::{AtomicU32, Ordering};

use liballoc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::{Mutex, Once};

use super::thread::Thread;

static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// A Mach-style task (process) containing one or more threads.
pub struct Task {
    pub pid: u32,
    pub threads: Vec<Arc<Mutex<Thread>>>,
}

impl Task {
    /// Allocate a new task with a unique PID.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
            threads: Vec::new(),
        }
    }
}

impl Default for Task {
    fn default() -> Self {
        Self::new()
    }
}

static TASK_TABLE: Once<Mutex<BTreeMap<u32, Arc<Task>>>> = Once::new();

/// Initialise the global task table.  Must be called once during boot.
pub fn init_task_table() {
    TASK_TABLE.call_once(|| Mutex::new(BTreeMap::new()));
}

/// Insert `task` into the global task table, keyed by its PID.
pub fn register_task(task: Arc<Task>) {
    let Some(table) = TASK_TABLE.get() else {
        return;
    };
    table.lock().insert(task.pid, task);
}

/// Return the PID of the currently running thread by reading the `Thread`
/// pointer from `TPIDR_EL1`.  Returns `0` when no thread has been scheduled.
#[must_use]
pub fn current_pid() -> u32 {
    let ptr = super::runqueue::current_thread_ptr();
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: `TPIDR_EL1` is set by `set_current_thread` to a valid `Thread`
    // pointer that lives for the duration of scheduling.
    let thread = unsafe { &*ptr };
    thread.tid
}
