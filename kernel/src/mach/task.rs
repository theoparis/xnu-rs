//! Mach task port initialisation.

use liballoc::sync::Arc;
use spin::Mutex;

use crate::ipc::mach_port::{NAMESPACE, Port};
use crate::ipc::rights::RightKind;

/// Well-known port names reserved in every task's namespace.
pub const TASK_SELF_NAME: u32 = 1;
pub const THREAD_SELF_NAME: u32 = 2;
pub const HOST_SELF_NAME: u32 = 3;
pub const BOOTSTRAP_NAME: u32 = 4;

/// Seed the global port namespace with well-known kernel ports.
///
/// Must be called once during boot before the first user thread runs.
pub fn init() {
    let mut ns = NAMESPACE.lock();
    for name in [
        TASK_SELF_NAME,
        THREAD_SELF_NAME,
        HOST_SELF_NAME,
        BOOTSTRAP_NAME,
    ] {
        let port = Arc::new(Mutex::new(Port::new()));
        ns.insert_at(name, port, RightKind::Receive);
    }
    // Also add a Send right for bootstrap so user code can send to it.
    if let Some(e) = ns.lookup(BOOTSTRAP_NAME) {
        let port = Arc::clone(&e.port);
        ns.insert_at(BOOTSTRAP_NAME + 100, port, RightKind::Send);
    }
}
