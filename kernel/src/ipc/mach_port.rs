use liballoc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use spin::{LazyLock, Mutex};

use super::rights::RightKind;

// ── Port ─────────────────────────────────────────────────────────────────────

/// A kernel IPC port: a FIFO queue of raw message bytes.
pub struct Port {
    pub(crate) messages: VecDeque<Vec<u8>>,
}

impl Port {
    pub(crate) fn new() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }
}

// ── NameEntry ─────────────────────────────────────────────────────────────────

/// One entry in a task's port namespace.
pub struct NameEntry {
    pub kind: RightKind,
    pub port: Arc<Mutex<Port>>,
}

// ── PortNamespace ────────────────────────────────────────────────────────────

/// Per-task mapping from port name (mach_port_t) to a right on a port.
///
/// Names 1–4 are reserved for well-known kernel ports and are seeded by
/// [`crate::mach::task::init`] before the first user thread runs.
pub struct PortNamespace {
    entries: BTreeMap<u32, NameEntry>,
    next_name: u32,
}

impl PortNamespace {
    pub(crate) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_name: 5, // 1-4 reserved for well-known ports
        }
    }

    /// Allocate a fresh name and insert `port` with the given `kind`.
    pub fn insert(&mut self, port: Arc<Mutex<Port>>, kind: RightKind) -> u32 {
        let name = self.next_name;
        self.next_name = self.next_name.wrapping_add(1).max(5);
        self.entries.insert(name, NameEntry { kind, port });
        name
    }

    /// Insert `port` under a specific `name` (used for well-known ports).
    pub fn insert_at(&mut self, name: u32, port: Arc<Mutex<Port>>, kind: RightKind) {
        self.entries.insert(name, NameEntry { kind, port });
    }

    /// Look up a port name.
    pub fn lookup(&self, name: u32) -> Option<&NameEntry> {
        self.entries.get(&name)
    }

    /// Release a right.  Returns `true` if the name existed.
    pub fn deallocate(&mut self, name: u32) -> bool {
        self.entries.remove(&name).is_some()
    }

    /// Allocate a matched receive+send pair on a fresh port.
    ///
    /// Returns `(recv_name, send_name)`.
    pub fn new_port_pair(&mut self) -> (u32, u32) {
        let port = Arc::new(Mutex::new(Port::new()));
        let recv_name = self.insert(Arc::clone(&port), RightKind::Receive);
        let send_name = self.insert(port, RightKind::Send);
        (recv_name, send_name)
    }
}

// ── Global namespace ──────────────────────────────────────────────────────────

/// The single global port namespace (single-task kernel model).
pub static NAMESPACE: LazyLock<Mutex<PortNamespace>> =
    LazyLock::new(|| Mutex::new(PortNamespace::new()));
