/// The kind of right a task holds on a port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RightKind {
    /// Holder can enqueue messages on the port.
    Send,
    /// One-shot send right; consumed on first use.
    SendOnce,
    /// Holder can dequeue messages from the port (at most one per port).
    Receive,
}
