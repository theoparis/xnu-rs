pub mod aarch64;

pub use aarch64::uart;
pub use aarch64::{thread_register_get, thread_register_set, time_ticks};
