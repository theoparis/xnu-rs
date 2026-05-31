//! dyld support — groundwork for a future dynamic linker.
//!
//! Currently logs the dylib dependencies parsed from a user binary's load
//! commands and provides helpers that a full dyld implementation will use.

use super::macho::UserImage;
use crate::arch::aarch64::uart;

/// Log the dylib dependencies and rpaths from `image` over UART.
///
/// This is called during boot for the main executable so the dependency
/// graph is visible in the serial log before any EL0 code runs.
pub fn log_deps(image: &UserImage<'_>, name: &str) {
    uart::write_str("xnu-rs: deps for ");
    uart::write_str(name);
    uart::write_str(":\n");
    for dep in &image.dylib_deps {
        uart::write_str("  LOAD   ");
        uart::write_str(dep.name);
        uart::write_str("\n");
    }
    for dep in &image.weak_dylib_deps {
        uart::write_str("  WEAK   ");
        uart::write_str(dep.name);
        uart::write_str("\n");
    }
    for rpath in &image.rpaths {
        uart::write_str("  RPATH  ");
        uart::write_str(rpath);
        uart::write_str("\n");
    }
    if let Some(uuid) = image.uuid {
        uart::write_str("  UUID   ");
        for b in &uuid {
            uart::write_hex_u64(u64::from(*b));
        }
        uart::write_str("\n");
    }
}
