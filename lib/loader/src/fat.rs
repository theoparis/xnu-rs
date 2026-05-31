//! FAT binary unwrapping — extract the arm64 thin slice.

use object::{
    LittleEndian,
    macho::CPU_TYPE_ARM64,
    read::macho::{FatArch, MachOFatFile32, MachOFatFile64, MachOFile64},
};

/// Extract the arm64/arm64e slice from a (possibly FAT) binary.
///
/// Returns a subslice of `bytes` containing the arm64 Mach-O, or `bytes`
/// itself when it is already a thin binary.  Returns `None` if no arm64
/// architecture is present or the input is not a Mach-O at all.
#[must_use]
pub fn arm64_slice(bytes: &[u8]) -> Option<&[u8]> {
    // Try 64-bit FAT headers first.
    if let Ok(fat) = MachOFatFile64::parse(bytes) {
        for arch in fat.arches() {
            if arch.cputype() == CPU_TYPE_ARM64 {
                return arch.data(bytes).ok();
            }
        }
    }

    // Try 32-bit FAT headers (some toolchains emit them).
    if let Ok(fat) = MachOFatFile32::parse(bytes) {
        for arch in fat.arches() {
            if arch.cputype() == CPU_TYPE_ARM64 {
                return arch.data(bytes).ok();
            }
        }
    }

    // Assume thin binary — verify with the Mach-O magic.
    if MachOFile64::<LittleEndian>::parse(bytes).is_ok() {
        return Some(bytes);
    }

    None
}
