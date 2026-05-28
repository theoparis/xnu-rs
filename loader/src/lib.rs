#![no_std]

extern crate alloc;

use goblin::{elf::Elf, mach::MachO};

pub struct MachOImage<'a> {
    bytes: &'a [u8],
}

impl<'a> MachOImage<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Parse the image as a Mach-O binary.
    ///
    /// # Errors
    /// Returns a parser error if the bytes are not a valid Mach-O image.
    pub fn parse(&self) -> Result<MachO<'a>, goblin::error::Error> {
        MachO::parse(self.bytes, 0)
    }
}

pub struct ElfImage<'a> {
    bytes: &'a [u8],
}

impl<'a> ElfImage<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Parse the image as an ELF binary.
    ///
    /// # Errors
    /// Returns a parser error if the bytes are not a valid ELF image.
    pub fn parse(&self) -> Result<Elf<'a>, goblin::error::Error> {
        Elf::parse(self.bytes)
    }
}

#[must_use]
pub fn is_macho(bytes: &[u8]) -> bool {
    MachO::parse(bytes, 0).is_ok()
}

#[must_use]
pub fn is_elf(bytes: &[u8]) -> bool {
    Elf::parse(bytes).is_ok()
}
