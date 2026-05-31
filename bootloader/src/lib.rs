#![no_std]

extern crate alloc;

use object::{Object, ObjectSegment, macho::LC_MAIN, read::Result as ObjectResult};

/// A parsed Mach-O image ready for loading from an in-memory byte slice.
#[derive(Debug)]
pub struct MachO<'data> {
    obj: object::read::macho::MachOFile64<'data, object::NativeEndian>,
    entry_va: u64,
}

impl<'data> MachO<'data> {
    /// Parse a raw Mach-O 64-bit binary (thin, not FAT).
    ///
    /// # Errors
    /// Returns a parser error if the data is not a valid 64-bit Mach-O.
    pub fn parse(data: &'data [u8]) -> ObjectResult<Self> {
        let obj = object::read::macho::MachOFile64::parse(data)?;
        let entry_va = compute_entry_va(&obj);
        Ok(Self { obj, entry_va })
    }

    /// Virtual address of the program entry point.
    #[must_use]
    pub const fn entry(&self) -> u64 {
        self.entry_va
    }

    /// Iterate over all loadable segments.
    pub fn segments(&self) -> impl Iterator<Item = Segment<'data, '_>> {
        self.obj.segments().map(Segment::from)
    }
}

/// A loadable segment from a Mach-O image.
#[derive(Debug)]
pub struct Segment<'data, 'file> {
    inner: object::read::macho::MachOSegment64<'data, 'file, object::NativeEndian>,
}

impl<'data, 'file> From<object::read::macho::MachOSegment64<'data, 'file, object::NativeEndian>>
    for Segment<'data, 'file>
{
    fn from(
        inner: object::read::macho::MachOSegment64<'data, 'file, object::NativeEndian>,
    ) -> Self {
        Self { inner }
    }
}

impl<'data> Segment<'data, '_> {
    /// Virtual address the segment expects to be mapped at.
    #[must_use]
    pub fn vmaddr(&self) -> u64 {
        self.inner.address()
    }

    /// Virtual size of the segment (may be larger than the file data).
    #[must_use]
    pub fn vmsize(&self) -> u64 {
        self.inner.size()
    }

    /// File offset of the segment data.
    #[must_use]
    pub fn fileoff(&self) -> u64 {
        self.inner.file_range().0
    }

    /// Size of the segment data in the file.
    #[must_use]
    pub fn filesize(&self) -> u64 {
        self.inner.file_range().1
    }

    /// Raw file bytes for this segment (may be empty for BSS-only segments).
    ///
    /// # Errors
    /// Returns an error if the segment data cannot be read.
    pub fn data(&self) -> ObjectResult<&'data [u8]> {
        self.inner.data()
    }
}

/// Compute the entry-point VA from the Mach-O.
///
/// For `LC_MAIN`, `object::entry()` returns the raw file offset (`entryoff`).
/// We convert it to a VA by using the `__TEXT` segment:
///   `entry_va = text_vmaddr + (entryoff - text_fileoff)`
///
/// For `LC_UNIXTHREAD`, `object::entry()` already returns a VA from the
/// thread state register.
fn compute_entry_va(macho: &object::read::macho::MachOFile64<'_, object::NativeEndian>) -> u64 {
    if let Ok(mut commands) = macho.macho_load_commands() {
        while let Ok(Some(cmd)) = commands.next() {
            if cmd.cmd() == LC_MAIN
                && let Ok(Some(entry)) = cmd.entry_point()
            {
                let entryoff = entry.entryoff.get(object::LittleEndian);
                if let Some(text) = macho
                    .segments()
                    .find(|s| s.name().ok().flatten() == Some("__TEXT"))
                {
                    let (text_fileoff, _) = text.file_range();
                    let text_vmaddr = text.address();
                    return text_vmaddr + (entryoff.saturating_sub(text_fileoff));
                }
            }
        }
    }

    macho.entry()
}

/// Detect whether `data` is a Mach-O binary (thin or FAT).
#[must_use]
pub fn is_macho(data: &[u8]) -> bool {
    use object::LittleEndian;
    object::read::macho::MachOFile64::<LittleEndian>::parse(data).is_ok()
        || object::read::macho::MachOFatFile64::parse(data).is_ok()
}

/// Detect whether `data` is an ELF binary.
#[must_use]
pub fn is_elf(data: &[u8]) -> bool {
    use object::LittleEndian;
    object::read::elf::ElfFile64::<LittleEndian>::parse(data).is_ok()
}
