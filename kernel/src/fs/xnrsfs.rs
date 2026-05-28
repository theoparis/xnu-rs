/// xnrsfs — simple flat read-only filesystem for the rootfs virtio-blk disk.
///
/// Layout (little-endian):
/// ```text
/// [0..4]   magic = 0x5352_4E58 ("XNRS")
/// [4..8]   file_count: u32
/// [8..]    file table: file_count × 80-byte entries
///          [0..64]  name: null-terminated UTF-8
///          [64..72] data_offset: u64 (from image start)
///          [72..80] data_size: u64
/// [aligned] file data at 4096-byte aligned offsets
/// ```
use crate::arch::aarch64::uart;
use crate::drivers::virtio::blk::VIRTIO_BLK;

const MAGIC: u32 = 0x5352_4E58;
const ENTRY_SIZE: usize = 80;
const SECTOR_SIZE: usize = 512;

/// Read whole 512-byte sectors starting at `lba` into `buf`.
///
/// Returns `false` on driver error.
fn read_sectors(lba: u64, buf: &mut [u8]) -> bool {
    let Some(blk) = VIRTIO_BLK.get() else {
        return false;
    };
    let mut guard = blk.lock();
    let sectors = buf.len() / SECTOR_SIZE;
    for i in 0..sectors {
        let Some(sector_buf) = buf[i * SECTOR_SIZE..].first_chunk_mut::<SECTOR_SIZE>() else {
            return false;
        };
        if !guard.read_block(lba + i as u64, sector_buf) {
            return false;
        }
    }
    true
}

/// Read bytes at an arbitrary byte `offset` from the disk into `buf`.
pub fn read_bytes(offset: u64, buf: &mut [u8]) -> bool {
    let size = buf.len();
    if size == 0 {
        return true;
    }
    let start_sector = offset / SECTOR_SIZE as u64;
    #[allow(clippy::cast_possible_truncation)]
    let sector_off = (offset % SECTOR_SIZE as u64) as usize;
    let sectors_needed = (sector_off + size).div_ceil(SECTOR_SIZE);

    let mut tmp = liballoc::vec![0u8; sectors_needed * SECTOR_SIZE];
    if !read_sectors(start_sector, &mut tmp) {
        return false;
    }
    buf.copy_from_slice(&tmp[sector_off..sector_off + size]);
    true
}

/// Locate a file by path and return its contents.
///
/// Returns `None` if the disk is unavailable, the filesystem is invalid, or
/// the path is not found.
#[must_use]
pub fn read_file(path: &str) -> Option<liballoc::vec::Vec<u8>> {
    let mut sector0 = [0u8; SECTOR_SIZE];
    if !read_sectors(0, &mut sector0) {
        uart::write_str("xnrsfs: disk read error\n");
        return None;
    }

    let magic = u32::from_le_bytes(sector0[0..4].try_into().ok()?);
    if magic != MAGIC {
        uart::write_str("xnrsfs: bad magic\n");
        return None;
    }
    let file_count = u32::from_le_bytes(sector0[4..8].try_into().ok()?) as usize;

    let table_bytes = file_count * ENTRY_SIZE;
    let mut table = liballoc::vec![0u8; table_bytes];
    if !read_bytes(8, &mut table) {
        return None;
    }

    for i in 0..file_count {
        let entry = &table[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];
        let name_end = entry[..64].iter().position(|&b| b == 0).unwrap_or(64);
        let name = core::str::from_utf8(&entry[..name_end]).unwrap_or("");
        if name != path {
            continue;
        }
        let data_offset = u64::from_le_bytes(entry[64..72].try_into().ok()?);
        #[allow(clippy::cast_possible_truncation)]
        let data_size = u64::from_le_bytes(entry[72..80].try_into().ok()?) as usize;

        let mut data = liballoc::vec![0u8; data_size];
        if !read_bytes(data_offset, &mut data) {
            uart::write_str("xnrsfs: read error for file\n");
            return None;
        }
        return Some(data);
    }

    None
}

/// Locate a file's info (offset and size) by path.
#[must_use]
pub fn get_file_info(path: &str) -> Option<(u64, u64)> {
    let mut sector0 = [0u8; SECTOR_SIZE];
    if !read_sectors(0, &mut sector0) {
        return None;
    }

    let magic = u32::from_le_bytes(sector0[0..4].try_into().ok()?);
    if magic != MAGIC {
        return None;
    }
    let file_count = u32::from_le_bytes(sector0[4..8].try_into().ok()?) as usize;

    let table_bytes = file_count * ENTRY_SIZE;
    let mut table = liballoc::vec![0u8; table_bytes];
    if !read_bytes(8, &mut table) {
        return None;
    }

    for i in 0..file_count {
        let entry = &table[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];
        let name_end = entry[..64].iter().position(|&b| b == 0).unwrap_or(64);
        let name = core::str::from_utf8(&entry[..name_end]).unwrap_or("");
        if name == path {
            let data_offset = u64::from_le_bytes(entry[64..72].try_into().ok()?);
            let data_size = u64::from_le_bytes(entry[72..80].try_into().ok()?);
            return Some((data_offset, data_size));
        }
    }

    None
}

/// List all files in the filesystem to UART.
pub fn list_files() {
    let mut sector0 = [0u8; SECTOR_SIZE];
    if !read_sectors(0, &mut sector0) {
        uart::write_str("xnrsfs: disk not found or read error\n");
        return;
    }
    let magic = u32::from_le_bytes(sector0[0..4].try_into().unwrap_or([0; 4]));
    if magic != MAGIC {
        uart::write_str("xnrsfs: no xnrsfs image on disk\n");
        return;
    }
    let file_count = u32::from_le_bytes(sector0[4..8].try_into().unwrap_or([0; 4])) as usize;
    uart::write_str("xnrsfs: ");
    uart::write_hex_u64(file_count as u64);
    uart::write_str(" file(s)\n");

    let table_bytes = file_count * ENTRY_SIZE;
    let mut table = liballoc::vec![0u8; table_bytes];
    if !read_bytes(8, &mut table) {
        return;
    }
    for i in 0..file_count {
        let entry = &table[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];
        let name_end = entry[..64].iter().position(|&b| b == 0).unwrap_or(64);
        let name = core::str::from_utf8(&entry[..name_end]).unwrap_or("?");
        let size = u64::from_le_bytes(entry[72..80].try_into().unwrap_or([0; 8]));
        uart::write_str("  ");
        uart::write_str(name);
        uart::write_str(" (");
        uart::write_hex_u64(size);
        uart::write_str(" bytes)\n");
    }
}
