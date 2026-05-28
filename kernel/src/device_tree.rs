#![allow(clippy::redundant_pub_crate)]

use core::str;

use kernel::arch::aarch64::uart;

const PROPERTY_NAME_LEN: usize = 32;

pub(crate) fn dump(bytes: &[u8]) {
    match AppleDeviceTree::new(bytes) {
        Ok(tree) => {
            uart::write_str("xnu-rs: Apple device tree\n");
            if dump_node(tree.root(), 0).is_err() {
                uart::write_str("xnu-rs: Apple device tree dump truncated/malformed\n");
            }
        }
        Err(()) => uart::write_str("xnu-rs: malformed Apple device tree\n"),
    }
}

struct AppleDeviceTree<'a> {
    bytes: &'a [u8],
}

impl<'a> AppleDeviceTree<'a> {
    const fn new(bytes: &'a [u8]) -> Result<Self, ()> {
        if bytes.len() < 8 {
            return Err(());
        }
        Ok(Self { bytes })
    }

    const fn root(&self) -> Node<'a> {
        Node { bytes: self.bytes }
    }
}

#[derive(Clone, Copy)]
struct Node<'a> {
    bytes: &'a [u8],
}

impl Node<'_> {
    fn property_count(&self) -> Result<u32, ()> {
        read_le_u32(self.bytes, 0)
    }

    fn child_count(&self) -> Result<u32, ()> {
        read_le_u32(self.bytes, 4)
    }

    fn properties_end(&self) -> Result<usize, ()> {
        let mut offset = 8usize;
        for _ in 0..self.property_count()? {
            let property = Property::parse(self.bytes, offset)?;
            offset = property.end;
        }
        Ok(offset)
    }

    fn child_at(&self, wanted: u32) -> Result<Self, ()> {
        let mut offset = self.properties_end()?;
        for index in 0..self.child_count()? {
            let child = Self {
                bytes: self.bytes.get(offset..).ok_or(())?,
            };
            let child_len = child.total_len()?;
            if index == wanted {
                return Ok(child);
            }
            offset = offset.checked_add(child_len).ok_or(())?;
        }
        Err(())
    }

    fn total_len(&self) -> Result<usize, ()> {
        let mut offset = self.properties_end()?;
        for index in 0..self.child_count()? {
            let child = self.child_at(index)?;
            offset = offset.checked_add(child.total_len()?).ok_or(())?;
        }
        Ok(offset)
    }
}

struct Property<'a> {
    name: &'a str,
    value: &'a [u8],
    end: usize,
}

impl<'a> Property<'a> {
    fn parse(bytes: &'a [u8], offset: usize) -> Result<Self, ()> {
        let name_bytes = bytes
            .get(offset..offset.checked_add(PROPERTY_NAME_LEN).ok_or(())?)
            .ok_or(())?;
        let name_len = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(PROPERTY_NAME_LEN);
        let name = str::from_utf8(&name_bytes[..name_len]).map_err(|_| ())?;
        let len_offset = offset.checked_add(PROPERTY_NAME_LEN).ok_or(())?;
        let len = usize::try_from(read_le_u32(bytes, len_offset)?).map_err(|_| ())?;
        let value_start = len_offset.checked_add(4).ok_or(())?;
        let value_end = value_start.checked_add(len).ok_or(())?;
        let value = bytes.get(value_start..value_end).ok_or(())?;
        let end = align_up_4(value_end).ok_or(())?;
        if end > bytes.len() {
            return Err(());
        }
        Ok(Self { name, value, end })
    }
}

fn dump_node(node: Node<'_>, depth: usize) -> Result<(), ()> {
    write_indent(depth);
    uart::write_str("node props=");
    uart::write_hex_u64(u64::from(node.property_count()?));
    uart::write_str(" children=");
    uart::write_hex_u64(u64::from(node.child_count()?));
    uart::write_str("\n");

    let mut offset = 8usize;
    for _ in 0..node.property_count()? {
        let property = Property::parse(node.bytes, offset)?;
        write_indent(depth + 1);
        uart::write_str(property.name);
        uart::write_str(" len=");
        uart::write_hex_u64(property.value.len() as u64);
        if is_printable(property.value) {
            uart::write_str(" value=\"");
            write_ascii(property.value);
            uart::write_str("\"");
        }
        uart::write_str("\n");
        offset = property.end;
    }

    for index in 0..node.child_count()? {
        dump_node(node.child_at(index)?, depth + 1)?;
    }
    Ok(())
}

fn is_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| matches!(*byte, b' '..=b'~' | 0))
}

fn write_ascii(bytes: &[u8]) {
    for byte in bytes.iter().copied().filter(|byte| *byte != 0) {
        // This intentionally routes through a one-byte str table rather than exposing a raw byte
        // UART API from the architecture module yet.
        let buf = [byte];
        if let Ok(text) = str::from_utf8(&buf) {
            uart::write_str(text);
        }
    }
}

fn write_indent(depth: usize) {
    for _ in 0..depth {
        uart::write_str("  ");
    }
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, ()> {
    let data = bytes
        .get(offset..offset.checked_add(4).ok_or(())?)
        .ok_or(())?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

const fn align_up_4(value: usize) -> Option<usize> {
    match value.checked_add(3) {
        Some(value) => Some(value & !3),
        None => None,
    }
}
