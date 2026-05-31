#![allow(clippy::redundant_pub_crate)]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use core::{ffi::c_void, ptr::copy_nonoverlapping, slice};
use uefi::{
    Guid,
    boot::{self, AllocateType, MemoryType, PAGE_SIZE},
    guid, system,
};

const EFI_DTB_TABLE_GUID: Guid = guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

pub(super) struct AppleDeviceTree {
    pub(super) ptr: *const c_void,
    pub(super) len: u32,
}

pub(super) fn build_apple_device_tree() -> Result<AppleDeviceTree, uefi::Status> {
    let bytes = if let Some(fdt) = find_fdt() {
        let root = FdtParser::new(fdt)?.parse()?;
        let mut out = Vec::new();
        write_adt_node(&root, &mut out)?;
        out
    } else {
        let root = AdtNode {
            props: vec![
                AdtProp::new("name", b"/")?,
                AdtProp::new("compatible", b"linux,dummy-virt")?,
                AdtProp::new("model", b"xnu-rs qemu virt")?,
                AdtProp::new("#address-cells", &2_u32.to_be_bytes())?,
                AdtProp::new("#size-cells", &2_u32.to_be_bytes())?,
            ],
            children: vec![
                AdtNode {
                    props: vec![
                        AdtProp::new("name", b"chosen")?,
                        AdtProp::new("bootargs", b"rd=*devfs")?,
                    ],
                    children: Vec::new(),
                },
                AdtNode {
                    props: vec![
                        AdtProp::new("name", b"memory")?,
                        AdtProp::new("device_type", b"memory")?,
                        AdtProp::new_owned(String::from("reg"), qemu_virt_memory_reg())?,
                    ],
                    children: Vec::new(),
                },
            ],
        };
        let mut out = Vec::new();
        write_adt_node(&root, &mut out)?;
        out
    };

    let len = u32::try_from(bytes.len()).map_err(|_| uefi::Status::LOAD_ERROR)?;
    let pages = bytes.len().div_ceil(PAGE_SIZE);
    let ptr = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|err| err.status())?;

    // SAFETY: `ptr` points to a loader-owned allocation of at least `bytes.len()` bytes.
    unsafe { copy_nonoverlapping(bytes.as_ptr(), ptr.as_ptr(), bytes.len()) };

    Ok(AppleDeviceTree {
        ptr: ptr.as_ptr().cast_const().cast::<c_void>(),
        len,
    })
}

fn find_fdt() -> Option<&'static [u8]> {
    system::with_config_table(|tables| {
        tables.iter().find_map(|entry| {
            if entry.guid != EFI_DTB_TABLE_GUID || entry.address.is_null() {
                return None;
            }

            let ptr = entry.address.cast::<u8>();
            // SAFETY: The UEFI FDT config table points at a valid FDT header. We initially read
            // only the 40-byte header to validate magic and discover the total size.
            let header = unsafe { slice::from_raw_parts(ptr, 40) };
            let total_size = read_be_u32(header, 4)?;
            if read_be_u32(header, 0)? != FDT_MAGIC || total_size < 40 {
                return None;
            }
            let total_size = usize::try_from(total_size).ok()?;
            // SAFETY: UEFI owns this FDT blob until boot services are exited; caller copies it
            // into loader-owned memory before handoff.
            Some(unsafe { slice::from_raw_parts(ptr, total_size) })
        })
    })
}

struct FdtParser<'a> {
    bytes: &'a [u8],
    strings_offset: usize,
    pos: usize,
}

impl<'a> FdtParser<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, uefi::Status> {
        if read_be_u32(bytes, 0).ok_or(uefi::Status::LOAD_ERROR)? != FDT_MAGIC {
            return Err(uefi::Status::LOAD_ERROR);
        }
        let totalsize = usize::try_from(read_be_u32(bytes, 4).ok_or(uefi::Status::LOAD_ERROR)?)
            .map_err(|_| uefi::Status::LOAD_ERROR)?;
        let struct_offset = usize::try_from(read_be_u32(bytes, 8).ok_or(uefi::Status::LOAD_ERROR)?)
            .map_err(|_| uefi::Status::LOAD_ERROR)?;
        let strings_offset =
            usize::try_from(read_be_u32(bytes, 12).ok_or(uefi::Status::LOAD_ERROR)?)
                .map_err(|_| uefi::Status::LOAD_ERROR)?;
        if totalsize > bytes.len() || struct_offset >= totalsize || strings_offset >= totalsize {
            return Err(uefi::Status::LOAD_ERROR);
        }
        Ok(Self {
            bytes: &bytes[..totalsize],
            strings_offset,
            pos: struct_offset,
        })
    }

    fn parse(mut self) -> Result<AdtNode, uefi::Status> {
        self.parse_node()
    }

    fn parse_node(&mut self) -> Result<AdtNode, uefi::Status> {
        self.expect_token(FDT_BEGIN_NODE)?;
        let name = self.read_cstr()?;
        self.align_pos()?;

        let mut props = Vec::new();
        let mut children = Vec::new();
        loop {
            match self.peek_token()? {
                FDT_PROP => props.push(self.parse_prop()?),
                FDT_BEGIN_NODE => children.push(self.parse_node()?),
                FDT_END_NODE => {
                    self.read_token()?;
                    break;
                }
                FDT_NOP => {
                    self.read_token()?;
                }
                FDT_END => break,
                _ => return Err(uefi::Status::LOAD_ERROR),
            }
        }

        if !props.iter().any(|prop| prop.name == "name") {
            let value = if name.is_empty() {
                b"/".as_slice()
            } else {
                name.as_bytes()
            };
            props.insert(0, AdtProp::new("name", value)?);
        }

        let _ = name;
        Ok(AdtNode { props, children })
    }

    fn parse_prop(&mut self) -> Result<AdtProp, uefi::Status> {
        self.expect_token(FDT_PROP)?;
        let len = usize::try_from(self.read_token()?).map_err(|_| uefi::Status::LOAD_ERROR)?;
        let nameoff = usize::try_from(self.read_token()?).map_err(|_| uefi::Status::LOAD_ERROR)?;
        let name = self.string_at(nameoff)?;
        let end = self.pos.checked_add(len).ok_or(uefi::Status::LOAD_ERROR)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(uefi::Status::LOAD_ERROR)?
            .to_vec();
        self.pos = end;
        self.align_pos()?;
        AdtProp::new_owned(name, value)
    }

    fn string_at(&self, offset: usize) -> Result<String, uefi::Status> {
        let start = self
            .strings_offset
            .checked_add(offset)
            .ok_or(uefi::Status::LOAD_ERROR)?;
        let mut end = start;
        while *self.bytes.get(end).ok_or(uefi::Status::LOAD_ERROR)? != 0 {
            end = end.checked_add(1).ok_or(uefi::Status::LOAD_ERROR)?;
        }
        core::str::from_utf8(&self.bytes[start..end])
            .map(String::from)
            .map_err(|_| uefi::Status::LOAD_ERROR)
    }

    fn read_cstr(&mut self) -> Result<String, uefi::Status> {
        let start = self.pos;
        while *self.bytes.get(self.pos).ok_or(uefi::Status::LOAD_ERROR)? != 0 {
            self.pos = self.pos.checked_add(1).ok_or(uefi::Status::LOAD_ERROR)?;
        }
        let end = self.pos;
        self.pos = self.pos.checked_add(1).ok_or(uefi::Status::LOAD_ERROR)?;
        core::str::from_utf8(&self.bytes[start..end])
            .map(String::from)
            .map_err(|_| uefi::Status::LOAD_ERROR)
    }

    fn peek_token(&self) -> Result<u32, uefi::Status> {
        read_be_u32(self.bytes, self.pos).ok_or(uefi::Status::LOAD_ERROR)
    }

    fn read_token(&mut self) -> Result<u32, uefi::Status> {
        let value = self.peek_token()?;
        self.pos = self.pos.checked_add(4).ok_or(uefi::Status::LOAD_ERROR)?;
        Ok(value)
    }

    fn expect_token(&mut self, expected: u32) -> Result<(), uefi::Status> {
        if self.read_token()? == expected {
            Ok(())
        } else {
            Err(uefi::Status::LOAD_ERROR)
        }
    }

    fn align_pos(&mut self) -> Result<(), uefi::Status> {
        self.pos = self.pos.checked_add(3).ok_or(uefi::Status::LOAD_ERROR)? & !3;
        Ok(())
    }
}

struct AdtNode {
    props: Vec<AdtProp>,
    children: Vec<Self>,
}

fn qemu_virt_memory_reg() -> Vec<u8> {
    let mut reg = Vec::new();
    reg.extend_from_slice(&0x4000_0000_u64.to_be_bytes());
    reg.extend_from_slice(&0x4000_0000_u64.to_be_bytes());
    reg
}

struct AdtProp {
    name: String,
    value: Vec<u8>,
}

impl AdtProp {
    fn new(name: &str, value: &[u8]) -> Result<Self, uefi::Status> {
        Self::new_owned(String::from(name), value.to_vec())
    }

    fn new_owned(name: String, value: Vec<u8>) -> Result<Self, uefi::Status> {
        if name.len() >= 32 {
            return Err(uefi::Status::LOAD_ERROR);
        }
        Ok(Self { name, value })
    }
}

fn write_adt_node(node: &AdtNode, out: &mut Vec<u8>) -> Result<(), uefi::Status> {
    write_le_u32(
        out,
        u32::try_from(node.props.len()).map_err(|_| uefi::Status::LOAD_ERROR)?,
    );
    write_le_u32(
        out,
        u32::try_from(node.children.len()).map_err(|_| uefi::Status::LOAD_ERROR)?,
    );
    for prop in &node.props {
        write_adt_prop(prop, out)?;
    }
    for child in &node.children {
        write_adt_node(child, out)?;
    }
    Ok(())
}

fn write_adt_prop(prop: &AdtProp, out: &mut Vec<u8>) -> Result<(), uefi::Status> {
    let mut name = [0_u8; 32];
    let src = prop.name.as_bytes();
    if src.len() >= name.len() {
        return Err(uefi::Status::LOAD_ERROR);
    }
    name[..src.len()].copy_from_slice(src);
    out.extend_from_slice(&name);
    write_le_u32(
        out,
        u32::try_from(prop.value.len()).map_err(|_| uefi::Status::LOAD_ERROR)?,
    );
    out.extend_from_slice(&prop.value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    Ok(())
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let data = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

fn write_le_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
