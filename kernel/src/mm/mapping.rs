use crate::arch::aarch64::mmu::MapFlags;

#[derive(Clone)]
pub struct VmMapping {
    pub va: u64,
    pub pa: u64,
    pub size: u64,
    pub flags: MapFlags,
}
