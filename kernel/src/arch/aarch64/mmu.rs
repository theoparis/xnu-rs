use crate::mm::frame;

// ---------------------------------------------------------------------------
// Public flags type (used by mm::mapping and callers)
// ---------------------------------------------------------------------------

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy)]
pub struct MapFlags {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub user: bool,
}

// ---------------------------------------------------------------------------
// AArch64 page-table constants (4 KiB granule, 3-level walk for 39-bit VA)
// ---------------------------------------------------------------------------

const PAGE_SIZE: u64 = 4096;
#[allow(dead_code)]
const PAGE_SHIFT: u64 = 12;
const TABLE_ENTRIES: usize = 512;

// Descriptor type bits
const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE: u64 = 1 << 1; // for L0/L1/L2 table descriptors
const DESC_PAGE: u64 = 1 << 1; // for L3 page descriptors (same bit, different level)

// Attribute fields for stage-1 EL1 descriptors
const ATTR_IDX_NORMAL: u64 = 0 << 2; // MAIR index 0 → Normal WB cacheable
const ATTR_IDX_DEVICE: u64 = 1 << 2; // MAIR index 1 → Device nGnRnE
const ATTR_AP_RW_EL1: u64 = 0b00 << 6; // EL1 R/W, EL0 no access
const ATTR_AP_RW_EL0: u64 = 0b01 << 6; // EL1 R/W, EL0 R/W
const ATTR_AP_RO_EL1: u64 = 0b10 << 6; // EL1 RO, EL0 no access
const ATTR_AP_RO_EL0: u64 = 0b11 << 6; // EL1 RO, EL0 RO
const ATTR_SH_INNER: u64 = 0b11 << 8; // Inner shareable
const ATTR_AF: u64 = 1 << 10; // Access flag — must be set or hardware fault
const ATTR_UXN: u64 = 1 << 54; // EL0 execute-never
const ATTR_PXN: u64 = 1 << 53; // EL1 execute-never
#[allow(dead_code)]
const ATTR_NS: u64 = 0; // not used at EL1 stage-1

// MAIR_EL1 value: index 0 = Normal WB/WA, index 1 = Device nGnRnE
const MAIR_NORMAL_WB: u64 = 0xFF; // Normal Inner/Outer WB WA RA
const MAIR_DEVICE_NGNRNE: u64 = 0x00; // Device nGnRnE
const MAIR_VALUE: u64 = MAIR_NORMAL_WB | (MAIR_DEVICE_NGNRNE << 8);

// TCR_EL1 value
// T0SZ=25 → 39-bit VA lower, T1SZ=25 → 39-bit VA upper
// TG0=0 (4K), TG1=0 (4K)
// SH0/SH1=11 (inner shareable), IRGN/ORGN=01 (WB WA)
// EPD1=0 (TTBR1 enabled), A1=0 (ASID from TTBR0)
const TCR_T0SZ: u64 = 25;
const TCR_T1SZ: u64 = 25 << 16;
const TCR_IRGN0: u64 = 0b01 << 8;
const TCR_ORGN0: u64 = 0b01 << 10;
const TCR_SH0: u64 = 0b11 << 12;
const TCR_TG0: u64 = 0b00 << 14; // 4K
const TCR_IRGN1: u64 = 0b01 << 24;
const TCR_ORGN1: u64 = 0b01 << 26;
const TCR_SH1: u64 = 0b11 << 28;
const TCR_TG1: u64 = 0b10 << 30; // 4K for TG1 uses encoding 10
const TCR_IPS: u64 = 0b001 << 32; // 36-bit PA (64 GiB)
const TCR_AS: u64 = 1 << 36; // 16-bit ASID
const TCR_VALUE: u64 = TCR_T0SZ
    | TCR_T1SZ
    | TCR_IRGN0
    | TCR_ORGN0
    | TCR_SH0
    | TCR_TG0
    | TCR_IRGN1
    | TCR_ORGN1
    | TCR_SH1
    | TCR_TG1
    | TCR_IPS
    | TCR_AS;

// ---------------------------------------------------------------------------
// Static kernel page table (identity-mapped TTBR0)
// ---------------------------------------------------------------------------

// A page table is 512 × 8-byte entries = 4 KiB.
#[repr(C, align(4096))]
struct PageTable([u64; TABLE_ENTRIES]);

// Three-level walk for 39-bit VA: L1 (root at TTBR0) → L2 → L3.
// Level 1 covers 1 GiB per entry; 512 entries cover 512 GiB.
// We use a single static L1 table as root and allocate L2/L3 via frame alloc.
//
// For the static kernel identity map we pre-allocate enough L2 tables to
// cover RAM (0x4000_0000 – 0xC000_0000, 2 GiB) and MMIO (0x0 – 0x4000_0000).
// Each L2 covers 1 GiB; two L2s suffice for 0–2 GiB.  We map with 2 MiB
// blocks (L2 block descriptors) to keep the static tables small.

#[repr(C, align(4096))]
struct KernelTables {
    l1: PageTable,       // TTBR0 root: 1-GiB slots
    l2_0gb: PageTable,   // L2 for 0x0000_0000 – 0x4000_0000 (MMIO)
    l2_1gb: PageTable,   // L2 for 0x4000_0000 – 0x8000_0000 (RAM lo)
    l2_2gb: PageTable,   // L2 for 0x8000_0000 – 0xC000_0000 (RAM hi)
}

static mut KERNEL_TABLES: KernelTables = KernelTables {
    l1: PageTable([0u64; TABLE_ENTRIES]),
    l2_0gb: PageTable([0u64; TABLE_ENTRIES]),
    l2_1gb: PageTable([0u64; TABLE_ENTRIES]),
    l2_2gb: PageTable([0u64; TABLE_ENTRIES]),
};

/// Initialise the kernel identity-map page tables and enable the MMU.
///
/// After this call TTBR0 identity-maps all RAM and MMIO so that the kernel
/// running at its linked physical addresses continues to work.  TTBR1 is left
/// zeroed (EPD1=0 is *not* set, but no mappings exist there — translation
/// faults on TTBR1 accesses are expected and fine for now since we only use
/// TTBR0).
///
/// # Safety
///
/// Must be called exactly once during early boot, before any TTBR0-dependent
/// code.  The static `KERNEL_TABLES` must not be aliased elsewhere.
pub unsafe fn init_kernel_tables() {
    // SAFETY: Single-threaded early boot; no aliases.
    // SAFETY: Single-threaded early boot; no aliases. Using raw pointer to avoid
    // `deref_addrof` and `static_mut_refs` lints.
    let tables: &mut KernelTables = unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_TABLES) };

    // 2 MiB block descriptor base flags (Normal WB cacheable, AF, Inner Shareable)
    let blk_normal = DESC_VALID | ATTR_IDX_NORMAL | ATTR_AP_RW_EL1 | ATTR_SH_INNER | ATTR_AF | ATTR_UXN;
    let blk_device = DESC_VALID | ATTR_IDX_DEVICE | ATTR_AP_RW_EL1 | ATTR_SH_INNER | ATTR_AF | ATTR_UXN | ATTR_PXN;

    // Map 0x0000_0000 – 0x4000_0000 as Device (MMIO lives here, e.g. UART 0x0900_0000)
    // 512 × 2 MiB = 1 GiB
    for i in 0..512usize {
        let pa = (i as u64) * (2 * 1024 * 1024);
        tables.l2_0gb.0[i] = pa | blk_device;
    }

    // Map 0x4000_0000 – 0x8000_0000 as Normal (RAM, kernel code)
    for i in 0..512usize {
        let pa = 0x4000_0000u64 + (i as u64) * (2 * 1024 * 1024);
        tables.l2_1gb.0[i] = pa | blk_normal;
    }

    // Map 0x8000_0000 – 0xC000_0000 as Normal (more RAM)
    for i in 0..512usize {
        let pa = 0x8000_0000u64 + (i as u64) * (2 * 1024 * 1024);
        tables.l2_2gb.0[i] = pa | blk_normal;
    }

    // Wire L1 entries → L2 tables (table descriptors)
    let l2_0_pa = tables.l2_0gb.0.as_ptr() as u64;
    let l2_1_pa = tables.l2_1gb.0.as_ptr() as u64;
    let l2_2_pa = tables.l2_2gb.0.as_ptr() as u64;
    tables.l1.0[0] = l2_0_pa | DESC_VALID | DESC_TABLE;
    tables.l1.0[1] = l2_1_pa | DESC_VALID | DESC_TABLE;
    tables.l1.0[2] = l2_2_pa | DESC_VALID | DESC_TABLE;

    let ttbr0 = tables.l1.0.as_ptr() as u64;

    // Enable the MMU.
    // SAFETY: Page tables are fully initialised above; all physical addresses
    // used by the kernel are covered.  The ISB after each system-register write
    // is required by the architecture before dependent instructions.
    unsafe {
        core::arch::asm!(
            // Programme memory attributes.
            "msr mair_el1, {mair}",
            "isb",
            // Programme translation control.
            "msr tcr_el1, {tcr}",
            "isb",
            // Load TTBR0 (identity map, ASID 0).
            "msr ttbr0_el1, {ttbr0}",
            "isb",
            // Enable MMU: set SCTLR_EL1.M (bit 0) and C (bit 2, data cache enable).
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, #(1 << 0)",  // M
            "orr {tmp}, {tmp}, #(1 << 2)",  // C
            "msr sctlr_el1, {tmp}",
            "isb",
            mair  = in(reg) MAIR_VALUE,
            tcr   = in(reg) TCR_VALUE,
            ttbr0 = in(reg) ttbr0,
            tmp   = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Per-process page tables (TTBR0, swapped on context switch)
// ---------------------------------------------------------------------------

// Raw 3-level page table for a user process (39-bit VA via TTBR0).
// Each process gets its own L1 root allocated from the frame allocator.
// L2 and L3 tables are also allocated on demand from the frame allocator.

pub struct ProcessPageTable {
    root_pa: u64,
    asid: u16,
}

impl ProcessPageTable {
    /// Allocate a new empty per-process page table with the given ASID.
    #[must_use]
    pub fn new(asid: u16) -> Option<Self> {
        let root_pa = frame::alloc_frame()?;
        // Zero the root table so all entries are invalid.
        // SAFETY: `root_pa` is a freshly allocated 4 KiB frame; we have
        // exclusive access until this function returns.
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            core::ptr::write_bytes(root_pa as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(Self { root_pa, asid })
    }

    /// Map `size` bytes at virtual address `va` to physical address `pa`.
    ///
    /// Mappings are always at 4 KiB granularity.  Returns `false` if frame
    /// allocation fails mid-walk.
    pub fn map(&mut self, va: u64, pa: u64, size: u64, flags: MapFlags) -> bool {
        let mut offset = 0u64;
        while offset < size {
            if self.map_page(va + offset, pa + offset, flags).is_none() {
                return false;
            }
            offset += PAGE_SIZE;
        }
        true
    }

    fn map_page(&mut self, va: u64, pa: u64, flags: MapFlags) -> Option<()> {
        let l3e_attrs = page_attrs(flags);

        // 39-bit VA layout (4K, 3-level):
        //   [38:30] L1 index (9 bits)
        //   [29:21] L2 index (9 bits)
        //   [20:12] L3 index (9 bits)
        //   [11:0]  page offset
        let l1_idx = ((va >> 30) & 0x1FF) as usize;
        let l2_idx = ((va >> 21) & 0x1FF) as usize;
        let l3_idx = ((va >> 12) & 0x1FF) as usize;

        // Walk / allocate L2 table.
        // SAFETY: `root_pa` was zero-filled on allocation and is 4 KiB aligned.
        let l1_table = unsafe { &mut *(self.root_pa as *mut [u64; TABLE_ENTRIES]) };
        let l2_pa = ensure_table(&mut l1_table[l1_idx])?;

        // Walk / allocate L3 table.
        // SAFETY: `l2_pa` was zero-filled when allocated.
        let l2_table = unsafe { &mut *(l2_pa as *mut [u64; TABLE_ENTRIES]) };
        let l3_pa = ensure_table(&mut l2_table[l2_idx])?;

        // Install L3 page descriptor.
        // SAFETY: `l3_pa` was zero-filled when allocated.
        let l3_table = unsafe { &mut *(l3_pa as *mut [u64; TABLE_ENTRIES]) };
        l3_table[l3_idx] = pa | l3e_attrs | DESC_VALID | DESC_PAGE;

        Some(())
    }

    /// Activate this page table by writing `TTBR0_EL1`.
    pub fn activate(&self) {
        let ttbr0 = self.root_pa | (u64::from(self.asid) << 48);
        // SAFETY: The page table is fully initialised.  ISB synchronises the
        // TTBR0 write before any subsequent instruction fetches.
        unsafe {
            core::arch::asm!(
                "msr ttbr0_el1, {v}",
                "isb",
                v = in(reg) ttbr0,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Deactivate the current TTBR0 and flush the TLB for this ASID.
    pub fn deactivate() {
        // SAFETY: Writing zero to TTBR0 disables user VA translations.
        // TLBI ASIDE1IS flushes all TLB entries for this inner-shareable domain
        // by ASID, which is required after swapping page tables.
        unsafe {
            core::arch::asm!(
                "msr ttbr0_el1, xzr",
                "isb",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags),
            );
        }
    }
}

// Return the `PagingAttributes` word for an L3 page descriptor given `flags`.
const fn page_attrs(flags: MapFlags) -> u64 {
    let mut attrs = ATTR_SH_INNER | ATTR_AF;

    attrs |= ATTR_IDX_NORMAL;

    attrs |= match (flags.read, flags.write, flags.user) {
        (_, true, true) => ATTR_AP_RW_EL0,
        (_, true, false) => ATTR_AP_RW_EL1,
        (true, false, true) => ATTR_AP_RO_EL0,
        _ => ATTR_AP_RO_EL1,
    };

    if !flags.exec {
        attrs |= ATTR_UXN | ATTR_PXN;
    } else if flags.user {
        // User exec: suppress PXN so kernel doesn't need to execute it; UXN=0 allows user exec.
        attrs |= ATTR_PXN;
    }

    attrs
}

/// Given a table-descriptor slot, return the physical address of the next-level
/// table.  If the slot is empty (not valid), a new frame is allocated, zeroed,
/// and the slot updated to point at it.
fn ensure_table(slot: &mut u64) -> Option<u64> {
    if *slot & DESC_VALID != 0 {
        // Already a table descriptor — extract the output address.
        return Some(*slot & 0x0000_FFFF_FFFF_F000);
    }
    let new_pa = frame::alloc_frame()?;
    // SAFETY: `new_pa` is a freshly allocated 4 KiB frame; exclusive access here.
    unsafe {
        #[allow(clippy::cast_possible_truncation)]
        core::ptr::write_bytes(new_pa as *mut u8, 0, PAGE_SIZE as usize);
    }
    *slot = new_pa | DESC_VALID | DESC_TABLE;
    Some(new_pa)
}
