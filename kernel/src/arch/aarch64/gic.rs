/// GIC v2 driver for QEMU virt `AArch64`.
///
/// Distributor base: `0x0800_0000` (GICD)
/// CPU interface base: `0x0801_0000` (GICC)
use super::uart;

const GICD_BASE: u64 = 0x0800_0000;
const GICC_BASE: u64 = 0x0801_0000;

// GICD register offsets
const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_SGIR: u64 = 0xF00;

// GICC register offsets
const GICC_CTLR: u64 = 0x000;
const GICC_PMR: u64 = 0x004;
const GICC_BPR: u64 = 0x008;
const GICC_IAR: u64 = 0x00C;
const GICC_EOIR: u64 = 0x010;

// SAFETY: MMIO write to GIC distributor register.
unsafe fn gicd_write(offset: u64, val: u32) {
    // SAFETY: Caller guarantees the offset maps to a valid GICD register.
    unsafe {
        core::ptr::write_volatile((GICD_BASE + offset) as *mut u32, val);
    }
}

// SAFETY: MMIO read from GIC distributor register.
unsafe fn gicd_read(offset: u64) -> u32 {
    // SAFETY: Caller guarantees the offset maps to a valid GICD register.
    unsafe { core::ptr::read_volatile((GICD_BASE + offset) as *const u32) }
}

// SAFETY: MMIO write to GIC CPU interface register.
unsafe fn gicc_write(offset: u64, val: u32) {
    // SAFETY: Caller guarantees the offset maps to a valid GICC register.
    unsafe {
        core::ptr::write_volatile((GICC_BASE + offset) as *mut u32, val);
    }
}

// SAFETY: MMIO read from GIC CPU interface register.
unsafe fn gicc_read(offset: u64) -> u32 {
    // SAFETY: Caller guarantees the offset maps to a valid GICC register.
    unsafe { core::ptr::read_volatile((GICC_BASE + offset) as *const u32) }
}

/// Initialize the GIC distributor. Call once from CPU0 during boot.
///
/// # Safety
///
/// Must be called from CPU0 only, during single-threaded early boot before
/// secondary CPUs are started.
pub unsafe fn init_distributor() {
    // 1. Disable distributor.
    // SAFETY: GICD MMIO access during single-core early boot.
    unsafe { gicd_write(GICD_CTLR, 0) };

    // 2. Get number of IRQs from GICD_TYPER bits [4:0].
    // SAFETY: GICD MMIO read.
    let typer = unsafe { gicd_read(GICD_TYPER) };
    let num_irqs = ((typer & 0x1F) + 1) * 32;
    let num_words = num_irqs / 32;

    // 3. Set all interrupt groups to 1 (non-secure / group 1).
    for i in 0..num_words {
        // SAFETY: i < num_words, within GICD IGROUPR range.
        unsafe { gicd_write(GICD_IGROUPR + u64::from(i) * 4, 0xFFFF_FFFF) };
    }

    // 4. Disable all IRQs.
    for i in 0..num_words {
        // SAFETY: i < num_words, within GICD ICENABLER range.
        unsafe { gicd_write(GICD_ICENABLER + u64::from(i) * 4, 0xFFFF_FFFF) };
    }

    // 5. Set all priorities to 0xA0 (medium). Each byte is one IRQ.
    for i in 0..(num_irqs / 4) {
        // SAFETY: i < num_irqs/4, within GICD IPRIORITYR range.
        unsafe { gicd_write(GICD_IPRIORITYR + u64::from(i) * 4, 0xA0A0_A0A0) };
    }

    // 6. Target all IRQs to CPU 0 (0x01 per byte).
    for i in 0..(num_irqs / 4) {
        // SAFETY: i < num_irqs/4, within GICD ITARGETSR range.
        unsafe { gicd_write(GICD_ITARGETSR + u64::from(i) * 4, 0x0101_0101) };
    }

    // 7. Enable distributor.
    // SAFETY: GICD MMIO write to enable distributor.
    unsafe { gicd_write(GICD_CTLR, 1) };
}

/// Initialize the GIC CPU interface. Call from each CPU during bring-up.
///
/// # Safety
///
/// Must be called once per CPU as part of that CPU's initialization sequence.
pub unsafe fn init_cpu_interface() {
    // 1. Set priority mask: allow all priorities.
    // SAFETY: GICC MMIO write.
    unsafe { gicc_write(GICC_PMR, 0xFF) };

    // 2. Set binary point to 0 (all priority bits used for preemption).
    // SAFETY: GICC MMIO write.
    unsafe { gicc_write(GICC_BPR, 0) };

    // 3. Enable CPU interface.
    // SAFETY: GICC MMIO write.
    unsafe { gicc_write(GICC_CTLR, 1) };
}

/// Enable a specific IRQ in the GIC distributor (set-enable).
pub fn enable_irq(irq: u32) {
    let word = irq / 32;
    let bit = irq % 32;
    // SAFETY: GICD ISENABLER MMIO write; irq determines word/bit.
    unsafe { gicd_write(GICD_ISENABLER + u64::from(word) * 4, 1 << bit) };
}

/// Disable a specific IRQ in the GIC distributor.
pub fn disable_irq(irq: u32) {
    let word = irq / 32;
    let bit = irq % 32;
    // SAFETY: GICD ICENABLER MMIO write; irq determines word/bit.
    unsafe { gicd_write(GICD_ICENABLER + u64::from(word) * 4, 1 << bit) };
}

/// Acknowledge the highest-priority pending interrupt.
/// Returns the IRQ ID; 1023 indicates a spurious interrupt.
#[must_use]
pub fn ack() -> u32 {
    // SAFETY: GICC IAR MMIO read.
    unsafe { gicc_read(GICC_IAR) & 0x3FF }
}

/// Signal end-of-interrupt for the given IRQ ID.
pub fn eoi(irq: u32) {
    // SAFETY: GICC EOIR MMIO write.
    unsafe { gicc_write(GICC_EOIR, irq) };
}

/// Dispatch a pending IRQ: acknowledge, handle, end-of-interrupt.
pub fn handle_irq() {
    let irq = ack();
    if irq == 1023 {
        // Spurious interrupt — no EOI required.
        return;
    }

    if irq == 0 {
        // SGI 0: IPI from another CPU — invoke scheduler stub.
        schedule();
    } else {
        uart::write_str("xnu-rs: unhandled IRQ ");
        uart::write_hex_u64(u64::from(irq));
        uart::write_str("\n");
    }

    eoi(irq);
}

/// Scheduler stub. No-op until cooperative scheduler is implemented.
const fn schedule() {
    // No-op: cooperative scheduler not yet implemented.
}

/// Send a software-generated interrupt (SGI 0) to the specified CPUs.
///
/// `target_cpu_mask` is a bitmask of target CPU interfaces (bit N = CPU N).
pub fn send_ipi(target_cpu_mask: u8) {
    // GICD_SGIR: TargetListFilter=0 (use TargetList), CPUTargetList in [23:16], SGIINTID in [3:0].
    // SAFETY: GICD SGIR MMIO write.
    unsafe { gicd_write(GICD_SGIR, u32::from(target_cpu_mask) << 16) };
}
