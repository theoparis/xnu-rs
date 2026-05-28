const PL011_UART_BASE: usize = 0x0900_0000;
const PL011_UART_DR: usize = PL011_UART_BASE;

pub fn write_str(message: &str) {
    for byte in message.bytes() {
        write_byte(byte);
    }
}

pub fn write_hex_usize(value: usize) {
    write_hex_u64(value as u64);
}

pub fn write_hex_u64(value: u64) {
    write_str("0x");
    for shift in (0..64).step_by(4).rev() {
        let nibble = ((value >> shift) & 0x0f) as u8;
        let byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        write_byte(byte);
    }
}

pub fn write_byte(byte: u8) {
    // SAFETY: QEMU virt exposes a PL011 UART at 0x0900_0000. This is a volatile MMIO write.
    unsafe {
        core::ptr::write_volatile(PL011_UART_DR as *mut u32, u32::from(byte));
    }
}
