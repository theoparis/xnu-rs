use spin::Mutex;

const PL011_UART_BASE: usize = 0x0900_0000;
const PL011_UART_DR: usize = PL011_UART_BASE;

// Global lock so concurrent CPUs don't interleave their UART output.
static UART_LOCK: Mutex<()> = Mutex::new(());

pub fn write_str(message: &str) {
    let _guard = UART_LOCK.lock();
    for byte in message.bytes() {
        write_byte_unlocked(byte);
    }
}

pub fn write_hex_usize(value: usize) {
    write_hex_u64(value as u64);
}

pub fn write_hex_u64(value: u64) {
    let _guard = UART_LOCK.lock();
    write_str_unlocked("0x");
    write_hex_u64_unlocked(value);
}

/// Write a UUID in standard `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` format.
pub fn write_uuid(uuid: &[u8; 16]) {
    let _guard = UART_LOCK.lock();
    for (i, &b) in uuid.iter().enumerate() {
        // Insert dashes after bytes 3, 5, 7, 9.
        if i == 4 || i == 6 || i == 8 || i == 10 {
            write_byte_unlocked(b'-');
        }
        write_nibble(b >> 4);
        write_nibble(b & 0xF);
    }
}

/// Write a string followed by a hex u64 and a newline, atomically.
pub fn write_str_hex_nl(prefix: &str, value: u64) {
    let _guard = UART_LOCK.lock();
    write_str_unlocked(prefix);
    write_str_unlocked("0x");
    write_hex_u64_unlocked(value);
    write_byte_unlocked(b'\n');
}

/// Write an entire log line as one atomic operation.
///
/// `parts` is a slice of string literals; hex values must be pre-formatted
/// by the caller or use separate `write_str_hex_nl` calls.
pub fn write_line(parts: &[&str]) {
    let _guard = UART_LOCK.lock();
    for s in parts {
        write_str_unlocked(s);
    }
}

// ── Unlocked primitives (caller must hold UART_LOCK) ──────────────────────

fn write_str_unlocked(s: &str) {
    for byte in s.bytes() {
        write_byte_unlocked(byte);
    }
}

fn write_hex_u64_unlocked(value: u64) {
    for shift in (0..64).step_by(4).rev() {
        write_nibble(((value >> shift) & 0x0F) as u8);
    }
}

fn write_nibble(n: u8) {
    let byte = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    write_byte_unlocked(byte);
}

pub fn write_byte(byte: u8) {
    let _guard = UART_LOCK.lock();
    write_byte_unlocked(byte);
}

fn write_byte_unlocked(byte: u8) {
    // SAFETY: QEMU virt exposes a PL011 UART at 0x0900_0000. Volatile MMIO write.
    unsafe {
        core::ptr::write_volatile(PL011_UART_DR as *mut u32, u32::from(byte));
    }
}
