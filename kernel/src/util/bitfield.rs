/// Extract bits [high:low] from a u64 value.
#[macro_export]
macro_rules! bitfield_extract {
    ($value:expr, $high:expr, $low:expr) => {{
        let v: u64 = $value;
        let width: u64 = $high - $low + 1;
        (v >> $low) & ((1u64 << width) - 1)
    }};
}

/// Insert `val` into bits [high:low] of `base`, returning the result.
#[macro_export]
macro_rules! bitfield_insert {
    ($base:expr, $high:expr, $low:expr, $val:expr) => {{
        let b: u64 = $base;
        let width: u64 = $high - $low + 1;
        let mask: u64 = ((1u64 << width) - 1) << $low;
        (b & !mask) | (($val as u64 & ((1u64 << width) - 1)) << $low)
    }};
}
