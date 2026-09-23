// Utility functions for Whesere kernel
use core::convert::TryInto;

/// Convertit un u32 en little-endian bytes array
#[inline(always)]
pub fn u32_to_le_bytes(val: u32) -> [u8; 4] {
    val.to_le_bytes()
}

/// Convertit un u64 en little-endian bytes array
#[inline(always)]
pub fn u64_to_le_bytes(val: u64) -> [u8; 8] {
    val.to_le_bytes()
}