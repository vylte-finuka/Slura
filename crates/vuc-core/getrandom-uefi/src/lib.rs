//! Implémentation minimale de getrandom pour la cible x86_64-unknown-uefi.
//! Utilise RDRAND (instruction x86_64) comme source d'entropie hardware.
//! Compatible no_std.

#![no_std]

/// Remplit `dest` avec des octets aléatoires via RDRAND (x86_64).
pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    fill_bytes(dest);
    Ok(())
}

fn fill_bytes(dest: &mut [u8]) {
    let mut i = 0;
    while i + 8 <= dest.len() {
        let val = rdrand64();
        dest[i..i+8].copy_from_slice(&val.to_le_bytes());
        i += 8;
    }
    if i < dest.len() {
        let val = rdrand64();
        let rem = &val.to_le_bytes()[..dest.len() - i];
        dest[i..].copy_from_slice(rem);
    }
}

#[inline(always)]
fn rdrand64() -> u64 {
    let mut val: u64 = 0;
    // RDRAND avec retry — l'instruction peut échouer (CF=0) sous charge.
    for _ in 0..10u32 {
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc   {ok}",
                val = out(reg) val,
                ok  = out(reg_byte) ok,
            );
        }
        if ok != 0 { return val; }
    }
    // Fallback : compteur TSC (entropie faible mais fonctionnel)
    let lo: u32;
    let hi: u32;
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi); }
    ((hi as u64) << 32) | (lo as u64)
}

/// Type d'erreur (compatible avec l'API getrandom 0.2.x).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error(core::num::NonZeroU32);

impl Error {
    pub const UNSUPPORTED: Self =
        Error(unsafe { core::num::NonZeroU32::new_unchecked(0xFFFFFFFF) });

    pub fn raw_os_error(&self) -> Option<i32> { None }
    pub fn code(&self) -> core::num::NonZeroU32 { self.0 }
}

impl core::fmt::Debug   for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "getrandom::Error({})", self.0)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "getrandom error: {}", self.0)
    }
}

// Implémentation de core::error::Error (stable depuis Rust 1.81, no_std).
impl core::error::Error for Error {}

/// Macro register_custom_getrandom — no-op car on utilise RDRAND directement.
#[macro_export]
macro_rules! register_custom_getrandom {
    ($fn:expr) => {};
}
