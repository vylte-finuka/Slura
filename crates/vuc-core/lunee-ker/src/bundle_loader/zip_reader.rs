//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — ZIP reader ___
//
//! Parseur ZIP pour les bundles Maratine.
//! Supporte stored (méthode 0) et DEFLATE (méthode 8, via miniz_oxide).

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use miniz_oxide::inflate::core::{
    decompress, DecompressorOxide,
    inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::TINFLStatus;

use super::BundleError;

// ── Signatures ZIP ────────────────────────────────────────────────────────────
const SIG_LOCAL:   u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD:    u32 = 0x0605_4b50;

// ── Offsets Central Directory ─────────────────────────────────────────────────
const CD_COMPRESS:    usize = 10;
const CD_COMP_SIZE:   usize = 20;
const CD_UNCOMP_SIZE: usize = 24;
const CD_FNAME_LEN:   usize = 28;
const CD_EXTRA_LEN:   usize = 30;
const CD_COMMENT_LEN: usize = 32;
const CD_LOCAL_OFF:   usize = 42;
const CD_HEADER_SIZE: usize = 46;

// ── Offsets Local File Header ─────────────────────────────────────────────────
const LFH_FNAME_LEN:  usize = 26;
const LFH_EXTRA_LEN:  usize = 28;
const LFH_HEADER_MIN: usize = 30;

// ── Offsets EOCD ──────────────────────────────────────────────────────────────
const EOCD_CD_SIZE:   usize = 12;
const EOCD_CD_OFFSET: usize = 16;
const EOCD_MIN_SIZE:  usize = 22;

pub struct ZipReader<'a> {
    data:      &'a [u8],
    cd_offset: usize,
    cd_size:   usize,
}

impl<'a> ZipReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, BundleError> {
        let eocd = find_eocd(data).ok_or(BundleError::InvalidZip)?;
        let cd_size   = r_u32(data, eocd + EOCD_CD_SIZE)   as usize;
        let cd_offset = r_u32(data, eocd + EOCD_CD_OFFSET) as usize;

        if cd_offset.saturating_add(cd_size) > data.len() {
            return Err(BundleError::InvalidZip);
        }
        Ok(Self { data, cd_offset, cd_size })
    }

    /// Extrait l'entrée `name` du ZIP.
    /// Supporte stored (0) et DEFLATE (8).
    /// Retourne un `Vec<u8>` pour les deux cas.
    pub fn extract_file(&self, name: &str) -> Result<Vec<u8>, BundleError> {
        let end = self.cd_offset + self.cd_size;
        let mut pos = self.cd_offset;

        while pos + CD_HEADER_SIZE <= end {
            if r_u32(self.data, pos) != SIG_CENTRAL { break; }

            let compress    = r_u16(self.data, pos + CD_COMPRESS);
            let comp_size   = r_u32(self.data, pos + CD_COMP_SIZE)   as usize;
            let uncomp_size = r_u32(self.data, pos + CD_UNCOMP_SIZE) as usize;
            let fname_len   = r_u16(self.data, pos + CD_FNAME_LEN)   as usize;
            let extra_len   = r_u16(self.data, pos + CD_EXTRA_LEN)   as usize;
            let comment_len = r_u16(self.data, pos + CD_COMMENT_LEN) as usize;
            let local_off   = r_u32(self.data, pos + CD_LOCAL_OFF)   as usize;

            let name_start = pos + CD_HEADER_SIZE;
            let name_end   = name_start + fname_len;
            if name_end > self.data.len() { break; }

            let entry_name = &self.data[name_start..name_end];

            // Comparaison insensible aux séparateurs / et \
            if names_match(entry_name, name.as_bytes()) {
                let raw = self.raw_data_from_local(local_off, comp_size)?;

                return match compress {
                    0 => Ok(raw.to_vec()),  // stored — copie directe
                    8 => {                   // DEFLATE — décompresser
                        inflate_raw(raw, uncomp_size)
                    }
                    _ => Err(BundleError::CompressedNotSupported),
                };
            }

            pos += CD_HEADER_SIZE + fname_len + extra_len + comment_len;
        }

        Err(BundleError::FileNotFound)
    }

    fn raw_data_from_local(&self, local_off: usize, size: usize) -> Result<&'a [u8], BundleError> {
        if local_off + LFH_HEADER_MIN > self.data.len() {
            return Err(BundleError::InvalidZip);
        }
        if r_u32(self.data, local_off) != SIG_LOCAL {
            return Err(BundleError::InvalidZip);
        }

        let fname_len  = r_u16(self.data, local_off + LFH_FNAME_LEN) as usize;
        let extra_len  = r_u16(self.data, local_off + LFH_EXTRA_LEN) as usize;
        let data_start = local_off + LFH_HEADER_MIN + fname_len + extra_len;

        if data_start.saturating_add(size) > self.data.len() {
            return Err(BundleError::InvalidZip);
        }
        Ok(&self.data[data_start..data_start + size])
    }
}

// ── Décompression DEFLATE (raw, sans zlib header) ────────────────────────────

fn inflate_raw(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, BundleError> {
    // Alloue le buffer de sortie avec la taille déclarée dans le ZIP.
    let cap = expected_size.max(1);
    let mut output = vec![0u8; cap];
    let mut decompressor = DecompressorOxide::new();

    let (status, _in_consumed, out_produced) = decompress(
        &mut decompressor,
        compressed,
        &mut output,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );

    match status {
        TINFLStatus::Done => {
            output.truncate(out_produced);
            Ok(output)
        }
        _ => Err(BundleError::InvalidZip),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compare deux noms de fichiers ZIP en traitant `\` et `/` comme identiques
/// (marai build sur Windows produit des backslashes).
fn names_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    for (x, y) in a.iter().zip(b.iter()) {
        let xn = if *x == b'\\' { b'/' } else { *x };
        let yn = if *y == b'\\' { b'/' } else { *y };
        if xn != yn { return false; }
    }
    true
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_MIN_SIZE { return None; }
    let search_from = data.len().saturating_sub(65535 + EOCD_MIN_SIZE);
    for i in (search_from..=data.len() - EOCD_MIN_SIZE).rev() {
        if r_u32(data, i) == SIG_EOCD { return Some(i); }
    }
    None
}

#[inline(always)] fn r_u16(data: &[u8], off: usize) -> usize {
    u16::from_le_bytes([data[off], data[off + 1]]) as usize
}
#[inline(always)] fn r_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}
