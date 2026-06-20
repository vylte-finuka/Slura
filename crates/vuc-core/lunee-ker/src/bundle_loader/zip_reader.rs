//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — ZIP reader ___
//
//! Parseur ZIP minimal pour les bundles Maratine.
//!
//! **Seule la méthode stored (compression = 0) est supportée.**
//! `marai build` doit produire des bundles non compressés quand il
//! cible le kernel Lunée (`--no-compress` ou `--target kernel`).
//!
//! L'implémentation ne fait aucune allocation : elle retourne des
//! sous-tranches `&'a [u8]` du buffer d'entrée.

use super::BundleError;

// ── Signatures ZIP ────────────────────────────────────────────────────────────
const SIG_LOCAL:   u32 = 0x0403_4b50;  // Local File Header
const SIG_CENTRAL: u32 = 0x0201_4b50;  // Central Directory File Header
const SIG_EOCD:    u32 = 0x0605_4b50;  // End of Central Directory

// ── Offsets dans le Central Directory File Header ────────────────────────────
const CD_COMPRESS:    usize = 10;  // u16 : méthode de compression
const CD_COMP_SIZE:   usize = 20;  // u32 : taille compressée
const CD_FNAME_LEN:   usize = 28;  // u16 : longueur du nom de fichier
const CD_EXTRA_LEN:   usize = 30;  // u16 : longueur du champ extra
const CD_COMMENT_LEN: usize = 32;  // u16 : longueur du commentaire
const CD_LOCAL_OFF:   usize = 42;  // u32 : offset du Local File Header
const CD_HEADER_SIZE: usize = 46;  // taille fixe de l'en-tête CD

// ── Offsets dans le Local File Header ────────────────────────────────────────
const LFH_FNAME_LEN:  usize = 26;  // u16
const LFH_EXTRA_LEN:  usize = 28;  // u16
const LFH_HEADER_MIN: usize = 30;  // taille minimale

// ── Offsets dans l'EOCD ──────────────────────────────────────────────────────
const EOCD_CD_SIZE:   usize = 12;  // u32
const EOCD_CD_OFFSET: usize = 16;  // u32
const EOCD_MIN_SIZE:  usize = 22;

/// Lecteur de ZIP en lecture seule, zéro copie pour les entrées stored.
pub struct ZipReader<'a> {
    data:      &'a [u8],
    cd_offset: usize,
    cd_size:   usize,
}

impl<'a> ZipReader<'a> {
    /// Vérifie la présence de l'EOCD et indexe le Central Directory.
    /// Retourne `Err(InvalidZip)` si le fichier n'est pas un ZIP valide.
    pub fn new(data: &'a [u8]) -> Result<Self, BundleError> {
        let eocd = find_eocd(data).ok_or(BundleError::InvalidZip)?;
        let cd_size   = r_u32(data, eocd + EOCD_CD_SIZE)   as usize;
        let cd_offset = r_u32(data, eocd + EOCD_CD_OFFSET) as usize;

        // Sanity : le CD doit tenir dans le buffer.
        if cd_offset.saturating_add(cd_size) > data.len() {
            return Err(BundleError::InvalidZip);
        }

        Ok(Self { data, cd_offset, cd_size })
    }

    /// Retourne une sous-tranche pointant directement sur les données brutes
    /// de l'entrée `name` (chemin ZIP, ex. `"native.efi"`).
    ///
    /// Retourne `Err(CompressedNotSupported)` si l'entrée est compressée.
    /// Retourne `Err(FileNotFound)` si l'entrée n'existe pas.
    pub fn extract_file(&self, name: &str) -> Result<&'a [u8], BundleError> {
        let end = self.cd_offset + self.cd_size;
        let mut pos = self.cd_offset;

        while pos + CD_HEADER_SIZE <= end {
            if r_u32(self.data, pos) != SIG_CENTRAL { break; }

            let compress    = r_u16(self.data, pos + CD_COMPRESS);
            let comp_size   = r_u32(self.data, pos + CD_COMP_SIZE)   as usize;
            let fname_len   = r_u16(self.data, pos + CD_FNAME_LEN)   as usize;
            let extra_len   = r_u16(self.data, pos + CD_EXTRA_LEN)   as usize;
            let comment_len = r_u16(self.data, pos + CD_COMMENT_LEN) as usize;
            let local_off   = r_u32(self.data, pos + CD_LOCAL_OFF)   as usize;

            let name_start = pos + CD_HEADER_SIZE;
            let name_end   = name_start + fname_len;
            if name_end > self.data.len() { break; }

            if &self.data[name_start..name_end] == name.as_bytes() {
                if compress != 0 {
                    return Err(BundleError::CompressedNotSupported);
                }
                return self.slice_from_local(local_off, comp_size);
            }

            pos += CD_HEADER_SIZE + fname_len + extra_len + comment_len;
        }

        Err(BundleError::FileNotFound)
    }

    /// Lit l'en-tête local et retourne la tranche des données brutes.
    fn slice_from_local(&self, local_off: usize, size: usize) -> Result<&'a [u8], BundleError> {
        if local_off + LFH_HEADER_MIN > self.data.len() {
            return Err(BundleError::InvalidZip);
        }
        if r_u32(self.data, local_off) != SIG_LOCAL {
            return Err(BundleError::InvalidZip);
        }

        let fname_len  = r_u16(self.data, local_off + LFH_FNAME_LEN)  as usize;
        let extra_len  = r_u16(self.data, local_off + LFH_EXTRA_LEN)  as usize;
        let data_start = local_off + LFH_HEADER_MIN + fname_len + extra_len;

        if data_start.saturating_add(size) > self.data.len() {
            return Err(BundleError::InvalidZip);
        }

        Ok(&self.data[data_start..data_start + size])
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Cherche l'EOCD en remontant depuis la fin du buffer.
/// Le commentaire ZIP peut faire jusqu'à 65535 octets, donc on cherche
/// dans les 65557 derniers octets au maximum.
fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_MIN_SIZE { return None; }
    let search_from = data.len().saturating_sub(65535 + EOCD_MIN_SIZE);
    for i in (search_from..=data.len() - EOCD_MIN_SIZE).rev() {
        if r_u32(data, i) == SIG_EOCD { return Some(i); }
    }
    None
}

#[inline(always)]
fn r_u16(data: &[u8], off: usize) -> usize {
    u16::from_le_bytes([data[off], data[off + 1]]) as usize
}

#[inline(always)]
fn r_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}
