//___  Vyft Ltd __  (c) 2026  ___
// ___ Lunée Kernel — OVC Executor (LLVM IR minimal, no_std) ___
//
//! Interpréteur LLVM IR texte pour les OVC Vyft (GpuImpl.ovc, APrevent.ovc…).
//! Supporte le sous-ensemble utilisé par SluGpu.slul / SluKeyMouse.slul.
//!
//! Toutes les valeurs sont des i64 (pointeurs = entiers via inttoptr).
//! Les appels `DrvManSpec___*` et `printf` sont dispatché via `ExecCtx`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── Stockage des OVC drivers (chargés par slul_loader) ───────────────────────

static mut GPU_OVC:          Option<Vec<u8>> = None;
static mut FONT_TTF_OVC:     Option<Vec<u8>> = None;
static mut FONT_RAST_OVC:    Option<Vec<u8>> = None;
static mut FONT_WOFF_OVC:    Option<Vec<u8>> = None;

// ── Cache SRFS (SDC: → octets chargés à la demande depuis l'ESP) ─────────────
// Plus aucun fichier hardcodé dans slul_loader.
// FontLoad(path) charge le fichier depuis l'ESP UEFI au premier appel.
static mut SRFS_CACHE: [Option<(String, Vec<u8>)>; 4] = [None, None, None, None];

// Handles UEFI pour le chargement à la demande — initialisés par render_from_marep
static mut UEFI_ST_PTR:     *mut core::ffi::c_void = core::ptr::null_mut();
static mut UEFI_IMG_HANDLE: usize = 0;

/// Initialise les handles UEFI pour le chargement dynamique des assets.
/// Appelé par kernel_runtime avant exec_marep.
pub fn init_uefi_handles(st_ptr: *mut core::ffi::c_void, image_handle: usize) {
    unsafe { UEFI_ST_PTR = st_ptr; UEFI_IMG_HANDLE = image_handle; }
}

/// Charge un fichier depuis l'ESP UEFI via le chemin SRFS `SDC:\...` à la demande.
/// Utilise le SystemTable stocké par init_uefi_handles.
fn srfs_load_on_demand(path_ptr: i64) -> i64 {
    if path_ptr == 0 { return 0; }

    serial_log(b"[FONT] uefi_read: ");
    serial_log(b"\r\n");

    // Extract the null-terminated string from the pointer
    let c_str_ptr = path_ptr as *const u8;
    let mut len = 0usize;
    unsafe {
        while *c_str_ptr.add(len) != 0 {
            len += 1;
            // Prevent infinite loop on invalid strings
            if len > 256 {
                break;
            }
        }
    }
    if len == 0 {
        serial_log(b"[FONT] Empty path\r\n");
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(c_str_ptr, len) };
    let rel = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            serial_log(b"[FONT] Invalid UTF-8 in path\r\n");
            return 0;
        }
    };

    serial_log(b"[FONT] Path: ");
    serial_log(rel.as_bytes());
    serial_log(b"\r\n");

    // Remove "SDC:" prefix if present
    let path_after_sdc = if rel.to_ascii_uppercase().starts_with("SDC:") {
        &rel[4..]
    } else {
        rel
    };

    // Skip any leading slash or backslash
    let mut idx = 0usize;
    while idx < path_after_sdc.len() && 
          (path_after_sdc.as_bytes()[idx] == b'/' || path_after_sdc.as_bytes()[idx] == b'\\') {
        idx += 1;
    }
    let uefi_rel = &path_after_sdc[idx..];

    let st_raw = unsafe { UEFI_ST_PTR };
    if st_raw.is_null() {
        serial_log(b"[FONT] ST_PTR null! init_uefi_handles non appele\r\n");
        return 0;
    }

    let data = match unsafe { srfs_uefi_read(st_raw, uefi_rel) } {
        Some(d) => d,
        None => {
            serial_log(b"[FONT] FontLoad: fichier non trouve\r\n");
            return 0;
        }
    };

    // Register the loaded data in SRFS cache for future use
    let key_owned = rel.to_string(); // Owned String for the key
    unsafe {
        srfs_register_file(key_owned, data);
        // Find the pointer to the data we just registered
        for slot in SRFS_CACHE.iter() {
            if let Some((ref k, ref d)) = slot {
                if k.as_str() == rel {
                    return d.as_ptr() as i64;
                }
            }
        }
    }
    // Fallback: should not happen if registration succeeded
    0
}

/// Lit un fichier depuis l'ESP UEFI en utilisant SimpleFileSystem.
unsafe fn srfs_uefi_read(st_raw: *mut core::ffi::c_void, rel_path: &str)
    -> Option<alloc::vec::Vec<u8>>
{
    use uefi::table::{Boot, SystemTable};
    use uefi::proto::media::{
        file::{File, FileAttribute, FileMode, FileType},
        fs::SimpleFileSystem,
    };
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    let mut st: SystemTable<Boot> = SystemTable::from_ptr(st_raw)?;
    // Build UCS-2 UEFI path.
    // Mara emits "\\" (double backslash) per path separator in OVC string constants.
    // Deduplicate consecutive separators to avoid "\\\path" → keep "\path".
    let mut ucs2: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(rel_path.len() + 2);
    ucs2.push(b'\\' as u16);  // mandatory leading separator
    let mut last_sep = true;   // skip duplicate separators at start of rel_path
    for b in rel_path.bytes() {
        if b == b'\\' || b == b'/' {
            if !last_sep { ucs2.push(b'\\' as u16); }
            last_sep = true;
        } else {
            ucs2.push(b as u16);
            last_sep = false;
        }
    }
    ucs2.push(0u16);
    let uefi_path = uefi::CStr16::from_u16_with_nul(&ucs2).ok()?;
    let img = uefi::Handle::from_ptr(UEFI_IMG_HANDLE as *mut core::ffi::c_void)?;
    let handles = st.boot_services().find_handles::<SimpleFileSystem>().ok()?;
    for &fs_h in handles.iter() {
        let mut fs = match st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_h, agent: img, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ) { Ok(f) => f, Err(_) => continue };
        let mut root = match fs.open_volume() { Ok(r) => r, Err(_) => continue };
        let fh = match root.open(uefi_path, FileMode::Read, FileAttribute::empty()) {
            Ok(f) => f, Err(_) => continue };
        let mut file = match fh.into_type() {
            Ok(FileType::Regular(f)) => f, _ => continue };
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break, Ok(n) => buf.extend_from_slice(&chunk[..n]), Err(_) => break,
            }
        }
        if !buf.is_empty() { return Some(buf); }
    }
    None
}

/// Enregistre un fichier SRFS (path = "SDC:\\...") depuis slul_loader.
pub fn srfs_register_file(path: String, data: Vec<u8>) {
    unsafe {
        for slot in SRFS_CACHE.iter_mut() {
            if slot.is_none() {
                *slot = Some((path, data));
                return;
            }
        }
    }
}

/// Retourne le pointeur + taille de la police TTF si chargée via SRFS.
pub fn srfs_font_ptr() -> (*const u8, usize) {
    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((_, ref v)) = slot {
                return (v.as_ptr(), v.len());
            }
        }
    }
    (core::ptr::null(), 0)
}

fn srfs_find(path_ptr: i64) -> Option<&'static [u8]> {
    if path_ptr == 0 { return None; }
    let p = path_ptr as *const u8;
    let mut len = 0usize;
    unsafe { while *p.add(len) != 0 { len += 1; } }
    let req = unsafe { core::str::from_utf8(core::slice::from_raw_parts(p, len)).ok()? };
    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((ref key, ref data)) = slot {
                // Comparer de façon case-insensitive (SDC: est Windows-style)
                if keys_match(req, key.as_str()) {
                    return Some(data.as_slice());
                }
            }
        }
    }
    None
}

fn keys_match(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

pub fn register_gpu_ovc(ovc: Vec<u8>) {
    unsafe { GPU_OVC = Some(ovc); }
}

pub fn register_font_ovc(ttf_parser: Vec<u8>, glyph_rasterizer: Vec<u8>, woff_reader: Vec<u8>) {
    unsafe {
        FONT_TTF_OVC  = Some(ttf_parser);
        FONT_RAST_OVC = Some(glyph_rasterizer);
        FONT_WOFF_OVC = Some(woff_reader);
    }
}

pub fn font_ovc_ready() -> bool {
    unsafe { FONT_TTF_OVC.is_some() && FONT_RAST_OVC.is_some() }
}

pub fn gpu_ovc() -> Option<&'static [u8]> {
    unsafe { GPU_OVC.as_deref() }
}

pub fn gpu_ready() -> bool {
    unsafe { GPU_OVC.is_some() }
}

// ── Police bitmap 8×16 (CP437 ASCII 0x00–0x7F) ───────────────────────────────
// Retournée par DrvManSpec___GetBitmapFont8x16___().
// Format : font[char_ascii * 16 + row], row ∈ 0..15, bit7 = pixel gauche.

#[rustfmt::skip]
static FONT8X8: &[[u8;8]; 128] = &[
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x00-0x07
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x08-0x0F
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x10-0x17
[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8],[0;8], // 0x18-0x1F
// 0x20-0x7F
[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],[0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00],
[0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00],[0x6C,0x6C,0xFE,0x6C,0xFE,0x6C,0x6C,0x00],
[0x18,0x7E,0xC0,0x7C,0x06,0x7E,0x18,0x00],[0x00,0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00],
[0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00],[0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00],
[0x0E,0x1C,0x30,0x30,0x30,0x1C,0x0E,0x00],[0x70,0x38,0x0C,0x0C,0x0C,0x38,0x70,0x00],
[0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00],[0x00,0x30,0x30,0xFC,0x30,0x30,0x00,0x00],
[0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30],[0x00,0x00,0x00,0xFC,0x00,0x00,0x00,0x00],
[0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00],[0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00],
[0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0x7C,0x00],[0x30,0x70,0x30,0x30,0x30,0x30,0xFC,0x00],
[0x78,0xCC,0x0C,0x38,0x60,0xCC,0xFC,0x00],[0x78,0xCC,0x0C,0x38,0x0C,0xCC,0x78,0x00],
[0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00],[0xFC,0xC0,0xF8,0x0C,0x0C,0xCC,0x78,0x00],
[0x38,0x60,0xC0,0xF8,0xCC,0xCC,0x78,0x00],[0xFC,0xCC,0x0C,0x18,0x30,0x30,0x30,0x00],
[0x78,0xCC,0xCC,0x78,0xCC,0xCC,0x78,0x00],[0x78,0xCC,0xCC,0x7C,0x0C,0x18,0x70,0x00],
[0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00],[0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00],
[0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00],[0x00,0x00,0xFC,0x00,0x00,0xFC,0x00,0x00],
[0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00],[0x78,0xCC,0x0C,0x18,0x18,0x00,0x18,0x00],
[0x7C,0xC6,0xDE,0xDE,0xDE,0xC0,0x78,0x00],[0x30,0x78,0xCC,0xCC,0xFC,0xCC,0xCC,0x00],
[0xFC,0x66,0x66,0x7C,0x66,0x66,0xFC,0x00],[0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00],
[0xF8,0x6C,0x66,0x66,0x66,0x6C,0xF8,0x00],[0xFE,0x62,0x68,0x78,0x68,0x62,0xFE,0x00],
[0xFE,0x62,0x68,0x78,0x68,0x60,0xF0,0x00],[0x3C,0x66,0xC0,0xC0,0xCE,0x66,0x3E,0x00],
[0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00],[0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00],
[0x1E,0x0C,0x0C,0x0C,0xCC,0xCC,0x78,0x00],[0xE6,0x66,0x6C,0x78,0x6C,0x66,0xE6,0x00],
[0xF0,0x60,0x60,0x60,0x62,0x66,0xFE,0x00],[0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0x00],
[0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00],[0x38,0x6C,0xC6,0xC6,0xC6,0x6C,0x38,0x00],
[0xFC,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00],[0x78,0xCC,0xCC,0xCC,0xDC,0x78,0x1C,0x00],
[0xFC,0x66,0x66,0x7C,0x6C,0x66,0xE6,0x00],[0x78,0xCC,0xE0,0x70,0x1C,0xCC,0x78,0x00],
[0xFC,0xB4,0x30,0x30,0x30,0x30,0x78,0x00],[0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xFC,0x00],
[0xCC,0xCC,0xCC,0xCC,0xCC,0x78,0x30,0x00],[0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00],
[0xC6,0x6C,0x38,0x38,0x38,0x6C,0xC6,0x00],[0xCC,0xCC,0xCC,0x78,0x30,0x30,0x78,0x00],
[0xFE,0xC6,0x8C,0x18,0x32,0x66,0xFE,0x00],[0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00],
[0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00],[0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00],
[0x18,0x3C,0x66,0xC3,0x00,0x00,0x00,0x00],[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF],
[0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00],[0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00],
[0xE0,0x60,0x60,0x7C,0x66,0x66,0xDC,0x00],[0x00,0x00,0x78,0xCC,0xC0,0xCC,0x78,0x00],
[0x1C,0x0C,0x0C,0x7C,0xCC,0xCC,0x76,0x00],[0x00,0x00,0x78,0xCC,0xFC,0xC0,0x78,0x00],
[0x38,0x6C,0x60,0xF0,0x60,0x60,0xF0,0x00],[0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0xF8],
[0xE0,0x60,0x6C,0x76,0x66,0x66,0xE6,0x00],[0x30,0x00,0x70,0x30,0x30,0x30,0x78,0x00],
[0x0C,0x00,0x0C,0x0C,0x0C,0xCC,0xCC,0x78],[0xE0,0x60,0x66,0x6C,0x78,0x6C,0xE6,0x00],
[0x70,0x30,0x30,0x30,0x30,0x30,0x78,0x00],[0x00,0x00,0xCC,0xFE,0xFE,0xD6,0xC6,0x00],
[0x00,0x00,0xF8,0xCC,0xCC,0xCC,0xCC,0x00],[0x00,0x00,0x78,0xCC,0xCC,0xCC,0x78,0x00],
[0x00,0x00,0xDC,0x66,0x66,0x7C,0x60,0xF0],[0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E],
[0x00,0x00,0xDC,0x76,0x66,0x60,0xF0,0x00],[0x00,0x00,0x7C,0xC0,0x78,0x0C,0xF8,0x00],
[0x10,0x30,0x7C,0x30,0x30,0x34,0x18,0x00],[0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00],
[0x00,0x00,0xCC,0xCC,0xCC,0x78,0x30,0x00],[0x00,0x00,0xC6,0xD6,0xFE,0xFE,0x6C,0x00],
[0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00],[0x00,0x00,0xCC,0xCC,0xCC,0x7C,0x0C,0xF8],
[0x00,0x00,0xFC,0x98,0x30,0x64,0xFC,0x00],[0x1C,0x30,0x30,0xE0,0x30,0x30,0x1C,0x00],
[0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00],[0xE0,0x30,0x30,0x1C,0x30,0x30,0xE0,0x00],
[0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00],[0x00,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0x00],
];

const fn build_font8x16() -> [u8; 128 * 16] {
    let mut f = [0u8; 128 * 16];
    let mut c = 0usize;
    while c < 128 {
        let g = FONT8X8[c];
        let mut r = 0usize;
        while r < 8 { f[c * 16 + r + 4] = g[r]; r += 1; }
        c += 1;
    }
    f
}
static FONT8X16: [u8; 128 * 16] = build_font8x16();

// ── Globals partagés SluFontConf / GlyphRasterizer ───────────────────────────
static mut FONT_UNITS_PER_EM: u32 = 1000;
static mut RAST_W: u32 = 0;
static mut RAST_H: u32 = 0;

// Cache de parse_string_consts par OVC text pointer — évite de re-parser
// TtfParser.ovc (34KB) et GlyphRasterizer.ovc (26KB) à chaque appel OVC.
// Box::into_raw → fuite permanente justifiée (UEFI boot, ~4 maps max).
static mut CONSTS_CACHE: [(usize, *const BTreeMap<String, i64>); 8] =
    [(0, core::ptr::null()); 8];

// ── Arène statique pour MemAlloc OVC (bitmaps glyphes, flagBuf, etc.) ────────
// Évite d'utiliser le heap UEFI (limité, fragmentation). Reset entre glyphes.
static mut OVC_ARENA: [u8; 512 * 1024] = [0u8; 512 * 1024];  // 512KB
static mut OVC_ARENA_POS: usize = 0;

fn ovc_arena_alloc(size: usize, align: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    unsafe {
        let pos = (OVC_ARENA_POS + align - 1) & !(align - 1);
        if pos + size > OVC_ARENA.len() { return core::ptr::null_mut(); }
        OVC_ARENA_POS = pos + size;
        OVC_ARENA[pos] = 0;  // mark first byte (bulk zeroing done lazily)
        core::ptr::write_bytes(OVC_ARENA[pos..pos+size].as_mut_ptr(), 0, size);
        OVC_ARENA[pos..].as_mut_ptr()
    }
}

pub fn ovc_arena_reset() { unsafe { OVC_ARENA_POS = 0; } }

// Cache parse_blocks par (ovc_ptr, func_start_ptr) — évite de re-allouer
// des centaines de BTreeMap<String,Vec<String>> par appel OVC.
static mut BLOCKS_CACHE: [(usize, usize, *const BTreeMap<String, Vec<String>>); 32] =
    [(0, 0, core::ptr::null()); 32];

// ── Registres OVC sans String (hash FNV-1a 64 bits) ─────────────────────────
// Remplace BTreeMap<String,i64> pour regs : zéro allocation String.
// Le Vec grossit en place — une seule alloc heap pour toute la durée de vie.
type Regs = Vec<(u64, i64)>;

#[inline(always)]
fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}
fn regs_get(r: &Regs, name: &str) -> i64 {
    let k = fnv64(name);
    r.iter().rev().find(|&&(h, _)| h == k).map(|&(_, v)| v).unwrap_or(0)
}
fn regs_set(r: &mut Regs, name: &str, val: i64) {
    let k = fnv64(name);
    if let Some(e) = r.iter_mut().rev().find(|(h, _)| *h == k) { e.1 = val; }
    else { r.push((k, val)); }
}

// ── TtfParser state (DrvManSpec***TtfGetData/Set + TtfScratchGet/Set) ─────────
// Partagé entre Load / GetGlyphId / GetGlyfOffset car ces appels
// passent par le dispatcher global, pas par les globals OVC.
static mut TTF_DATA_PTR: i64 = 0;
static mut TTF_SCRATCH:  [i64; 200] = [0i64; 200];
static mut WOFF_SCRATCH: [i64; 256] = [0i64; 256];

// ── Disque virtuel SRFS (pour SRFSMan.slul) ───────────────────────────────────
// Superblock SRFS v2 minimal : magic 'SRF2', blockSize=32768, rootBlock=3.
// SRFSMan.slul vérifie ce magic puis monte SDC:\.
// Le contenu réel (fichiers) est servi par le cache SRFS (srfs_find).
static SRFS_DISK_IMAGE: [u8; 512] = {
    let mut b = [0u8; 512];
    // Magic 'SRF2' = 0x53524632 big-endian
    b[0] = 0x53; b[1] = 0x52; b[2] = 0x46; b[3] = 0x32;
    // Version 0x00020000 big-endian
    b[4] = 0x00; b[5] = 0x02; b[6] = 0x00; b[7] = 0x00;
    // Block size 32768 = 0x00008000 big-endian
    b[8]  = 0x00; b[9]  = 0x00; b[10] = 0x80; b[11] = 0x00;
    // Total blocks = 256
    b[12] = 0x00; b[13] = 0x00; b[14] = 0x01; b[15] = 0x00;
    // Free blocks = 250
    b[16] = 0x00; b[17] = 0x00; b[18] = 0x00; b[19] = 0xFA;
    // Reserved fields (28, 36, 44, 52, 60) → 1, 2, 3, 32, 4
    b[31] = 0x01; b[39] = 0x02; b[47] = 0x03;
    b[55] = 0x20; b[63] = 0x04;
    // Root block = 3 at offset 68
    b[71] = 0x03;
    // Flags = 7 at offset 112
    b[115] = 0x07;
    b
};

/// Retourne un pointeur vers le superblock SRFS virtuel.
/// Appelé par `DrvManSpec***UefiLocateDisk***`.
pub fn srfs_disk_handle() -> i64 {
    SRFS_DISK_IMAGE.as_ptr() as i64
}

/// Lit `size` octets depuis le disque virtuel SRFS à l'offset `offset`.
/// Appelé par `DrvManSpec***DiskRead***`.
pub fn srfs_disk_read(offset: usize, dst: *mut u8, size: usize) -> i64 {
    if dst.is_null() { return 0; }
    let src = SRFS_DISK_IMAGE.as_ptr();
    let avail = SRFS_DISK_IMAGE.len().saturating_sub(offset);
    let n = size.min(avail);
    if n > 0 {
        unsafe { core::ptr::copy_nonoverlapping(src.add(offset), dst, n); }
    }
    // Si on dépasse le superblock, remplir de zéros (blocs vides)
    if size > n {
        unsafe { core::ptr::write_bytes(dst.add(n), 0, size - n); }
    }
    size as i64  // toujours retourner size demandé
}

// ── Compteurs GPU (diagnostic) ────────────────────────────────────────────────
static mut GPU_FILLS:  u32 = 0;
static mut GPU_RECTS:  u32 = 0;
static mut GPU_TEXTS:  u32 = 0;

pub fn reset_gpu_counters() {
    unsafe { GPU_FILLS = 0; GPU_RECTS = 0; GPU_TEXTS = 0; }
}
pub fn gpu_counters() -> (u32, u32, u32) {
    unsafe { (GPU_FILLS, GPU_RECTS, GPU_TEXTS) }
}

// ── Contexte

/// Contexte d'exécution pour un OVC — fourni par le kernel au moment du rendu.
/// La police 8×16 est embarquée dans ovc_exec (FONT8X16), pas dans la struct.
pub struct ExecCtx {
    pub fb:     *mut u32,
    pub width:  i32,
    pub height: i32,
    pub stride: i32,
    /// Octets TTF de brsonomasemibold.ttf — chargés depuis l'ESP par le kernel.
    /// Sert aux dispatchers DrvManSpec___FSGetSize___ / DrvManSpec___FSRead___.
    pub font:   *const u8,
    pub font_len: usize,
}

unsafe impl Send for ExecCtx {}
unsafe impl Sync for ExecCtx {}

// ── Utilitaires de parsing ────────────────────────────────────────────────────

/// Extrait le nom du registre depuis `%name` ou `%name.suffix`.
fn reg_name(tok: &str) -> String {
    tok.trim_start_matches('%').to_string()
}

/// Résout un opérande complet (peut être une expression entière de LLVM IR).
/// Exemples :
///   "%20"                              → regs["20"]
///   "@0"                               → consts["0"]
///   "ptr nonnull inttoptr (i32 2 to ptr)"  → 2
///   "inttoptr (i64 1710638 to ptr)"    → 1710638
///   "ptr null"                         → 0
///   "42"                               → 42
fn resolve(tok: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> i64 {
    let tok = tok.trim().trim_end_matches(',');

    // Registre %name
    if tok.starts_with('%') {
        return regs_get(regs, reg_name(tok).as_str());
    }
    // Constante @name
    if tok.starts_with('@') {
        let k = tok.trim_start_matches('@').trim_end_matches(',');
        return *consts.get(k).unwrap_or(&0);
    }

    // inttoptr (iN N to ptr) — peut être précédé de "ptr nonnull" etc.
    if let Some(p) = tok.find("inttoptr (") {
        let rest = &tok[p + 10..];  // "i64 1710638 to ptr)" ou "i32 2 to ptr)"
        // Sauter le type (premier mot : i32/i64)
        let after_type = rest.find(' ').map(|i| &rest[i+1..]).unwrap_or(rest);
        let num_end = after_type.find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(after_type.len());
        return after_type[..num_end].parse().unwrap_or(0);
    }

    // "ptr null" ou "null"
    if tok == "null" || tok == "nullptr" || tok.ends_with(" null") { return 0; }

    // Dernier mot : peut être un registre %N, une constante @N, ou un entier.
    // Exemples : "ptr %9" → "%9" → regs["9"]
    //            "ptr nonnull @0" → "@0" → consts["0"]
    //            "i32 42" → "42" → 42
    let last = tok.split_whitespace().last().unwrap_or(tok);
    if last.starts_with('%') {
        return regs_get(regs, reg_name(last).as_str());
    }
    if last.starts_with('@') {
        let k = last.trim_start_matches('@').trim_end_matches(',');
        return *consts.get(k).unwrap_or(&0);
    }
    last.trim_end_matches(')').parse().unwrap_or(0)
}

/// Lit les arguments d'un `call` ou d'une `define` : `(ptr %a, i32 %b, …)`.
/// Retourne la liste des valeurs ou noms d'arguments.
fn parse_call_args(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open  = match src.find('(') { Some(p) => p, None => return out };
    let close = match src.rfind(')') { Some(p) => p, None => return out };
    let inner = &src[open+1..close];

    // Découper sur les virgules HORS parenthèses imbriquées
    // (gère "ptr nonnull inttoptr (i32 2 to ptr)" comme un seul token)
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(inner[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    // Dernier argument
    let last_part = inner[start..].trim();
    if !last_part.is_empty() {
        out.push(last_part.to_string());
    }
    out
}

// ── Parsing des constantes de chaîne : @N = ... c"text\00" ───────────────────

fn parse_string_consts(ovc: &str) -> &'static BTreeMap<String, i64> {
    let key = ovc.as_ptr() as usize;
    unsafe {
        // Cherche dans le cache (OVC pointer = identifiant unique du module)
        for &(k, ptr) in CONSTS_CACHE.iter() {
            if k == key && !ptr.is_null() { return &*ptr; }
        }
        // Non trouvé — parser et mettre en cache
        let mut map = BTreeMap::new();
        for line in ovc.lines() {
            let line = line.trim();
            if !line.starts_with('@') { continue; }
            let Some(eq) = line.find('=') else { continue };
            let name = line[1..eq].trim().to_string();
            let Some(cp) = line.find(" c\"") else { continue };
            let after = &line[cp+3..];
            let Some(ep) = after.find("\\00\"") else { continue };
            let s: &str = &after[..ep];
            // Décoder les escapes \xx → byte, stocker avec \0 final
            let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let sb = s.as_bytes();
            let mut i = 0;
            while i < sb.len() {
                if sb[i] == b'\\' && i + 2 < sb.len() {
                    if let (Some(hi), Some(lo)) = (
                        (sb[i+1] as char).to_digit(16),
                        (sb[i+2] as char).to_digit(16)) {
                        bytes.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                }
                bytes.push(sb[i]); i += 1;
            }
            bytes.push(0u8);
            let boxed: alloc::boxed::Box<[u8]> = bytes.into_boxed_slice();
            let ptr_val = alloc::boxed::Box::into_raw(boxed) as *const u8 as i64;
            map.insert(name, ptr_val);
        }
        // Fuite justifiée : UEFI boot, max ~8 modules, chacun parsé une seule fois
        let boxed_map = alloc::boxed::Box::new(map);
        let map_ptr = alloc::boxed::Box::into_raw(boxed_map) as *const BTreeMap<String, i64>;
        for slot in CONSTS_CACHE.iter_mut() {
            if slot.0 == 0 { *slot = (key, map_ptr); break; }
        }
        &*map_ptr
    }
}

// ── Localisation d'une fonction ───────────────────────────────────────────────

/// Retourne le corps d'une fonction `define ... @name(...) { ... }`.
fn find_function<'a>(ovc: &'a str, name: &str) -> Option<&'a str> {
    let marker = alloc::format!("@{}(", name);
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in ovc.char_indices() {
        if start.is_none() {
            if ovc[i..].starts_with("define ") {
                // Vérifier que @name( est sur LA MÊME LIGNE (pas dans le reste du fichier)
                let line_end = ovc[i..].find('\n').map(|n| i + n).unwrap_or(ovc.len());
                if ovc[i..line_end].contains(marker.as_str()) {
                    start = Some(i);
                }
            }
        } else {
            if c == '{' { depth += 1; }
            if c == '}' {
                depth -= 1;
                if depth == 0 {
                    return Some(&ovc[start.unwrap()..i+1]);
                }
            }
        }
    }
    None
}

/// Extrait les noms de paramètres d'une définition de fonction.
fn parse_def_args(func: &str) -> Vec<String> {
    let first_line = func.lines().next().unwrap_or("");
    parse_call_args(first_line)
        .into_iter()
        .filter_map(|s| {
            // Chaque arg LLVM IR est du type "ptr %name", "i32 %name", "ptr nonnull %name"...
            // Extraire le token qui commence par '%' (le nom du registre).
            s.split_whitespace()
             .find(|w| w.starts_with('%'))
             .map(|w| w.trim_start_matches('%').trim_end_matches(',').to_string())
        })
        .collect()
}

// ── Parsing des blocs de base ─────────────────────────────────────────────────

fn parse_blocks(func: &str) -> &'static BTreeMap<String, Vec<String>> {
    // Cache par pointeur de texte de fonction — parsé UNE SEULE FOIS par fonction OVC
    let key_ovc  = func.as_ptr() as usize;
    let key_func = func.len();
    unsafe {
        for &(ko, kf, ptr) in BLOCKS_CACHE.iter() {
            if ko == key_ovc && kf == key_func && !ptr.is_null() { return &*ptr; }
        }
    }
    let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur = "entry".to_string();
    blocks.insert(cur.clone(), Vec::new());

    let mut switch_buf: Option<String> = None;
    for line in func.lines().skip(1) {
        let t = line.trim();
        if t.is_empty() || t == "{" || t == "}" { continue; }
        if t.starts_with(';') { continue; }

        // Fusionner les instructions switch multi-lignes "switch ... [ ... ]"
        if let Some(ref mut buf) = switch_buf {
            buf.push(' ');
            buf.push_str(t);
            if t == "]" || t.ends_with(']') {
                let done = buf.clone();
                switch_buf = None;
                if let Some(v) = blocks.get_mut(&cur) { v.push(done); }
            }
            continue;
        }
        if t.starts_with("switch ") {
            if t.ends_with(']') {
                if let Some(v) = blocks.get_mut(&cur) { v.push(t.to_string()); }
            } else {
                switch_buf = Some(t.to_string());
            }
            continue;
        }

        // Supprimer le commentaire de fin de ligne avant le test de label
        let t_nc = if let Some(sc) = t.find(';') { t[..sc].trim() } else { t };
        if !t_nc.starts_with('%') && !t_nc.starts_with("store")
            && !t_nc.starts_with("br") && !t_nc.starts_with("ret")
            && t_nc.ends_with(':')
        {
            let label = t_nc.trim_end_matches(':').trim().to_string();
            cur = label.clone();
            blocks.entry(cur.clone()).or_insert_with(Vec::new);
            continue;
        }
        if let Some(v) = blocks.get_mut(&cur) {
            v.push(t.to_string());
        }
    }
    // Fuite justifiée (UEFI boot) — chaque fonction parsée une seule fois
    unsafe {
        let boxed = alloc::boxed::Box::new(blocks);
        let ptr   = alloc::boxed::Box::into_raw(boxed) as *const BTreeMap<String, Vec<String>>;
        for slot in BLOCKS_CACHE.iter_mut() {
            if slot.0 == 0 { *slot = (key_ovc, key_func, ptr); break; }
        }
        &*ptr
    }
}

// ── Exécution ─────────────────

pub fn exec_fn(
    ovc:     &[u8],
    fn_name: &str,
    args:    &[i64],
    ctx:     &ExecCtx,
) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return -1; }

    let consts  = parse_string_consts(text);
    let func    = match find_function(text, fn_name) { Some(f) => f, None => return -1 };
    let arg_names = parse_def_args(func);
    let blocks  = parse_blocks(func);

    let mut regs: Regs = Vec::new();
    let mut globals: Regs = Vec::new();

    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }

    run_blocks(&blocks, &consts, &mut globals, &mut regs, ctx, "entry")
}

/// Exécute plusieurs fonctions d'un même OVC en partageant les globals.
/// Utilisé pour HelloWorld() puis Create() qui lisent les mêmes variables module.
pub fn exec_module(ovc: &[u8], fns: &[(&str, &[i64])], ctx: &ExecCtx) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return -1; }

    let consts  = parse_string_consts(text);
    let mut globals: Regs = Vec::new();
    let mut last = 0i64;

    for (fn_name, args) in fns {
        let func = match find_function(text, fn_name) { Some(f) => f, None => continue };
        let arg_names = parse_def_args(func);
        let blocks    = parse_blocks(func);
        let mut regs: Regs = Vec::new();
        for (i, a) in arg_names.iter().enumerate() {
            regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
        }
        last = run_blocks(&blocks, &consts, &mut globals, &mut regs, ctx, "entry");
    }
    last
}

/// Exécute un marep complet dynamiquement.
///
/// Le kernel ne connaît que `OEntry.ovc` + la fonction `OEntry()` —
/// point d'entrée universel de tout marep (comme `main()` en C).
/// Les autres OVC sont découverts et chargés via les appels cross-module.
///
/// Résolution des appels cross-module :
///   `@ModuleName___FuncName` → cherche `@FuncName` dans `ModuleName.ovc`
///   `@self___FuncName`       → cherche `@FuncName` dans tous les modules
///   `@std___core___self___ModuleName___FuncName` → normalise et résout
///
/// `modules`: liste de `(nom_module, bytes_ovc)` extraits du marep.
/// Écriture sur COM1 (0x3F8) — visible dans QEMU -serial stdio sans borrow conflict.
fn serial_log(msg: &[u8]) {
    for &b in msg {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") 0x3F8u16,
                in("al") b,
                options(nomem, nostack)
            );
        }
    }
}

pub fn exec_marep(
    modules: &[(&str, &[u8])],  // [("OEntry", bytes), ("HelloWorld", bytes), ...]
    ctx:     &ExecCtx,
) -> i64 {
    serial_log(b"[OVC] exec_marep start\r\n");

    // Construire la table modules → texte OVC + consts
    let mut mod_texts: Vec<(&str, &str)> = Vec::new();
    let mut all_consts: BTreeMap<String, i64> = BTreeMap::new();

    for (name, bytes) in modules {
        let text = core::str::from_utf8(bytes).unwrap_or("");
        if text.starts_with("# Vyft OVC v1.0") {
            // Fusionner les constantes de chaque module dans un espace global
            // (préfixées par le module pour éviter les collisions)
            let c = parse_string_consts(text);
            for (k, v) in c.iter() {
                all_consts.insert(alloc::format!("{}::{}", name, k), *v);
                all_consts.entry(k.clone()).or_insert(*v);
            }
            mod_texts.push((name, text));
        }
    }

    // Globals partagés entre tous les modules
    let mut globals: Regs = Vec::new();

    serial_log(b"[OVC] constructors start\r\n");

    // Étape 1 : constructeurs des COMPOSANTS (pas OEntry)
    for (mod_name, mod_text) in &mod_texts {
        if mod_name.eq_ignore_ascii_case("OEntry") { continue; }
        let has_fn = find_function(mod_text, mod_name).is_some();
        if has_fn {
            exec_marep_fn(
                mod_name, mod_text, mod_name, &[],
                &all_consts, &mut globals, ctx, &mod_texts, 0,
            );
        }
    }

    serial_log(b"[OVC] OEntry start\r\n");

    // Étape 2 : OEntry() — point d'entrée universel
    let oentry_text = mod_texts.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("OEntry"))
        .map(|(_, t)| *t)
        .unwrap_or("");

    if oentry_text.is_empty() {
        serial_log(b"[OVC] OEntry NOT FOUND\r\n");
        return -1;
    }

    let ret = exec_marep_fn(
        "OEntry", oentry_text, "OEntry", &[],
        &all_consts, &mut globals, ctx, &mod_texts,
        0,
    );
    serial_log(b"[OVC] exec_marep done\r\n");
    ret
}

/// Exécute une fonction dans un module donné avec résolution cross-module.
/// IMPORTANT : chaque module utilise SES PROPRES consts numériques (@0, @1…).
/// Les globals nommés (@message, @bgColor…) sont partagés entre modules.
/// Ceci évite la collision des constantes numériques entre modules.
fn exec_marep_fn(
    mod_name:   &str,
    ovc_text:   &str,
    fn_name:    &str,
    args:       &[i64],
    _all_consts: &BTreeMap<String, i64>,
    globals:    &mut Regs,
    ctx:        &ExecCtx,
    modules:    &[(&str, &str)],
    depth:      u32,
) -> i64 {
    if depth > 32 { return 0; }

    // Log uniquement les fonctions publiques (pas les helpers internes _xxx)
    let is_public = !fn_name.starts_with('_');
    if is_public {
        serial_log(b"[FN] ");
        serial_log(mod_name.as_bytes());
        serial_log(b"::");
        serial_log(fn_name.as_bytes());
        serial_log(b"\r\n");
    }

    let local_consts = parse_string_consts(ovc_text);
    let func = match find_function(ovc_text, fn_name) {
        Some(f) => f,
        None    => {
            serial_log(b"[FN] NOT FOUND\r\n");
            return 0;
        }
    };
    let arg_names = parse_def_args(func);
    let blocks = parse_blocks(func);

    let mut regs: Regs = Vec::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }

    run_blocks_cross(
        &blocks, &local_consts, globals, &mut regs, ctx,
        "entry", mod_name, modules, depth,
    )
}

/// Mapping cycle de vie Maratine : event → méthode de composant.
/// `onCreate`  → `Create`   (LaPrevent appelle TemplateView::Create)
/// `onDestroy` → `Destroy`
/// `onPause`   → `Pause`
/// `onResume`  → `Resume`
fn maratine_lifecycle_fn(event: &str) -> &str {
    match event {
        "onCreate"  => "Create",
        "onDestroy" => "Destroy",
        "onPause"   => "Pause",
        "onResume"  => "Resume",
        other       => other,
    }
}

/// Normalise un nom de fonction cross-module.
/// `@std___core___self___LAPrevent___Launch` → (`LAPrevent`, `Launch`)
/// `@HelloWorld___Create`                   → (`HelloWorld`, `Create`)
/// `@self___onCreate`                       → (`self`, `Create`)  ← lifecycle mapping
fn resolve_cross_module_call(fname: &str) -> Option<(&str, &str)> {
    // Supprimer le préfixe std___core___self___
    let stripped = fname.strip_prefix("std___core___self___").unwrap_or(fname);

    // Chercher le dernier `___` (séparateur module___fonction)
    if let Some(pos) = stripped.rfind("___") {
        let module   = &stripped[..pos];
        let raw_fn   = &stripped[pos+3..];
        // Appliquer le mapping cycle de vie Maratine
        let function = maratine_lifecycle_fn(raw_fn);
        if !module.is_empty() && !function.is_empty() {
            return Some((module, function));
        }
    }
    None
}

/// Version cross-module de run_blocks.
fn run_blocks_cross(
    blocks:   &BTreeMap<String, Vec<String>>,
    consts:   &BTreeMap<String, i64>,
    globals:  &mut Regs,
    regs:     &mut Regs,
    ctx:      &ExecCtx,
    start:    &str,
    mod_name: &str,
    modules:  &[(&str, &str)],
    depth:    u32,
) -> i64 {
    let mut cur  = start.to_string();
    let mut prev = String::new();
    let mut iters = 0u32;

    loop {
        iters += 1;
        if iters > 200_000 { break; }

        let instrs = match blocks.get(&cur) {
            Some(v) => v.clone(),
            None    => break,
        };

        let prev_blk = prev.clone();
        prev = cur.clone();

        let mut jumped = false;
        for instr in &instrs {
            // Pour les appels de fonction, intercepter les appels cross-module
            let result = if instr.contains(" = ") && instr.contains("call ") {
                let eq = instr.find(" = ").unwrap();
                let dst = instr[1..eq].trim().to_string();
                let rhs_raw = instr[eq+3..].trim();
                let rhs = rhs_raw.trim_start_matches("tail ").trim_start_matches("musttail ");

                if rhs.starts_with("call ") || rhs.starts_with("call i") || rhs.starts_with("call (") {
                    // Extraire le nom de la fonction
                    if let Some(at_pos) = rhs.find('@') {
                        let after_at = &rhs[at_pos+1..];
                        let fn_end = after_at.find('(').unwrap_or(after_at.len());
                        let fname = &after_at[..fn_end];

                        // Tenter la résolution cross-module
                        let raw_args = parse_call_args(rhs);
                        let arg_vals: Vec<i64> = raw_args.iter().map(|a| resolve(a, regs, consts)).collect();

                        let call_result = if let Some((target_mod, target_fn)) = resolve_cross_module_call(fname) {
                            // Appel cross-module
                            let found = if target_mod.eq_ignore_ascii_case("self") {
                                // self → chercher dans tous les modules sauf le courant
                                modules.iter()
                                    .filter(|(n, _)| !n.eq_ignore_ascii_case(mod_name))
                                    .find(|(_, t)| find_function(t, target_fn).is_some())
                                    .map(|(n, t)| (*n, *t))
                            } else {
                                modules.iter()
                                    .find(|(n, _)| n.eq_ignore_ascii_case(target_mod))
                                    .map(|(n, t)| (*n, *t))
                            };

                            if let Some((found_mod, found_text)) = found {
                                // Log uniquement les appels cross-module publics
                                if !target_fn.starts_with('_') {
                                    serial_log(b"[CM] ");
                                    serial_log(found_mod.as_bytes());
                                    serial_log(b"::");
                                    serial_log(target_fn.as_bytes());
                                    serial_log(b"\r\n");
                                }
                                exec_marep_fn(
                                    found_mod, found_text, target_fn,
                                    &arg_vals, consts, globals, ctx, modules, depth + 1,
                                )
                            } else {
                                serial_log(b"[XM] miss ");
                                serial_log(target_fn.as_bytes());
                                serial_log(b" in ");
                                serial_log(target_mod.as_bytes());
                                serial_log(b"\r\n");
                                dispatch(fname, &arg_vals, consts, globals, ctx)
                            }
                        } else {
                            // Fast-paths pour _r8/_r16/_r32/_rtag de TtfParser
                            // (évite de re-parser TtfParser.ovc 34KB à chaque lecture)
                            let fast = match fname {
                                "_r8" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off >= sz { Some(0i64) }
                                    else { Some(unsafe { *ptr.add(off as usize) as i64 }) }
                                },
                                "_r16" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off + 1 >= sz { Some(0i64) }
                                    else { unsafe {
                                        let hi = *ptr.add(off as usize) as i64;
                                        let lo = *ptr.add(off as usize + 1) as i64;
                                        Some((hi << 8) | lo)
                                    }}
                                },
                                "_r32" | "_rtag" => {
                                    let off = arg_vals.get(0).copied().unwrap_or(0);
                                    let ptr = unsafe { TTF_DATA_PTR } as *const u8;
                                    let sz  = unsafe { TTF_SCRATCH[100] } as i64;
                                    if ptr.is_null() || off < 0 || off + 3 >= sz { Some(0i64) }
                                    else { unsafe {
                                        let b0 = *ptr.add(off as usize)     as i64;
                                        let b1 = *ptr.add(off as usize + 1) as i64;
                                        let b2 = *ptr.add(off as usize + 2) as i64;
                                        let b3 = *ptr.add(off as usize + 3) as i64;
                                        Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
                                    }}
                                },
                                _ => None,
                            };
                            if let Some(v) = fast { v } else {
                                // Pas de séparateur "___" → fonction interne du module courant
                                let self_text = modules.iter()
                                    .find(|(n, _)| n.eq_ignore_ascii_case(mod_name))
                                    .map(|(_, t)| *t);
                                if let Some(st) = self_text {
                                    if find_function(st, fname).is_some() {
                                        exec_marep_fn(
                                            mod_name, st, fname,
                                            &arg_vals, consts, globals, ctx, modules, depth + 1,
                                        )
                                    } else {
                                        dispatch(fname, &arg_vals, consts, globals, ctx)
                                    }
                                } else {
                                    dispatch(fname, &arg_vals, consts, globals, ctx)
                                }
                            }  // end if let Some(v) = fast
                        };

                        regs_set(regs, &dst, call_result);
                        RunResult::Ok
                    } else {
                        run_instr(instr, consts, globals, regs, ctx, &prev_blk)
                    }
                } else {
                    run_instr(instr, consts, globals, regs, ctx, &prev_blk)
                }
            } else {
                run_instr(instr, consts, globals, regs, ctx, &prev_blk)
            };

            match result {
                RunResult::Ok          => {},
                RunResult::Branch(lbl) => {
                    prev = cur.clone();
                    cur  = lbl;
                    jumped = true;
                    break;
                },
                RunResult::Return(v) => return v,
            }
        }
        if !jumped { break; }
    }
    0
}

fn run_blocks(
    blocks:  &BTreeMap<String, Vec<String>>,
    consts:  &BTreeMap<String, i64>,
    globals: &mut Regs,
    regs:    &mut Regs,
    ctx:     &ExecCtx,
    start:   &str,
) -> i64 {
    let mut cur  = start.to_string();
    let mut prev = String::new();
    let mut iters = 0u32;

    loop {
        iters += 1;
        if iters > 200_000 { break; }  // garde-fou boucle infinie

        let instrs = match blocks.get(&cur) {
            Some(v) => v.clone(),
            None    => break,
        };

        let prev_blk = prev.clone();
        prev = cur.clone();

        let mut jumped = false;
        for instr in &instrs {
            match run_instr(instr, consts, globals, regs, ctx, &prev_blk) {
                RunResult::Ok          => {},
                RunResult::Branch(lbl) => {
                    prev = cur.clone();
                    cur  = lbl;
                    jumped = true;
                    break;
                },
                RunResult::Return(v)   => return v,
            }
        }
        if !jumped { break; }
    }
    0
}

enum RunResult { Ok, Branch(String), Return(i64) }

fn run_instr(
    instr:   &str,
    consts:  &BTreeMap<String, i64>,
    globals: &mut Regs,
    regs:    &mut Regs,
    ctx:     &ExecCtx,
    prev:    &str,
) -> RunResult {
    let instr = instr.trim();
    if instr.is_empty() || instr.starts_with(';') { return RunResult::Ok; }

    // ── switch i32 %val, label %default [ i32 N, label %lbl ... ] ───────────
    if instr.starts_with("switch ") {
        let toks: Vec<&str> = instr.split_whitespace().collect();
        // toks[2] = value token (e.g. "%14"), toks[4] = default label (e.g. "%merge80")
        let val_tok     = toks.get(2).unwrap_or(&"0");
        let default_lbl = toks.get(4).unwrap_or(&"").trim_start_matches('%').to_string();
        let val = resolve(val_tok, regs, consts);
        let mut target = default_lbl;
        // Scan pairs: "i32 CONST, label %LBL"
        let mut i = 5usize;
        while i + 3 <= toks.len() {
            if toks[i] == "[" { i += 1; continue; }
            if toks[i] == "]" { break; }
            // "i32" CONST "label" "%LBL"
            if toks[i].starts_with("i") {
                let case_val: i64 = toks.get(i+1).unwrap_or(&"").trim_end_matches(',').parse().unwrap_or(i64::MAX);
                let case_lbl = toks.get(i+3).unwrap_or(&"").trim_start_matches('%').trim_end_matches(']');
                if val == case_val {
                    target = case_lbl.to_string();
                    break;
                }
                i += 4;
            } else { i += 1; }
        }
        return RunResult::Branch(target);
    }

    // ── br ───────────────────────────────────────────────────────────────────
    if instr.starts_with("br ") {
        let rest = &instr[3..];
        if rest.starts_with("label ") {
            let lbl = rest[6..].trim().trim_start_matches('%').to_string();
            return RunResult::Branch(lbl);
        }
        if rest.starts_with("i1 ") {
            let parts: Vec<&str> = rest.splitn(4, ',').collect();
            let cond_tok = parts[0].trim().strip_prefix("i1 ").unwrap_or("").trim();
            let cond = resolve(cond_tok, regs, consts) != 0;
            let true_lbl  = parts.get(1).unwrap_or(&"").trim().strip_prefix("label %").unwrap_or("").to_string();
            let false_lbl = parts.get(2).unwrap_or(&"").trim().strip_prefix("label %").unwrap_or("").to_string();
            let dest = if cond { true_lbl } else { false_lbl };
            return RunResult::Branch(dest);
        }
    }

    // ── ret ──────────────────────────────────────────────────────────────────
    if instr.starts_with("ret ") {
        let rest = instr[4..].trim();
        // "ret i32 0" / "ret i32 %N"
        let val_tok = rest.split_whitespace().last().unwrap_or("0");
        return RunResult::Return(resolve(val_tok, regs, consts));
    }

    // ── store ────────────────────────────────────────────────────────────────
    if instr.starts_with("store ") {
        // store ptr @const, ptr @global  |  store i1 true, ptr @global
        // store ptr %reg,   ptr @global
        let parts: Vec<&str> = instr.splitn(3, ',').collect();
        // Source : dernier token de parts[0]
        let src_tok  = parts[0].trim().split_whitespace().last().unwrap_or("0");
        // Destination : @global_name dans parts[1]
        let dest_part = parts.get(1).unwrap_or(&"").trim();
        let dest_tok = dest_part.split_whitespace().last().unwrap_or("").trim_end_matches(',');
        let dest_k   = dest_tok.trim_start_matches('@').to_string();
        let val = if src_tok == "true" { 1i64 }
                  else if src_tok == "false" { 0i64 }
                  else { resolve(src_tok, regs, consts) };
        regs_set(globals, &dest_k, val);
        return RunResult::Ok;
    }

    // ── load : %N = load type, ptr @global / ptr %reg ────────────────────────
    // load i1, ptr @bgColor  → globals["bgColor"]
    // load ptr, ptr @message → globals["message"]
    if instr.starts_with("load ") && instr.contains(" = ") {
        // handled in assignment block below — fall through
    }

    // ── assignment: %N = ... ──────────────────────────────────────────────────
    let Some(eq) = instr.find(" = ") else { return RunResult::Ok };
    let dst = instr[1..eq].trim().to_string();
    let rhs = instr[eq+3..].trim();

    // Supprime les qualificateurs call
    let rhs = rhs.trim_start_matches("tail ");
    let rhs = rhs.trim_start_matches("musttail ");

    let val: i64 = if rhs.starts_with("call ") || rhs.starts_with("call i")
                   || rhs.starts_with("call (")
    {
        // Extraire le nom de la fonction
        let fn_start = match rhs.find('@') { Some(p) => p, None => { regs_set(regs, &dst, 0); return RunResult::Ok; } };
        let after_at = &rhs[fn_start+1..];
        let fn_end = after_at.find('(').unwrap_or(after_at.len());
        let fname = &after_at[..fn_end];

        // Extraire les arguments
        let raw_args = parse_call_args(rhs);
        let arg_vals: Vec<i64> = raw_args.iter().map(|a| resolve(a, regs, consts)).collect();

        dispatch(fname, &arg_vals, consts, globals, ctx)
    }
    else if rhs.starts_with("phi ") {
        // phi i32 [ v1, %lbl1 ], [ v2, %lbl2 ]
        // Cherche la valeur associée au bloc précédent.
        // Si le prédécesseur n'est pas dans la phi (optimisation LLVM : le compilateur
        // peut fusionner des chemins), on retourne la valeur actuelle du registre de
        // destination — c'est le comportement attendu pour les phi de boucles.
        if let Some(v) = parse_phi_opt(rhs, prev, regs, consts) { v }
        else { regs_get(regs, &dst) }  // prédécesseur non trouvé → valeur inchangée
    }
    else if rhs.starts_with("load ") {
        // load i1, ptr @global  |  load ptr, ptr @global
        // → retourne globals["global"] ou regs si c'est un %reg
        let parts: Vec<&str> = rhs.splitn(3, ',').collect();
        let src = parts.get(1).map(|s| s.trim()).unwrap_or("");
        // dernier token = @global ou %reg
        let key = src.split_whitespace().last().unwrap_or("").trim_end_matches(',');
        if key.starts_with('@') {
            let k = key.trim_start_matches('@');
            regs_get(globals, k)
        } else if key.starts_with('%') {
            regs_get(regs, reg_name(key).as_str())
        } else {
            0
        }
    }
    else if rhs.starts_with("select ") {
        // select i1 %cond, ptr A, ptr B
        // A peut être "ptr inttoptr (i64 N to ptr)" → passer la CHAÎNE ENTIÈRE à resolve
        let parts: Vec<&str> = rhs.splitn(4, ',').collect();
        let cond_tok = parts[0].trim().split_whitespace().last().unwrap_or("0");
        let cond = resolve(cond_tok, regs, consts) != 0;
        // Passer la partie entière (pas juste le dernier mot) pour gérer inttoptr inline
        let a_part = parts.get(1).map(|s| s.trim()).unwrap_or("0");
        let b_part = parts.get(2).map(|s| s.trim()).unwrap_or("0");
        if cond { resolve(a_part, regs, consts) } else { resolve(b_part, regs, consts) }
    }
    else if rhs.starts_with("icmp ") {
        // icmp sgt/eq/ugt/samesign ...
        let parts: Vec<&str> = rhs.splitn(4, ' ').collect();
        let op = parts.get(1).unwrap_or(&"eq");
        let toks: Vec<&str> = rhs.split_whitespace().collect();
        // find the two value tokens (after type)
        let len = toks.len();
        let a_tok = if len >= 4 { toks[len-2] } else { "0" };
        let b_tok = if len >= 3 { toks[len-1] } else { "0" };
        let a = resolve(a_tok, regs, consts);
        let b = resolve(b_tok, regs, consts);
        match *op {
            "sgt"              => (a > b) as i64,
            "sge"              => (a >= b) as i64,
            "eq"               => (a == b) as i64,
            "ne"               => (a != b) as i64,
            "slt"              => (a < b) as i64,
            "sle"              => (a <= b) as i64,
            "ugt" | "samesign" => ((a as u64) > (b as u64)) as i64,
            "uge"              => ((a as u64) >= (b as u64)) as i64,
            "ult"              => ((a as u64) < (b as u64)) as i64,
            "ule"              => ((a as u64) <= (b as u64)) as i64,
            _                  => 0,
        }
    }
    else {
        // Opérations arithmétiques / casts
        let toks: Vec<&str> = rhs.split_whitespace().collect();
        // Pattern: "op [qualifiers] type %a, %b"  |  "op [qualifiers] type %a, N"
        if toks.len() < 2 { 0 }
        else {
            let op = toks[0];
            // Trouver les deux opérandes (dernier et avant-dernier token non-type)
            let (a_tok, b_tok) = extract_binop_args(&toks);
            let a = resolve(a_tok, regs, consts);
            let b = resolve(b_tok, regs, consts);
            match op {
                "add"   => a.wrapping_add(b),
                "sub"   => a.wrapping_sub(b),
                "mul"   => a.wrapping_mul(b),
                "sdiv"  => if b != 0 { a / b } else { 0 },
                "udiv"  => if b != 0 { (a as u64 / b as u64) as i64 } else { 0 },
                "srem"  => if b != 0 { a % b } else { 0 },
                "urem"  => if b != 0 { (a as u64 % b as u64) as i64 } else { 0 },
                "shl"   => a.wrapping_shl(b as u32),
                "ashr"  => a >> (b & 63),
                "lshr"  => ((a as u64) >> (b & 63)) as i64,
                "and"   => a & b,
                "or"    => a | b,
                "xor"   => a ^ b,
                // Casts : format "op [qualifiers] src_type VALUE to dst_type"
                // La valeur est le token JUSTE AVANT "to".
                // extract_binop_args prend les MAUVAIS tokens pour les casts
                // (ex. "inttoptr i64 %8 to ptr" → donne "to" et "ptr" au lieu de "%8").
                "zext" | "sext" | "trunc" | "inttoptr" | "ptrtoint" | "bitcast" => {
                    // Trouver "to" dans les tokens, la valeur est juste avant
                    if let Some(to_pos) = toks.iter().position(|&t| t == "to") {
                        if to_pos > 0 {
                            resolve(toks[to_pos - 1], regs, consts)
                        } else { 0 }
                    } else {
                        a // fallback
                    }
                },
                _ => 0,
            }
        }
    };

    regs_set(regs, &dst, val);
    RunResult::Ok
}

fn extract_binop_args<'a>(toks: &[&'a str]) -> (&'a str, &'a str) {
    // Cherche "op [flags...] type a, b"
    // Les flags sont : nuw, nsw, exact, nofree, etc.
    // On cherche le dernier token avant la virgule = a, et le dernier = b
    let len = toks.len();
    if len < 2 { return ("0", "0"); }
    let b_tok = toks[len-1].trim_end_matches(',');
    // 'a' est juste avant la virgule : cherche la virgule dans les tokens
    for i in (1..len-1).rev() {
        if toks[i].ends_with(',') {
            return (toks[i].trim_end_matches(','), b_tok);
        }
    }
    (toks[len-2].trim_end_matches(','), b_tok)
}

// Retourne Some(val) si le prédécesseur est trouvé, None sinon.
fn parse_phi_opt(rhs: &str, prev: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> Option<i64> {
    let mut pos = 0usize;
    while pos < rhs.len() {
        let Some(open) = rhs[pos..].find('[') else { break };
        let open_abs = pos + open;
        let Some(close) = rhs[open_abs..].find(']') else { break };
        let inner = &rhs[open_abs+1..open_abs+close];
        let parts: Vec<&str> = inner.split(',').collect();
        let val_tok = parts.first().map(|s| s.trim()).unwrap_or("0");
        let lbl_tok = parts.get(1).map(|s| s.trim().trim_start_matches('%')).unwrap_or("");
        if lbl_tok == prev {
            return Some(resolve(val_tok, regs, consts));
        }
        pos = open_abs + close + 1;
    }
    None
}
fn parse_phi(rhs: &str, prev: &str, regs: &Regs, consts: &BTreeMap<String, i64>) -> i64 {
    parse_phi_opt(rhs, prev, regs, consts).unwrap_or(0)
}

// ── Rendu texte ──────────────────────────────────────────────────────────────

/// Rendu bitmap 8×16 (FONT8X16) — fallback quand TTF non disponible.
unsafe fn draw_text_bitmap(
    x: i32, y: i32, tp: *const u8, fg: u32, bg: u32,
    fb: *mut u32, s: i32,
) {
    let font = FONT8X16.as_ptr();
    let mut cx = x;
    let mut ci = 0usize;
    loop {
        let ch = *tp.add(ci);
        if ch == 0 { break; }
        let glyph_off = (ch as usize) * 16;
        for row in 0..16i32 {
            let bits = *font.add(glyph_off + row as usize);
            for col in 0..8i32 {
                let on = (bits >> (7 - col)) & 1 != 0;
                let c = if on { fg } else { bg };
                let idx = ((y + row) * s + cx + col) as usize;
                fb.add(idx).write_volatile(c);
            }
        }
        cx += 8;
        ci += 1;
    }
}

/// Appelle une fonction OVC avec des arguments et retourne la valeur i64.
/// `extra_mods` : modules supplémentaires accessibles pour les appels cross-module
/// (ex. l'OVC lui-même pour les appels internes, GlyphRasterizer pour TtfParser).
fn exec_fn_raw_with_mods<'a>(
    ovc:        &'a [u8],
    mod_name:   &'a str,
    fn_name:    &str,
    args:       &[i64],
    ctx:        &ExecCtx,
    extra_mods: &[(&'a str, &'a str)],
) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return 0; }
    let local_consts = parse_string_consts(text);
    let func = match find_function(text, fn_name) { Some(f) => f, None => return 0 };
    let arg_names = parse_def_args(func);
    let blocks = parse_blocks(func);
    let mut regs: Regs = Vec::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs_set(&mut regs, &a, args.get(i).copied().unwrap_or(0));
    }
    let mut globals: Regs = Vec::new();
    // Construire la liste modules : le module courant + les modules extra
    let mut mods_vec: Vec<(&str, &str)> = alloc::vec::Vec::new();
    mods_vec.push((mod_name, text));
    for &(n, t) in extra_mods { mods_vec.push((n, t)); }
    run_blocks_cross(&blocks, &local_consts, &mut globals, &mut regs, ctx, "entry", mod_name, &mods_vec, 0)
}

fn exec_fn_raw(ovc: &[u8], fn_name: &str, args: &[i64], ctx: &ExecCtx) -> i64 {
    exec_fn_raw_with_mods(ovc, fn_name, fn_name, args, ctx, &[])
}

// ── Dispatch des appels externes ──────────────────────────────────────────────

fn dispatch(
    fname:   &str,
    args:    &[i64],
    _consts: &BTreeMap<String, i64>,
    _globals:&Regs,
    ctx:     &ExecCtx,
) -> i64 {
    match fname {
        // ── DrvManSpec GOP ────────────────────────────────────────────────────
        "DrvManSpec___GopGetFrameBuffer___"     => ctx.fb as i64,
        "DrvManSpec___GopGetWidth___"           => ctx.width  as i64,
        "DrvManSpec___GopGetHeight___"          => ctx.height as i64,

        // ── DrvManSpec Block Device (SRFSMan.slul) ────────────────────────────
        "DrvManSpec___UefiLocateDisk___" => srfs_disk_handle(),

        "DrvManSpec___DiskRead___" => {
            if args.len() >= 3 {
                let off  = args[0] as usize;
                let dst  = args[1] as *mut u8;
                let size = args[2] as usize;
                srfs_disk_read(off, dst, size)
            } else { 0 }
        },
        "DrvManSpec___DiskWrite___" => {
            // Écriture sur disque virtuel — no-op en phase UEFI
            if args.len() >= 3 { args[2] } else { 0 }
        },
        "DrvManSpec___MountPointRegister___" |
        "DrvAPIInterCon___MountPointRegister___" => {
            serial_log(b"[SRFS] SDC: monte\r\n");
            0
        },
        "DrvManSpec___PtrWrite8At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1];
                let v   = args[2] as u8;
                if !p.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    unsafe { *p.add(off as usize) = v; }
                }
            }
            0
        },
        "DrvManSpec___PtrWrite32At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1];
                let val = args[2] as u32;
                if !p.is_null() && off >= 0 && off < 256 * 1024 * 1024 {
                    unsafe {
                        // écriture 4 octets little-endian (framebuffer BGRA)
                        core::ptr::write_unaligned(p.add(off as usize) as *mut u32, val);
                    }
                }
            }
            0
        },
        "DrvManSpec___WoffGetData___" => 0,
        "DrvManSpec___WoffScratchGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 256 { unsafe { WOFF_SCRATCH[idx] } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___WoffScratchSet___" => {
            if args.len() >= 2 {
                let idx = args[0] as usize;
                let val = args[1];
                if idx < 256 { unsafe { WOFF_SCRATCH[idx] = val; } }
            }
            0
        },

        // ── DrvManSpec TtfParser state ────────────────────────────────────────
        // TtfGetData/SetData : pointeur vers les bytes TTF en mémoire
        "DrvManSpec___TtfGetData___" => unsafe { TTF_DATA_PTR },
        "DrvManSpec___TtfSetData___" => {
            if args.len() >= 1 { unsafe { TTF_DATA_PTR = args[0]; } }
            0
        },
        // TtfScratchGet/Set : registres temporaires indexés (200 slots)
        // idx 100 = taille font, 101 = nb tables, 102-108 = offsets tables TTF,
        // 109 = unitsPerEm, 110-112 = hhea, 113 = locaFormat, 114 = numHMetrics
        "DrvManSpec___TtfScratchGet___" => {
            if args.len() >= 1 {
                let idx = args[0] as usize;
                if idx < 200 { unsafe { TTF_SCRATCH[idx] } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___TtfScratchSet___" => {
            if args.len() >= 2 {
                let idx = args[0] as usize;
                let val = args[1];
                if idx < 200 { unsafe { TTF_SCRATCH[idx] = val; } }
            }
            0
        },

        // ── DrvManSpec Filesystem via cache SRFS (SRFSMan.slul) ──────────────
        // FSGetSize(path_ptr) → taille du fichier dans le cache SRFS
        // FSRead(path_ptr, buf, size) → copie les octets depuis le cache
        "DrvManSpec___FSGetSize___" => {
            let path_ptr = if args.len() >= 1 { args[0] } else { 0 };
            srfs_find(path_ptr).map(|d| d.len() as i64).unwrap_or(0)
        },
        "DrvManSpec___FSRead___" => {
            if args.len() >= 3 {
                if let Some(data) = srfs_find(args[0]) {
                    let dst = args[1] as *mut u8;
                    let req = args[2] as usize;
                    if !dst.is_null() {
                        let n = req.min(data.len());
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n); }
                        return n as i64;
                    }
                }
            }
            0
        },

        // ── DrvManSpec Mémoire brute (TtfParser / GlyphRasterizer) ───────────
        // Limite de sécurité: offset > 16MB → accès invalide probable (offset négatif converti en usize énorme)
        "DrvManSpec___PtrReadI16At___" | "DrvManSpec___PtrRead16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    let o = off as usize;
                    unsafe {
                        let hi = *base.add(o)     as i64;
                        let lo = *base.add(o + 1) as i64;
                        (hi << 8) | lo
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadU16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    let o = off as usize;
                    unsafe {
                        let hi = *base.add(o)     as i64;
                        let lo = *base.add(o + 1) as i64;
                        (hi << 8) | lo
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadI32At___" | "DrvManSpec___PtrRead32At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    // Lecture native-endian : cohérente avec PtrWrite32At (buffers internes OVC)
                    // TtfParser utilise _r32 fast-path (big-endian) pour les données font TTF
                    unsafe { core::ptr::read_unaligned(base.add(off as usize) as *const i32) as i64 }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrRead8At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1];
                if !base.is_null() && off >= 0 && off < 16 * 1024 * 1024 {
                    unsafe { *base.add(off as usize) as i64 }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrAdd___" => {
            if args.len() >= 2 { args[0].wrapping_add(args[1]) } else { 0 }
        },

        // ── DrvManSpec Police (TtfParser utilise ces primitives) ─────────────
        // UnitsPerEm est stocké dans un global partagé au moment du parse TTF.
        "DrvManSpec___FontGetUnitsPerEm___" => {
            // Valeur typique pour brsonomasemibold.ttf (1000 ou 2048)
            unsafe { FONT_UNITS_PER_EM as i64 }
        },
        "DrvManSpec___FontSetUnitsPerEm___" => {
            if args.len() >= 1 { unsafe { FONT_UNITS_PER_EM = args[0] as u32; } }
            0
        },
        // MathSafety : fonctions clamp (utilisées par GlyphRasterizer)
        "MathSafety___ClampI32___" => {
            if args.len() >= 3 {
                let v   = args[0];
                let min = args[1];
                let max = args[2];
                if v < min { min } else if v > max { max } else { v }
            } else { 0 }
        },
        "MathSafety___ClampU32___" => {
            if args.len() >= 3 {
                let v   = args[0] as u64;
                let min = args[1] as u64;
                let max = args[2] as u64;
                if v < min { min as i64 } else if v > max { max as i64 } else { v as i64 }
            } else { 0 }
        },

        "DrvManSpec___RastSetDims___" => {
            // Stocke les dimensions du raster en cours (width, height)
            if args.len() >= 2 {
                unsafe { RAST_W = args[0] as u32; RAST_H = args[1] as u32; }
            }
            0
        },
        "DrvManSpec___RastGetWidth___"  => unsafe { RAST_W as i64 },
        "DrvManSpec___RastGetHeight___" => unsafe { RAST_H as i64 },

        // ── DrvManSpec Chaîne ─────────────────────────────────────────────────
        "DrvManSpec___StrLen___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if p.is_null() { return 0; }
                let mut n = 0usize;
                unsafe { while *p.add(n) != 0 { n += 1; } }
                n as i64
            } else { 0 }
        },
        "DrvManSpec___StrCharAt___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                let i = args[1] as usize;
                if p.is_null() { return 0; }
                unsafe { *p.add(i) as i64 }
            } else { 0 }
        },

        // ── MathSafety (GlyphRasterizer utilise ClampI32) ────────────────────
        "MathSafety___ClampI32___" => {
            if args.len() >= 3 {
                let v   = args[0] as i32;
                let lo  = args[1] as i32;
                let hi  = args[2] as i32;
                v.max(lo).min(hi) as i64
            } else { 0 }
        },

        // ── DrvAPIInterCon Mémoire (GlyphRasterizer utilise MemAlloc/Set) ────
        // Utilise l'arène statique OVC (512KB) au lieu du heap UEFI limité.
        "DrvAPIInterCon___MemAlloc___" => {
            if args.len() >= 1 {
                let size  = args[0] as usize;
                let align = if args.len() >= 3 { args[2] as usize } else { 8 };
                let align = align.max(1).next_power_of_two().min(64);
                let p = ovc_arena_alloc(size, align);
                p as i64
            } else { 0 }
        },
        "DrvAPIInterCon___MemFree___" => {
            // Note : on ne libère pas en UEFI boot (heap gérée par UEFI)
            0
        },
        "DrvAPIInterCon___MemSet___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let val = args[1] as u8;
                let sz  = args[2] as usize;
                if !p.is_null() { unsafe { core::ptr::write_bytes(p, val, sz); } }
            }
            0
        },
        "DrvAPIInterCon___MemCopy___" => {
            if args.len() >= 3 {
                let dst = args[0] as *mut u8;
                let src = args[1] as *const u8;
                let sz  = args[2] as usize;
                if !dst.is_null() && !src.is_null() {
                    unsafe { core::ptr::copy_nonoverlapping(src, dst, sz); }
                }
            }
            0
        },
        "DrvAPIInterCon___MemRead8___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                let i = args[1] as usize;
                if !p.is_null() { unsafe { *p.add(i) as i64 } } else { 0 }
            } else { 0 }
        },
        "DrvAPIInterCon___MemWrite8___" => {
            if args.len() >= 3 {
                let p = args[0] as *mut u8;
                let i = args[1] as usize;
                let v = args[2] as u8;
                if !p.is_null() { unsafe { *p.add(i) = v; } }
            }
            0
        },
        "DrvAPIInterCon___MemWrite32___" | "DrvAPIInterCon___PtrWrite32At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1] as usize;
                let val = args[2] as u32;
                if !p.is_null() {
                    unsafe { *(p.add(off) as *mut u32) = val; }
                }
            }
            0
        },
        "DrvAPIInterCon___MemRead32___" => {
            if args.len() >= 2 {
                let p = args[0] as *const u8;
                let i = args[1] as usize;
                if !p.is_null() { unsafe { *(p.add(i) as *const u32) as i64 } } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___GopGetPixelsPerScanLine___" => ctx.stride as i64,
        "DrvManSpec___GetBitmapFont8x16___"     => FONT8X16.as_ptr() as i64,
        "DrvManSpec___GopCacheState___"         => 0,

        // (PtrWrite32At et PtrRead8At déjà définis ci-dessus avec bounds check)

        // StrLen(ptr) — null-terminated
        "DrvManSpec___StrLen___" => {
            if args.len() >= 1 {
                let p = args[0] as *const u8;
                if !p.is_null() {
                    let mut n = 0i64;
                    unsafe { while *p.add(n as usize) != 0 { n += 1; } }
                    return n;
                }
            }
            0
        },

        // StrCharAt(ptr, idx)
        "DrvManSpec___StrCharAt___" => {
            if args.len() >= 2 {
                let p   = args[0] as *const u8;
                let idx = args[1] as usize;
                if !p.is_null() {
                    return unsafe { *p.add(idx) } as i64;
                }
            }
            0
        },

        // ── DrvAPIInterCon GPU — appelés depuis HelloWorld.ovc ───────────────
        // Ces fonctions sont le pont entre HelloSlura.marep et SluGpu.slul.

        "DrvAPIInterCon___GpuGetWidth___"  => ctx.width  as i64,
        "DrvAPIInterCon___GpuGetHeight___" => ctx.height as i64,

        // GpuFill(color_as_ptr) — remplit tout le framebuffer
        "DrvAPIInterCon___GpuFill___" => {
            unsafe { GPU_FILLS += 1; }
            serial_log(b"[GPU] GpuFill\r\n");
            if args.len() >= 1 {
                let color = args[0] as u32;
                let fb    = ctx.fb;
                let total = (ctx.stride * ctx.height) as usize;
                if !fb.is_null() {
                    for i in 0..total {
                        unsafe { fb.add(i).write_volatile(color); }
                    }
                }
            }
            0
        },

        // GpuDrawRect(x, y, w, h, color) — tous passés comme entiers (inttoptr)
        "DrvAPIInterCon___GpuDrawRect___" => {
            unsafe { GPU_RECTS += 1; }
            if args.len() >= 5 {
                let x     = args[0] as i32;
                let y     = args[1] as i32;
                let w     = args[2] as i32;
                let h     = args[3] as i32;
                let color = args[4] as u32;
                let fb    = ctx.fb;
                let s     = ctx.stride;
                if !fb.is_null() && w > 0 && h > 0 {
                    for row in 0..h {
                        for col in 0..w {
                            let idx = ((y + row) * s + x + col) as usize;
                            unsafe { fb.add(idx).write_volatile(color); }
                        }
                    }
                }
            }
            0
        },

        // GpuDrawText(x, y, text_ptr, fg, bg) — police 8×16 depuis FONT8X16
        "DrvAPIInterCon___GpuDrawText___" => {
            unsafe { GPU_TEXTS += 1; }
            serial_log(b"[GPU] GpuDrawText\r\n");
            if args.len() >= 5 {
                let x    = args[0] as i32;
                let y    = args[1] as i32;
                let tp   = args[2] as *const u8;
                let fg   = args[3] as u32;
                let bg   = args[4] as u32;
                let fb   = ctx.fb;
                let s    = ctx.stride;
                if !fb.is_null() && !tp.is_null() {
                    let font = FONT8X16.as_ptr();
                    let mut cx = x;
                    let mut ci = 0usize;
                    loop {
                        let ch = unsafe { *tp.add(ci) };
                        if ch == 0 { break; }
                        let glyph_off = (ch as usize) * 16;
                        for row in 0..16i32 {
                            let bits = unsafe { *font.add(glyph_off + row as usize) };
                            for col in 0..8i32 {
                                let on = (bits >> (7 - col)) & 1 != 0;
                                let c = if on { fg } else { bg };
                                let idx = ((y + row) * s + cx + col) as usize;
                                unsafe { fb.add(idx).write_volatile(c); }
                            }
                        }
                        cx += 8;
                        ci += 1;
                    }
                }
            }
            0
        },

        // DrvAPIInterCon***FontGetDefault*** — retourne le 1er font du cache SRFS
        "DrvAPIInterCon___FontGetDefault___" => {
            let (ptr, _) = srfs_font_ptr();
            ptr as i64
        },

        // DrvAPIInterCon***FontLoad*** — charge un font par chemin SRFS déclaré dans le marep.
        // Chemin déclaré dans HelloWorld.mara : "SDC:\\boot\\assets\\font\\..."
        // 1. Cherche dans le cache SRFS (si déjà chargé)
        // 2. Sinon, charge depuis l'ESP UEFI via le loader dynamique
        "DrvAPIInterCon___FontLoad___" => {
            if args.len() >= 1 {
                serial_log(b"[FontLoad] path_ptr=");
                    serial_log(b"\r\n");
                if args[0] == 0 {
                    serial_log(b"[FontLoad] path=0 constructor not run?\r\n");
                    return 0;
                }
                // Cache hit ?
                if let Some(data) = srfs_find(args[0]) {
                    serial_log(b"[FontLoad] cache hit\r\n");
                    return data.as_ptr() as i64;
                }
                // Chargement à la demande depuis l'ESP
                let ptr = srfs_load_on_demand(args[0]);
                if ptr == 0 { serial_log(b"[FONT] FontLoad: echec\r\n"); }
                ptr
            } else { 0 }
        },

        // GpuDrawTextFont(x, y, text, fg, bg, font, pixelSize)
        // Version avec police TTF — utilise TtfParser + GlyphRasterizer si disponibles,
        // sinon fallback sur FONT8X16.
        // GpuDrawTextFont : orchestration Rust → TtfParser.ovc + GlyphRasterizer.ovc
        // Les algorithmes de rendu restent dans SluFontConf.slul/base/
        "DrvAPIInterCon___GpuDrawTextFont___" => {
            unsafe { GPU_TEXTS += 1; }
            serial_log(b"[GPU] GpuDrawTextFont\r\n");
            if args.len() < 5 { serial_log(b"[D] args<5\r\n"); return 0; }
            let x        = args[0] as i32;
            let y        = args[1] as i32;
            let tp       = args[2] as *const u8;
            let fg       = args[3];
            let bg       = args[4];
            let font_ptr = if args.len() >= 6 { args[5] } else { 0 };
            let size     = if args.len() >= 7 { args[6] as i32 } else { 16 };

            // Logs détaillés : font_ptr, fg, bg, size, ctx.font_len
            serial_log(b" fl=");
            serial_log(&[(ctx.font_len % 1000) as u8 / 100 + b'0',
                          (ctx.font_len % 100)  as u8 / 10  + b'0',
                          (ctx.font_len % 10)   as u8        + b'0']);
            serial_log(b"\r\n");
            let fg_b = (fg as u32).to_be_bytes();
            serial_log(&fg_b);
            serial_log(b" bg=");
            let bg_b = (bg as u32).to_be_bytes();
            serial_log(&bg_b);
            serial_log(b"\r\n");

            if tp.is_null() || font_ptr == 0 { serial_log(b"[D] skip null\r\n"); return 0; }

            let ttf_bytes  = unsafe { FONT_TTF_OVC.as_deref()  }.unwrap_or(&[]);
            let rast_bytes = unsafe { FONT_RAST_OVC.as_deref() }.unwrap_or(&[]);
            let woff_bytes = unsafe { FONT_WOFF_OVC.as_deref() }.unwrap_or(&[]);
            if ttf_bytes.is_empty() || rast_bytes.is_empty() { return 0; }
            let ttf_text  = core::str::from_utf8(ttf_bytes).unwrap_or("");
            let rast_text = core::str::from_utf8(rast_bytes).unwrap_or("");
            let woff_text = core::str::from_utf8(woff_bytes).unwrap_or("");

            // ── Étape 1 : Load ─────────────────────────────────────────────
            if unsafe { TTF_SCRATCH[104] == 0 } {
                // WoffReader est appelé depuis TtfParser.ovc sous le nom
                // "std___core___self___WoffReader___Decode" — on expose les deux alias.
                let load_mods: alloc::vec::Vec<(&str, &str)> = if woff_text.starts_with("# Vyft OVC") {
                    alloc::vec![
                        ("GlyphRasterizer",                rast_text),
                        ("WoffReader",                     woff_text),
                        ("std___core___self___WoffReader",  woff_text),
                    ]
                } else {
                    alloc::vec![("GlyphRasterizer", rast_text)]
                };
                let load_r = exec_fn_raw_with_mods(
                    ttf_bytes, "TtfParser", "Load",
                    &[font_ptr, ctx.font_len as i64], ctx, &load_mods,
                );
                if load_r != 0 {
                                    serial_log(b"\r\n");
                } else {
                            let cmap = unsafe { TTF_SCRATCH[104] as u32 }.to_be_bytes();
                    serial_log(&cmap[2..]);
                    serial_log(b" upm=");
                    serial_log(&[(unsafe { FONT_UNITS_PER_EM } / 100) as u8 + b'0',
                                  (unsafe { FONT_UNITS_PER_EM } / 10 % 10) as u8 + b'0',
                                  (unsafe { FONT_UNITS_PER_EM } % 10) as u8 + b'0']);
                    serial_log(b"\r\n");
                }
            } else {
                }

            let fb_i64     = ctx.fb as i64;
            let stride_i64 = ctx.stride as i64;
            let ttf_mods   = [("GlyphRasterizer", rast_text)];
            let rast_mods  = [("TtfParser", ttf_text)];
            let mut rendered = 0u32;

            // ── Étape 2 : Boucle sur les caractères ──────────────────────────
            let mut cx = x;
            let mut ci = 0usize;
            loop {
                let ch = unsafe { *tp.add(ci) };
                if ch == 0 { break; }
                ci += 1;

                let glyph_id = exec_fn_raw_with_mods(
                    ttf_bytes, "TtfParser", "GetGlyphId",
                    &[ch as i64], ctx, &ttf_mods,
                );
                if glyph_id <= 0 {
                    if ci <= 2 { serial_log(b"[D] G=0\r\n"); }
                    cx += size / 2; continue;
                }
                if ci <= 2 { serial_log(b"[D] G+\r\n"); }

                let glyf_off = exec_fn_raw_with_mods(
                    ttf_bytes, "TtfParser", "GetGlyfOffset",
                    &[glyph_id], ctx, &ttf_mods,
                );
                if glyf_off <= 0 {
                    if ci <= 2 { serial_log(b"[D] off=0\r\n"); }
                    cx += size / 2; continue;
                }

                let glyf_data = font_ptr.wrapping_add(glyf_off);
                ovc_arena_reset();  // reset arène avant chaque glyphe

                let bitmap = exec_fn_raw_with_mods(
                    rast_bytes, "GlyphRasterizer", "RasterizeGlyph",
                    &[glyf_data, size as i64], ctx, &rast_mods,
                );
                if bitmap == 0 {
                    if ci <= 2 { serial_log(b"[D] bmp=0\r\n"); }
                    cx += size / 2; continue;
                }

                let bmp_w = unsafe { RAST_W as i32 };
                let bmp_h = unsafe { RAST_H as i32 };
                if ci <= 2 {
                                    serial_log(b" H=");
                            serial_log(b"\r\n");
                }

                exec_fn_raw_with_mods(
                    rast_bytes, "GlyphRasterizer", "DrawGlyphAt",
                    &[fb_i64, stride_i64, cx as i64, y as i64, bitmap,
                      bmp_w as i64, bmp_h as i64, fg, bg],
                    ctx, &rast_mods,
                );
                rendered += 1;
                cx += bmp_w + 1;
            }
            serial_log(b"[FONT] rendered=");
            serial_log(b"\r\n");
            0
        },

        // GpuFlushRenderContext — retourne -1 en UEFI pour quitter la boucle
        // de rendu de LAPrevent après 1 frame (Render loop exit condition).
        // En OS runtime, ce serait 0 (flush réel du buffer).
        "DrvAPIInterCon___GpuFlushRenderContext___" => -1,

        // MaratineKit UI — stubs (pas de RenderContext en UEFI boot)
        "MaratineKit___UI___TextLabel___New"        => 0,
        "MaratineKit___UI___TextLabel___SetAlign"   => 0,
        "MaratineKit___UI___TextLabel___SetFontSize"=> 0,
        "MaratineKit___RenderContext___Attach"      => 0,
        "MaratineKit___RenderContext___Detach"      => 0,
        "MaratineKit___PIDActivity___ObtInfo"       => 0,
        "MaratineKit___AuthARoot"                   => 0,
        "MaratineKit___RenRootUI"                   => 0,
        "ObtProcess"                                => 0,
        "PAccess"                                   => 0,
        "gcc___archInfo___"                         => 0,

        // printf — no-op silencieux en UEFI
        "printf" => 0,

        // ── CryptoAssetSupport dispatchers (*.ca simple + bundle) ────────────
        // Écrire un fichier .ca dans SRFS (simple ou bundle JSON brut)
        // args[0]=path_ptr  args[1]=json_ptr_or_bytes
        "DrvAPIInterCon___CaWriteFile___" => {
            if args.len() >= 2 {
                let path_ptr = args[0] as *const u8;
                let json_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !json_ptr.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    let json_str = unsafe { read_cstr(json_ptr) };
                    srfs_write_chain_file(&path_str, json_str.as_bytes());
                }
            }
            0
        },

        // Lire un fichier .ca depuis SRFS vers un buffer alloué par l'appelant
        // (identique à FSRead mais dans le namespace Ca)
        "DrvAPIInterCon___CaReadFile___" => {
            if args.len() >= 3 {
                let path_ptr = args[0] as *const u8;
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !path_ptr.is_null() && !out_buf.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        let n = data.len().min(out_size);
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, n); }
                        return n as i64;
                    }
                }
            }
            -1
        },

        // Compter les fichiers .ca dans un répertoire SRFS
        // args[0]=dir_path_ptr → nombre de .ca trouvés dans le cache
        "DrvAPIInterCon___CaCountFiles___" => {
            let count = unsafe {
                SRFS_CACHE.iter()
                    .filter(|s| {
                        if let Some((k, _)) = s { k.ends_with(".ca") } else { false }
                    })
                    .count() as i64
            };
            count
        },

        // Lister les .ca (noms séparés par \n) dans un répertoire SRFS
        // args[0]=dir_path_ptr  args[1]=out_buf  args[2]=max_size
        "DrvAPIInterCon___CaListFiles___" => {
            if args.len() >= 3 {
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !out_buf.is_null() && out_size > 0 {
                    let mut listing = alloc::string::String::new();
                    unsafe {
                        for slot in SRFS_CACHE.iter() {
                            if let Some((k, _)) = slot {
                                if k.ends_with(".ca") {
                                    listing.push_str(k);
                                    listing.push('\n');
                                }
                            }
                        }
                    }
                    let bytes = listing.as_bytes();
                    let n = bytes.len().min(out_size - 1);
                    if n > 0 {
                        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, n); }
                        unsafe { *out_buf.add(n) = 0; }
                    }
                    return n as i64;
                }
            }
            -1
        },

        // Vérifier si un buffer contient une substring (pour IsBundle)
        // args[0]=buf_ptr  args[1]=needle_ptr → 1 si trouvé, 0 sinon
        "DrvAPIInterCon___CaContains___" => {
            if args.len() >= 2 {
                let buf_ptr    = args[0] as *const u8;
                let needle_ptr = args[1] as *const u8;
                if !buf_ptr.is_null() && !needle_ptr.is_null() {
                    let buf_str    = unsafe { read_cstr(buf_ptr) };
                    let needle_str = unsafe { read_cstr(needle_ptr) };
                    return if buf_str.contains(needle_str.as_str()) { 1 } else { 0 };
                }
            }
            0
        },

        // Lire un champ de premier niveau dans un JSON .ca
        // args[0]=json_buf_ptr  args[1]=field_ptr → pointeur vers valeur (alloc), ou null
        "DrvAPIInterCon___CaReadField___" => {
            if args.len() >= 2 {
                let json_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                if !json_ptr.is_null() && !field_ptr.is_null() {
                    let json_str  = unsafe { read_cstr(json_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    let needle = alloc::format!("\"{}\":", field_str);
                    if let Some(pos) = json_str.find(&needle) {
                        let rest = json_str[pos + needle.len()..].trim_start();
                        let value = if rest.starts_with('"') {
                            // Valeur string : extraire entre guillemets
                            let inner = &rest[1..];
                            let end = inner.find('"').unwrap_or(inner.len());
                            inner[..end].to_string()
                        } else {
                            // Valeur numérique/bool
                            let end = rest.find(|c: char| c == ',' || c == '}' || c == '\n')
                                .unwrap_or(rest.len());
                            rest[..end].trim().to_string()
                        };
                        if !value.is_empty() {
                            let mut bytes = value.into_bytes();
                            bytes.push(0);
                            let boxed = bytes.into_boxed_slice();
                            return alloc::boxed::Box::into_raw(boxed) as *mut u8 as i64;
                        }
                    }
                }
            }
            0
        },

        // Extraire un sous-objet nested dans un bundle JSON
        // args[0]=json_buf_ptr  args[1]=parent_key_ptr  args[2]=child_key_ptr
        // Ex : CaExtractSubObject(buf, "contracts", "VEZproxy") → JSON de VEZproxy
        "DrvAPIInterCon___CaExtractSubObject___" => {
            if args.len() >= 3 {
                let json_ptr   = args[0] as *const u8;
                let parent_ptr = args[1] as *const u8;
                let child_ptr  = args[2] as *const u8;
                if !json_ptr.is_null() && !parent_ptr.is_null() && !child_ptr.is_null() {
                    let json_str   = unsafe { read_cstr(json_ptr) };
                    let parent_str = unsafe { read_cstr(parent_ptr) };
                    let child_str  = unsafe { read_cstr(child_ptr) };
                    // Trouver "parent":{ puis "child":{ ... }
                    let parent_key = alloc::format!("\"{}\":", parent_str);
                    let child_key  = alloc::format!("\"{}\":", child_str);
                    if let Some(p_pos) = json_str.find(&parent_key) {
                        let after_parent = &json_str[p_pos + parent_key.len()..];
                        if let Some(c_pos) = after_parent.find(&child_key) {
                            let after_child = &after_parent[c_pos + child_key.len()..].trim_start();
                            // Extraire l'objet JSON { ... } avec comptage de braces
                            if after_child.starts_with('{') {
                                let mut depth = 0usize;
                                let mut end   = 0usize;
                                for (i, c) in after_child.char_indices() {
                                    if c == '{' { depth += 1; }
                                    if c == '}' {
                                        depth -= 1;
                                        if depth == 0 { end = i + 1; break; }
                                    }
                                }
                                if end > 0 {
                                    let sub = after_child[..end].to_string();
                                    let mut bytes = sub.into_bytes();
                                    bytes.push(0);
                                    let boxed = bytes.into_boxed_slice();
                                    return alloc::boxed::Box::into_raw(boxed) as *mut u8 as i64;
                                }
                            }
                        }
                    }
                }
            }
            0
        },

        // Mettre à jour un champ de premier niveau dans un fichier .ca SRFS
        // args[0]=path_ptr  args[1]=field_ptr  args[2]=value_ptr
        "DrvAPIInterCon___CaUpdateField___" => {
            if args.len() >= 3 {
                let path_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                let val_ptr   = args[2] as *const u8;
                if !path_ptr.is_null() && !field_ptr.is_null() && !val_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    let val_str   = unsafe { read_cstr(val_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(mut json_str) = alloc::string::String::from_utf8(data) {
                            let needle = alloc::format!("\"{}\":", field_str);
                            if let Some(pos) = json_str.find(&needle) {
                                let val_start = pos + needle.len();
                                let rest = json_str[val_start..].trim_start().to_string();
                                let val_end = rest.find(|c: char| c == ',' || c == '}')
                                    .unwrap_or(rest.len());
                                let old_val = &rest[..val_end];
                                let new_val = alloc::format!("\"{}\"", val_str);
                                json_str = json_str.replacen(old_val, &new_val, 1);
                                srfs_write_chain_file(&path_str, json_str.as_bytes());
                                return 0;
                            }
                        }
                    }
                }
            }
            -1
        },

        // Mettre à jour un champ nested contracts.<contract>.<field> dans un bundle
        // args[0]=path  args[1]=parent("contracts")  args[2]=contract_name  args[3]=field  args[4]=value
        "DrvAPIInterCon___CaUpdateNestedField___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let contract_ptr = args[2] as *const u8;
                let field_ptr    = args[3] as *const u8;
                let val_ptr      = args[4] as *const u8;
                if !path_ptr.is_null() && !contract_ptr.is_null() && !field_ptr.is_null() && !val_ptr.is_null() {
                    let path_str     = unsafe { read_cstr(path_ptr) };
                    let contract_str = unsafe { read_cstr(contract_ptr) };
                    let field_str    = unsafe { read_cstr(field_ptr) };
                    let val_str      = unsafe { read_cstr(val_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(mut json_str) = alloc::string::String::from_utf8(data) {
                            // Trouver "contractName":{ ... "field":"old" ... }
                            let contract_key = alloc::format!("\"{}\":", contract_str);
                            let field_key    = alloc::format!("\"{}\":", field_str);
                            if let Some(c_pos) = json_str.find(&contract_key) {
                                let sub = &json_str[c_pos..];
                                if let Some(f_pos) = sub.find(&field_key) {
                                    let abs_pos  = c_pos + f_pos + field_key.len();
                                    let rest     = json_str[abs_pos..].trim_start().to_string();
                                    let val_end  = rest.find(|c: char| c == ',' || c == '}')
                                        .unwrap_or(rest.len());
                                    let old_val  = &rest[..val_end];
                                    let new_val  = alloc::format!("\"{}\"", val_str);
                                    json_str     = json_str.replacen(old_val, &new_val, 1);
                                    srfs_write_chain_file(&path_str, json_str.as_bytes());
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        // Ajouter une entrée à l'index SRFS (SDC:\env\.index)
        // args[0]=index_path_ptr  args[1]=entry_ptr ("NOM=VALEUR\n")
        "DrvAPIInterCon___EnvAppendIndex___" => {
            if args.len() >= 2 {
                let path_ptr  = args[0] as *const u8;
                let entry_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !entry_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let entry_str = unsafe { read_cstr(entry_ptr) };
                    let existing  = srfs_read_chain_file(&path_str)
                        .and_then(|d| alloc::string::String::from_utf8(d).ok())
                        .unwrap_or_default();
                    let new_index = alloc::format!("{}{}", existing, entry_str);
                    srfs_write_chain_file(&path_str, new_index.as_bytes());
                }
            }
            0
        },

        // Parser les entrées NOM=VALEUR\n d'un buffer d'index et les injecter
        // args[0]=buf_ptr  args[1]=buf_size → nombre de vars parsées
        "DrvAPIInterCon___EnvParseIndex___" => {
            if args.len() >= 2 {
                let buf_ptr  = args[0] as *const u8;
                let buf_size = args[1] as usize;
                if !buf_ptr.is_null() && buf_size > 0 {
                    let data  = unsafe { core::slice::from_raw_parts(buf_ptr, buf_size) };
                    let text  = core::str::from_utf8(data).unwrap_or("");
                    let count = text.lines()
                        .filter(|line| line.contains('='))
                        .count();
                    return count as i64;
                }
            }
            0
        },

        // LLVM intrinsics (utilisés par GlyphRasterizer pour smax/smin)
        "llvm.smax.i32" => if args.len() >= 2 { args[0].max(args[1]) } else { 0 },
        "llvm.smin.i32" => if args.len() >= 2 { args[0].min(args[1]) } else { 0 },
        "llvm.umax.i32" => if args.len() >= 2 { (args[0] as u64).max(args[1] as u64) as i64 } else { 0 },
        "llvm.umin.i32" => if args.len() >= 2 { (args[0] as u64).min(args[1] as u64) as i64 } else { 0 },

        // self___onDriverInit → appelé depuis APrevent::OnPowerOn
        "self___onDriverInit" => 0,

        // ── SluraChain Bridge (SluChainBridge.mara) ──────────────────────────
        // Pont SRFS ↔ vuc-platform : sérialise txns/calls en JSON dans SRFS.
        // vuc-platform (engine_platform.rs) les consomme en mode deferred.

        // Générer un ID unique pour une transaction/call (monotone, basé sur compteur)
        "DrvAPIInterCon___BlockchainGenTxId___" => {
            unsafe {
                static mut CHAIN_TX_COUNTER: u32 = 0;
                CHAIN_TX_COUNTER = CHAIN_TX_COUNTER.wrapping_add(1);
                CHAIN_TX_COUNTER as i64
            }
        },

        // Enqueue une transaction dans SRFS : SDC:\chain\pending_txs\<id>.json
        // args[0]=path_ptr args[1]=from_ptr args[2]=to_ptr args[3]=data_ptr args[4]=value args[5]=txId
        "DrvAPIInterCon___BlockchainQueueTx___" => {
            if args.len() >= 6 {
                let path_ptr = args[0] as *const u8;
                let to_ptr   = args[2] as *const u8;
                let data_ptr = args[3] as *const u8;
                let value    = args[4] as u64;
                let tx_id    = args[5] as u32;
                if !path_ptr.is_null() && !to_ptr.is_null() {
                    // Sérialiser en JSON minimaliste et écrire dans SRFS via srfs_write_chain_file
                    let to_str   = unsafe { read_cstr(to_ptr) };
                    let data_str = if data_ptr.is_null() { "0x".to_string() }
                                   else { unsafe { read_cstr(data_ptr) } };
                    let path_str = unsafe { read_cstr(path_ptr) };
                    let json = alloc::format!(
                        "{{\"type\":\"tx\",\"id\":{},\"to\":\"{}\",\"data\":\"{}\",\"value\":{}}}",
                        tx_id, to_str, data_str, value
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());
                }
            }
            0
        },

        // Enqueue un eth_call en lecture seule : SDC:\chain\calls\<id>.req.json
        // args[0]=reqPath args[1]=contract args[2]=selector args[3]=args_data args[4]=callId
        "DrvAPIInterCon___BlockchainQueueCall___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let contract_ptr = args[1] as *const u8;
                let sel_ptr      = args[2] as *const u8;
                let args_ptr     = args[3] as *const u8;
                let call_id      = args[4] as u32;
                if !path_ptr.is_null() && !contract_ptr.is_null() {
                    let path_str     = unsafe { read_cstr(path_ptr) };
                    let contract_str = unsafe { read_cstr(contract_ptr) };
                    let sel_str      = if sel_ptr.is_null()  { "0x".to_string() } else { unsafe { read_cstr(sel_ptr) } };
                    let args_str     = if args_ptr.is_null() { "0x".to_string() } else { unsafe { read_cstr(args_ptr) } };
                    let json = alloc::format!(
                        "{{\"type\":\"call\",\"id\":{},\"to\":\"{}\",\"selector\":\"{}\",\"args\":\"{}\"}}",
                        call_id, contract_str, sel_str, args_str
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());
                }
            }
            0
        },

        // Polling sur la réponse d'un call : SDC:\chain\calls\<id>.resp.json
        // args[0]=respPath args[1]=outBuf args[2]=outSize args[3]=timeout_ms
        // Retourne le nombre d'octets lus dans outBuf, ou -1 si timeout
        "DrvAPIInterCon___BlockchainPollResp___" => {
            if args.len() >= 4 {
                let path_ptr = args[0] as *const u8;
                let out_buf  = args[1] as *mut u8;
                let out_size = args[2] as usize;
                if !path_ptr.is_null() && !out_buf.is_null() && out_size > 0 {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    // Lire depuis SRFS cache (mis à jour par vuc-platform)
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        let n = data.len().min(out_size);
                        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, n); }
                        return n as i64;
                    }
                }
            }
            -1
        },

        // Enqueue un déploiement de contrat : SDC:\chain\pending_txs\<id>.deploy.json
        // args[0]=queuePath args[1]=bytecodePath args[2]=ctorArgs args[3]=from args[4]=txId
        "DrvAPIInterCon___BlockchainQueueDeploy___" => {
            if args.len() >= 5 {
                let path_ptr     = args[0] as *const u8;
                let bc_path_ptr  = args[1] as *const u8;
                let ctor_ptr     = args[2] as *const u8;
                let from_ptr     = args[3] as *const u8;
                let tx_id        = args[4] as u32;
                if !path_ptr.is_null() && !bc_path_ptr.is_null() {
                    let path_str    = unsafe { read_cstr(path_ptr) };
                    let bc_path_str = unsafe { read_cstr(bc_path_ptr) };
                    let ctor_str    = if ctor_ptr.is_null()  { "0x".to_string() } else { unsafe { read_cstr(ctor_ptr) } };
                    let from_str    = if from_ptr.is_null()  { "0x0000000000000000000000000000000000000000".to_string() } else { unsafe { read_cstr(from_ptr) } };
                    let json = alloc::format!(
                        "{{\"type\":\"deploy\",\"id\":{},\"bytecodePath\":\"{}\",\"ctorArgs\":\"{}\",\"from\":\"{}\"}}",
                        tx_id, bc_path_str, ctor_str, from_str
                    );
                    srfs_write_chain_file(&path_str, json.as_bytes());
                }
            }
            0
        },

        // Lire la balance depuis SRFS : SDC:\chain\state\balances\<addr>.json
        // args[0]=statePath_ptr → retourne la balance (i32 simplifié) ou -1
        "DrvAPIInterCon___BlockchainReadBalance___" => {
            if args.len() >= 1 {
                let path_ptr = args[0] as *const u8;
                if !path_ptr.is_null() {
                    let path_str = unsafe { read_cstr(path_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        // Parse JSON minimaliste {"balance":12345}
                        if let Ok(s) = core::str::from_utf8(&data) {
                            if let Some(pos) = s.find("\"balance\":") {
                                let rest = &s[pos + 10..];
                                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                                if let Ok(v) = rest[..end].parse::<i64>() {
                                    return v;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        // Lire un champ JSON depuis un fichier SRFS de métadonnées
        // args[0]=path_ptr args[1]=field_ptr → valeur du champ (i32) ou -1
        "DrvAPIInterCon___BlockchainReadMeta___" => {
            if args.len() >= 2 {
                let path_ptr  = args[0] as *const u8;
                let field_ptr = args[1] as *const u8;
                if !path_ptr.is_null() && !field_ptr.is_null() {
                    let path_str  = unsafe { read_cstr(path_ptr) };
                    let field_str = unsafe { read_cstr(field_ptr) };
                    if let Some(data) = srfs_read_chain_file(&path_str) {
                        if let Ok(s) = core::str::from_utf8(&data) {
                            let needle = alloc::format!("\"{}\":", field_str);
                            if let Some(pos) = s.find(&needle) {
                                let rest = &s[pos + needle.len()..].trim_start();
                                let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
                                if let Ok(v) = rest[..end].parse::<i64>() {
                                    return v;
                                }
                            }
                        }
                    }
                }
            }
            -1
        },

        _ => 0,
    }
}

// ── Helpers internes pour le bridge blockchain ────────────────────────────────

/// Lit une chaîne C nulle-terminée depuis un pointeur brut.
unsafe fn read_cstr(ptr: *const u8) -> alloc::string::String {
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 512 { len += 1; }
    core::str::from_utf8(core::slice::from_raw_parts(ptr, len))
        .unwrap_or("")
        .to_string()
}

/// Écrit un fichier JSON dans la queue blockchain SRFS.
/// Cherche d'abord dans SRFS_CACHE un slot libre ; sinon enregistre directement.
fn srfs_write_chain_file(path: &str, data: &[u8]) {
    unsafe {
        for slot in SRFS_CACHE.iter_mut() {
            if slot.is_none() {
                *slot = Some((path.to_string(), data.to_vec()));
                return;
            }
        }
        // Cache plein : écraser le premier slot chain (pas de font/marep)
        for slot in SRFS_CACHE.iter_mut() {
            if let Some((ref k, _)) = slot {
                if k.contains("chain") {
                    *slot = Some((path.to_string(), data.to_vec()));
                    return;
                }
            }
        }
    }
    serial_log(b"[CHAIN] cache plein, tx perdue\r\n");
}

/// Lit un fichier de réponse blockchain depuis SRFS_CACHE.
fn srfs_read_chain_file(path: &str) -> Option<alloc::vec::Vec<u8>> {
    unsafe {
        for slot in SRFS_CACHE.iter() {
            if let Some((ref k, ref data)) = slot {
                if k == path {
                    return Some(data.clone());
                }
            }
        }
    }
    None
}

// ── Bridge C-ABI pour vuc-platform (uefi-kernel feature) ─────────────────────
//
// vuc-platform appelle slura_mgc_register_executor() au démarrage.
// Ici on expose exec_module sous l'ABI C attendue.
//
// Signature : fn(bytecode: *const u8, len: usize, entry: *const u8) -> i32
// Enregistrement : kernel_runtime::platform_init() appelle
//   slura_mgc_register_executor(exec_module_raw)

/// Point d'entrée C-ABI de l'exécuteur OVC — enregistré dans vuc_platform.
///
/// `bytecode` : octets OVC (# Vyft OVC v1.0...)
/// `len`      : longueur du bytecode
/// `entry`    : nom de la fonction d'entrée null-terminated ("OEntry\0")
#[no_mangle]
pub unsafe extern "C" fn exec_module_raw(
    bytecode: *const u8,
    len:      usize,
    entry:    *const u8,
) -> i32 {
    if bytecode.is_null() || len == 0 { return -1; }
    let ovc = core::slice::from_raw_parts(bytecode, len);
    // Extraire le nom de la fonction
    let fn_name = if entry.is_null() {
        "OEntry"
    } else {
        let mut n = 0usize;
        while *entry.add(n) != 0 { n += 1; }
        core::str::from_utf8(core::slice::from_raw_parts(entry, n))
            .unwrap_or("OEntry")
    };
    // Contexte nul — l'appelant doit avoir initialisé via slura_mgc_set_ctx
    let ctx = ExecCtx { fb: core::ptr::null_mut(), width: 0, height: 0, stride: 0,
                        font: core::ptr::null(), font_len: 0 };
    exec_module(ovc, &[(fn_name, &[])], &ctx) as i32
}