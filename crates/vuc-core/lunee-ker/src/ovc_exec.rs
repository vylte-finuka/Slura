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

// ── Cache SRFS (SDC: → octets pré-chargés depuis l'ESP par slul_loader) ──────
// Capacité fixe : 4 fichiers max pour éviter les allocations dynamiques en UEFI.
static mut SRFS_CACHE: [Option<(&'static str, Vec<u8>)>; 4] = [None, None, None, None];

/// Enregistre un fichier SRFS (path = "SDC:\\...") depuis slul_loader.
pub fn srfs_register_file(path: &'static str, data: Vec<u8>) {
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
            if let Some((key, ref data)) = slot {
                // Comparer de façon case-insensitive (SDC: est Windows-style)
                if keys_match(req, key) {
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

// ── TtfParser state (DrvManSpec***TtfGetData/Set + TtfScratchGet/Set) ─────────
// Partagé entre Load / GetGlyphId / GetGlyfOffset car ces appels
// passent par le dispatcher global, pas par les globals OVC.
static mut TTF_DATA_PTR: i64 = 0;
static mut TTF_SCRATCH: [i64; 200] = [0i64; 200];

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

// ── Contexte d'exécution ──────────────────────────────────────────────────────

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
fn resolve(tok: &str, regs: &BTreeMap<String, i64>, consts: &BTreeMap<String, i64>) -> i64 {
    let tok = tok.trim().trim_end_matches(',');

    // Registre %name
    if tok.starts_with('%') {
        return *regs.get(reg_name(tok).as_str()).unwrap_or(&0);
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
        return *regs.get(reg_name(last).as_str()).unwrap_or(&0);
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

fn parse_string_consts(ovc: &str) -> BTreeMap<String, i64> {
    let mut map = BTreeMap::new();
    for line in ovc.lines() {
        let line = line.trim();
        if !line.starts_with('@') { continue; }
        let Some(eq) = line.find('=') else { continue };
        let name = line[1..eq].trim().to_string();
        // Cherche c"text\00"
        let Some(cp) = line.find(" c\"") else { continue };
        let after = &line[cp+3..];
        let Some(ep) = after.find("\\00\"") else { continue };
        let s: String = after[..ep].to_string();
        // Stocker avec null-terminator pour GpuDrawText (loop cherche \0)
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0u8);
        let boxed: alloc::boxed::Box<[u8]> = bytes.into_boxed_slice();
        let ptr = alloc::boxed::Box::into_raw(boxed) as *const u8 as i64;
        map.insert(name, ptr);
    }
    map
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

fn parse_blocks(func: &str) -> BTreeMap<String, Vec<String>> {
    let mut blocks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cur = "entry".to_string();
    blocks.insert(cur.clone(), Vec::new());

    for line in func.lines().skip(1) {
        let t = line.trim();
        if t.is_empty() || t == "{" || t == "}" { continue; }
        // Commentaire de prédécesseur : "; preds = ..."
        if t.starts_with(';') { continue; }
        // Déclaration de label : "name:" ou "name:  ; ..."
        if !t.starts_with('%') && !t.starts_with("store")
            && !t.starts_with("br") && !t.starts_with("ret")
            && t.ends_with(':')
        {
            let label = t.trim_end_matches(':').trim().to_string();
            cur = label.clone();
            blocks.entry(cur.clone()).or_insert_with(Vec::new);
            continue;
        }
        if let Some(v) = blocks.get_mut(&cur) {
            v.push(t.to_string());
        }
    }
    blocks
}

// ── Exécution ─────────────────────────────────────────────────────────────────

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

    let mut regs:    BTreeMap<String, i64> = BTreeMap::new();
    let mut globals: BTreeMap<String, i64> = BTreeMap::new();

    for (i, a) in arg_names.iter().enumerate() {
        regs.insert(a.clone(), args.get(i).copied().unwrap_or(0));
    }

    run_blocks(&blocks, &consts, &mut globals, &mut regs, ctx, "entry")
}

/// Exécute plusieurs fonctions d'un même OVC en partageant les globals.
/// Utilisé pour HelloWorld() puis Create() qui lisent les mêmes variables module.
pub fn exec_module(ovc: &[u8], fns: &[(&str, &[i64])], ctx: &ExecCtx) -> i64 {
    let text = core::str::from_utf8(ovc).unwrap_or("");
    if !text.starts_with("# Vyft OVC v1.0") { return -1; }

    let consts  = parse_string_consts(text);
    let mut globals: BTreeMap<String, i64> = BTreeMap::new();
    let mut last = 0i64;

    for (fn_name, args) in fns {
        let func = match find_function(text, fn_name) { Some(f) => f, None => continue };
        let arg_names = parse_def_args(func);
        let blocks    = parse_blocks(func);
        let mut regs: BTreeMap<String, i64> = BTreeMap::new();
        for (i, a) in arg_names.iter().enumerate() {
            regs.insert(a.clone(), args.get(i).copied().unwrap_or(0));
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
            for (k, v) in c {
                all_consts.insert(alloc::format!("{}::{}", name, k), v);
                all_consts.entry(k).or_insert(v); // sans préfixe aussi
            }
            mod_texts.push((name, text));
        }
    }

    // Globals partagés entre tous les modules
    let mut globals: BTreeMap<String, i64> = BTreeMap::new();

    serial_log(b"[OVC] constructors start\r\n");

    // Étape 1 : constructeurs des COMPOSANTS (pas OEntry)
    for (mod_name, mod_text) in &mod_texts {
        if mod_name.eq_ignore_ascii_case("OEntry") { continue; }
        if find_function(mod_text, mod_name).is_some() {
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
    globals:    &mut BTreeMap<String, i64>,
    ctx:        &ExecCtx,
    modules:    &[(&str, &str)],
    depth:      u32,
) -> i64 {
    if depth > 32 { return 0; }

    // Log chaque appel (visible COM1 dans QEMU stdio)
    serial_log(b"[FN] ");
    serial_log(mod_name.as_bytes());
    serial_log(b"::");
    serial_log(fn_name.as_bytes());
    serial_log(b"\r\n");

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

    let mut regs: BTreeMap<String, i64> = BTreeMap::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs.insert(a.clone(), args.get(i).copied().unwrap_or(0));
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
    globals:  &mut BTreeMap<String, i64>,
    regs:     &mut BTreeMap<String, i64>,
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
            // Log compact : uniquement si l'instruction contient "call"
            if instr.contains("call ") && instr.contains('@') {
                serial_log(b"[I] ");
                let s = instr.as_bytes();
                let n = s.len().min(60);
                serial_log(&s[..n]);
                serial_log(b"\r\n");
            }
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
                                serial_log(b"[CM] ");
                                serial_log(found_mod.as_bytes());
                                serial_log(b"::");
                                serial_log(target_fn.as_bytes());
                                serial_log(b"\r\n");
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
                            // Pas de séparateur "___" → fonction interne du module courant
                            // (ex. _r8, _r16, _r32 dans TtfParser.ovc)
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
                        };

                        regs.insert(dst, call_result);
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
    globals: &mut BTreeMap<String, i64>,
    regs:    &mut BTreeMap<String, i64>,
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
    globals: &mut BTreeMap<String, i64>,
    regs:    &mut BTreeMap<String, i64>,
    ctx:     &ExecCtx,
    prev:    &str,
) -> RunResult {
    let instr = instr.trim();
    if instr.is_empty() || instr.starts_with(';') { return RunResult::Ok; }

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
        globals.insert(dest_k, val);
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
        let fn_start = match rhs.find('@') { Some(p) => p, None => { regs.insert(dst, 0); return RunResult::Ok; } };
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
        // Cherche la valeur associée au bloc précédent
        parse_phi(rhs, prev, regs, consts)
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
            *globals.get(k).unwrap_or(&0)
        } else if key.starts_with('%') {
            *regs.get(reg_name(key).as_str()).unwrap_or(&0)
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
            "eq"               => (a == b) as i64,
            "ne"               => (a != b) as i64,
            "slt"              => (a < b) as i64,
            "ugt" | "samesign" => (a > b) as i64,
            "ult"              => ((a as u64) < (b as u64)) as i64,
            _                  => 0,
        }
    }
    else {
        // Opérations arithmétiques / casts
        let toks: Vec<&str> = rhs.split_whitespace().collect();
        // Pattern: "op type %a, %b"  |  "op type %a, N"
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
                "shl"   => a.wrapping_shl(b as u32),
                "ashr"  => (a >> (b & 63)),
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

    regs.insert(dst, val);
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

fn parse_phi(rhs: &str, prev: &str, regs: &BTreeMap<String, i64>, consts: &BTreeMap<String, i64>) -> i64 {
    // phi i32 [ val1, %label1 ], [ val2, %label2 ], ...
    let mut pos = 0usize;
    let bytes = rhs.as_bytes();
    while pos < bytes.len() {
        // Cherche '['
        let Some(open) = rhs[pos..].find('[') else { break };
        let open_abs = pos + open;
        let Some(close) = rhs[open_abs..].find(']') else { break };
        let inner = &rhs[open_abs+1..open_abs+close];
        // inner = " val, %label "
        let parts: Vec<&str> = inner.split(',').collect();
        let val_tok = parts.first().map(|s| s.trim()).unwrap_or("0");
        let lbl_tok = parts.get(1).map(|s| s.trim().trim_start_matches('%')).unwrap_or("");
        if lbl_tok == prev {
            return resolve(val_tok, regs, consts);
        }
        pos = open_abs + close + 1;
    }
    0
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

/// Rendu TTF via TtfParser.ovc + GlyphRasterizer.ovc.
/// API TtfParser : Load(fontPtr, size) → GetGlyphId(cp) → GetGlyfOffset(id)
/// API GlyphRasterizer : RasterizeGlyph(fontPtr + glyfOffset, pixelSize)
unsafe fn draw_text_ttf(
    x: i32, y: i32, tp: *const u8, fg: u32, bg: u32,
    font: *const u8, size: i32,
    fb: *mut u32, s: i32, ctx: &ExecCtx,
) {
    let ttf_bytes  = match FONT_TTF_OVC.as_deref()  { Some(b) => b, None => { draw_text_bitmap(x, y, tp, fg, bg, fb, s); return; } };
    let rast_bytes = match FONT_RAST_OVC.as_deref() { Some(b) => b, None => { draw_text_bitmap(x, y, tp, fg, bg, fb, s); return; } };
    let ttf_text   = core::str::from_utf8(ttf_bytes).unwrap_or("");
    let rast_text  = core::str::from_utf8(rast_bytes).unwrap_or("");

    // WoffReader est nécessaire pour Load (décode WOFF/WOFF2 avant parsing TTF)
    let woff_bytes = FONT_WOFF_OVC.as_deref().unwrap_or(&[]);
    let woff_text  = core::str::from_utf8(woff_bytes).unwrap_or("");

    // Étape 1 : Load(fontPtr, fontSize) — initialise les globals TtfParser
    // WoffReader et GlyphRasterizer doivent être accessibles pour Load
    let load_mods = if woff_text.starts_with("# Vyft OVC") {
        alloc::vec![("WoffReader", woff_text), ("GlyphRasterizer", rast_text)]
    } else {
        alloc::vec![("GlyphRasterizer", rast_text)]
    };
    let load_r = exec_fn_raw_with_mods(
        ttf_bytes, "TtfParser", "Load",
        &[font as i64, ctx.font_len as i64], ctx, &load_mods,
    );
    if load_r != 0 {
        serial_log(b"[TTF] Load failed\r\n");
        draw_text_bitmap(x, y, tp, fg, bg, fb, s);
        return;
    }
    serial_log(b"[TTF] Load OK\r\n");

    // Modules disponibles pour les appels cross-module
    let ttf_mods  = [("GlyphRasterizer", rast_text)];
    let rast_mods = [("TtfParser", ttf_text)];

    let mut cx = x;
    let mut ci = 0usize;
    loop {
        let ch = *tp.add(ci);
        if ch == 0 { break; }
        ci += 1;

        // Étape 2 : GetGlyphId(codepoint) → glyphId
        let glyph_id = exec_fn_raw_with_mods(
            ttf_bytes, "TtfParser", "GetGlyphId",
            &[ch as i64], ctx, &ttf_mods,
        );

        // Étape 3 : GetGlyfOffset(glyphId) → offset dans le TTF
        let glyf_off = exec_fn_raw_with_mods(
            ttf_bytes, "TtfParser", "GetGlyfOffset",
            &[glyph_id], ctx, &ttf_mods,
        );

        // Le pointeur vers les données du glyphe = fontPtr + offset
        let glyf_data = (font as i64).wrapping_add(glyf_off);

        if glyf_off == 0 || glyf_data == 0 {
            cx += size / 2;
            continue;
        }

        // Étape 4 : RasterizeGlyph(glyfDataPtr, pixelSize) → bitmap ptr
        let bitmap = exec_fn_raw_with_mods(
            rast_bytes, "GlyphRasterizer", "RasterizeGlyph",
            &[glyf_data, size as i64], ctx, &rast_mods,
        );

        if bitmap == 0 {
            cx += size / 2;
            continue;
        }

        // Écrire le bitmap dans le framebuffer
        let gw = RAST_W as i32;
        let gh = RAST_H as i32;
        let bptr = bitmap as *const u8;
        for row in 0..gh {
            for col in 0..gw {
                let alpha = *bptr.add((row * gw + col) as usize);
                if alpha > 0 {
                    let px_idx = ((y + row) * s + cx + col) as usize;
                    // Blend simple : alpha > 127 → fg, sinon bg
                    fb.add(px_idx).write_volatile(if alpha > 127 { fg } else { bg });
                }
            }
        }
        cx += gw + 1;
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
    let mut regs: BTreeMap<String, i64> = BTreeMap::new();
    for (i, a) in arg_names.iter().enumerate() {
        regs.insert(a.clone(), args.get(i).copied().unwrap_or(0));
    }
    let mut globals: BTreeMap<String, i64> = BTreeMap::new();
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
    _globals:&BTreeMap<String, i64>,
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
                let off = args[1] as usize;
                let v   = args[2] as u8;
                if !p.is_null() { unsafe { *p.add(off) = v; } }
            }
            0
        },
        "DrvManSpec___PtrWrite32At___" => {
            if args.len() >= 3 {
                let p   = args[0] as *mut u8;
                let off = args[1] as usize;
                let v   = (args[2] as u32).to_be_bytes(); // SRFS = big-endian
                if !p.is_null() {
                    unsafe {
                        *p.add(off)   = v[0]; *p.add(off+1) = v[1];
                        *p.add(off+2) = v[2]; *p.add(off+3) = v[3];
                    }
                }
            }
            0
        },
        "DrvManSpec___WoffGetData___"     => 0,
        "DrvManSpec___WoffScratchGet___"  => 0,
        "DrvManSpec___WoffScratchSet___"  => 0,

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
        "DrvManSpec___PtrReadI16At___" | "DrvManSpec___PtrRead16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1] as usize;
                if !base.is_null() {
                    unsafe {
                        let hi = *base.add(off)     as i16;
                        let lo = *base.add(off + 1) as i16;
                        ((hi << 8) | lo) as i64
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadU16At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1] as usize;
                if !base.is_null() {
                    unsafe {
                        let hi = *base.add(off)     as u16;
                        let lo = *base.add(off + 1) as u16;
                        ((hi << 8) | lo) as i64
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrReadI32At___" | "DrvManSpec___PtrRead32At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1] as usize;
                if !base.is_null() {
                    unsafe {
                        let b0 = *base.add(off)     as i32;
                        let b1 = *base.add(off + 1) as i32;
                        let b2 = *base.add(off + 2) as i32;
                        let b3 = *base.add(off + 3) as i32;
                        ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) as i64
                    }
                } else { 0 }
            } else { 0 }
        },
        "DrvManSpec___PtrRead8At___" => {
            if args.len() >= 2 {
                let base = args[0] as *const u8;
                let off  = args[1] as usize;
                if !base.is_null() { unsafe { *base.add(off) as i64 } } else { 0 }
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
        "DrvAPIInterCon___MemAlloc___" => {
            if args.len() >= 1 {
                let size = args[0] as usize;
                if size == 0 { return 0; }
                let layout = alloc::alloc::Layout::from_size_align(size, 8)
                    .unwrap_or(alloc::alloc::Layout::new::<u8>());
                let p = unsafe { alloc::alloc::alloc_zeroed(layout) };
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

        // PtrWrite32At(fb_ptr, byte_offset, value)
        "DrvManSpec___PtrWrite32At___" => {
            if args.len() >= 3 {
                let fb   = args[0] as *mut u8;
                let off  = args[1] as usize;
                let val  = args[2] as u32;
                if !fb.is_null() {
                    unsafe { (fb.add(off) as *mut u32).write_volatile(val); }
                }
            }
            0
        },

        // PtrRead8At(base_ptr, byte_offset)
        "DrvManSpec___PtrRead8At___" => {
            if args.len() >= 2 {
                let p   = args[0] as *const u8;
                let off = args[1] as usize;
                if !p.is_null() {
                    return unsafe { *p.add(off) } as i64;
                }
            }
            0
        },

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

        // DrvAPIInterCon***FontGetDefault*** — retourne _fontPtr de SluFontConf
        // (les bytes TTF chargés par SluFontConf::onDriverInit via SRFS)
        "DrvAPIInterCon___FontGetDefault___" => {
            let (ptr, _) = srfs_font_ptr();
            ptr as i64
        },

        // GpuDrawTextFont(x, y, text, fg, bg, font, pixelSize)
        // Version avec police TTF — utilise TtfParser + GlyphRasterizer si disponibles,
        // sinon fallback sur FONT8X16.
        "DrvAPIInterCon___GpuDrawTextFont___" => {
            unsafe { GPU_TEXTS += 1; }
            serial_log(b"[GPU] GpuDrawTextFont\r\n");
            if args.len() >= 5 {
                let x    = args[0] as i32;
                let y    = args[1] as i32;
                let tp   = args[2] as *const u8;
                let fg   = args[3] as u32;
                let bg   = args[4] as u32;
                let font = if args.len() >= 6 { args[5] as *const u8 } else { core::ptr::null() };
                let size = if args.len() >= 7 { args[6] as i32 } else { 16 };
                let fb   = ctx.fb;
                let s    = ctx.stride;

                // Utiliser le rendu TTF si font disponible, sinon FONT8X16
                let has_ttf = !font.is_null() && !ctx.font.is_null() && ctx.font_len > 0;

                if !fb.is_null() && !tp.is_null() {
                    if has_ttf && font_ovc_ready() {
                        unsafe { draw_text_ttf(x, y, tp, fg, bg, font, size, fb, s, ctx); }
                    } else {
                        unsafe { draw_text_bitmap(x, y, tp, fg, bg, fb, s); }
                    }
                }
            }
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

        // self___onDriverInit → appelé depuis APrevent::OnPowerOn
        "self___onDriverInit" => 0,

        _ => 0,
    }
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
