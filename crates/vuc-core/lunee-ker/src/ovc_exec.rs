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

static mut GPU_OVC: Option<Vec<u8>> = None;

pub fn register_gpu_ovc(ovc: Vec<u8>) {
    unsafe { GPU_OVC = Some(ovc); }
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

// ── Contexte d'exécution ──────────────────────────────────────────────────────

/// Contexte d'exécution pour un OVC — fourni par le kernel au moment du rendu.
/// La police 8×16 est embarquée dans ovc_exec (FONT8X16), pas dans la struct.
pub struct ExecCtx {
    pub fb:     *mut u32,
    pub width:  i32,
    pub height: i32,
    pub stride: i32,
}

unsafe impl Send for ExecCtx {}
unsafe impl Sync for ExecCtx {}

// ── Utilitaires de parsing ────────────────────────────────────────────────────

/// Extrait le nom du registre depuis `%name` ou `%name.suffix`.
fn reg_name(tok: &str) -> String {
    tok.trim_start_matches('%').to_string()
}

/// Résout un opérande : `%name`, entier littéral, ou `inttoptr (iN N to ptr)`.
fn resolve(tok: &str, regs: &BTreeMap<String, i64>, consts: &BTreeMap<String, i64>) -> i64 {
    let tok = tok.trim().trim_end_matches(',');
    if tok.starts_with('%') {
        return *regs.get(reg_name(tok).as_str()).unwrap_or(&0);
    }
    if tok.starts_with('@') {
        let k = tok.trim_start_matches('@').trim_end_matches(',');
        return *consts.get(k).unwrap_or(&0);
    }
    // inttoptr (i32 N to ptr)  |  inttoptr (i64 N to ptr)
    if let Some(p) = tok.find("inttoptr (") {
        let rest = &tok[p + 10..];
        if let Some(sp) = rest.find(' ') {
            return rest[..sp].parse().unwrap_or(0);
        }
    }
    // null → 0
    if tok == "null" || tok == "nullptr" { return 0; }
    tok.parse().unwrap_or(0)
}

/// Lit les arguments d'un `call` ou d'une `define` : `(ptr %a, i32 %b, …)`.
/// Retourne la liste des valeurs ou noms d'arguments.
fn parse_call_args(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let open  = match src.find('(') { Some(p) => p, None => return out };
    let close = match src.rfind(')') { Some(p) => p, None => return out };
    let inner = &src[open+1..close];
    for part in inner.split(',') {
        let part = part.trim();
        // dernier token = valeur / registre
        let last = part.split_whitespace().last().unwrap_or("").trim();
        out.push(last.to_string());
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
        // Stocker la chaîne dans une alloc Box, retourner le pointeur brut comme i64
        let boxed: alloc::boxed::Box<str> = s.into_boxed_str();
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
            if ovc[i..].starts_with("define ") && ovc[i..].contains(marker.as_str()) {
                start = Some(i);
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
        .filter(|s| s.starts_with('%'))
        .map(|s| s.trim_start_matches('%').to_string())
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
        let parts: Vec<&str> = instr.splitn(3, ',').collect();
        let src_tok  = parts[0].trim().split_whitespace().last().unwrap_or("0");
        let dest_part = parts.get(1).unwrap_or(&"").trim();
        let dest_tok = dest_part.split_whitespace().last().unwrap_or("").trim_end_matches(',');
        let dest_k   = dest_tok.trim_start_matches('@').to_string();
        let val = if src_tok == "true" { 1i64 }
                  else if src_tok == "false" { 0i64 }
                  else { resolve(src_tok, regs, consts) };
        globals.insert(dest_k, val);
        return RunResult::Ok;
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
    else if rhs.starts_with("select ") {
        // select i1 %cond, ptr A, ptr B
        let parts: Vec<&str> = rhs.splitn(4, ',').collect();
        let cond_tok = parts[0].trim().split_whitespace().last().unwrap_or("0");
        let cond = resolve(cond_tok, regs, consts) != 0;
        let a_tok = parts.get(1).unwrap_or(&"0").trim().split_whitespace().last().unwrap_or("0");
        let b_tok = parts.get(2).unwrap_or(&"0").trim().split_whitespace().last().unwrap_or("0");
        if cond { resolve(a_tok, regs, consts) } else { resolve(b_tok, regs, consts) }
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
                // casts — même valeur
                "zext" | "sext" | "trunc" | "inttoptr" | "ptrtoint"
                | "bitcast" => a,
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

        // printf — no-op silencieux en UEFI (pas de console série ici)
        "printf" => 0,

        // self___onDriverInit → appelé depuis APrevent::OnPowerOn
        // Pour SluGpu : GpuInit sera appelé séparément via exec_fn("GpuInit", ...)
        "self___onDriverInit" => 0,

        _ => 0,
    }
}
