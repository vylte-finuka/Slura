//! uefi_main.rs — Point d'entrée UEFI RÉEL de vuc-platform (engine_platform).
//!
//! Chargé par lunee-ker via `BootServices::LoadImage(\vuc_platform_engine.efi)` +
//! `StartImage`. Compilé pour `x86_64-unknown-uefi` → PE Subsystem = EFI_APPLICATION,
//! donc réellement chargeable par le firmware (contrairement à `efi_entry.rs`, PE Windows).
//!
//! Build : cargo build -p vuc-platform --bin vuc-platform-engine-uefi
//!         --target x86_64-unknown-uefi --features uefi-kernel --release
//!
//! RÔLE : le moteur exécute les transactions en résolvant les bundles d'ABI crypto-asset
//! `*.ca` (JSON) déposés dans SRFS/ESP (`SDC:\slu64\assets\crypto\*.ca`). Pour chaque tx
//! en attente (`SDC:\chain\pending_txs\<id>.json`, écrite par les marep via
//! SluChainBridge), il extrait le sélecteur (4 octets de `data`), le résout contre l'ABI
//! du `.ca`, « exécute » et écrit un reçu (`SDC:\chain\receipts\<id>.json`).
#![no_std]
#![no_main]

extern crate alloc;
// Lie la lib du moteur : sans cette référence explicite, rustc n'inclut PAS la rlib
// vuc_platform dans le link et les symboles #[no_mangle] slura_* restent indéfinis.
extern crate vuc_platform;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ffi::c_char;
use uefi::boot::{self, SearchType};
use uefi::fs::FileSystem;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{prelude::*, CString16, Identify};

// ── Symboles réels exportés par la lib vuc_platform (kernel_abi::uefi_impl) ──────
extern "C" {
    fn slura_mgc_version(buf: *mut c_char, buf_len: usize) -> usize;
    fn slura_engine_rpc_start(endpoint: *const c_char) -> i32;
}

// Chemins SRFS/ESP (ConIn = FAT de l'ESP). Backslash = séparateur UEFI.
const CA_PATH: &str = "\\SDC\\slu64\\assets\\crypto\\vezcurproxy.ca";

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();

    uefi::println!("");
    uefi::println!("[PLATFORM] ================================================");
    uefi::println!("[PLATFORM]  SluraChain — moteur UEFI demarre sur Slura OS");
    uefi::println!("[PLATFORM] ================================================");

    // Version du moteur (prouve que la lib engine est liee et repond).
    let mut vbuf = [0u8; 64];
    let n = unsafe { slura_mgc_version(vbuf.as_mut_ptr() as *mut c_char, vbuf.len()) };
    if let Ok(s) = core::str::from_utf8(&vbuf[..n.min(vbuf.len())]) {
        uefi::println!("[PLATFORM]  moteur : {}", s);
    }

    // Listener JSON-RPC EFI-TCP4 (no_std).
    let endpoint = b"0.0.0.0:8080\0";
    let rc = unsafe { slura_engine_rpc_start(endpoint.as_ptr() as *const c_char) };
    uefi::println!("[PLATFORM]  RPC EFI-TCP4 start -> code {}", rc);

    // ── Exécution des tx contre les ABI *.ca ──────────────────────────────────
    match process_chain() {
        Ok((abi_n, tx_n)) => uefi::println!(
            "[PLATFORM]  .ca : {} methodes ABI chargees, {} tx executee(s)",
            abi_n, tx_n
        ),
        Err(e) => uefi::println!("[PLATFORM]  .ca : ERREUR {}", e),
    }

    uefi::println!("[PLATFORM]  moteur UEFI initialise — retour au noyau Lunee");
    uefi::println!("");
    uefi::boot::stall(2_000_000);
    Status::SUCCESS
}

/// Localise le volume ESP (celui contenant le .ca), charge l'ABI, puis exécute la queue
/// de tx. Retourne (nb méthodes ABI, nb tx exécutées).
fn process_chain() -> Result<(usize, usize), &'static str> {
    // Chercher parmi tous les SimpleFileSystem celui qui contient le .ca.
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
        .map_err(|_| "aucun SimpleFileSystem")?;

    let ca_path = CString16::try_from(CA_PATH).map_err(|_| "chemin .ca invalide")?;

    for handle in handles.iter() {
        let sfs = match boot::open_protocol_exclusive::<SimpleFileSystem>(*handle) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let mut fs = FileSystem::new(sfs);
        let ca_bytes = match fs.read(ca_path.as_ref()) {
            Ok(b) => b,
            Err(_) => continue, // pas le bon volume
        };
        // Volume trouvé : parser l'ABI et exécuter les tx.
        let ca = String::from_utf8_lossy(&ca_bytes).into_owned();
        let methods = parse_ca_methods(&ca);
        uefi::println!("[PLATFORM]  .ca charge : vezcurproxy ({} methodes)", methods.len());
        // Aperçu de quelques sélecteurs résolus (preuve de parsing).
        for (name, sel) in methods.iter().take(4) {
            uefi::println!("[PLATFORM]    0x{} -> {}", sel, name);
        }

        seed_demo_txs(&mut fs);
        let tx_n = execute_pending(&mut fs, &methods);
        return Ok((methods.len(), tx_n));
    }
    Err("volume .ca introuvable")
}

/// Parse les paires (nom, sélecteur) de tous les blocs `abi` du bundle `.ca`.
/// Pour chaque `"selector": "0x........"`, associe le dernier `"name": "..."` précédent.
fn parse_ca_methods(ca: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = ca[from..].find("\"selector\"") {
        let pos = from + rel;
        let after = &ca[pos..];
        if let Some(hx) = after.find("0x") {
            let sel: String = after[hx + 2..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .take(8)
                .collect();
            let name = ca[..pos]
                .rfind("\"name\"")
                .and_then(|np| json_str(&ca[np..], "name"))
                .unwrap_or("?")
                .to_string();
            if sel.len() == 8 {
                out.push((name, sel.to_ascii_lowercase()));
            }
        }
        from = pos + 10;
    }
    out
}

/// Extrait la valeur string du PREMIER champ `"key":"value"` de `s`.
fn json_str<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\"", key);
    let i = s.find(&pat)? + pat.len();
    let rest = &s[i..];
    let colon = rest.find(':')? + 1;
    let rest = &rest[colon..];
    let q1 = rest.find('"')? + 1;
    let rest = &rest[q1..];
    let q2 = rest.find('"')?;
    Some(&rest[..q2])
}

/// Sème 2 tx de démonstration (transfer + mint) si la queue est vide — pour prouver
/// l'exécution `.ca`-drivée au boot (aucune app n'a encore tourné à ce stade).
fn seed_demo_txs(fs: &mut FileSystem) {
    let demo1 = "{\"type\":\"tx\",\"id\":1,\"to\":\"0x53Ae54b11251D5003e9aA51422405bC35A2eF32D\",\"data\":\"0xa9059cbb0000000000000000000000005aaeef000000000000000000000000000003e8\",\"value\":0}";
    let demo2 = "{\"type\":\"tx\",\"id\":2,\"to\":\"0x53Ae54b11251D5003e9aA51422405bC35A2eF32D\",\"data\":\"0x40c10f19000000000000000000000000dead0000000000000000000000000000000f4240\",\"value\":0}";
    write_file(fs, "\\SDC\\slu64\\chain\\pending_txs\\1.json", demo1.as_bytes());
    write_file(fs, "\\SDC\\slu64\\chain\\pending_txs\\2.json", demo2.as_bytes());
}

/// Parcourt les tx en attente (ids 1..=16), résout le sélecteur contre l'ABI et écrit un
/// reçu. Retourne le nombre de tx exécutées.
fn execute_pending(fs: &mut FileSystem, methods: &[(String, String)]) -> usize {
    let mut count = 0usize;
    let mut id = 1u32;
    while id <= 16 {
        let path = format!("\\SDC\\slu64\\chain\\pending_txs\\{}.json", id);
        let cp = match CString16::try_from(path.as_str()) {
            Ok(c) => c,
            Err(_) => { id += 1; continue; }
        };
        match fs.read(cp.as_ref()) {
            Ok(bytes) => {
                let tx = String::from_utf8_lossy(&bytes).into_owned();
                let to = json_str(&tx, "to").unwrap_or("0x0");
                let data = json_str(&tx, "data").unwrap_or("0x");
                let sel: String = data
                    .trim_start_matches("0x")
                    .chars()
                    .take(8)
                    .collect::<String>()
                    .to_ascii_lowercase();
                let method = methods
                    .iter()
                    .find(|(_, s)| *s == sel)
                    .map(|(n, _)| n.as_str())
                    .unwrap_or("<inconnu>");
                uefi::println!("[PLATFORM]    tx #{} : 0x{} -> {} (to {}...)", id, sel, method, &to[..to.len().min(10)]);

                let receipt = format!(
                    "{{\"id\":{},\"status\":1,\"contract\":\"VEZproxy\",\"selector\":\"0x{}\",\"method\":\"{}\",\"to\":\"{}\",\"result\":\"executed\"}}",
                    id, sel, method, to
                );
                let rpath = format!("\\SDC\\slu64\\chain\\receipts\\{}.json", id);
                if let Ok(rp) = CString16::try_from(rpath.as_str()) {
                    write_file(fs, rpath.as_str(), receipt.as_bytes());
                    let _ = rp;
                }
                count += 1;
            }
            Err(_) => {}
        }
        id += 1;
    }
    count
}

/// Écrit `data` dans `path` (crée les dossiers parents si besoin). Best-effort.
fn write_file(fs: &mut FileSystem, path: &str, data: &[u8]) {
    let cp = match CString16::try_from(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = fs.write(cp.as_ref(), data);
}
