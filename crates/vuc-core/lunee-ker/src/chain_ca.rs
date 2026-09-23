//! chain_ca.rs — Exécuteur de transactions piloté par les ABI crypto-asset (`.ca`).
//!
//! Pur (core + alloc, AUCUNE dépendance UEFI) → linkable dans le noyau sans conflit avec
//! la crate `uefi` 0.27. Résout le sélecteur (4 octets de calldata) contre l'ABI JSON d'un
//! bundle `.ca` et produit un reçu JSON. Appelé SYNCHRONE par `ovc_exec::BlockchainQueueTx`
//! à chaque tx mise en file par un marep via SluChainBridge → le reçu atterrit dans le même
//! store (`SRFS_CACHE`) que celui lu par `GetTxStatus`/`BlockchainReadMeta`.
//!
//! Le moteur UEFI autonome (`vuc_platform_engine.efi`, `uefi_main.rs`) porte la même logique
//! pour son mode démonstration au boot ; ici c'est le chemin de production (tx d'app réelles).

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Résout le sélecteur du calldata `data` contre l'ABI du bundle `.ca` et retourne un reçu
/// JSON. `to` = adresse destination, `id` = txId. status = 1 (minée) si le sélecteur est
/// résolu, 2 (échec) sinon.
pub fn execute_tx(ca: &[u8], to: &str, data: &str, id: u32) -> String {
    let ca_str = core::str::from_utf8(ca).unwrap_or("");
    let methods = parse_ca_methods(ca_str);
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
    let status = if method == "<inconnu>" { 2 } else { 1 };
    format!(
        "{{\"id\":{},\"status\":{},\"contract\":\"VEZproxy\",\"selector\":\"0x{}\",\"method\":\"{}\",\"to\":\"{}\",\"result\":\"executed\"}}",
        id, status, sel, method, to
    )
}

/// Solde de TEST attribué au gestionnaire (owner) du stablecoin VEZ. Le réseau est en
/// TEST → pas d'état on-chain réel ; ce solde de démonstration alimente `balanceOf`.
pub const TEST_VEZ_BALANCE: i64 = 1_000_000;

/// Adresse `owner` déclarée dans le bundle `.ca` = gestionnaire du stablecoin.
pub fn owner_addr(ca: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(ca).ok()?;
    json_str(s, "owner").map(|v| v.to_string())
}

/// Symbole du token (ex. "VEZ") déclaré dans le `.ca`.
pub fn token_symbol(ca: &[u8]) -> String {
    core::str::from_utf8(ca)
        .ok()
        .and_then(|s| json_str(s, "symbol"))
        .unwrap_or("?")
        .to_string()
}

/// Vrai si le `.ca` déclare bien la méthode ERC20 `balanceOf` (sélecteur 0x70a08231).
pub fn has_balance_of(ca: &[u8]) -> bool {
    let s = core::str::from_utf8(ca).unwrap_or("");
    parse_ca_methods(s).iter().any(|(_, sel)| sel == "70a08231")
}

/// Parse les paires (nom, sélecteur) de tous les blocs `abi` du bundle `.ca`. Pour chaque
/// `"selector": "0x........"`, associe le dernier `"name": "..."` qui le précède.
pub fn parse_ca_methods(ca: &str) -> Vec<(String, String)> {
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
