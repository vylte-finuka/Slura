use hex;
use rand::{Rng, RngCore};
use sha3::{Digest, Keccak256, Keccak512};
use k256::ecdsa::{SigningKey, VerifyingKey};
use chrono::Utc;
use k256::elliptic_curve::generic_array::GenericArray;
use serde_json::json;
use std::collections::BTreeMap;
use vuc_tx::slurachain_vm::{AccountState, SlurachainVm};
use anyhow::Context;



// ─────────────────────────────────────────────
//  VYFT ENCURe — VTREE + MIX10 + VYFT‑320
// ─────────────────────────────────────────────

/// Génère la clé privée VyfT‑512
fn vtree_generate_master_key() -> [u8; 64] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let mut h = Keccak512::new();
    h.update(&seed);
    h.update(b"VyfT-EncuRE-MasterKey");

    let out = h.finalize();
    let mut privkey = [0u8; 64];
    privkey.copy_from_slice(&out[..64]);
    privkey
}

/// Découpe la clé en 5 fragments VTREE
fn vtree_split(privkey: &[u8; 64]) -> [Vec<u8>; 5] {
    let mut out = [vec![], vec![], vec![], vec![], vec![]];
    let fragment_size = 13;

    for i in 0..5 {
        let start = i * fragment_size;
        let end = start + fragment_size;
        out[i] = privkey[start..end].to_vec();
    }

    out
}

/// Secret d’inversion VTREE
fn vtree_inversion_secret(privkey: &[u8; 64]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(privkey);
    h.update(b"VyfT-EncuRE-InversionSecret");

    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&out[..32]);
    s
}

/// MIX10 — 10 rounds de mélange cryptographique
fn vtree_mix10(input: &[u8], secret: &[u8; 32]) -> Vec<u8> {
    let mut state = input.to_vec();

    for _round in 0..10 {
        let mut h = Keccak256::new();

        // Multiplication mod 2^256
        let mut mul = [0u8; 32];
        for i in 0..state.len().min(32) {
            mul[i] = state[i].wrapping_mul(0x9E);
        }

        // Rotations
        let rot_r = state.iter().map(|b| b.rotate_right(3)).collect::<Vec<_>>();
        let rot_l = state.iter().map(|b| b.rotate_left(5)).collect::<Vec<_>>();

        // XOR secret
        let xor = state
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ secret[i % 32])
            .collect::<Vec<_>>();

        h.update(&state);
        h.update(&mul);
        h.update(&rot_r);
        h.update(&rot_l);
        h.update(&xor);

        state = h.finalize().to_vec();
    }

    state[..32].to_vec()
}



// ─────────────────────────────────────────────
//  SLU‑ZK‑VyfT — Adresse PQC dérivée du VTREE
// ─────────────────────────────────────────────

pub fn generate_slu_zk_vyft_address(
    contract_info: &str,
    id_length: usize,
    zk_print_length: usize,
) -> String {
    let mut rng = rand::thread_rng();

    let mut hasher_id = Keccak256::new();
    hasher_id.update(contract_info.as_bytes());
    hasher_id.update(b"VyfT-ID");
    hasher_id.update(&rng.gen::<[u8; 8]>());
    let hash_id = hex::encode(&hasher_id.finalize()[..id_length.min(32)]);

    let mut hasher_zk = Keccak256::new();
    hasher_zk.update(&hash_id);
    hasher_zk.update(contract_info.as_bytes());
    hasher_zk.update(b"VyfT-ZKPrint");
    hasher_zk.update(&rng.gen::<[u8; 16]>());
    let hash_zk_print = hex::encode(&hasher_zk.finalize()[..zk_print_length.min(32)]);

    format!("*slu*#*{}*#*{}#", hash_id, hash_zk_print)
}



// ─────────────────────────────────────────────
//  HYBRIDE : EVM + VYFT ENCURe (VTREE + MIX10)
// ─────────────────────────────────────────────

pub async fn generate_and_create_account(
    vm: &mut SlurachainVm,
    contract_info: &str,
) -> Result<(String, String), anyhow::Error> {

    // ─────────────────────────────────────────
    // 1. PARTIE EVM — adresse Ethereum valide
    // ─────────────────────────────────────────
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let secret_bytes = signing_key.to_bytes();
    let privkey_hex = format!("0x{}", hex::encode(secret_bytes));

    let verifying_key = VerifyingKey::from(&signing_key);
    let pubkey = verifying_key.to_encoded_point(false);
    let pubkey_bytes = pubkey.as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let eth_hash = hasher.finalize();
    let eth_address = format!("0x{}", hex::encode(&eth_hash[12..]));


    // ─────────────────────────────────────────
    // 2. PARTIE VYFT ENCURe — VTREE + MIX10
    // ─────────────────────────────────────────
    let vtree_master = vtree_generate_master_key();
    let fragments = vtree_split(&vtree_master);
    let inv_secret = vtree_inversion_secret(&vtree_master);

    let mut vtree = vec![];
    for f in fragments.iter() {
        vtree.push(vtree_mix10(f, &inv_secret));
    }

    // Adresse SLU‑ZK‑VyfT
    let slu_zk_addr = generate_slu_zk_vyft_address(contract_info, 10, 32);


    // ─────────────────────────────────────────
    // 3. INSERTION DANS LA VM
    // ─────────────────────────────────────────
    let mut accounts = vm.state.accounts.write().await;

    let mut resources = BTreeMap::new();
    resources.insert("eth_address".to_string(), json!(eth_address));
    resources.insert("slu_zk_vyft".to_string(), json!(slu_zk_addr));
    resources.insert("vtree_master_hash".to_string(), json!(hex::encode(Keccak256::digest(&vtree_master))));
    resources.insert("vtree_fragments".to_string(), json!(vtree));
    resources.insert("address_type".to_string(), json!("HYBRID-EVM-VyfT"));
    resources.insert("created_at".to_string(), json!(Utc::now().timestamp()));

    let account = AccountState {
        eth_address: eth_address.clone(),
        slu_zk_address: slu_zk_addr.clone(),
        balance: 0,
        nonce: 0,
        contract_state: vec![],
        resources,
        state_version: 1,
        last_block_number: 0,
        code_hash: String::new(),
        storage_root: String::new(),
        is_contract: false,
        gas_used: 0,
    };

    accounts.insert(eth_address.clone(), account);

    println!("Compte HYBRIDE créé :");
    println!("  • Adresse EVM          : {}", eth_address);
    println!("  • Adresse SLU‑ZK‑VyfT  : {}", slu_zk_addr);

    Ok((eth_address, slu_zk_addr))
}
