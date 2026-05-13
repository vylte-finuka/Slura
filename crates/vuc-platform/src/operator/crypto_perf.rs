use hex;
use rand::{Rng, RngCore};
use sha3::{Digest, Keccak256, Keccak512};
use k256::ecdsa::{SigningKey, VerifyingKey};
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeMap;
use vuc_tx::slurachain_vm::{AccountState, SlurachainVm};
use anyhow::Context;



// ─────────────────────────────────────────────
//  VTREE‑X (renforcé) — structure VTREE intacte
// ─────────────────────────────────────────────

fn vtree_generate_master_key_x() -> [u8; 64] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let mut h = Keccak512::new();
    h.update(&seed);
    h.update(b"VTREE-X-MasterKey");

    let out = h.finalize();
    let mut privkey = [0u8; 64];
    privkey.copy_from_slice(&out[..64]);
    privkey
}

fn vtree_split_x(privkey: &[u8; 64]) -> [Vec<u8>; 5] {
    let mut out = [vec![], vec![], vec![], vec![], vec![]];
    let fragment_size = 13;

    for i in 0..5 {
        let start = i * fragment_size;
        let end = start + fragment_size;
        out[i] = privkey[start..end].to_vec();
    }

    out
}

fn vtree_inversion_secret_x(privkey: &[u8; 64]) -> [u8; 64] {
    let mut h = Keccak512::new();
    h.update(privkey);
    h.update(b"VTREE-X-InversionSecret");

    let out = h.finalize();
    let mut s = [0u8; 64];
    s.copy_from_slice(&out[..64]);
    s
}

fn vtree_mix24_x(input: &[u8], secret: &[u8; 64]) -> Vec<u8> {
    let mut state = input.to_vec();

    for _round in 0..24 {
        let mut h = Keccak256::new();

        // Multiplication mod 2^256
        let mut mul = [0u8; 32];
        for i in 0..state.len().min(32) {
            mul[i] = state[i].wrapping_mul(0xD3);
        }

        // Rotations
        let rot_r = state.iter().map(|b| b.rotate_right(5)).collect::<Vec<_>>();
        let rot_l = state.iter().map(|b| b.rotate_left(7)).collect::<Vec<_>>();

        // XOR secret renforcé
        let xor = state
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ secret[i % 64])
            .collect::<Vec<_>>();

        // Domain separator
        h.update(b"VTREE-X-2026");
        h.update(&state);
        h.update(&mul);
        h.update(&rot_r);
        h.update(&rot_l);
        h.update(&xor);

        state = h.finalize().to_vec();
    }

    // Final compression hash
    let mut final_h = Keccak256::new();
    final_h.update(&state);
    let compressed = final_h.finalize();

    // Checksum anti‑tampering
    let checksum = compressed[0] ^ compressed[15] ^ compressed[31];

    let mut out = compressed[..32].to_vec();
    out.push(checksum);

    out
}



// ─────────────────────────────────────────────
//  TON CODE ORIGINAL — inchangé
// ─────────────────────────────────────────────

pub fn generate_slu_zk_address(
    contract_info: &str,
    id_length: usize,
    zk_print_length: usize,
) -> String {
    let mut rng = rand::thread_rng();

    let mut hasher_id = Keccak256::new();
    hasher_id.update(contract_info.as_bytes());
    hasher_id.update(b"slu-id-v1");
    hasher_id.update(&rng.gen::<[u8; 8]>());
    let hash_id = hex::encode(&hasher_id.finalize()[..id_length.min(32)]);

    let mut hasher_zk = Keccak256::new();
    hasher_zk.update(&hash_id);
    hasher_zk.update(contract_info.as_bytes());
    hasher_zk.update(b"slu-zk-print-v1-2026");
    hasher_zk.update(&rng.gen::<[u8; 16]>());
    let hash_zk_print = hex::encode(&hasher_zk.finalize()[..zk_print_length.min(32)]);

    format!("*slu*#*{}*#*{}#", hash_id, hash_zk_print)
}



// ─────────────────────────────────────────────
//  TON generate_and_create_account()
//  → inchangé en signature
//  → mais VTREE‑X intégré proprement
// ─────────────────────────────────────────────

pub async fn generate_and_create_account(
    vm: &mut SlurachainVm,
    contract_info: &str,
) -> Result<(String, String), anyhow::Error> {

    // 1. Adresse EVM classique
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
    // 2. VTREE‑X (structure VTREE intacte)
    // ─────────────────────────────────────────
    let vtree_master = vtree_generate_master_key_x();
    let fragments = vtree_split_x(&vtree_master);
    let inv_secret = vtree_inversion_secret_x(&vtree_master);

    let mut vtree_x = vec![];
    for f in fragments.iter() {
        vtree_x.push(vtree_mix24_x(f, &inv_secret));
    }


    // 3. Adresse SLU‑ZK (inchangée)
    let slu_zk_addr = generate_slu_zk_address(contract_info, 10, 32);


    // 4. Insertion VM
    let mut accounts = vm.state.accounts.write().await;

    let mut resources = BTreeMap::new();
    resources.insert("eth_address".to_string(), json!(eth_address));
    resources.insert("slu_zk_address".to_string(), json!(slu_zk_addr));

    // Ajout VTREE‑X dans resources
    resources.insert("vtree_master_hash".to_string(), json!(hex::encode(Keccak256::digest(&vtree_master))));
    resources.insert("vtree_fragments_x".to_string(), json!(vtree_x));

    resources.insert("privkey_hash".to_string(), json!(hex::encode(Keccak256::digest(privkey_hex.as_bytes()))));
    resources.insert("address_type".to_string(), json!("user+zk-print+vtree-x"));
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

    accounts.insert(eth_address.clone(), account.clone());

    println!("Compte créé avec deux adresses + VTREE‑X :");
    println!("  • Ethereum racine : {}", eth_address);
    println!("  • SLU zk-print     : {}", slu_zk_addr);

    Ok((eth_address, slu_zk_addr))
}
