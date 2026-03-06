use hex;
use rand::{Rng};
use sha3::{Digest, Keccak256};
use k256::ecdsa::{SigningKey, VerifyingKey};
use chrono::Utc;
use k256::elliptic_curve::generic_array::GenericArray;
use serde_json::json;
use std::collections::BTreeMap;
use vuc_tx::slurachain_vm::{AccountState, SlurachainVm};
use anyhow::Context;

/// Génère une adresse au format EXACT demandé :
/// *slu*#*{hash_id}*#*{hash_zk_print}#
pub fn generate_slu_zk_address(
    contract_info: &str,
    id_length: usize,          // ex: 10 hex chars pour hash_id
    zk_print_length: usize,    // ex: 32 hex chars pour zk_print
) -> String {
    let mut rng = rand::thread_rng();

    // ─── hash_id (court) ───
    let mut hasher_id = Keccak256::new();
    hasher_id.update(contract_info.as_bytes());
    hasher_id.update(b"slu-id-v1");
    hasher_id.update(&rng.gen::<[u8; 8]>());
    let hash_id = hex::encode(&hasher_id.finalize()[..id_length.min(32)]);

    // ─── hash_zk_print (long) ───
    let mut hasher_zk = Keccak256::new();
    hasher_zk.update(&hash_id);
    hasher_zk.update(contract_info.as_bytes());
    hasher_zk.update(b"slu-zk-print-v1-2026");
    hasher_zk.update(&rng.gen::<[u8; 16]>());
    let hash_zk_print = hex::encode(&hasher_zk.finalize()[..zk_print_length.min(32)]);

    // ─── Assemblage EXACT du format ───
    format!("*slu*#*{}*#*{}#", hash_id, hash_zk_print)
}

/// Génère l'adresse + clé privée + insertion VM
pub async fn generate_and_create_account(
    vm: &mut SlurachainVm,
    contract_info: &str,   // ex: "acc" ou nom du contrat
) -> Result<(String, String), anyhow::Error> {   // retourne (eth_address, slu_zk_address)
    // 1. Clé privée secp256k1 → adresse Ethereum classique
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

    // 2. Génération de l'adresse zk-print longue (format exact demandé)
    let slu_zk_addr = generate_slu_zk_address(contract_info, 10, 32);

    // 3. Insertion dans la VM avec LES DEUX adresses
    let mut accounts = vm.state.accounts.write().await;

    let mut resources = BTreeMap::new();
    resources.insert("eth_address".to_string(), json!(eth_address));
    resources.insert("slu_zk_address".to_string(), json!(slu_zk_addr));
    resources.insert("privkey_hash".to_string(), json!(hex::encode(Keccak256::digest(privkey_hex.as_bytes()))));
    resources.insert("address_type".to_string(), json!("user+zk-print"));
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
    
    // Optionnel : index secondaire par slu_zk_address si tu veux lookup rapide
    // accounts.insert(slu_zk_addr.clone(), account);  // ← à activer si besoin

    println!("Compte créé avec deux adresses :");
    println!("  • Ethereum racine : {}", eth_address);
    println!("  • SLU zk-print     : {}", slu_zk_addr);

    Ok((eth_address, slu_zk_addr))
}