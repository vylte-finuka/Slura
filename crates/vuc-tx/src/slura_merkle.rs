#![allow(dead_code)]

use alloy_primitives::{keccak256, B256, U256 as AlloyU256};
use reth_trie::{HashedPostState, TrieAccount};
use reth_primitives_traits::Account as RethAccount;
use std::collections::{BTreeMap, HashMap};
use sha3::{Digest, Keccak256};
use hex;
use crate::slurachain_vm::AccountState;

/// Hash Keccak-256 (32 bytes)
pub type MerkleHash = B256;

/// Hash Keccak d'une string
fn keccak_str(s: &str) -> B256 {
    keccak256(s.as_bytes())
}

/// Convertit une adresse hex en B256 (padding left) — VERSION ROBUSTE
fn addr_to_b256(addr: &str) -> B256 {
    let clean = addr.trim_start_matches("0x");

    // Une adresse Ethereum valide = 20 bytes = 40 hex chars
    if clean.len() != 40 {
        panic!("Adresse invalide (longueur incorrecte) : {}", addr);
    }

    let bytes = hex::decode(clean)
        .unwrap_or_else(|_| panic!("Adresse hex invalide : {}", addr));

    if bytes.len() != 20 {
        panic!("Adresse invalide (doit faire 20 bytes) : {}", addr);
    }

    // Padding left vers 32 bytes
    let mut arr = [0u8; 32];
    arr[12..].copy_from_slice(&bytes);
    B256::from(arr)
}

/// Racine canonique d'un trie vide (keccak256(rlp.encode(b"")) = keccak256(0x80))
fn empty_trie_root() -> B256 {
    let empty_rlp = [0x80u8];
    keccak256(&empty_rlp)
}

/// Hash canonique du bytecode vide (keccak256(b""))
fn empty_code_hash() -> B256 {
    keccak256(&[])
}

/// Structure intermédiaire pour le calcul zk-aware
#[derive(Clone, Debug)]
pub struct ExtendedTrieAccount {
    pub evm_account: RethAccount,
    pub slu_zk_hash: B256,
    pub metadata_hash: B256,
    pub storage_root_hash: B256,
    pub state_version: u64,
}

/// Construit un state trie étendu (EVM + zk extensions)
pub fn build_extended_state_trie(
    accounts: &BTreeMap<String, AccountState>,
) -> (HashedPostState, B256, B256) {
    let mut hashed_accounts: Vec<(B256, Option<RethAccount>)> = Vec::new();
    let mut extended_accounts: HashMap<B256, ExtendedTrieAccount> = HashMap::new();

    let empty_root = empty_trie_root();
    let empty_code = empty_code_hash();

    for (addr_str, account) in accounts.iter() {
        let addr = addr_to_b256(addr_str);

        // Compte EVM standard
        let evm_account = RethAccount {
            nonce: account.nonce,
            balance: AlloyU256::from(account.balance),
            bytecode_hash: if account.code_hash.trim().is_empty()
                || account.code_hash.trim() == "0x"
            {
                Some(empty_code)
            } else {
                hex::decode(account.code_hash.trim_start_matches("0x"))
                    .ok()
                    .filter(|v| v.len() == 32)
                    .map(|v| B256::from_slice(&v))
                    .or(Some(empty_code))
            },
        };

        // SLU zk hash
        let slu_zk_hash = if account.slu_zk_address.trim().is_empty() {
            empty_root
        } else {
            keccak_str(&account.slu_zk_address)
        };

        // Metadata hash
        let mut metadata_buf = Vec::new();
        let mut sorted_resources: Vec<(&String, &serde_json::Value)> =
            account.resources.iter().collect();
        sorted_resources.sort_by_key(|&(k, _)| k);

        for (k, v) in sorted_resources {
            metadata_buf.extend_from_slice(k.as_bytes());
            if let Ok(json) = serde_json::to_vec(v) {
                metadata_buf.extend_from_slice(&json);
            }
        }

        let metadata_hash = keccak256(&metadata_buf);

        // Storage root hash
        let storage_root_hash = if account.storage_root.trim().is_empty() {
            empty_root
        } else {
            keccak_str(&account.storage_root)
        };

        let extended = ExtendedTrieAccount {
            evm_account,
            slu_zk_hash,
            metadata_hash,
            storage_root_hash,
            state_version: account.state_version,
        };

        extended_accounts.insert(addr, extended);
        hashed_accounts.push((addr, Some(evm_account)));
    }

    // Tri obligatoire
    hashed_accounts.sort_by(|a, b| a.0.cmp(&b.0));

    // HashedPostState
    let mut post_state = HashedPostState::default();
    post_state = post_state.with_accounts(
        hashed_accounts.iter().cloned().map(|(addr, acc_opt)| (addr, acc_opt)),
    );

    // Calcul du state root standard (EVM)
    let trie_entries = hashed_accounts.into_iter().filter_map(|(addr, acc_opt)| {
        acc_opt.map(|acc| {
            (
                addr,
                TrieAccount {
                    nonce: acc.nonce,
                    balance: acc.balance,
                    storage_root: empty_trie_root(),
                    code_hash: acc.bytecode_hash.unwrap_or_else(empty_code_hash),
                },
            )
        })
    });

    let standard_root = reth_trie::root::state_root(trie_entries);

    // Calcul du root zk-aware
    let mut zk_leaves = Vec::new();

    for (addr, ext) in extended_accounts.iter() {
        let mut leaf_buf = Vec::new();
        leaf_buf.extend_from_slice(&addr.to_vec());
        leaf_buf.extend_from_slice(&ext.slu_zk_hash.0);
        leaf_buf.extend_from_slice(&ext.metadata_hash.0);
        leaf_buf.extend_from_slice(&ext.storage_root_hash.0);
        leaf_buf.extend_from_slice(&ext.state_version.to_be_bytes());

        let leaf_hash = keccak256(&leaf_buf);
        zk_leaves.push(leaf_hash);
    }

    zk_leaves.sort();

    let mut hasher = Keccak256::default();
    for leaf in zk_leaves {
        hasher.update(&leaf);
    }
    let zk_root = B256::from_slice(&hasher.finalize());

    // Logs
    println!("build_extended_state_trie:");
    println!("  → Comptes traités ................ : {}", accounts.len());
    println!("  → Standard EVM state root ......... : 0x{}", hex::encode(standard_root));
    println!("  → ZK-aware extended root .......... : 0x{}", hex::encode(zk_root));

    (post_state, standard_root, zk_root)
}

/// Version simplifiée (compatibilité)
pub fn build_state_trie(accounts: &BTreeMap<String, AccountState>) -> HashedPostState {
    let (post_state, _, _) = build_extended_state_trie(accounts);
    post_state
}
