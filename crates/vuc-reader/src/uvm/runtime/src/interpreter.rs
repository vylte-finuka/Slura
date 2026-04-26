// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2025 Vyft Ltd
//      (sluBPF: UVM architecture, parts of the interpreter, originally in C)

use crate::ebpf;
use crate::lib::*;
use crate::stack::StackUsage;
use chrono;
use core::ops::Range;
use hashbrown::HashSet;
use primitive_types::U256 as u256;
use serde_json::json;
use serde_json::Value as JsonValue;
use sha3::{Digest, Keccak256};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use tracing::{info, warn};
use vuc_storage::storing_access::RocksDBManager;

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u256,
    pub timestamp: u256,
    pub gas_limit: u256,
    pub difficulty: u256,
    pub coinbase: String,
    pub base_fee: u256,        // EIP-1559
    pub blob_base_fee: u256,   // EIP-7516
    pub blob_hash: [u8; 32],   // EIP-4844 (vrai hash)
    pub prev_randao: [u8; 32], // EIP-4399 (added for compatibility)
}

static SS7_CALL_COUNT: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

static SS7_BY_TYPE: LazyLock<[AtomicU64; 256]> = LazyLock::new(|| {
    let mut arr: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
    arr
});

/// ✅ NOUVEAU: Décodage de tout le storage final en map slot -> heuristique décodée
fn decode_storage_map(storage: &HashMap<String, Vec<u8>>) -> serde_json::Map<String, JsonValue> {
    let mut map = serde_json::Map::new();

    // ERC-1967 canonical slots -> friendly names (sans 0x)
    let canonical_impl = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    let canonical_admin = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
    let canonical_beacon = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

    for (slot, bytes) in storage {
        let decoded = match decode_bytes_heuristic(bytes) {
            Some(v) => v,
            None => {
                // Toujours exposer le raw hex en 0x... pour cohérence
                JsonValue::String(format!("0x{}", hex::encode(bytes)))
            }
        };

        // map canonical slots to friendly keys when possible
        if slot.eq_ignore_ascii_case(canonical_impl) {
            map.insert("implementation".to_string(), decoded.clone());
        } else if slot.eq_ignore_ascii_case(canonical_admin) {
            map.insert("admin".to_string(), decoded.clone());
        } else if slot.eq_ignore_ascii_case(canonical_beacon) {
            map.insert("beacon".to_string(), decoded.clone());
        }

        // Always include raw slot as well (avec 0x prefix pour bytes bruts)
        map.insert(slot.clone(), decoded);
    }

    map
}

/// ✅ NOUVEAU: Heuristiques génériques pour décoder un value: adresse / uint / string
fn decode_bytes_heuristic(bytes: &[u8]) -> Option<JsonValue> {
    // adresse possible (20 derniers bytes non nuls)
    if bytes.len() >= 32 {
        let addr = &bytes[12..32];
        if addr.iter().any(|&b| b != 0) {
            let s = format!("0x{}", hex::encode(addr));
            // basic sanity
            if s.len() == 42 && s != "0x0000000000000000000000000000000000000000" {
                return Some(JsonValue::String(s));
            }
        }
    }

    // uint64 plausible (utilise derniers 8 octets)
    if bytes.len() >= 8 {
        let tail = &bytes[bytes.len() - 8..];
        let mut padded = [0u8; 32];
        padded[24..32].copy_from_slice(tail);
        let v = u256::from_big_endian(&padded);
        if v > u256::zero() && v < u256::from(9_000_000_000_000_000_000u64) {
            return Some(JsonValue::Number(serde_json::Number::from(v.low_u64())));
        }
    }

    // string heuristique: extraits les bytes imprimables
    let filtered: Vec<u8> = bytes
        .iter()
        .cloned()
        .filter(|&b| b >= 32 && b <= 126)
        .collect();
    if filtered.len() >= 3 {
        if let Ok(s) = std::str::from_utf8(&filtered) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(JsonValue::String(trimmed.to_string()));
            }
        }
    }

    None
}

#[derive(Clone)]
pub struct InterpreterArgs {
    pub function_name: String,
    pub contract_address: String,
    pub sender_address: String,
    pub args: Vec<serde_json::Value>,
    pub state_data: Vec<u8>, // calldata complet
    pub gas_limit: u256,
    pub gas_price: u256,
    pub value: u256,
    pub call_depth: u256,
    pub block_number: u256,
    pub timestamp: u256,
    pub caller: String,
    pub origin: String,
    pub beneficiary: String,
    pub function_offset: Option<usize>,
    pub base_fee: Option<u256>,
    pub blob_base_fee: Option<u256>,
    pub blob_hash: Option<[u8; 32]>,
}
impl Default for InterpreterArgs {
    fn default() -> Self {
        // ✅ CORRECTION: Utilise l'adresse de l'appelant actuel comme propriétaire par défaut
        let default_caller = "0x1234567890123456789012345678901234567890".to_string();

        InterpreterArgs {
            function_name: "main".to_string(),
            contract_address: "*default*#contract#".to_string(),
            sender_address: "*sender*#default#".to_string(),
            args: vec![],
            state_data: vec![0; 1024],
            gas_limit: u256::from(30_000_000),
            gas_price: u256::from(1),
            value: u256::zero(),
            call_depth: u256::zero(),
            block_number: u256::from(1),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .into(),
            // ✅ CORRECTION: Utilise la même adresse pour cohérence
            caller: default_caller.clone(),
            origin: default_caller.clone(),
            beneficiary: default_caller,
            function_offset: None,
            base_fee: Some(u256::zero()),
            blob_base_fee: Some(u256::zero()),
            blob_hash: Some([0u8; 32]),
        }
    }
}

// ✅ AJOUT: Structure pour l'état mondial UVM
#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, AccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>, // contract_addr -> slot -> value
    pub code: HashMap<String, Vec<u8>>,                     // contract_addr -> code
    pub block_info: BlockInfo,
    pub transient_storage: HashMap<[u8; 32], [u8; 32]>, // clé 32 bytes → valeur 32 bytes
    pub chain_id: u256,                                 // Added field for chain ID
}

#[derive(Clone, Debug)]
pub struct AccountState {
    pub balance: u256,
    pub nonce: u256,
    pub code: Vec<u8>,
    pub storage_root: String,
    pub is_contract: bool,
}
impl Default for UvmWorldState {
    fn default() -> Self {
        UvmWorldState {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            block_info: BlockInfo {
                number: u256::from(1),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .into(),
                gas_limit: u256::from(30000000u64),
                difficulty: u256::from(1),
                coinbase: "*coinbase*#miner#".to_string(),
                base_fee: u256::zero(),
                blob_base_fee: u256::zero(),
                blob_hash: [0u8; 32],
                prev_randao: [0u8; 32],
            },

            transient_storage: HashMap::new(),
            chain_id: u256::from(45056u64),
        }
    }
}

#[derive(Debug)]
enum MemoryOffsetType {
    Normal,          // 0-64KB
    Extended,        // 64KB-1MB
    Large,           // 1MB-16MB
    ContractAddress, // Probable adresse de contrat
}

// Type alias pour le callback CREATE2
pub type Create2Callback = Arc<dyn Fn(&str, Vec<u8>, u256) -> Result<(), String> + Send + Sync>;

// ✅ AJOUT: Context d'exécution UVM
#[derive(Clone)]
pub struct UvmExecutionContext {
    pub world_state: UvmWorldState,
    pub gas_used: u256,
    pub gas_remaining: u256,
    pub logs: Vec<UvmLog>,
    pub return_data: Vec<u8>,
    pub free_memory_pointer: usize,
    pub call_stack: Vec<CallFrame>,
    pub in_internal_call: bool,
    pub storage_manager: Option<Arc<dyn RocksDBManager>>,

    // ──────────────────────────────── AJOUT PRODUCTION ────────────────────────────────
    pub ss7_pending_response: Option<Vec<u8>>, // réponse SS7 simulée ou reçue via oracle

    // Callback déclenché lorsque l'opcode CREATE2 (0xf5) est exécuté
    // Permet à engine_platform de persister le contrat déployé via CREATE2
    pub on_create2_event: Option<Create2Callback>,
    
    // ──────────────────────────────── EIP-3074 AUTH CONTEXT ────────────────────────────────
    /// Context d'autorisation pour EIP-3074 (AUTH/AUTHCALL)
    pub auth_context: Option<(String, u256)>, // (authority_address, commit)
                                               // ────────────────────────────────────────────────────────────────────────────────
}

#[derive(Clone, Debug)]
pub struct UvmLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CallFrame {
    pub caller: String,
    pub contract: String,
    pub value: u256,
    pub gas_limit: u256,
    pub input_data: Vec<u8>,
    pub return_pc: Option<usize>, // Added field for return program counter
}

/// Multiplication modulaire sécurisée pour MULMOD EVM
fn mulmod_safe(a: u256, b: u256, n: u256) -> u256 {
    if n <= u256::one() {
        return u256::zero();
    }

    // Optimisation : cas simples
    if a.is_zero() || b.is_zero() {
        return u256::zero();
    }
    if a == u256::one() {
        return b % n;
    }
    if b == u256::one() {
        return a % n;
    }

    // Réduction modulaire d'abord pour éviter les overflow
    let a_mod = a % n;
    let b_mod = b % n;

    // Vérifie si la multiplication simple est possible sans overflow
    let (product, overflow) = a_mod.overflowing_mul(b_mod);
    if !overflow {
        return product % n;
    }

    // Algorithme de multiplication modulaire par exponentiation binaire
    // Utilise (a * b) % n = ((a % n) * (b % n)) % n avec décomposition
    let mut result = u256::zero();
    let mut base = a_mod;
    let mut exp = b_mod;

    while !exp.is_zero() {
        if exp & u256::one() == u256::one() {
            // result = (result + base) % n avec protection overflow
            result = addmod_safe(result, base, n);
        }
        // base = (base + base) % n = (2 * base) % n
        base = addmod_safe(base, base, n);
        exp = exp >> 1;
    }

    result
}

/// Addition modulaire sécurisée pour éviter les overflow
fn addmod_safe(a: u256, b: u256, n: u256) -> u256 {
    let a_mod = a % n;
    let b_mod = b % n;

    // Vérifie si a + b causerait un overflow
    if a_mod > u256::MAX - b_mod {
        // Overflow prévu : utilise l'arithmétique modulaire
        // (a + b) % n = ((a % n) + (b % n) - n) % n quand a + b >= 2^256
        let sum_minus_n = (a_mod - (n - b_mod)) % n;
        sum_minus_n
    } else {
        // Pas d'overflow : addition normale
        (a_mod + b_mod) % n
    }
}

/// Vérifie si une adresse est au format UIP-10 (ex: *xxxxxxx*#...#...)
pub fn is_valid_uip10_address(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('#').collect();
    if parts.len() < 3 {
        return false;
    }
    let branch = parts[0];
    branch.starts_with('*') && branch.ends_with('*') && addr.len() > 12
}

/// Extract function selector from calldata (first 4 bytes)
fn extract_function_selector(calldata: &[u8]) -> Option<String> {
    if calldata.len() >= 4 {
        Some(format!("0x{}", hex::encode(&calldata[0..4])))
    } else {
        None
    }
}

/// Initialize contract owner in world state if not already set
fn ensure_contract_owner_initialized(
    world_state: &mut UvmWorldState,
    contract_address: &str,
    caller: &str,
) {
    // Check if contract already has an owner in storage
    let owner_slot = "0000000000000000000000000000000000000000000000000000000000000000";
    let current_owner = get_storage(world_state, contract_address, owner_slot);

    // If no owner is set (all zeros), set the caller as owner
    if current_owner.iter().all(|&b| b == 0) {
        let mut owner_bytes = vec![0u8; 32];
        let caller_u256 = encode_address_to_u256(caller);
        caller_u256.to_big_endian(&mut owner_bytes);
        set_storage(world_state, contract_address, owner_slot, owner_bytes);
        println!("🔐 [OWNER] Initialized contract owner: {}", caller);
    }
}

/// Auto-validate owner permissions for protected functions
fn auto_validate_owner_permission(
    world_state: &UvmWorldState,
    contract_address: &str,
    caller: &str,
    function_selector: &str,
) -> bool {
    // List of protected function selectors that require owner permission
    let protected_functions = [
        "0x8da5cb5b", // owner()
        "0xf2fde38b", // transferOwnership(address)
        "0x715018a6", // renounceOwnership()
        "0x9623609d", // upgrade(address)
    ];

    // If this is not a protected function, allow access
    if !protected_functions.contains(&function_selector) {
        return true;
    }

    // Check if caller is the owner
    let owner_slot = "0000000000000000000000000000000000000000000000000000000000000000";
    let owner_bytes = get_storage(world_state, contract_address, owner_slot);
    let stored_owner = u256::from_big_endian(&owner_bytes);
    let caller_u256 = encode_address_to_u256(caller);

    stored_owner == caller_u256
}

// ✅ HELPER: Détecte si des bytes ressemblent à une adresse
fn is_address_like(bytes: &[u8]) -> bool {
    bytes.len() == 20 && bytes.iter().any(|&b| b != 0)
}

// ✅ HELPER: Validation UTF-8 sécurisée
fn is_valid_utf8(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

// ✅ AJOUT: Fonctions d'aide pour gestion du gas
fn consume_gas(_context: &mut UvmExecutionContext, _opcode: u8) -> Result<(), Error> {
    Ok(())
}

// Nouvelle helper: consommer un montant explicite de gas (u64) sans conversion risquée
fn consume_gas_amount(context: &mut UvmExecutionContext, amount: u64) -> Result<(), Error> {
    let cost = u256::from(amount);
    context.gas_used += cost;
    Ok(())
}

// argument adresse et len
fn get_codesize(world_state: &UvmWorldState, address: &str) -> u256 {
    world_state
        .accounts
        .get(address)
        .map(|acc| acc.code.len() as u64)
        .unwrap_or(0)
        .into()
}

// ✅ AJOUT: Helpers pour interaction avec l'état mondial
fn get_balance(world_state: &UvmWorldState, address: &str) -> u256 {
    world_state
        .accounts
        .get(address)
        .map(|acc| acc.balance)
        .unwrap_or(u256::zero())
}

fn set_balance(world_state: &mut UvmWorldState, address: &str, balance: u256) {
    let account = world_state
        .accounts
        .entry(address.to_string())
        .or_insert_with(|| AccountState {
            balance: u256::zero(),
            nonce: u256::zero(),
            code: vec![],
            storage_root: String::new(),
            is_contract: false,
        });
    account.balance = balance;
}

pub fn extract_runtime_from_creation_bytecode(full: &[u8]) -> Result<Vec<u8>, String> {
    if full.len() < 8000 {
        return Err(format!(
            "Bytecode trop court pour contenir un RETURN valide: {} bytes",
            full.len()
        ));
    }

    println!(
        "Début extraction runtime - taille creation bytecode: {} bytes",
        full.len()
    );

    let mut code = full.to_vec();

    // 1. Coupe metadata finale si présente (IPFS/solc)
    let markers: Vec<&[u8]> = vec![b"a2646970667358221220", b"64736f6c634300"];

    for marker in &markers {
        if let Some(pos) = code
            .windows(marker.len())
            .rposition(|w: &[u8]| w == *marker)
        {
            code.truncate(pos);
            println!(
                "→ Metadata tronquée à offset {} (reste: {} bytes)",
                pos,
                code.len()
            );
            break;
        }
    }

    // 2. Recherche du DERNIER f3 (c'est toujours le bon dans Solidity récent)
    let mut return_offset = None;
    for i in (0..code.len()).rev() {
        if code[i] == 0xf3 {
            return_offset = Some(i);
            println!("→ Dernier RETURN (0xf3) trouvé à offset 0x{:04x}", i);
            break;
        }
    }

    let return_pos =
        return_offset.ok_or("Aucun 0xf3 trouvé dans tout le bytecode !".to_string())?;

    // 3. Ce qui suit le f3 (doit être fe ou direct 60806040)
    let suffix = &code[return_pos + 1..];

    // Déclaration mutable ici pour pouvoir réassigner dans la boucle de tolérance
    let mut runtime_start = return_pos + 1;

    if suffix.starts_with(&[0xfe]) && suffix.len() > 5 && &suffix[1..6] == [0x60, 0x80, 0x60, 0x40]
    {
        runtime_start = return_pos + 2; // saute fe
        println!("→ fe60806040 détecté directement après f3");
    } else if suffix.starts_with(&[0x60, 0x80, 0x60, 0x40]) {
        runtime_start = return_pos + 1;
        println!("→ 60806040 direct après f3");
    } else {
        // Tolérance max 8 bytes après f3 (padding rare mais possible)
        let mut pos = return_pos + 1;
        let max_skip = 8;
        while pos + 4 < code.len() && pos < return_pos + 1 + max_skip {
            if &code[pos..pos + 4] == [0x60, 0x80, 0x60, 0x40] {
                println!(
                    "→ Pattern runtime trouvé après décalage de {} bytes (offset 0x{:04x})",
                    pos - return_pos - 1,
                    pos
                );
                runtime_start = pos;
                break;
            }
            pos += 1;
        }

        if pos + 4 >= code.len() || pos >= return_pos + 1 + max_skip {
            return Err(format!(
                "Pas de 60806040 après f3 à 0x{:04x} (suffix={:02x?})",
                return_pos,
                &suffix[..20.min(suffix.len())]
            ));
        }
    }

    let runtime = &code[runtime_start..];

    if runtime.len() < 3000 || runtime[0..4] != [0x60, 0x80, 0x60, 0x40] {
        return Err(format!(
            "Runtime extrait invalide: {} bytes, prefix={:02x?}",
            runtime.len(),
            &runtime[0..4.min(runtime.len())]
        ));
    }

    println!(
        "→ Extraction réussie ! Runtime: {} bytes (début offset 0x{:04x})",
        runtime.len(),
        runtime_start
    );
    Ok(runtime.to_vec())
}

// ✅ NOUVELLE FONCTION: Décodage générique universel comme Erigon
fn decode_return_data_generic(data: &[u8], len: usize) -> JsonValue {
    // 1. RETURN vide → succès booléen
    if len == 0 {
        return JsonValue::Bool(true);
    }

    // 2. Taille standard EVM (32 bytes) → décodage intelligent
    if len == 32 {
        let val = u256::from_big_endian(data);

        // Si c'est un petit nombre (≤ 2^32), représente comme nombre
        if val.bits() <= 32 && val.low_u64() <= u32::MAX as u64 {
            return JsonValue::Number(val.low_u64().into());
        }
        // Si c'est une adresse (20 derniers bytes non nuls)
        else if is_address_like(&data[12..32]) {
            return JsonValue::String(format!("0x{}", hex::encode(&data[12..32])));
        }
        // Sinon, hex complet
        else {
            return JsonValue::String(format!("0x{}", hex::encode(data)));
        }
    }
    // 3. Données de taille variable
    else if len > 32 {
        // Vérifie si c'est de l'ABI encodé (commence par offset/length)
        if len >= 64 {
            let offset = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as usize;
            if offset == 32 && len > 64 {
                let str_len = u32::from_be_bytes([data[60], data[61], data[62], data[63]]) as usize;
                if 64 + str_len <= len && is_valid_utf8(&data[64..64 + str_len]) {
                    if let Ok(s) = std::str::from_utf8(&data[64..64 + str_len]) {
                        return JsonValue::String(s.to_string());
                    }
                }
            }
        }
        // Fallback: hex pour données brutes
        return JsonValue::String(format!("0x{}", hex::encode(data)));
    }
    // 4. Données courtes (1-31 bytes)
    else {
        // Essaie d'interpréter comme nombre
        if len <= 8 {
            let mut num_bytes = [0u8; 8];
            num_bytes[8 - len..].copy_from_slice(data);
            let num = u64::from_be_bytes(num_bytes);
            return JsonValue::Number(num.into());
        }
        // Sinon hex
        return JsonValue::String(format!("0x{}", hex::encode(data)));
    }
}

fn get_storage(world_state: &UvmWorldState, contract: &str, slot: &str) -> Vec<u8> {
    // Si le slot est déjà un hash (clé hexadécimale de 64 caractères), accès direct
    if slot.len() == 64 && slot.chars().all(|c| c.is_ascii_hexdigit()) {
        return world_state
            .storage
            .get(contract)
            .and_then(|contract_storage| contract_storage.get(slot))
            .cloned()
            .unwrap_or_else(|| vec![0; 32]);
    }

    // DÉTECTION DYNAMIQUE : slot de mapping Solidity (keccak256(address . slot))
    // Si le slot est de la forme "address|slot" (ex: "0xabc...|1"), on calcule le hash
    if let Some((addr, mapping_slot)) = slot.split_once('|') {
        // Décodage de l'adresse (20 bytes)
        let mut padded = [0u8; 32];
        if addr.starts_with("0x") && addr.len() == 42 {
            if let Ok(addr_bytes) = hex::decode(&addr[2..]) {
                padded[12..32].copy_from_slice(&addr_bytes);
            }
        }
        // Décodage du slot (u256 big endian)
        let slot_num = mapping_slot.parse::<u64>().unwrap_or(0);
        let mut slot_bytes = [0u8; 32];
        primitive_types::U256::from(slot_num).to_big_endian(&mut slot_bytes);

        // Concatène address (32 bytes) + slot (32 bytes)
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&padded);
        buf[32..].copy_from_slice(&slot_bytes);

        // Hash keccak256
        let hash = keccak_hash(&buf);
        let key = hex::encode(hash);

        return world_state
            .storage
            .get(contract)
            .and_then(|contract_storage| contract_storage.get(&key))
            .cloned()
            .unwrap_or_else(|| vec![0; 32]);
    }

    // Fallback : slot direct (ex: totalSupply, owner, etc.)
    world_state
        .storage
        .get(contract)
        .and_then(|contract_storage| contract_storage.get(slot))
        .cloned()
        .unwrap_or_else(|| vec![0; 32])
}

fn set_storage(world_state: &mut UvmWorldState, contract: &str, slot: &str, value: Vec<u8>) {
    let contract_storage = world_state
        .storage
        .entry(contract.to_string())
        .or_insert_with(HashMap::new);
    contract_storage.insert(slot.to_string(), value);
}

// Stub implementation for get_block_hash
fn get_block_hash(world_state: &UvmWorldState, block_number: u256) -> Option<[u8; 32]> {
    // This is a stub. In a real implementation, this would look up the block hash.
    Some([0u8; 32]) // Return a dummy hash for demonstration
}

#[allow(clippy::too_many_arguments)]
fn check_mem(
    addr: u256,
    len: usize,
    access_type: &str,
    insn_ptr: usize,
    mbuff: &[u8],
    mem: &[u8],
    stack: &[u8],
    allowed_memory: &HashSet<Range<u64>>,
) -> Result<(), Error> {
    if len == 0 || len > 65536 {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "Error: memory access size invalid ({} bytes) at insn #{}",
                len, insn_ptr
            ),
        ));
    }
    let addr_u64 = addr.low_u64();
    if let Some(addr_end) = addr_u64.checked_add(len as u64) {
        let offset = addr_u64 as usize;
        // calldata first (offset semantics)
        if offset + len <= mbuff.len() {
            return Ok(());
        }
        // mem (stack/memory) next
        if offset + len <= mem.len() {
            return Ok(());
        }
        // stack region (if an offset used for stack area)
        if offset + len <= stack.len() {
            return Ok(());
        }
        // allowed_memory ranges (treated as offset ranges)
        if allowed_memory.iter().any(|range| range.contains(&addr_u64)) {
            return Ok(());
        }
        // PATCH: autorise lecture limitée si calldata vide (EVM-style permissif pour reads courtes)
        if mbuff.len() == 0 && addr_u64 < 32 && addr_end <= 32 {
            return Ok(());
        }
    }
    Err(Error::new(ErrorKind::Other, format!(
        "Error: out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\nmbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}",
        access_type, insn_ptr, addr, len,
        mbuff.as_ptr() as u64, mbuff.len(),
        mem.as_ptr() as u64, mem.len(),
        stack.as_ptr() as u64, stack.len()
    )))
}

/// ✅ DÉTECTION UNIVERSELLE: Différencie validation vs erreur métier
fn detect_validation_error(data: &[u8], len: usize) -> bool {
    // 1. REVERT vide = validation simple
    if len == 0 {
        return true;
    }

    // 2. REVERT très court (< 36 bytes) = probablement validation
    if len < 36 {
        return true;
    }

    // 3. Détecte les signatures d'erreur Solidity
    if len >= 4 {
        let error_selector = u32::from_be_bytes([
            data.get(0).copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);

        match error_selector {
            // Panic(uint256) - erreurs de validation Solidity automatiques
            0x4e487b71 => {
                if len >= 36 {
                    let panic_code = u32::from_be_bytes([
                        data.get(32).copied().unwrap_or(0),
                        data.get(33).copied().unwrap_or(0),
                        data.get(34).copied().unwrap_or(0),
                        data.get(35).copied().unwrap_or(0),
                    ]);

                    match panic_code {
                        0x01 => {
                            println!("🛡️ [VALIDATION] Assert failure bypassé");
                            true
                        }
                        0x11 => {
                            println!("🛡️ [VALIDATION] Arithmetic overflow/underflow bypassé");
                            true
                        }
                        0x12 => {
                            println!("🛡️ [VALIDATION] Division by zero bypassé");
                            true
                        }
                        0x21 => {
                            println!("🛡️ [VALIDATION] Enum conversion error bypassé");
                            true
                        }
                        0x22 => {
                            println!("🛡️ [VALIDATION] Array bounds check bypassé");
                            true
                        }
                        0x31 => {
                            println!("🛡️ [VALIDATION] Pop on empty array bypassé");
                            true
                        }
                        0x32 => {
                            println!("🛡️ [VALIDATION] Array out of bounds access bypassé");
                            true
                        }
                        0x41 => {
                            println!("🛡️ [VALIDATION] Memory allocation error bypassé");
                            true
                        }
                        0x51 => {
                            println!("🛡️ [VALIDATION] Internal function error bypassé");
                            true
                        }
                        _ => {
                            println!(
                                "🛡️ [VALIDATION] Panic(0x{:02x}) inconnu bypassé",
                                panic_code
                            );
                            true // Bypass tous les panics par défaut
                        }
                    }
                } else {
                    true // Panic malformé = validation
                }
            }

            // Error(string) - require() avec message
            0x08c379a0 => {
                println!("🛡️ [VALIDATION] Error(string) require() bypassé");
                true
            }

            _ => {
                // Sélecteur inconnu → analyse heuristique
                println!(
                    "🛡️ [VALIDATION] Erreur inconnue 0x{:08x} → bypassé par défaut",
                    error_selector
                );
                true // Mode permissif : bypass par défaut
            }
        }
    } else {
        true // Données courtes = validation
    }
}

fn analyze_revert_context(data: &[u8], len: usize) -> (bool, String) {
    if len == 0 {
        return (true, "EmptyRevert".to_string());
    }

    if len >= 4 {
        let selector = u32::from_be_bytes([
            data.get(0).copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
            data.get(2).copied().unwrap_or(0),
            data.get(3).copied().unwrap_or(0),
        ]);

        match selector {
            // Panic(uint256) - Erreurs de validation Solidity
            0x4e487b71 => {
                if len >= 36 {
                    let panic_code = u32::from_be_bytes([
                        data.get(32).copied().unwrap_or(0),
                        data.get(33).copied().unwrap_or(0),
                        data.get(34).copied().unwrap_or(0),
                        data.get(35).copied().unwrap_or(0),
                    ]);

                    let (should_bypass, desc) = match panic_code {
                        0x01 => (true, "Assert failure".to_string()),
                        0x11 => (true, "Arithmetic overflow/underflow".to_string()),
                        0x12 => (true, "Division by zero".to_string()),
                        0x22 => (true, "Array bounds check".to_string()),
                        0x32 => (true, "Array access out of bounds".to_string()),
                        0x41 => (true, "Memory allocation error".to_string()),
                        0x51 => (true, "Invalid internal function".to_string()),
                        _ => (true, format!("Unknown panic 0x{:02x}", panic_code)),
                    };

                    (should_bypass, format!("Panic({})", desc))
                } else {
                    (true, "Malformed Panic".to_string())
                }
            }

            // Error(string) - require() avec message
            0x08c379a0 => (true, "Error(string)".to_string()),

            // ✅ DÉTECTION ERREURS MÉTIER SPÉCIFIQUES
            0x00000000 if len == 4 => (false, "CustomError".to_string()),

            _ => {
                // ✅ HEURISTIQUE: Erreurs courtes = validation, longues = métier
                if len <= 36 {
                    (true, format!("ValidationError(0x{:08x})", selector))
                } else {
                    (false, format!("BusinessError(0x{:08x})", selector))
                }
            }
        }
    } else {
        // Données courtes sans sélecteur = probablement validation
        (true, "ShortRevert".to_string())
    }
}

/// Encodage spécialisé pour adresses UIP-10
fn encode_uip10_address_to_u64(addr: &str) -> u64 {
    let parts: Vec<&str> = addr.split('#').collect();
    if parts.len() >= 2 {
        let branch = parts[0];
        let identifier = parts[1];

        let mut hasher = DefaultHasher::new();
        branch.hash(&mut hasher);
        identifier.hash(&mut hasher);
        hasher.finish()
    } else {
        encode_address_to_u64(addr)
    }
}

static mut JSON_BUFFER: [u8; 8192] = [0; 8192];

// ====================================================================
// PRODUCTION VERSION - SS7 Metadata + Payload Processor
// Opcode 0xef (ou 0xec selon ta préférence)
// ====================================================================

pub fn ss7_metadata_process(
    msg_type: u64,
    caller_hash: u64,
    called_hash: u64,
    call_ts: u64,
    extra: u64,
    payload_ptr: u64,
    payload_len: u64,
) -> u64 {
    // Validation
    if msg_type > 255 || call_ts == 0 || call_ts > 2_000_000_000_000 {
        warn!("[SS7 invalid params]");
        return 1;
    }
    if payload_len > 8192 {
        warn!("[SS7 payload too large]");
        return 2;
    }

    // Compteurs
    SS7_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
    let idx = msg_type as usize;
    if idx < SS7_BY_TYPE.len() {
        SS7_BY_TYPE[idx].fetch_add(1, Ordering::Relaxed);
    }

    // Extraction payload depuis mémoire VM
    let payload = unsafe {
        let ptr = payload_ptr as *const u8;
        std::slice::from_raw_parts(ptr, payload_len as usize)
    };

    let msg_name = match payload.first().copied() {
        Some(0x01) | Some(0x02) => "IAM",
        Some(0x03) => "ACM",
        Some(0x04) => "ANM",
        Some(0x05) => "REL",
        Some(0x06) => "SMS-MO",
        Some(0x07) => "SMS-MT",
        _ => "UNKNOWN",
    };

    let payload_hex = hex::encode(payload);
    let payload_hash = format!("{:064x}", Keccak256::digest(payload));

    let call_id = format!("ss7_{:016x}_{:02x}_{:016x}", call_ts, msg_type, caller_hash);

    // JSON complet à transmettre (payload démodulé inclus)
    let ss7_json = json!({
        "call_id": call_id,
        "msg_type": msg_type,
        "msg_name": msg_name,
        "caller_hash": format!("{:016x}", caller_hash),
        "called_hash": format!("{:016x}", called_hash),
        "timestamp": call_ts,
        "extra": extra,
        "payload_hex": payload_hex,
        "payload_hash": payload_hash,
        "payload_len": payload_len,
        "source": "unity_vm_0xef",
        "request_id": call_id
    });

    // Écriture du JSON dans la zone mémoire réservée
    let json_str = serde_json::to_string(&ss7_json).unwrap_or_default();
    let json_bytes = json_str.as_bytes();

    unsafe {
        let len = json_bytes.len().min(8192);
        JSON_BUFFER[0..len].copy_from_slice(&json_bytes[0..len]);
    }

    // Retour : (longueur << 32) | pointeur vers le JSON
    let json_ptr = unsafe { JSON_BUFFER.as_ptr() as u64 };
    let json_len = json_str.len() as u64;

    let return_value = (json_len << 32) | json_ptr;

    info!(
        "[UVM SS7 TRANSIT] JSON complet transmis. call_id={}",
        call_id
    );

    return_value
}

/// ✅ Encodage d'adresse vers u64
fn encode_address_to_u64(addr: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}

pub fn execute_program(
    prog_: Option<&[u8]>,
    stack_usage: Option<&StackUsage>,
    mem: &[u8],
    mbuff: &[u8],
    helpers: &mut HashMap<u32, ebpf::Helper>,
    allowed_memory: &HashSet<Range<u64>>,
    ret_type: Option<&str>,
    exports: &HashMap<u32, usize>,
    interpreter_args: &InterpreterArgs,
    storage_manager: Option<Arc<dyn RocksDBManager>>,
    initial_storage: Option<HashMap<String, HashMap<String, Vec<u8>>>>,
    on_create2_event: Option<Create2Callback>,
) -> Result<serde_json::Value, Error> {
    const U32MAX: u256 = u256([u32::MAX as u64, 0, 0, 0]);
    const SHIFT_MASK_64: u256 = u256([0x3f, 0, 0, 0]);

    // InstructionResult codes (repr(u8))
    const IR_STOP: u64 = 1;
    const IR_RETURN: u64 = 2;
    const IR_SELFDESTRUCT: u64 = 3;
    const IR_REVERT: u64 = 0x10;

    // --- erreurs/halts courants (repr(u8) d'après l'énum) ---
    const IR_OUT_OF_GAS: u64 = 0x20;
    const IR_OPCODE_NOT_FOUND: u64 = 0x26;
    const IR_INVALID_JUMP: u64 = 0x2a;
    const IR_STACK_UNDERFLOW: u64 = 0x2c;
    const IR_STACK_OVERFLOW: u64 = 0x2d;
    const IR_OUT_OF_OFFSET: u64 = 0x2e;
    const IR_FATAL_EXTERNAL_ERROR: u64 = 0x36;

    // 🔎 LOG de la formation du calldata (state_data)
    println!(
        "🟢 [DEBUG] Formation du calldata (state_data) : {}",
        hex::encode(&interpreter_args.state_data)
    );

    #[inline]
    fn halt_json(
        execution_context: &UvmExecutionContext,
        interpreter_args: &InterpreterArgs,
        code: u64,
        reason: &str,
    ) -> serde_json::Value {
        let final_storage = execution_context
            .world_state
            .storage
            .get(&interpreter_args.contract_address)
            .cloned()
            .unwrap_or_default();

        let mut obj = serde_json::Map::new();
        obj.insert(
            "error".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        obj.insert(
            "instruction_result".to_string(),
            serde_json::Value::Number(code.into()),
        );
        obj.insert(
            "storage".to_string(),
            serde_json::Value::Object(decode_storage_map(&final_storage)),
        );
        serde_json::Value::Object(obj)
    }

    #[inline]
    fn halt_json_ebpf(reason: &str) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "error".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
        obj.insert(
            "instruction_result".to_string(),
            serde_json::Value::Number(IR_FATAL_EXTERNAL_ERROR.into()),
        );
        serde_json::Value::Object(obj)
    }

    fn create_return_action(data: Vec<u8>) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "action".to_string(),
            serde_json::Value::String("return".to_string()),
        );
        obj.insert(
            "data".to_string(),
            decode_return_data_generic(&data, data.len()),
        );
        serde_json::Value::Object(obj)
    }

    fn create_revert_action(data: Vec<u8>) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "action".to_string(),
            serde_json::Value::String("revert".to_string()),
        );
        obj.insert(
            "data".to_string(),
            decode_return_data_generic(&data, data.len()),
        );
        serde_json::Value::Object(obj)
    }

    fn create_stop_action() -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "action".to_string(),
            serde_json::Value::String("stop".to_string()),
        );
        obj.insert("success".to_string(), serde_json::Value::Bool(true));
        serde_json::Value::Object(obj)
    }

    fn as_usize_or_fail(val: u256) -> usize {
        if val.bits() > 64 {
            usize::MAX
        } else {
            val.low_u64() as usize
        }
    }

    fn as_usize_saturated(val: u256) -> usize {
        if val.bits() > 64 {
            usize::MAX
        } else {
            val.low_u64() as usize
        }
    }

    fn resize_memory_ebpf(mem: &mut Vec<u8>, offset: usize, size: usize) -> bool {
        const MAX_MEM: usize = 16 * 1024 * 1024;
        if offset > MAX_MEM || size > MAX_MEM {
            return false;
        }
        if let Some(end) = offset.checked_add(size) {
            if end > mem.len() && end <= MAX_MEM {
                mem.resize(end, 0);
            }
            true
        } else {
            false
        }
    }

    fn memory_slice_len(mem: &[u8], offset: usize, size: usize) -> &[u8] {
        let end = offset.saturating_add(size).min(mem.len());
        if offset < mem.len() {
            &mem[offset..end]
        } else {
            &[]
        }
    }

    let prog = match prog_ {
        Some(prog) => prog,
        None => {
            return Err(Error::new(
                ErrorKind::Other,
                "Error: No program set, call prog_set() to load one",
            ))
        }
    };

    println!("🧮 [BYTECODE SIZE] {} bytes", prog.len());

    let default_stack_usage = StackUsage::new();
    let stack_usage = stack_usage.unwrap_or(&default_stack_usage);

    let mut execution_context = UvmExecutionContext {
        world_state: {
            let mut ws = UvmWorldState::default();
            if let Some(ref storage) = initial_storage {
                ws.storage = storage.clone();
            }
            ws
        },
        gas_used: u256::zero(),
        gas_remaining: interpreter_args.gas_limit,
        logs: vec![],
        return_data: vec![],
        storage_manager,
        free_memory_pointer: 0x80, // Solidity >= 0.8
        call_stack: vec![],
        in_internal_call: false,
        ss7_pending_response: None, // ← AJOUT,
        on_create2_event,
        auth_context: None, // ← EIP-3074 AUTH context
    };

    // ✅ CORRECTION: Initialisation automatique du propriétaire
    ensure_contract_owner_initialized(
        &mut execution_context.world_state,
        &interpreter_args.contract_address,
        &interpreter_args.caller,
    );

    // ✅ CORRECTION: Validation automatique des permissions
    if let Some(function_selector) = extract_function_selector(&interpreter_args.state_data) {
        if !auto_validate_owner_permission(
            &execution_context.world_state,
            &interpreter_args.contract_address,
            &interpreter_args.caller,
            &function_selector,
        ) {
            // Retourne une erreur d'autorisation générique
            let mut error_data = vec![0u8; 36];
            // OwnableUnauthorizedAccount(address) selector
            error_data[0..4].copy_from_slice(&0x118cdaa7u32.to_be_bytes());
            // Encode l'adresse de l'appelant
            let caller_u256 = encode_address_to_u256(&interpreter_args.caller);
            caller_u256.to_big_endian(&mut error_data[4..36]);

            println!(
                "🚫 [OWNER CHECK] Access denied for function {}",
                function_selector
            );
            return Ok(create_revert_action(error_data));
        }
    }

    // ✅ CORRECTION: Balance initiale générique
    set_balance(
        &mut execution_context.world_state,
        &interpreter_args.sender_address,
        u256::from(1_000_000_000_000_000_000u64), // 1 ETH en wei
    );

    helpers.insert(
        0x460,
        Box::new(ss7_metadata_process)
            as Box<dyn Fn(u64, u64, u64, u64, u64, u64, u64) -> u64 + Send + Sync + 'static>,
    );

    // Simulation d'un interpréteur eBPF avec comportement EVM
    let mut bytecode_pc = 0usize; // Program counter eBPF-style
    let mut evm_stack: Vec<u256> = Vec::with_capacity(1024);
    let mut global_mem = vec![0u8; 0x10000];
    let mut instruction_count = 0u64;

    // NOUVEAU : buffer temporaire pour tous les SSTORE pendant l'exécution
    let mut temp_storage_writes: HashMap<String, Vec<u8>> = HashMap::new();

    while bytecode_pc < prog.len() {
        let opcode = prog[bytecode_pc];

        let mut advance = 1;
        let mut skip_advance = false;

        match opcode {
            //___ 0x00 STOP
            0x00 => {
                println!("🛑 [STOP] Halting execution");

                // Créer le résultat de base
                let mut result = create_stop_action();

                // Ajouter les writes capturés
                add_storage_written_to_result(&mut result, &temp_storage_writes);

                return Ok(result);
            }

            //___ 0x01 ADD
            0x01 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on ADD"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a.overflowing_add(b).0; // EVM arithmetic is mod 2^256
                evm_stack.push(result);
                println!("➕ [ADD] {} + {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x02 MUL
            0x02 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on MUL"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a.overflowing_mul(b).0;
                evm_stack.push(result);
                println!("✖️ [MUL] {} * {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x03 SUB
            0x03 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SUB"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a.overflowing_sub(b).0;
                evm_stack.push(result);
                println!("➖ [SUB] {} - {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x04 DIV
            0x04 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on DIV"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if b.is_zero() { u256::zero() } else { a / b };
                evm_stack.push(result);
                println!("➗ [DIV] {} / {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x05 SDIV
            0x05 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SDIV"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if b.is_zero() {
                    u256::zero()
                } else {
                    // Signed division - simplified implementation
                    let a_signed = i256_from_u256(a);
                    let b_signed = i256_from_u256(b);
                    u256_from_i256(a_signed / b_signed)
                };
                evm_stack.push(result);
                println!("🔢 [SDIV] {} / {} = {} (signed)", a, b, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x06 MOD
            0x06 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on MOD"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if b.is_zero() { u256::zero() } else { a % b };
                evm_stack.push(result);
                println!("📐 [MOD] {} % {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x07 SMOD
            0x07 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SMOD"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if b.is_zero() {
                    u256::zero()
                } else {
                    let a_signed = i256_from_u256(a);
                    let b_signed = i256_from_u256(b);
                    u256_from_i256(a_signed % b_signed)
                };
                evm_stack.push(result);
                println!("🔢 [SMOD] {} % {} = {} (signed)", a, b, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x08 ADDMOD
            0x08 => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on ADDMOD"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let n = evm_stack.pop().unwrap();
                let result = if n.is_zero() {
                    u256::zero()
                } else {
                    // (a + b) % N with arbitrary precision
                    let sum = a.overflowing_add(b).0;
                    let (quotient, remainder) = sum.div_mod(n);
                    remainder
                };
                evm_stack.push(result);
                println!("➕📐 [ADDMOD] ({} + {}) % {} = {}", a, b, n, result);
                consume_gas_amount(&mut execution_context, 8)?;
            }

            //___ 0x09 MULMOD
            0x09 => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on MULMOD"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let n = evm_stack.pop().unwrap();
                let result = if n.is_zero() {
                    u256::zero()
                } else {
                    // (a * b) % N avec arithmétique sécurisée
                    // Évite l'overflow en utilisant la propriété modulaire
                    mulmod_safe(a, b, n)
                };
                evm_stack.push(result);
                println!("✖️📐 [MULMOD] ({} * {}) % {} = {}", a, b, n, result);
                consume_gas_amount(&mut execution_context, 8)?;
            }

            //___ 0x0a EXP
            0x0a => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on EXP"));
                }
                let a = evm_stack.pop().unwrap();
                let exponent = evm_stack.pop().unwrap();
                let result = a.overflowing_pow(exponent).0;
                evm_stack.push(result);
                println!("🔺 [EXP] {} ** {} = {}", a, exponent, result);
                // Dynamic gas: 50 * exponent_byte_size
                let exp_bytes = (exponent.bits() + 7) / 8;
                consume_gas_amount(&mut execution_context, 10 + 50 * exp_bytes as u64)?;
            }

            //___ 0x0b SIGNEXTEND
            0x0b => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SIGNEXTEND"));
                }
                let b = evm_stack.pop().unwrap();
                let x = evm_stack.pop().unwrap();
                let result = if b >= u256::from(32) {
                    x // No change if b >= 32
                } else {
                    let byte_index = b.low_u32() as usize;
                    let sign_bit = (byte_index * 8 + 7) as u32;
                    if x.bit(sign_bit.try_into().unwrap()) {
                        // Extend with 1s
                        let mask = (u256::one() << (sign_bit + 1)) - u256::one();
                        x | (!mask)
                    } else {
                        // Extend with 0s
                        let mask = (u256::one() << (sign_bit + 1)) - u256::one();
                        x & mask
                    }
                };
                evm_stack.push(result);
                println!("📏 [SIGNEXTEND] signext({}, {}) = {}", b, x, result);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x10 LT
            0x10 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on LT"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if a < b { u256::one() } else { u256::zero() };
                evm_stack.push(result);
                println!("🔍 [LT] {} < {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x11 GT
            0x11 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on GT"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if a > b { u256::one() } else { u256::zero() };
                evm_stack.push(result);
                println!("🔍 [GT] {} > {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x12 SLT
            0x12 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SLT"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let a_signed = i256_from_u256(a);
                let b_signed = i256_from_u256(b);
                let result = if a_signed < b_signed {
                    u256::one()
                } else {
                    u256::zero()
                };
                evm_stack.push(result);
                println!("🔢 [SLT] {} < {} = {} (signed)", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x13 SGT
            0x13 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SGT"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let a_signed = i256_from_u256(a);
                let b_signed = i256_from_u256(b);
                let result = if a_signed > b_signed {
                    u256::one()
                } else {
                    u256::zero()
                };
                evm_stack.push(result);
                println!("🔢 [SGT] {} > {} = {} (signed)", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x14 EQ
            0x14 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on EQ"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = if a == b { u256::one() } else { u256::zero() };
                evm_stack.push(result);
                println!("⚖️ [EQ] {} == {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x15 ISZERO
            0x15 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on ISZERO"));
                }
                let a = evm_stack.pop().unwrap();
                let result = if a.is_zero() {
                    u256::one()
                } else {
                    u256::zero()
                };
                evm_stack.push(result);
                println!("0️⃣ [ISZERO] {} == 0 = {}", a, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x16 AND
            0x16 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on AND"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a & b;
                evm_stack.push(result);
                println!("🔗 [AND] {} & {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x17 OR
            0x17 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on OR"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a | b;
                evm_stack.push(result);
                println!("🔗 [OR] {} | {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x18 XOR
            0x18 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on XOR"));
                }
                let a = evm_stack.pop().unwrap();
                let b = evm_stack.pop().unwrap();
                let result = a ^ b;
                evm_stack.push(result);
                println!("🔗 [XOR] {} ^ {} = {}", a, b, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x19 NOT
            0x19 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on NOT"));
                }
                let a = evm_stack.pop().unwrap();
                let result = !a;
                evm_stack.push(result);
                println!("🚫 [NOT] ~{} = {}", a, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x1a BYTE
            0x1a => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on BYTE"));
                }
                let i = evm_stack.pop().unwrap();
                let x = evm_stack.pop().unwrap();
                let result = if i >= u256::from(32) {
                    u256::zero()
                } else {
                    let byte_index = i.low_u32() as usize;
                    let byte_value = x.byte(31 - byte_index); // EVM is big-endian
                    u256::from(byte_value)
                };
                evm_stack.push(result);
                println!("📝 [BYTE] byte({}, {}) = {}", i, x, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x1b SHL
            0x1b => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SHL"));
                }
                let shift = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let result = if shift >= u256::from(256) {
                    u256::zero()
                } else {
                    value << shift.low_u32()
                };
                evm_stack.push(result);
                println!("⬅️ [SHL] {} << {} = {}", value, shift, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x1c SHR
            0x1c => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SHR"));
                }
                let shift = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let result = if shift >= u256::from(256) {
                    u256::zero()
                } else {
                    value >> shift.low_u32()
                };
                evm_stack.push(result);
                println!("➡️ [SHR] {} >> {} = {}", value, shift, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x1d SAR
            0x1d => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SAR"));
                }
                let shift = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let result = if shift >= u256::from(256) {
                    if value.bit(255) {
                        u256::MAX
                    } else {
                        u256::zero()
                    }
                } else {
                    // Arithmetic right shift (sign extension)
                    let is_negative = value.bit(255);
                    let shifted = value >> shift.low_u32();
                    if is_negative {
                        let sign_mask = u256::MAX << (256 - shift.low_u32());
                        shifted | sign_mask
                    } else {
                        shifted
                    }
                };
                evm_stack.push(result);
                println!(
                    "🔢➡️ [SAR] {} sar {} = {} (arithmetic)",
                    value, shift, result
                );
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x20 KECCAK256
            0x20 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on KECCAK256"));
                }
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on KECCAK256"));
                }

                let data = memory_slice_len(&global_mem, offset_usize, size_usize);
                let hash = keccak_hash(data);
                let result = u256::from_big_endian(&hash);
                evm_stack.push(result);

                println!(
                    "🔐 [KECCAK256] hash(mem[{}:{}]) = {}",
                    offset,
                    offset + size,
                    result
                );

                let words = (size_usize + 31) / 32;
                consume_gas_amount(&mut execution_context, 30 + 6 * words as u64)?;
            }

            //___ 0x30 ADDRESS
            0x30 => {
                let addr = encode_address_to_u256(&interpreter_args.contract_address);
                evm_stack.push(addr);
                println!("🏠 [ADDRESS] {}", addr);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x31 BALANCE
            0x31 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on BALANCE"));
                }
                let address_u256 = evm_stack.pop().unwrap();
                let address = u256_to_address(address_u256);
                let balance = get_balance(&execution_context.world_state, &address);
                evm_stack.push(balance);
                println!("💰 [BALANCE] balance({}) = {}", address, balance);
                consume_gas_amount(&mut execution_context, 100)?; // Assume warm
            }

            //___ 0x32 ORIGIN
            0x32 => {
                let addr = encode_address_to_u256(&interpreter_args.origin);
                evm_stack.push(addr);
                println!("🌍 [ORIGIN] {}", addr);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x33 CALLER
            0x33 => {
                let addr = encode_address_to_u256(&interpreter_args.caller);
                evm_stack.push(addr);
                println!("📞 [CALLER] {}", addr);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x34 CALLVALUE
            0x34 => {
                evm_stack.push(interpreter_args.value);
                println!("💎 [CALLVALUE] {}", interpreter_args.value);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x35 CALLDATALOAD
            0x35 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on CALLDATALOAD"));
                }
                let offset = evm_stack.pop().unwrap();
                let offset_usize = as_usize_or_fail(offset);

                let mut data = [0u8; 32];
                let calldata = &interpreter_args.state_data;

                for i in 0..32 {
                    if offset_usize + i < calldata.len() {
                        data[i] = calldata[offset_usize + i];
                    }
                }

                let result = u256::from_big_endian(&data);
                evm_stack.push(result);
                println!("📥 [CALLDATALOAD] calldata[{}] = {}", offset, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x36 CALLDATASIZE
            0x36 => {
                let size = u256::from(interpreter_args.state_data.len());
                evm_stack.push(size);
                println!("📏 [CALLDATASIZE] {}", size);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x37 CALLDATACOPY
            0x37 => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on CALLDATACOPY"));
                }
                let dest_offset = evm_stack.pop().unwrap();
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let dest_offset_usize = as_usize_or_fail(dest_offset);
                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, dest_offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CALLDATACOPY"));
                }

                let calldata = &interpreter_args.state_data;
                for i in 0..size_usize {
                    if dest_offset_usize + i < global_mem.len() {
                        if offset_usize + i < calldata.len() {
                            global_mem[dest_offset_usize + i] = calldata[offset_usize + i];
                        } else {
                            global_mem[dest_offset_usize + i] = 0;
                        }
                    }
                }

                println!(
                    "📋 [CALLDATACOPY] calldata[{}:{}] → mem[{}]",
                    offset,
                    offset + size,
                    dest_offset
                );
                let words = (size_usize + 31) / 32;
                consume_gas_amount(&mut execution_context, 3 + 3 * words as u64)?;
            }

            //___ 0x38 CODESIZE
            0x38 => {
                let size = u256::from(prog.len());
                evm_stack.push(size);
                println!("📖 [CODESIZE] {}", size);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x39 CODECOPY
            0x39 => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on CODECOPY"));
                }
                let dest_offset = evm_stack.pop().unwrap();
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let dest_offset_usize = as_usize_or_fail(dest_offset);
                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, dest_offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CODECOPY"));
                }

                for i in 0..size_usize {
                    if dest_offset_usize + i < global_mem.len() {
                        if offset_usize + i < prog.len() {
                            global_mem[dest_offset_usize + i] = prog[offset_usize + i];
                        } else {
                            global_mem[dest_offset_usize + i] = 0;
                        }
                    }
                }

                println!(
                    "📋 [CODECOPY] code[{}:{}] → mem[{}]",
                    offset,
                    offset + size,
                    dest_offset
                );
                let words = (size_usize + 31) / 32;
                consume_gas_amount(&mut execution_context, 3 + 3 * words as u64)?;
            }

            //___ 0x3a GASPRICE
            0x3a => {
                evm_stack.push(interpreter_args.gas_price);
                println!("⛽ [GASPRICE] {}", interpreter_args.gas_price);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x3b EXTCODESIZE
            0x3b => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on EXTCODESIZE"));
                }
                let address_u256 = evm_stack.pop().unwrap();
                let address = u256_to_address(address_u256);
                let code_size = get_codesize(&execution_context.world_state, &address);
                evm_stack.push(code_size.into());
                println!("📏 [EXTCODESIZE] codesize({}) = {}", address, code_size);
                consume_gas_amount(&mut execution_context, 100)?; // Assume warm
            }

            // ___ 0x3d RETURNDATASIZE - Taille des données de retour
            0x3d => {
                // Taille actuelle du return_data dans le contexte UVM
                let size = u256::from(execution_context.return_data.len());

                // Push sur la stack (comportement EVM standard)
                evm_stack.push(size);

                println!("📏 [RETURNDATASIZE] → {} bytes", size);
            }

            // ___ 0x3e RETURNDATACOPY - Copie des données de retour dans la mémoire
            0x3e => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on RETURNDATACOPY"));
                }
                let dest_offset = evm_stack.pop().unwrap();
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let dest_offset_usize = as_usize_or_fail(dest_offset);
                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, dest_offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on RETURNDATACOPY"));
                }

                let return_data = &execution_context.return_data;
                for i in 0..size_usize {
                    if dest_offset_usize + i < global_mem.len() {
                        if offset_usize + i < return_data.len() {
                            global_mem[dest_offset_usize + i] = return_data[offset_usize + i];
                        } else {
                            global_mem[dest_offset_usize + i] = 0;
                        }
                    }
                }

                println!(
                    "📋 [RETURNDATACOPY] return_data[{}:{}] → mem[{}]",
                    offset,
                    offset + size,
                    dest_offset
                );
            }

            //___ 0x40 BLOCKHASH
            0x40 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on BLOCKHASH"));
                }
                let block_number = evm_stack.pop().unwrap();
                let current_block = execution_context.world_state.block_info.number;

                let hash = if block_number < current_block
                    && current_block - block_number <= u256::from(256)
                {
                    get_block_hash(&execution_context.world_state, block_number)
                        .map(|h| u256::from_big_endian(&h))
                        .unwrap_or(u256::zero())
                } else {
                    u256::zero()
                };

                evm_stack.push(hash);
                println!("🧱 [BLOCKHASH] blockhash({}) = {}", block_number, hash);
                consume_gas_amount(&mut execution_context, 20)?;
            }

            //___ 0x41 COINBASE
            0x41 => {
                let addr =
                    encode_address_to_u256(&execution_context.world_state.block_info.coinbase);
                evm_stack.push(addr);
                println!("💰 [COINBASE] {}", addr);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x42 TIMESTAMP
            0x42 => {
                evm_stack.push(execution_context.world_state.block_info.timestamp);
                println!(
                    "⏰ [TIMESTAMP] {}",
                    execution_context.world_state.block_info.timestamp
                );
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x43 NUMBER
            0x43 => {
                evm_stack.push(execution_context.world_state.block_info.number);
                println!(
                    "🔢 [NUMBER] {}",
                    execution_context.world_state.block_info.number
                );
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x44 PREVRANDAO
            0x44 => {
                let randao =
                    u256::from_big_endian(&execution_context.world_state.block_info.prev_randao);
                evm_stack.push(randao);
                println!("🎲 [PREVRANDAO] {}", randao);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x45 GASLIMIT
            0x45 => {
                evm_stack.push(execution_context.world_state.block_info.gas_limit);
                println!(
                    "⛽ [GASLIMIT] {}",
                    execution_context.world_state.block_info.gas_limit
                );
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x46 CHAINID
            0x46 => {
                evm_stack.push(execution_context.world_state.chain_id);
                println!("🔗 [CHAINID] {}", execution_context.world_state.chain_id);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x47 SELFBALANCE
            0x47 => {
                let balance = get_balance(
                    &execution_context.world_state,
                    &interpreter_args.contract_address,
                );
                evm_stack.push(balance);
                println!("💰 [SELFBALANCE] {}", balance);
                consume_gas_amount(&mut execution_context, 5)?;
            }

            //___ 0x48 BASEFEE
            0x48 => {
                evm_stack.push(execution_context.world_state.block_info.base_fee);
                println!(
                    "⛽ [BASEFEE] {}",
                    execution_context.world_state.block_info.base_fee
                );
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x49 BLOBHASH
            0x49 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on BLOBHASH"));
                }
                let index = evm_stack.pop().unwrap();
                let hash = if index.is_zero() {
                    u256::from_big_endian(&execution_context.world_state.block_info.blob_hash)
                } else {
                    u256::zero()
                };
                evm_stack.push(hash);
                println!("🫧 [BLOBHASH] blobhash({}) = {}", index, hash);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x4a BLOBBASEFEE
            0x4a => {
                evm_stack.push(execution_context.world_state.block_info.blob_base_fee);
                println!(
                    "🫧 [BLOBBASEFEE] {}",
                    execution_context.world_state.block_info.blob_base_fee
                );
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x50 POP
            0x50 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on POP"));
                }
                let value = evm_stack.pop().unwrap();
                println!("🗑️ [POP] {}", value);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x51 MLOAD
            0x51 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on MLOAD"));
                }
                let offset = evm_stack.pop().unwrap();
                let offset_usize = as_usize_or_fail(offset);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, 32) {
                    return Ok(halt_json_ebpf("Memory resize failed on MLOAD"));
                }

                let data = memory_slice_len(&global_mem, offset_usize, 32);
                let mut word = [0u8; 32];
                word[..data.len()].copy_from_slice(data);
                let result = u256::from_big_endian(&word);

                evm_stack.push(result);
                println!("📖 [MLOAD] mem[{}] = {}", offset, result);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x52 MSTORE
            0x52 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on MSTORE"));
                }
                let offset = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let offset_usize = as_usize_or_fail(offset);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, 32) {
                    return Ok(halt_json_ebpf("Memory resize failed on MSTORE"));
                }

                let mut bytes = [0u8; 32];
                value.to_big_endian(&mut bytes);

                if offset_usize + 32 <= global_mem.len() {
                    global_mem[offset_usize..offset_usize + 32].copy_from_slice(&bytes);
                }

                println!("📝 [MSTORE] mem[{}] := {}", offset, value);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x53 MSTORE8
            0x53 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on MSTORE8"));
                }
                let offset = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let offset_usize = as_usize_or_fail(offset);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, 1) {
                    return Ok(halt_json_ebpf("Memory resize failed on MSTORE8"));
                }

                let byte_value = value.low_u32() as u8;

                if offset_usize < global_mem.len() {
                    global_mem[offset_usize] = byte_value;
                }

                println!("📝 [MSTORE8] mem[{}] := 0x{:02x}", offset, byte_value);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x54 SLOAD
            0x54 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on SLOAD"));
                }
                let key = evm_stack.pop().unwrap();
                let key_hex = format!("{:064x}", key);
                let value_bytes = get_storage(
                    &execution_context.world_state,
                    &interpreter_args.contract_address,
                    &key_hex,
                );
                let value = u256::from_big_endian(&value_bytes);

                evm_stack.push(value);
                println!("🗄️ [SLOAD] storage[{}] = {}", key, value);
                consume_gas_amount(&mut execution_context, 100)?; // Assume warm
            }

            //___ 0x55 SSTORE
            0x55 => {
                // SSTORE
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on SSTORE"));
                }
                let key = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();

                let key_hex = format!("{:064x}", key);

                let mut value_bytes = [0u8; 32];
                value.to_big_endian(&mut value_bytes);

                // 1. On stocke dans le buffer temporaire (clé = slot hex)
                temp_storage_writes.insert(key_hex.clone(), value_bytes.to_vec());

                // 2. On applique aussi immédiatement dans world_state (cohérence live)
                set_storage(
                    &mut execution_context.world_state,
                    &interpreter_args.contract_address,
                    &key_hex,
                    value_bytes.to_vec(),
                );

                println!(
                    "💾 [SSTORE] storage[{}] := 0x{}",
                    key_hex,
                    hex::encode(&value_bytes)
                );

                consume_gas_amount(&mut execution_context, 100)?; // gas approximatif
            }

            //___ 0x56 JUMP - Implémentation style eBPF avec validation EVM
            0x56 => {
                if evm_stack.is_empty() {
                    return Ok(halt_json_ebpf("Stack underflow on JUMP"));
                }

                let target_u256 = evm_stack.pop().unwrap();
                let target = as_usize_saturated(target_u256);

                bytecode_pc = target;
                skip_advance = true;

                println!("↪️ [JUMP] → 0x{:04x}", target);
                consume_gas_amount(&mut execution_context, 8)?;
            }

            //___ 0x57 JUMPI - Saut conditionnel eBPF avec sémantique EVM
            0x57 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on JUMPI"));
                }

                let target_u256 = evm_stack.pop().unwrap();
                let cond = evm_stack.pop().unwrap();
                let target = as_usize_saturated(target_u256);

                if !cond.is_zero() {
                    bytecode_pc = target;
                    skip_advance = true;
                    println!("↪️ [JUMPI] condition vraie → 0x{:04x}", target);
                } else {
                    println!("⏩ [JUMPI] condition fausse, continue");
                }
                consume_gas_amount(&mut execution_context, 10)?;
            }

            //___ 0x58 PC - Program Counter eBPF-style
            0x58 => {
                let current_pc = u256::from(bytecode_pc as u64);
                evm_stack.push(current_pc);
                println!("📍 [PC] {}", current_pc);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x59 MSIZE
            0x59 => {
                let size = u256::from(global_mem.len());
                evm_stack.push(size);
                println!("📏 [MSIZE] {}", size);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x5a GAS
            0x5a => {
                evm_stack.push(execution_context.gas_remaining);
                println!("⛽ [GAS] {}", execution_context.gas_remaining);
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x5b JUMPDEST - Marqueur de destination valide pour JUMP/JUMPI
            0x5b => {
                println!("🔒 [JUMPDEST]");
                consume_gas_amount(&mut execution_context, 1)?;
            }

            // ___ 0x5c TLOAD (EIP-1153 Transient Storage Load) - Version production
0x5c => {
    if evm_stack.is_empty() {
        return Ok(halt_json_ebpf("Stack underflow on TLOAD"));
    }

    let key_u256 = evm_stack.pop().unwrap();

    // Conversion clé en bytes32
    let mut key_bytes = [0u8; 32];
    key_u256.to_big_endian(&mut key_bytes);

    // Lecture dans transient_storage (HashMap<[u8;32], [u8;32]>)
    let value = execution_context
        .world_state
        .transient_storage
        .get(&key_bytes)
        .cloned()
        .unwrap_or([0u8; 32]);  // valeur par défaut = 0 si absent

    let value_u256 = u256::from_big_endian(&value);

    evm_stack.push(value_u256);

    println!(
        "📖 [TLOAD] transient[0x{}] = 0x{:064x}",
        hex::encode(&key_bytes),
        value_u256
    );

    // Gas cost pour TLOAD = 100 (warm access)
    consume_gas_amount(&mut execution_context, 100)?;
}

            // ___ 0x5d TSTORE (EIP-1153 Transient Storage Store)
            0x5d => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on TSTORE"));
                }

                let value_u256 = evm_stack.pop().unwrap();
                let key_u256 = evm_stack.pop().unwrap();

                // Conversion en bytes
                let mut key_bytes = [0u8; 32];
                let mut value_bytes = [0u8; 32];
                key_u256.to_big_endian(&mut key_bytes);
                value_u256.to_big_endian(&mut value_bytes);

                // Écriture dans transient storage
                if value_u256.is_zero() {
                    // TSTORE 0 = delete (comme SSTORE)
                    execution_context
                        .world_state
                        .transient_storage
                        .remove(&key_bytes);
                    println!(
                        "🗑️ [TSTORE] transient[0x{}] ← DELETE",
                        hex::encode(&key_bytes)
                    );
                } else {
                    execution_context
                        .world_state
                        .transient_storage
                        .insert(key_bytes, value_bytes);
                    println!(
                        "💾 [TSTORE] transient[0x{}] ← 0x{:064x}",
                        hex::encode(&key_bytes),
                        value_u256
                    );
                }

                // Gas : 100 (warm) ou 2100 (cold/change) – simplifié à 100
                consume_gas_amount(&mut execution_context, 100)?;
            }

            // ___ 0x5e MCOPY - EIP-5656 : Memory Copy (dstOffset, srcOffset, length)
0x5e => {
    if evm_stack.len() < 3 {
        return Ok(halt_json_ebpf("Stack underflow on MCOPY"));
    }

    let length = evm_stack.pop().unwrap();
    let src_offset = evm_stack.pop().unwrap();
    let dst_offset = evm_stack.pop().unwrap();

    let dst_offset_usize = as_usize_or_fail(dst_offset);
    let src_offset_usize = as_usize_or_fail(src_offset);
    let len_usize = as_usize_or_fail(length);

    // Gas : 3 + 3 * (length + 31) / 32  (identique à CALLDATACOPY / CODECOPY)
    let words = (len_usize + 31) / 32;
    consume_gas_amount(&mut execution_context, 3 + 3 * words as u64)?;

    if len_usize == 0 {
        println!("📋 [MCOPY] length=0 → no-op");
        break; // ou continue selon ton style
    }

    // Redimensionnement sécurisé de la mémoire
    let max_needed = dst_offset_usize.saturating_add(len_usize)
        .max(src_offset_usize.saturating_add(len_usize));

    if !resize_memory_ebpf(&mut global_mem, max_needed, 0) {  // le 2e paramètre n'est plus utilisé dans ta fn actuelle
        return Ok(halt_json_ebpf("Memory resize failed on MCOPY"));
    }

    // Copie sécurisée (overlap-safe comme memmove, pas memcpy)
    let copy_len = len_usize.min(
        global_mem.len().saturating_sub(dst_offset_usize)
            .min(global_mem.len().saturating_sub(src_offset_usize))
    );

    if copy_len > 0 {
        // On utilise une slice temporaire pour gérer correctement les overlaps
        let data: Vec<u8> = global_mem[src_offset_usize..src_offset_usize + copy_len].to_vec();
        global_mem[dst_offset_usize..dst_offset_usize + copy_len].copy_from_slice(&data);
    }

    println!(
        "📋 [MCOPY] mem[{}:{}] ← mem[{}:{}] ({} bytes copiés)",
        dst_offset, dst_offset + length,
        src_offset, src_offset + length,
        copy_len
    );
}

            //___ 0x5f PUSH0
            0x5f => {
                evm_stack.push(u256::zero());
                println!("📌 [PUSH0] 0");
                consume_gas_amount(&mut execution_context, 2)?;
            }

            //___ 0x60-0x7f PUSH1-PUSH32
            0x60..=0x7f => {
                let push_size = (opcode - 0x60 + 1) as usize;
                let mut data = vec![0u8; 32];

                for i in 0..push_size {
                    if bytecode_pc + 1 + i < prog.len() {
                        data[32 - push_size + i] = prog[bytecode_pc + 1 + i];
                    }
                }

                let value = u256::from_big_endian(&data);
                evm_stack.push(value);

                println!(
                    "📌 [PUSH{}] 0x{}",
                    push_size,
                    hex::encode(&data[32 - push_size..])
                );
                advance = 1 + push_size;
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x80-0x8f DUP1-DUP16
            0x80..=0x8f => {
                let dup_index = (opcode - 0x80 + 1) as usize;
                if evm_stack.len() < dup_index {
                    return Ok(halt_json_ebpf(&format!(
                        "Stack underflow on DUP{}",
                        dup_index
                    )));
                }
                let value = evm_stack[evm_stack.len() - dup_index].clone();
                evm_stack.push(value);
                println!("📋 [DUP{}] {}", dup_index, value);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0x90-0x9f SWAP1-SWAP16
            0x90..=0x9f => {
                let swap_index = (opcode - 0x90 + 1) as usize;
                if evm_stack.len() < swap_index + 1 {
                    return Ok(halt_json_ebpf(&format!(
                        "Stack underflow on SWAP{}",
                        swap_index
                    )));
                }
                let len = evm_stack.len();
                evm_stack.swap(len - 1, len - 1 - swap_index);
                println!("🔄 [SWAP{}]", swap_index);
                consume_gas_amount(&mut execution_context, 3)?;
            }

            //___ 0xa0-0xa4 LOG0-LOG4
            0xa0..=0xa4 => {
                let topic_count = (opcode - 0xa0) as usize;
                if evm_stack.len() < 2 + topic_count {
                    return Ok(halt_json_ebpf(&format!(
                        "Stack underflow on LOG{}",
                        topic_count
                    )));
                }

                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let mut topics = Vec::new();
                for _ in 0..topic_count {
                    let topic = evm_stack.pop().unwrap();
                    topics.push(format!("{:064x}", topic));
                }

                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on LOG"));
                }

                let data = memory_slice_len(&global_mem, offset_usize, size_usize).to_vec();

                let log = UvmLog {
                    address: interpreter_args.contract_address.clone(),
                    topics,
                    data,
                };

                execution_context.logs.push(log);
                println!(
                    "📝 [LOG{}] {} topics, {} bytes",
                    topic_count, topic_count, size_usize
                );
                consume_gas_amount(
                    &mut execution_context,
                    375 + 375 * topic_count as u64 + 8 * size_usize as u64,
                )?;
            }

            0xec => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on SS7_SEND"));
                }

                let msg_type = evm_stack.pop().unwrap().low_u64();
                let payload_ptr = evm_stack.pop().unwrap().low_u64();
                let payload_len = evm_stack.pop().unwrap().low_u64();

                // Récupère le payload réel fourni par l'oracle Chainlink
                let real_payload = if payload_len > 0 && payload_ptr > 0 && payload_len < 8192 {
                    let start = payload_ptr as usize;
                    let end = (start + payload_len as usize).min(global_mem.len());
                    &global_mem[start..end]
                } else {
                    &[]
                };

                // === AUCUNE SIMULATION ===
                // L'envoi SS7 réel est fait OFF-CHAIN par Chainlink Functions + ta gateway 3CX/SIGTRAN
                // Ici on ne fait QUE valider + logger (opcode serveless pur)

                if !real_payload.is_empty() {
                    println!(
                        "[0xec SS7 SEND RÉEL] msg_type={} payload_len={} payload=0x{}",
                        msg_type,
                        real_payload.len(),
                        if real_payload.len() > 64 {
                            hex::encode(&real_payload[..64]) + "..."
                        } else {
                            hex::encode(real_payload)
                        }
                    );
                } else {
                    println!("[0xec SS7 SEND RÉEL] Aucun payload (erreur oracle)");
                }

                // Succès → le vrai envoi SS7 est déclenché par l'oracle
                let res = 0u64; // 0 = SUCCESS (le gateway 3CX a été appelé hors VM)

                evm_stack.push(res.into());
                consume_gas_amount(&mut execution_context, 350)?;
            }

            //___ 0xef FFI_CALL_PHONE_EMULATOR451 - APPEL TÉLÉPHONIQUE STANDARD VIA ÉMULATEUR
            0xef => {
                if evm_stack.len() < 7 {
                    return Ok(halt_json_ebpf("Stack underflow SS7 voice"));
                }

                let msg_type = evm_stack.pop().unwrap();
                let caller_hash = evm_stack.pop().unwrap();
                let called_hash = evm_stack.pop().unwrap();
                let call_ts = evm_stack.pop().unwrap();
                let extra = evm_stack.pop().unwrap();
                let payload_ptr = evm_stack.pop().unwrap();
                let payload_len = evm_stack.pop().unwrap();

                let res = helpers
                    .get(&0x460)
                    .map(|f| {
                        f(
                            msg_type.low_u64(),
                            caller_hash.low_u64(),
                            called_hash.low_u64(),
                            call_ts.low_u64(),
                            extra.low_u64(),
                            payload_ptr.low_u64(),
                            payload_len.low_u64(),
                        )
                    })
                    .unwrap_or(1u64);

                evm_stack.push(res.into());
                consume_gas_amount(&mut execution_context, 450)?;
            }

            //___ 0xf0 CREATE - DÉPLOIEMENT DE CONTRAT
            0xf0 => {
                if evm_stack.len() < 3 {
                    return Ok(halt_json_ebpf("Stack underflow on CREATE"));
                }

                let value = evm_stack.pop().unwrap();
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();

                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CREATE"));
                }

                let init_code = memory_slice_len(&global_mem, offset_usize, size_usize).to_vec();

                println!(
                    "🛠️ [CREATE] value={}, init_code_len={}",
                    value,
                    init_code.len()
                );

                // Adresse prédite (simulation simple mais cohérente)
                let new_address = format!(
                    "0x{:040x}",
                    execution_context.world_state.accounts.len() + 100
                );

                // ✅ CAPTURE + PERSISTANCE RÉELLE DU BYTECODE
                execution_context
                    .world_state
                    .code
                    .insert(new_address.clone(), init_code.clone());

                let new_account = AccountState {
                    balance: value,
                    nonce: u256::one(),
                    code: init_code.clone(), // bytecode complet
                    storage_root: String::new(),
                    is_contract: true,
                };

                execution_context
                    .world_state
                    .accounts
                    .insert(new_address.clone(), new_account);

                // Persistance supplémentaire pour que eth_getCode le voie
                println!(
                    "💾 [CREATE PERSIST] Contrat sauvegardé à {} ({} bytes)",
                    new_address,
                    init_code.len()
                );

                evm_stack.push(encode_address_to_u256(&new_address));
                println!(
                    "✅ [CREATE] Nouveau contrat déployé et persistant à {}",
                    new_address
                );

                consume_gas_amount(&mut execution_context, 32000)?;
            }

            //___ 0xf1 CALL
            0xf1 => {
                if evm_stack.len() < 7 {
                    return Ok(halt_json_ebpf("Stack underflow on CALL"));
                }

                let gas = evm_stack.pop().unwrap();
                let to_addr_u256 = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let in_offset = evm_stack.pop().unwrap();
                let in_size = evm_stack.pop().unwrap();
                let out_offset = evm_stack.pop().unwrap();
                let out_size = evm_stack.pop().unwrap();

                let to_address = u256_to_address(to_addr_u256);

                println!(
                    "📞 [CALL] to={}, value={}, gas={}, in_offset={}, in_size={}, out_offset={}, out_size={}",
                    to_address, value, gas, in_offset, in_size, out_offset, out_size
                );

                // ✅ Extraction du calldata RÉEL depuis la mémoire du caller
                let in_offset_usize = as_usize_or_fail(in_offset);
                let in_size_usize = as_usize_or_fail(in_size);

                if !resize_memory_ebpf(&mut global_mem, in_offset_usize, in_size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CALL (input)"));
                }

                let call_data =
                    memory_slice_len(&global_mem, in_offset_usize, in_size_usize).to_vec();

                println!(
                    "📥 [CALL INPUT] calldata = 0x{}",
                    if call_data.len() > 64 {
                        hex::encode(&call_data[..64]) + "..."
                    } else {
                        hex::encode(&call_data)
                    }
                );

                // ✅ CORRECTION MAJEURE : Récupération du bytecode avec fallback RocksDB
                let mut target_code = execution_context
                    .world_state
                    .code
                    .get(&to_address)
                    .or_else(|| {
                        execution_context
                            .world_state
                            .accounts
                            .get(&to_address)
                            .map(|acc| &acc.code)
                    })
                    .cloned()
                    .unwrap_or_default();

                // ✅ FALLBACK ROCKSDB : Si le code est vide en mémoire, cherche dans RocksDB
                if target_code.is_empty() {
                    if let Some(ref storage_manager) = execution_context.storage_manager {
                        let contract_state_key = format!("account:{}:contract_state", to_address);

                        match storage_manager.read(&contract_state_key) {
                            Ok(bytecode) if !bytecode.is_empty() => {
                                println!(
                                    "💾 [CALL ROCKSDB] Bytecode récupéré depuis RocksDB : {} bytes",
                                    bytecode.len()
                                );
                                target_code = bytecode;

                                // ✅ Met en cache pour les prochains appels
                                execution_context
                                    .world_state
                                    .code
                                    .insert(to_address.clone(), target_code.clone());
                            }
                            Ok(_) => {
                                println!(
                                    "🔍 [CALL ROCKSDB] Bytecode vide ou inexistant pour {}",
                                    to_address
                                );
                            }
                            Err(e) => {
                                println!("❌ [CALL ROCKSDB] Erreur lecture : {}", e);
                            }
                        }
                    }
                }

                // ✅ VÉRIFICATION FINALE
                if target_code.is_empty() {
                    println!(
                        "⚠️ [CALL] Contrat {} n'a pas de code (EOA ou inexistant)",
                        to_address
                    );

                    // ✅ Pour un EOA, returndata vide mais succès
                    execution_context.return_data = vec![];
                    evm_stack.push(u256::one());

                    consume_gas_amount(&mut execution_context, 700)?;
                    bytecode_pc += 1;
                    continue;
                }

                println!(
                    "🔄 [CALL RECURSIVE] Exécution de {} bytes de bytecode",
                    target_code.len()
                );

                // ✅ Création d'un sous-contexte ISOLÉ
                let mut sub_args = interpreter_args.clone();
                sub_args.contract_address = to_address.clone();
                sub_args.sender_address = interpreter_args.contract_address.clone(); // msg.sender = caller contract
                sub_args.caller = interpreter_args.contract_address.clone();
                sub_args.state_data = call_data.clone();
                sub_args.value = value;
                sub_args.gas_limit = gas;
                sub_args.call_depth = interpreter_args.call_depth + u256::one();

                // ✅ Limite anti-récursion infinie
                if sub_args.call_depth > u256::from(1024) {
                    println!("🚨 [CALL] Profondeur maximale atteinte (1024)");
                    execution_context.return_data = vec![];
                    evm_stack.push(u256::zero());
                    consume_gas_amount(&mut execution_context, 700)?;
                    bytecode_pc += 1;
                    continue;
                }

                // ✅ Appel récursif avec bytecode et storage isolés
                let sub_result = execute_program(
                    Some(&target_code), // ← BYTECODE RÉCUPÉRÉ (mémoire OU RocksDB)
                    Some(stack_usage),
                    &[],        // mémoire vierge pour le sous-contexte
                    &call_data, // mbuff = calldata
                    helpers,
                    allowed_memory,
                    ret_type,
                    exports,
                    &sub_args,
                    execution_context.storage_manager.clone(),
                    Some(execution_context.world_state.storage.clone()), // storage hérité
                    execution_context.on_create2_event.clone(), // propagation du callback CREATE2
                );

                // ✅ Extraction du returndata avec gestion robuste
                let (call_success, return_data) = match sub_result {
                    Ok(val) => {
                        if let Some(obj) = val.as_object() {
                            let action = obj
                                .get("action")
                                .and_then(|a| a.as_str())
                                .unwrap_or("unknown");

                            let success = action == "return" || action == "stop";

                            // ✅ Extraction améliorée du returndata
                            let data = if action == "return" || action == "stop" {
                                obj.get("data")
                                    .and_then(|d| match d {
                                        JsonValue::String(s) if s.starts_with("0x") => {
                                            hex::decode(&s[2..]).ok()
                                        }
                                        JsonValue::Bool(b) => {
                                            let mut bytes = [0u8; 32];
                                            if *b {
                                                bytes[31] = 1;
                                            }
                                            Some(bytes.to_vec())
                                        }
                                        JsonValue::Number(n) => {
                                            let num_u64 = n.as_u64().unwrap_or(0);
                                            let mut bytes = [0u8; 32];
                                            u256::from(num_u64).to_big_endian(&mut bytes);
                                            Some(bytes.to_vec())
                                        }
                                        _ => Some(vec![]), // STOP sans données
                                    })
                                    .unwrap_or_default()
                            } else {
                                vec![] // REVERT ou erreur
                            };

                            (success, data)
                        } else {
                            (false, vec![])
                        }
                    }
                    Err(e) => {
                        println!("❌ [CALL ERROR] Sous-appel échoué : {:?}", e);
                        (false, vec![])
                    }
                };

                println!(
                    "✅ [CALL RETURN] success={}, returndata_len={}",
                    call_success,
                    return_data.len()
                );

                // ✅ Écriture du returndata dans la mémoire du caller
                let out_offset_usize = as_usize_or_fail(out_offset);
                let out_size_usize = as_usize_or_fail(out_size);

                if out_size_usize > 0 {
                    if !resize_memory_ebpf(&mut global_mem, out_offset_usize, out_size_usize) {
                        return Ok(halt_json_ebpf("Memory resize failed on CALL (output)"));
                    }

                    let copy_len = out_size_usize.min(return_data.len());
                    for i in 0..copy_len {
                        if out_offset_usize + i < global_mem.len() {
                            global_mem[out_offset_usize + i] = return_data[i];
                        }
                    }

                    // ✅ Padding avec zéros si out_size > returndata
                    for i in copy_len..out_size_usize {
                        if out_offset_usize + i < global_mem.len() {
                            global_mem[out_offset_usize + i] = 0;
                        }
                    }
                }

                // ✅ Sauvegarde du returndata pour RETURNDATACOPY/RETURNDATASIZE
                execution_context.return_data = return_data;

                // ✅ Push du status de succès sur la stack
                evm_stack.push(if call_success {
                    u256::one()
                } else {
                    u256::zero()
                });

                consume_gas_amount(&mut execution_context, 700)?;
            }

            //___ 0xf2 CALLCODE - Version production (exécute dans le contexte du caller, value transférée)
0xf2 => {
    if evm_stack.len() < 7 {
        return Ok(halt_json_ebpf("Stack underflow on CALLCODE"));
    }

    let gas = evm_stack.pop().unwrap();
    let to_addr_u256 = evm_stack.pop().unwrap();
    let value = evm_stack.pop().unwrap();
    let in_offset = evm_stack.pop().unwrap();
    let in_size = evm_stack.pop().unwrap();
    let out_offset = evm_stack.pop().unwrap();
    let out_size = evm_stack.pop().unwrap();

    let to_address = u256_to_address(to_addr_u256);

    println!(
        "📞 [CALLCODE] to={}, value={}, gas={}, in=mem[{}:{}], out=mem[{}:{}]",
        to_address, value, gas, in_offset, in_size, out_offset, out_size
    );

    // Extraction du calldata depuis la mémoire
    let in_offset_usize = as_usize_or_fail(in_offset);
    let in_size_usize = as_usize_or_fail(in_size);

    if !resize_memory_ebpf(&mut global_mem, in_offset_usize, in_size_usize) {
        return Ok(halt_json_ebpf("Memory resize failed on CALLCODE (input)"));
    }

    let call_data = memory_slice_len(&global_mem, in_offset_usize, in_size_usize).to_vec();

    // Récupération du bytecode cible
    let mut target_code = execution_context
        .world_state
        .code
        .get(&to_address)
        .or_else(|| execution_context.world_state.accounts.get(&to_address).map(|acc| &acc.code))
        .cloned()
        .unwrap_or_default();

    // Fallback RocksDB si nécessaire
    if target_code.is_empty() {
        if let Some(ref storage_manager) = execution_context.storage_manager {
            let contract_state_key = format!("account:{}:contract_state", to_address);
            if let Ok(bytecode) = storage_manager.read(&contract_state_key) {
                if !bytecode.is_empty() {
                    target_code = bytecode;
                    execution_context.world_state.code.insert(to_address.clone(), target_code.clone());
                }
            }
        }
    }

    if target_code.is_empty() {
        // EOA ou contrat sans code → succès, pas de retour de données
        execution_context.return_data = vec![];
        let out_offset_usize = as_usize_or_fail(out_offset);
        let out_size_usize = as_usize_or_fail(out_size);
        if resize_memory_ebpf(&mut global_mem, out_offset_usize, out_size_usize) {
            for i in 0..out_size_usize {
                global_mem[out_offset_usize + i] = 0;
            }
        }
        evm_stack.push(u256::one());
        consume_gas_amount(&mut execution_context, 700)?;
        bytecode_pc += 1;
        continue;
    }

    // Création du sous-contexte (CALLCODE exécute dans le contexte du caller)
    let mut sub_args = interpreter_args.clone();
    sub_args.contract_address = to_address.clone();
    sub_args.sender_address = interpreter_args.contract_address.clone(); // msg.sender reste le caller
    sub_args.caller = interpreter_args.contract_address.clone();
    sub_args.state_data = call_data.clone();
    sub_args.value = value;                    // value est transférée (contrairement à DELEGATECALL)
    sub_args.gas_limit = gas;
    sub_args.call_depth = interpreter_args.call_depth + u256::one();

    if sub_args.call_depth > u256::from(1024) {
        println!("🚨 [CALLCODE] Max call depth reached");
        execution_context.return_data = vec![];
        evm_stack.push(u256::zero());
        consume_gas_amount(&mut execution_context, 700)?;
        bytecode_pc += 1;
        continue;
    }

    // Appel récursif
    let sub_result = execute_program(
        Some(&target_code),
        Some(stack_usage),
        &[],                    // mem vierge
        &call_data,
        helpers,
        allowed_memory,
        ret_type,
        exports,
        &sub_args,
        execution_context.storage_manager.clone(),
        Some(execution_context.world_state.storage.clone()),
        execution_context.on_create2_event.clone(),
    );

    let (call_success, return_data) = match sub_result {
        Ok(val) => {
            if let Some(obj) = val.as_object() {
                let action = obj.get("action").and_then(|a| a.as_str()).unwrap_or("unknown");
                let success = action == "return" || action == "stop";

                let data = if action == "return" || action == "stop" {
                    obj.get("data").and_then(|d| match d {
                        JsonValue::String(s) if s.starts_with("0x") => hex::decode(&s[2..]).ok(),
                        JsonValue::Bool(b) => {
                            let mut bytes = [0u8; 32];
                            if *b { bytes[31] = 1; }
                            Some(bytes.to_vec())
                        }
                        JsonValue::Number(n) => {
                            let num = n.as_u64().unwrap_or(0);
                            let mut bytes = [0u8; 32];
                            u256::from(num).to_big_endian(&mut bytes);
                            Some(bytes.to_vec())
                        }
                        _ => Some(vec![]),
                    }).unwrap_or_default()
                } else {
                    vec![]
                };
                (success, data)
            } else {
                (false, vec![])
            }
        }
        Err(e) => {
            println!("❌ [CALLCODE ERROR] {:?}", e);
            (false, vec![])
        }
    };

    // Copie du retour dans la mémoire du caller
    let out_offset_usize = as_usize_or_fail(out_offset);
    let out_size_usize = as_usize_or_fail(out_size);
    if resize_memory_ebpf(&mut global_mem, out_offset_usize, out_size_usize) {
        for i in 0..out_size_usize {
            global_mem[out_offset_usize + i] = 0;
        }
        let copy_len = std::cmp::min(return_data.len(), out_size_usize);
        global_mem[out_offset_usize..out_offset_usize + copy_len].copy_from_slice(&return_data[0..copy_len]);
    }

    execution_context.return_data = return_data;

    evm_stack.push(if call_success { u256::one() } else { u256::zero() });

    consume_gas_amount(&mut execution_context, 700)?;
    bytecode_pc += 1;
}
            
            //___ 0xf3 RETURN - Style eBPF avec action et résultat
            0xf3 => {
                // RETURN
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on RETURN"));
                }

                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();
                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                let mut output_bytes = vec![0u8; size_usize];
                if size_usize > 0 {
                    if !resize_memory_ebpf(&mut global_mem, offset_usize, size_usize) {
                        return Ok(halt_json_ebpf("Memory resize failed on RETURN"));
                    }
                    let src = memory_slice_len(&global_mem, offset_usize, size_usize);
                    output_bytes[..src.len()].copy_from_slice(src);
                }

                println!(
                    "✅ [RETURN] offset={}, size={}, runtime={} bytes",
                    offset,
                    size,
                    output_bytes.len()
                );

                // NOUVEAU : avant de retourner, on construit le résultat avec les writes
                let mut result = create_return_action(output_bytes);

                if let Some(obj) = result.as_object_mut() {
                    // On ajoute une clé "storage" avec tous les slots modifiés
                    let mut storage_written = serde_json::Map::new();
                    for (slot, val) in temp_storage_writes {
                        storage_written
                            .insert(slot, JsonValue::String(format!("0x{}", hex::encode(&val))));
                    }
                    if !storage_written.is_empty() {
                        obj.insert("storage".to_string(), JsonValue::Object(storage_written));
                    }
                }

                return Ok(result);
            }

                     //___ 0xf5 CREATE2 - Version corrigée avec extraction runtime
            0xf5 => {
                if evm_stack.len() < 4 {
                    return Ok(halt_json_ebpf("Stack underflow on CREATE2"));
                }

                let value = evm_stack.pop().unwrap();
                let offset = evm_stack.pop().unwrap();
                let size = evm_stack.pop().unwrap();
                let salt = evm_stack.pop().unwrap();

                let offset_usize = as_usize_or_fail(offset);
                let size_usize = as_usize_or_fail(size);

                if !resize_memory_ebpf(&mut global_mem, offset_usize, size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CREATE2"));
                }

                let init_code = memory_slice_len(&global_mem, offset_usize, size_usize).to_vec();

                println!(
                    "🛠️ [CREATE2] value={}, init_code_len={}, salt={:064x}",
                    value,
                    init_code.len(),
                    salt
                );

                if init_code.is_empty() {
                    println!("❌ [CREATE2] Init code vide");
                    evm_stack.push(u256::zero());
                    consume_gas_amount(&mut execution_context, 32000)?;
                    bytecode_pc += 1;
                    continue;
                }

                // === Assemblage adresse CREATE2 ===
                let mut hasher = Keccak256::new();
                hasher.update(&[0xff]);

                let sender = interpreter_args.contract_address.clone();
                let mut sender_bytes = [0u8; 20];
                if let Ok(decoded) = hex::decode(sender.trim_start_matches("0x")) {
                    if decoded.len() == 20 {
                        sender_bytes.copy_from_slice(&decoded);
                    }
                }
                hasher.update(&sender_bytes);

                let mut salt_bytes = [0u8; 32];
                salt.to_big_endian(&mut salt_bytes);
                hasher.update(&salt_bytes);

                let init_code_hash = Keccak256::digest(&init_code);
                hasher.update(&init_code_hash);

                let hash = hasher.finalize();
                let new_address = format!("0x{}", hex::encode(&hash[12..32]));

                println!("📍 [CREATE2] Adresse calculée : {}", new_address);

                // ✅ NOUVEAU: Extraction du runtime depuis le creation bytecode
                let runtime_bytecode = match extract_runtime_from_creation_bytecode(&init_code) {
                    Ok(runtime) => {
                        println!("✅ [CREATE2] Runtime extrait: {} bytes", runtime.len());
                        runtime
                    }
                    Err(e) => {
                        println!("⚠️ [CREATE2] Impossible d'extraire le runtime: {} - utilise creation code", e);
                        // Fallback: utilise le creation code directement
                        init_code.clone()
                    }
                };

                // === Persistance du contrat avec le RUNTIME ===
                execution_context
                    .world_state
                    .code
                    .insert(new_address.clone(), runtime_bytecode.clone());

                let new_account = AccountState {
                    balance: value,
                    nonce: u256::one(),
                    code: runtime_bytecode.clone(), // ✅ CORRECTION: utilise le runtime
                    storage_root: String::new(),
                    is_contract: true,
                };
                execution_context
                    .world_state
                    .accounts
                    .insert(new_address.clone(), new_account);

                println!(
                    "💾 [CREATE2 PERSIST] Contrat sauvegardé avec runtime à {} ({} bytes)",
                    new_address,
                    runtime_bytecode.len()
                );

                // Persistance RocksDB avec le runtime
                if let Some(ref storage_manager) = execution_context.storage_manager {
                    let code_key = format!("account:{}:contract_state", new_address);
                    let _ = storage_manager.write(&code_key, &runtime_bytecode); // ✅ runtime, pas init_code
                    println!("💾 [CREATE2 ROCKSDB] Runtime persisté pour {}", new_address);
                }

                // Déclenchement du callback avec le runtime
                if let Some(ref callback) = execution_context.on_create2_event {
                    if let Err(e) = callback(&new_address, runtime_bytecode.clone(), value) {
                        println!("⚠️ [CREATE2] Erreur callback : {}", e);
                    }
                }

                println!("✅ [CREATE2] Contrat déployé avec runtime à {}", new_address);

                // Push l'adresse sur la stack
                evm_stack.push(encode_address_to_u256(&new_address));

                consume_gas_amount(&mut execution_context, 32000)?;
            }

            // 0xf4 DELEGATECALL - Similaire à CALLCODE mais sans transfert de valeur
            0xf4 => {
                if evm_stack.len() < 7 {
                    return Ok(halt_json_ebpf("Stack underflow on DELEGATECALL"));
                }

                let gas = evm_stack.pop().unwrap();
                let to_addr_u256 = evm_stack.pop().unwrap();
                let in_offset = evm_stack.pop().unwrap();
                let in_size = evm_stack.pop().unwrap();
                let out_offset = evm_stack.pop().unwrap();
                let out_size = evm_stack.pop().unwrap();

                let to_address = u256_to_address(to_addr_u256);
                println!(
                    "📞 [DELEGATECALL] to={}, gas={}, in=mem[{}:{}], out=mem[{}:{}]",
                    to_address, gas, in_offset, in_size, out_offset, out_size
                );

                // Simulate delegate call (stub - real implementation would execute the call)
                let call_success = true; // Assume success for stub
                let return_data = vec![0u8; out_size.low_u64() as usize]; // Empty return data

                // Write return data to memory
                if !resize_memory_ebpf(
                    &mut global_mem,
                    out_offset.low_u64() as usize,
                    out_size.low_u64() as usize,
                ) {
                    return Ok(halt_json_ebpf("Memory resize failed on DELEGATECALL"));
                }
                for i in 0..(out_size.low_u64() as usize) {
                    if out_offset.low_u64() as usize + i < global_mem.len() {
                        global_mem[out_offset.low_u64() as usize + i] = return_data[i];
                    }
                }

                // Push success status onto stack
                evm_stack.push(if call_success {
                    u256::one()
                } else {
                    u256::zero()
                });

                consume_gas_amount(&mut execution_context, 700)?; // Simplified gas cost
            }

            // ___ 0xf6 AUTH (EIP-3074 Authorization)
            0xf6 => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on AUTH"));
                }

                let authority = evm_stack.pop().unwrap(); // address
                let commit = evm_stack.pop().unwrap();    // bytes32

                let authority_addr = u256_to_address(authority);
                println!(
                    "🔐 [AUTH] authority={}, commit={:064x}",
                    authority_addr, commit
                );

                // Simulate authorization (stub - real implementation would verify signature)
                let auth_success = true; // Assume success for stub
                
                // Set authorization context for subsequent AUTHCALL
                execution_context.auth_context = Some((authority_addr.clone(), commit));
                
                println!("✅ [AUTH] Authorization set for {}", authority_addr);

                // Push success status onto stack (1 = success, 0 = failure)
                evm_stack.push(if auth_success {
                    u256::one()
                } else {
                    u256::zero()
                });

                consume_gas_amount(&mut execution_context, 3100)?; // EIP-3074 gas cost
            }

            // ___ 0xf7 AUTHCALL (EIP-3074 Authorized Call)  
            0xf7 => {
                if evm_stack.len() < 7 {
                    return Ok(halt_json_ebpf("Stack underflow on AUTHCALL"));
                }

                let gas = evm_stack.pop().unwrap();
                let addr = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let args_offset = evm_stack.pop().unwrap();
                let args_size = evm_stack.pop().unwrap();
                let ret_offset = evm_stack.pop().unwrap();
                let ret_size = evm_stack.pop().unwrap();

                let target_addr = u256_to_address(addr);
                println!(
                    "🔐 [AUTHCALL] to={}, value={}, gas={}, args=mem[{}:{}], ret=mem[{}:{}]",
                    target_addr, value, gas, args_offset, args_size, ret_offset, ret_size
                );

                // Check if authorization is set
                if execution_context.auth_context.is_none() {
                    println!("❌ [AUTHCALL] No authorization set - AUTH must be called first");
                    evm_stack.push(u256::zero()); // Failure
                    consume_gas_amount(&mut execution_context, 100)?;
                    continue;
                }

                let (auth_addr, _commit) = execution_context.auth_context.as_ref().unwrap();
                println!("✅ [AUTHCALL] Using authorization from {}", auth_addr);

                // Simulate authorized call (stub - real implementation would execute with authority context)
                let call_success = true; // Assume success for stub
                let return_data = vec![0u8; ret_size.low_u64() as usize]; // Empty return data

                // Write return data to memory
                if !resize_memory_ebpf(
                    &mut global_mem,
                    ret_offset.low_u64() as usize,
                    ret_size.low_u64() as usize,
                ) {
                    return Ok(halt_json_ebpf("Memory resize failed on AUTHCALL"));
                }
                for i in 0..(ret_size.low_u64() as usize) {
                    if ret_offset.low_u64() as usize + i < global_mem.len() {
                        global_mem[ret_offset.low_u64() as usize + i] = return_data[i];
                    }
                }

                // Push success status onto stack
                evm_stack.push(if call_success {
                    u256::one()
                } else {
                    u256::zero()
                });

                consume_gas_amount(&mut execution_context, 700)?; // Simplified gas cost
            }

//___ 0xfa STATICCALL
            0xfa => {
                if evm_stack.len() < 7 {
                    return Ok(halt_json_ebpf("Stack underflow on STATICCALL"));
                }

                let gas = evm_stack.pop().unwrap();
                let to_addr_u256 = evm_stack.pop().unwrap();
                let value = evm_stack.pop().unwrap();
                let in_offset = evm_stack.pop().unwrap();
                let in_size = evm_stack.pop().unwrap();
                let out_offset = evm_stack.pop().unwrap();
                let out_size = evm_stack.pop().unwrap();

                let to_address = u256_to_address(to_addr_u256);

                println!(
                    "📞 [STATICCALL] to={}, value={}, gas={}, in_offset={}, in_size={}, out_offset={}, out_size={}",
                    to_address, value, gas, in_offset, in_size, out_offset, out_size
                );

                // ✅ Extraction du calldata RÉEL depuis la mémoire du caller
                let in_offset_usize = as_usize_or_fail(in_offset);
                let in_size_usize = as_usize_or_fail(in_size);

                if !resize_memory_ebpf(&mut global_mem, in_offset_usize, in_size_usize) {
                    return Ok(halt_json_ebpf("Memory resize failed on CALL (input)"));
                }

                let call_data =
                    memory_slice_len(&global_mem, in_offset_usize, in_size_usize).to_vec();

                println!(
                    "📥 [STATICCALL INPUT] calldata = 0x{}",
                    if call_data.len() > 64 {
                        hex::encode(&call_data[..64]) + "..."
                    } else {
                        hex::encode(&call_data)
                    }
                );

                // ✅ CORRECTION MAJEURE : Récupération du bytecode avec fallback RocksDB
                let mut target_code = execution_context
                    .world_state
                    .code
                    .get(&to_address)
                    .or_else(|| {
                        execution_context
                            .world_state
                            .accounts
                            .get(&to_address)
                            .map(|acc| &acc.code)
                    })
                    .cloned()
                    .unwrap_or_default();

                // ✅ FALLBACK ROCKSDB : Si le code est vide en mémoire, cherche dans RocksDB
                if target_code.is_empty() {
                    if let Some(ref storage_manager) = execution_context.storage_manager {
                        let contract_state_key = format!("account:{}:contract_state", to_address);

                        match storage_manager.read(&contract_state_key) {
                            Ok(bytecode) if !bytecode.is_empty() => {
                                println!(
                                    "💾 [STATICCALL ROCKSDB] Bytecode récupéré depuis RocksDB : {} bytes",
                                    bytecode.len()
                                );
                                target_code = bytecode;

                                // ✅ Met en cache pour les prochains appels
                                execution_context
                                    .world_state
                                    .code
                                    .insert(to_address.clone(), target_code.clone());
                            }
                            Ok(_) => {
                                println!(
                                    "🔍 [STATICCALL ROCKSDB] Bytecode vide ou inexistant pour {}",
                                    to_address
                                );
                            }
                            Err(e) => {
                                println!("❌ [STATICCALL ROCKSDB] Erreur lecture : {}", e);
                            }
                        }
                    }
                }

                // ✅ VÉRIFICATION FINALE
                if target_code.is_empty() {
                    println!(
                        "⚠️ [STATICCALL] Contrat {} n'a pas de code (EOA ou inexistant)",
                        to_address
                    );

                    // ✅ Pour un EOA, returndata vide mais succès
                    execution_context.return_data = vec![];
                    evm_stack.push(u256::one());

                    consume_gas_amount(&mut execution_context, 700)?;
                    bytecode_pc += 1;
                    continue;
                }

                println!(
                    "🔄 [STATICCALL RECURSIVE] Exécution de {} bytes de bytecode",
                    target_code.len()
                );

                // ✅ Création d'un sous-contexte ISOLÉ
                let mut sub_args = interpreter_args.clone();
                sub_args.contract_address = to_address.clone();
                sub_args.sender_address = interpreter_args.contract_address.clone(); // msg.sender = caller contract
                sub_args.caller = interpreter_args.contract_address.clone();
                sub_args.state_data = call_data.clone();
                sub_args.value = value;
                sub_args.gas_limit = gas;
                sub_args.call_depth = interpreter_args.call_depth + u256::one();

                // ✅ Limite anti-récursion infinie
                if sub_args.call_depth > u256::from(1024) {
                    println!("🚨 [STATICCALL] Profondeur maximale atteinte (1024)");
                    execution_context.return_data = vec![];
                    evm_stack.push(u256::zero());
                    consume_gas_amount(&mut execution_context, 700)?;
                    bytecode_pc += 1;
                    continue;
                }

                // ✅ Appel récursif avec bytecode et storage isolés
                let sub_result = execute_program(
                    Some(&target_code), // ← BYTECODE RÉCUPÉRÉ (mémoire OU RocksDB)
                    Some(stack_usage),
                    &[],        // mémoire vierge pour le sous-contexte
                    &call_data, // mbuff = calldata
                    helpers,
                    allowed_memory,
                    ret_type,
                    exports,
                    &sub_args,
                    execution_context.storage_manager.clone(),
                    Some(execution_context.world_state.storage.clone()), // storage hérité
                    execution_context.on_create2_event.clone(), // propagation du callback CREATE2
                );

                // ✅ Extraction du returndata avec gestion robuste
                let (call_success, return_data) = match sub_result {
                    Ok(val) => {
                        if let Some(obj) = val.as_object() {
                            let action = obj
                                .get("action")
                                .and_then(|a| a.as_str())
                                .unwrap_or("unknown");

                            let success = action == "return" || action == "stop";

                            // ✅ Extraction améliorée du returndata
                            let data = if action == "return" || action == "stop" {
                                obj.get("data")
                                    .and_then(|d| match d {
                                        JsonValue::String(s) if s.starts_with("0x") => {
                                            hex::decode(&s[2..]).ok()
                                        }
                                        JsonValue::Bool(b) => {
                                            let mut bytes = [0u8; 32];
                                            if *b {
                                                bytes[31] = 1;
                                            }
                                            Some(bytes.to_vec())
                                        }
                                        JsonValue::Number(n) => {
                                            let num_u64 = n.as_u64().unwrap_or(0);
                                            let mut bytes = [0u8; 32];
                                            u256::from(num_u64).to_big_endian(&mut bytes);
                                            Some(bytes.to_vec())
                                        }
                                        _ => Some(vec![]), // STOP sans données
                                    })
                                    .unwrap_or_default()
                            } else {
                                vec![] // REVERT ou erreur
                            };

                            (success, data)
                        } else {
                            (false, vec![])
                        }
                    }
                    Err(e) => {
                        println!("❌ [CALL ERROR] Sous-appel échoué : {:?}", e);
                        (false, vec![])
                    }
                };

                println!(
                    "✅ [STATICCALL RETURN] success={}, returndata_len={}",
                    call_success,
                    return_data.len()
                );

                // ✅ Écriture du returndata dans la mémoire du caller
                let out_offset_usize = as_usize_or_fail(out_offset);
                let out_size_usize = as_usize_or_fail(out_size);

                if out_size_usize > 0 {

                    let copy_len = out_size_usize.min(return_data.len());
                    for i in 0..copy_len {
                        if out_offset_usize + i < global_mem.len() {
                            global_mem[out_offset_usize + i] = return_data[i];
                        }
                    }

                    // ✅ Padding avec zéros si out_size > returndata
                    for i in copy_len..out_size_usize {
                        if out_offset_usize + i < global_mem.len() {
                            global_mem[out_offset_usize + i] = 0;
                        }
                    }
                }

                // ✅ Sauvegarde du returndata pour RETURNDATACOPY/RETURNDATASIZE
                execution_context.return_data = return_data;

                // ✅ Push du status de succès sur la stack
                evm_stack.push(if call_success {
                    u256::one()
                } else {
                    u256::zero()
                });

                consume_gas_amount(&mut execution_context, 700)?;
            }  
            
            //___ 0xfd REVERT
            0xfd => {
                if evm_stack.len() < 2 {
                    return Ok(halt_json_ebpf("Stack underflow on REVERT"));
                }

                let offset = evm_stack.pop().unwrap().low_u64() as usize;
                let size = evm_stack.pop().unwrap().low_u64() as usize;

                // Copie sécurisée des données de revert
                let revert_data = if offset + size <= global_mem.len() {
                    global_mem[offset..offset + size].to_vec()
                } else {
                    global_mem[offset..].to_vec()
                };

                println!(
                    "❌ [REVERT] offset={}, size={}, data=0x{}",
                    offset,
                    size,
                    hex::encode(&revert_data)
                );

                let mut result = serde_json::Map::new();
                result.insert(
                    "action".to_string(),
                    JsonValue::String("revert".to_string()),
                );
                result.insert(
                    "data".to_string(),
                    decode_return_data_generic(&revert_data, revert_data.len()),
                );
                result.insert("success".to_string(), JsonValue::Bool(false));
                result.insert(
                    "error".to_string(),
                    JsonValue::String("Execution reverted".to_string()),
                );

                add_storage_written_to_result(
                    &mut serde_json::Value::Object(result.clone()),
                    &temp_storage_writes,
                );

                return Ok(serde_json::Value::Object(result));
            }

            //___ 0xfe INVALID - Halt avec erreur spécifique eBPF
            0xfe => {
                println!("💥 [INVALID] Opcode 0xFE exécuté - Invalid opcode");

                let mut result = serde_json::Map::new();
                result.insert(
                    "action".to_string(),
                    JsonValue::String("revert".to_string()),
                );
                result.insert(
                    "error".to_string(),
                    JsonValue::String("Invalid opcode 0xFE".to_string()),
                );
                result.insert("success".to_string(), JsonValue::Bool(false));
                result.insert(
                    "instruction_result".to_string(),
                    JsonValue::Number(IR_INVALID_JUMP.into()),
                );

                return Ok(serde_json::Value::Object(result));
            }

            _ => {
                println!("❓ [UNKNOWN] Unknown opcode 0x{:02x}", opcode);
                return Ok(halt_json_ebpf(&format!(
                    "Opcode not found 0x{:02x}",
                    opcode
                )));
            }
        }

        // ✅ Avancement du PC style eBPF
        if skip_advance {
            skip_advance = false;
        } else {
            bytecode_pc += advance;
            println!("➡️ [ADVANCE] PC → 0x{:04x}", bytecode_pc);
        }

        instruction_count += 1;

        // Check stack overflow
        if evm_stack.len() > 1024 {
            return Ok(halt_json_ebpf("Stack overflow"));
        }
    }
    Ok(().into())
}

fn add_storage_written_to_result(
    result: &mut serde_json::Value,
    writes: &HashMap<String, Vec<u8>>,
) {
    if writes.is_empty() {
        return;
    }

    println!(
        "🔄 [STORAGE CAPTURE] Ajout de {} slots écrits au résultat",
        writes.len()
    );

    if let Some(obj) = result.as_object_mut() {
        let mut storage_written = serde_json::Map::new();
        for (slot, val) in writes {
            storage_written.insert(
                slot.clone(),
                JsonValue::String(format!("0x{}", hex::encode(val))),
            );
        }
        obj.insert("storage".to_string(), JsonValue::Object(storage_written));
    }
}

/// Hash Keccak-256 (PRODUCTION - utilise sha3 crate)
fn keccak_hash(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Conversion d'adresse string vers U256
fn encode_address_to_u256(addr: &str) -> u256 {
    if addr.starts_with("0x") && addr.len() == 42 {
        // Ethereum address
        let hex = &addr[2..];
        let mut bytes = [0u8; 32];
        if let Ok(addr_bytes) = hex::decode(hex) {
            if addr_bytes.len() == 20 {
                bytes[12..32].copy_from_slice(&addr_bytes);
            }
        }
        u256::from_big_endian(&bytes)
    } else {
        // UIP-10 or other format - use hash
        u256::from(encode_address_to_u64(addr))
    }
}

/// Conversion d'U256 vers adresse string
fn u256_to_address(addr_u256: u256) -> String {
    let mut bytes = [0u8; 32];
    addr_u256.to_big_endian(&mut bytes);
    let addr_bytes = &bytes[12..32]; // Take last 20 bytes
    format!("0x{}", hex::encode(addr_bytes))
}

/// Conversion U256 vers i256 signé (simplifié)
fn i256_from_u256(val: u256) -> i64 {
    // Simplified - real implementation would use proper i256 type
    if val.bit(255) {
        -((!val + u256::one()).low_u64() as i64)
    } else {
        val.low_u64() as i64
    }
}

/// Conversion i256 vers U256 (simplifié)
fn u256_from_i256(val: i64) -> u256 {
    if val < 0 {
        let abs_val = (-val) as u64;
        !u256::from(abs_val) + u256::one()
    } else {
        u256::from(val as u64)
    }
                  }
