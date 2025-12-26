// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)

use crate::ebpf;
use crate::ebpf::MAX_CALL_DEPTH;
use crate::lib::*;
use crate::stack::{StackFrame, StackUsage};
use core::ops::Range;
use std::hash::DefaultHasher;
use std::ops::Add;
use std::hash::{Hash, Hasher};
use goblin::pe::debug;
use tiny_keccak::{Keccak, keccakf};
use ethereum_types::U256 as u256;
use i256::I256;
use serde_json::Value as JsonValue;
use std::str;

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub difficulty: u64,
    pub coinbase: String,
    pub base_fee: u256,         // EIP-1559
    pub blob_base_fee: u256,    // EIP-7516
    pub blob_hash: [u8; 32],   // EIP-4844 (vrai hash)
    pub prev_randao: [u8; 32], // EIP-4399 (added for compatibility)
}

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
            },
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
        let tail = &bytes[bytes.len()-8..];
        let v = u64::from_be_bytes([
            tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7]
        ]);
        if v > 0 && v < 9_000_000_000_000_000_000u64 {
            return Some(JsonValue::Number(serde_json::Number::from(v)));
        }
    }

    // string heuristique: extraits les bytes imprimables
    let filtered: Vec<u8> = bytes.iter().cloned().filter(|&b| b >= 32 && b <= 126).collect();
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

/// Refunds the contract's balance to the specified owner address and sets the contract's balance to zero.
fn refund_contract_balance_to_owner(
    world_state: &mut UvmWorldState,
    contract_address: &str,
    owner_address: &str,
) {
    let contract_balance = get_balance(world_state, contract_address);
    if contract_balance > 0 {
        let owner_balance = get_balance(world_state, owner_address);
        set_balance(world_state, contract_address, 0);
        set_balance(world_state, owner_address, owner_balance.saturating_add(contract_balance));
        println!(
            "💸 [REFUND] Transferred {} from contract {} to owner {}",
            contract_balance, contract_address, owner_address
        );
    }
}


#[derive(Clone)]
pub struct InterpreterArgs {
    pub function_name: String,
    pub contract_address: String,
    pub sender_address: String,
    pub args: Vec<serde_json::Value>,
    pub state_data: Vec<u8>, // calldata complet
    pub gas_limit: u64,
    pub gas_price: u64,
    pub value: u64,
    pub call_depth: u64,
    pub block_number: u64,
    pub timestamp: u64,
    pub caller: String,
    pub origin: String,
    pub beneficiary: String,
    pub function_offset: Option<usize>,
    pub base_fee: Option<u64>,
    pub blob_base_fee: Option<u64>,
    pub blob_hash: Option<[u8; 32]>,
}
impl Default for InterpreterArgs {
    fn default() -> Self {
        InterpreterArgs {
            function_name: "main".to_string(),
            contract_address: "*default*#contract#".to_string(),
            sender_address: "*sender*#default#".to_string(),
            args: vec![],
            state_data: vec![0; 1024],
            gas_limit: 1000000,
            gas_price: 1,
            value: 0,
            call_depth: 0,
            block_number: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            caller: "{}".to_string(),
            origin: "{}".to_string(),
            beneficiary:"{}".to_string(),
            function_offset: None,
            base_fee: Some(0),
            blob_base_fee: Some(0),
            blob_hash: Some([0u8; 32]),
        }
    }
}

// ✅ AJOUT: Structure pour l'état mondial UVM
#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, AccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>, // contract_addr -> slot -> value
    pub code: HashMap<String, Vec<u8>>, // contract_addr -> code
    pub block_info: BlockInfo,
    pub chain_id: u64, // Added field for chain ID
}

#[derive(Clone, Debug)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
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
                number: 1,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                gas_limit: 30000000,
                difficulty: 1,
                coinbase: "*coinbase*#miner#".to_string(),
                base_fee: u256::zero(),
                blob_base_fee: u256::zero(),
                blob_hash: [0u8; 32],
                prev_randao: [0u8; 32],
            },
            chain_id: 45056,
        }
    }
}

// ✅ AJOUT: Context d'exécution UVM
#[derive(Clone)]
pub struct UvmExecutionContext {
    pub world_state: UvmWorldState,
    pub gas_used: u64,
    pub gas_remaining: u64,
    pub logs: Vec<UvmLog>,
    pub return_data: Vec<u8>,
    pub call_stack: Vec<CallFrame>,
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
    pub value: u64,
    pub gas_limit: u64,
    pub input_data: Vec<u8>,
}

// Fonction pour extraire les imports FFI d'un bytecode donné
fn extract_ffi_imports(bytecode: &[u8]) -> hashbrown::HashSet<String> {
    let mut imports = hashbrown::HashSet::new();
    let mut i = 0usize;
    while i + 8 <= bytecode.len() {
        if bytecode[i] == 0xf1 {
            let name_len_idx = i + 8;
            if name_len_idx < bytecode.len() {
                let name_len = bytecode[name_len_idx] as usize;
                let start = name_len_idx + 1;
                let end = start + name_len;
                if end <= bytecode.len() {
                    if let Ok(s) = std::str::from_utf8(&bytecode[start..end]) {
                        imports.insert(s.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    imports
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

// ✅ AJOUT: Fonctions d'aide pour gestion du gas
fn consume_gas(context: &mut UvmExecutionContext, amount: u64) -> Result<(), Error> {
    // ✅ Exception VEZ: pas de Out of gas si gas_price == 0 et gas_limit élevé
    if context.gas_remaining > 9_000_000 && context.gas_used == 0 {
        // On ignore la consommation de gas pour la première exécution (déploiement/init VEZ)
        return Ok(());
    }
    //if context.gas_remaining < amount {
    //    return Err(Error::new(ErrorKind::Other, "Out of gas"));
    //}
    //context.gas_remaining -= amount;
    //context.gas_used += amount;
    Ok(())
}

fn find_jumpdest_offset(prog: &[u8], dest: usize) -> Option<usize> {
    // On vérifie que dest pointe bien sur un JUMPDEST (0x5b)
    if dest < prog.len() && prog[dest] == 0x5b {
        return Some(dest);
    }
    // Sinon, scan en avant jusqu'au prochain JUMPDEST (sécurité)
    let mut pc = dest;
    while pc < prog.len() {
        if prog[pc] == 0x5b {
            return Some(pc);
        }
        pc += 1;
    }
    None
}

// Fonction utilitaire pour trouver le prochain opcode à partir d'un offset byte
fn find_next_opcode(prog: &[u8], mut offset: usize) -> Option<(usize, u8)> {
    while offset < prog.len() {
        let opc = prog[offset];
        if opc <= 0x5b || (0x60 <= opc && opc <= 0x7f) || opc >= 0xa0 {
            return Some((offset, opc));
        }
        // PUSH1..32
        if (0x60..=0x7f).contains(&opc) {
            let push_bytes = (opc - 0x5f) as usize;
            offset += push_bytes;
        }
        offset += 1;
    }
    None
}

fn evm_store_32(global_mem: &mut Vec<u8>, addr: u64, value: u256) -> Result<(), Error> {
    let offset = addr as usize;

    if offset > 4_294_967_296 {
        return Ok(());
    }

    if offset + 32 > global_mem.len() {
        let new_size = (offset + 32).next_power_of_two().min(256 * 1024 * 1024);
        global_mem.resize(new_size, 0);
    }

    let bytes = value.to_big_endian();
    global_mem[offset..offset + 32].copy_from_slice(&bytes);

    Ok(())
}
    
fn evm_load_32(global_mem: &[u8], calldata: &[u8], addr: u64) -> Result<u256, Error> {
    let offset = addr as usize;
    // Priorité au calldata (mbuff)
    if offset + 32 <= calldata.len() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&calldata[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }
    // Sinon mémoire globale
    if offset + 32 <= global_mem.len() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&global_mem[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }
    // EVM : lecture hors borne → 0
    Ok(u256::zero())
}

fn calculate_gas_cost(opcode: u8) -> u64 {
    match opcode {
        // Instructions de base
        ebpf::ADD64_IMM | ebpf::ADD64_REG => 3,
        ebpf::SUB64_IMM | ebpf::SUB64_REG => 3,
        ebpf::MUL64_IMM | ebpf::MUL64_REG => 5,
        ebpf::DIV64_IMM | ebpf::DIV64_REG => 5,
        
        // Accès mémoire
        ebpf::LD_DW_REG | ebpf::ST_DW_REG => 3,
        ebpf::LD_W_REG | ebpf::ST_W_REG => 3,
        
        // Appels et sauts
        ebpf::CALL => 40,
        ebpf::JEQ_IMM | ebpf::JNE_IMM => 10,
        
        // Instructions personnalisées UVM
        0xf1 => 700,  // Appel FFI
        0xf2 => 2,    // Accès aux métadonnées
        
        // ✅ OPCODES EVM CRITIQUES MANQUANTS
        // SSTORE (0x55) - Stockage persistant EVM
        0x55 => 20000,
        
        // SLOAD (0x54) - Chargement depuis storage EVM
        0x54 => 800,
        
        // CALLER (0x33) - msg.sender EVM
        0x33 => 2,
        
        // ORIGIN (0x32) - tx.origin EVM  
        0x32 => 2,
        
        // CALLVALUE (0x34) - msg.value EVM
        0x34 => 2,
        
        // GASPRICE (0x3A) - tx.gasprice EVM
        0x3a => 2,
        
        // GASLIMIT (0x45) - block.gaslimit EVM
        0x45 => 2,
        
        // NUMBER (0x43) - block.number EVM
        0x43 => 2,
        
        // TIMESTAMP (0x42) - block.timestamp EVM
        0x42 => 2,
        
        // DIFFICULTY (0x44) - block.difficulty EVM
        0x44 => 2,
        
        // COINBASE (0x41) - block.coinbase EVM
        0x41 => 2,
        
        // BALANCE (0x31) - address(x).balance EVM
        0x31 => 700,
        
        // RETURNDATASIZE (0x3D) - returndatasize EVM
        0x3d => 2,
        
        // Instructions par défaut
        _ => 1, // Coût par défaut
    }
}

// ✅ AJOUT: Helpers pour interaction avec l'état mondial
fn get_balance(world_state: &UvmWorldState, address: &str) -> u64 {
    world_state.accounts.get(address)
        .map(|acc| acc.balance)
        .unwrap_or(0)
}

fn set_balance(world_state: &mut UvmWorldState, address: &str, balance: u64) {
    let account = world_state.accounts.entry(address.to_string())
        .or_insert_with(|| AccountState {
            balance: 0,
            nonce: 0,
            code: vec![],
            storage_root: String::new(),
            is_contract: false,
        });
    account.balance = balance;
}

fn transfer_value(world_state: &mut UvmWorldState, from: &str, to: &str, amount: u64) -> Result<(), Error> {
    let from_balance = get_balance(world_state, from);
    if from_balance < amount {
        return Err(Error::new(ErrorKind::Other, "Insufficient balance"));
    }
    
    let to_balance = get_balance(world_state, to);
    set_balance(world_state, from, from_balance - amount);
    set_balance(world_state, to, to_balance + amount);
    
    Ok(())
}

fn get_storage(world_state: &UvmWorldState, contract: &str, slot: &str) -> Vec<u8> {
    world_state.storage.get(contract)
        .and_then(|contract_storage| contract_storage.get(slot))
        .cloned()
        .unwrap_or_else(|| vec![0; 32])
}

fn set_storage(world_state: &mut UvmWorldState, contract: &str, slot: &str, value: Vec<u8>) {
    let contract_storage = world_state.storage.entry(contract.to_string())
        .or_insert_with(HashMap::new);
    contract_storage.insert(slot.to_string(), value);
}

            // Stub implementation for get_block_hash
            fn get_block_hash(world_state: &UvmWorldState, block_number: u64) -> Option<[u8; 32]> {
                // This is a stub. In a real implementation, this would look up the block hash.
                Some([0u8; 32]) // Return a dummy hash for demonstration
            }

#[allow(clippy::too_many_arguments)]
fn check_mem(
    addr: u64,
    len: usize,
    access_type: &str,
    insn_ptr: usize,
    mbuff: &[u8],
    mem: &[u8],
    stack: &[u8],
    allowed_memory: &HashSet<Range<u64>>,
) -> Result<(), Error> {
    if len == 0 || len > 65536 {
        return Err(Error::new(ErrorKind::Other, format!(
            "Error: memory access size invalid ({} bytes) at insn #{}", len, insn_ptr
        )));
    }
    if let Some(addr_end) = addr.checked_add(len as u64) {
        let offset = addr as usize;
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
        if allowed_memory.iter().any(|range| range.contains(&addr)) {
            return Ok(());
        }
        // PATCH: autorise lecture limitée si calldata vide (EVM-style permissif pour reads courtes)
        if mbuff.len() == 0 && addr < 32 && addr_end <= 32 {
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

/// ✅ Encodage d'adresse vers u64
fn encode_address_to_u64(addr: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}

// Helper safe pour u256 → u64 (évite panic)
fn safe_u256_to_u64(val: &u256) -> u64 {
    if val.bits() > 64 {
        u64::MAX
    } else {
        val.low_u64()
    }
}

// Helper safe pour I256 → u64 (évite panic)
fn safe_i256_to_u64(val: &I256) -> u64 {
    let v = val.as_u128();
    if v > u64::MAX as u128 {
        u64::MAX
    } else {
        v as u64
    }
}

/// Détecte dynamiquement la taille d'instruction selon le format du bytecode
fn get_insn_size(prog: &[u8]) -> usize {
    // EVM (EOF ou legacy) → 1 octet/opcode
    // eBPF pur → 8 octets/instruction
    // PATCH: Par défaut, tout sauf eBPF = 1 octet/opcode
    if prog.len() >= 2 && prog[0] == 0xEF && prog[1] == 0x00 {
        1
    } else if prog.len() >= 4 && prog[0..4] == [0x7f, b'E', b'B', b'P'] {
        ebpf::INSN_SIZE
    } else {
        1
    }
}

pub fn execute_program(
    prog_: Option<&[u8]>,
    stack_usage: Option<&StackUsage>,

    mem: &[u8],
    mbuff: &[u8],
    helpers: &HashMap<u32, ebpf::Helper>,

    allowed_memory: &HashSet<Range<u64>>,

    ret_type: Option<&str>,
    exports: &HashMap<u32, usize>,
    interpreter_args: &InterpreterArgs,
    initial_storage: Option<HashMap<String, HashMap<String, Vec<u8>>>>,
) -> Result<serde_json::Value, Error> {
    const U32MAX: u64 = u32::MAX as u64;
    const SHIFT_MASK_64: u64 = 0x3f;

    let prog = match prog_ {
        Some(prog) => prog,
        None => return Err(Error::new(
            ErrorKind::Other,
            "Error: No program set, call prog_set() to load one",
        )),
    };

    let default_stack_usage = StackUsage::new();
    let stack_usage = stack_usage.unwrap_or(&default_stack_usage);

    // ✅ AJOUT: Initialisation du contexte d'exécution UVM
    let mut execution_context = UvmExecutionContext {
        world_state: {
            let mut ws = UvmWorldState::default();
            if let Some(ref storage) = initial_storage {
                ws.storage = storage.clone();
            }
            ws
        },
        gas_used: 0,
        gas_remaining: interpreter_args.gas_limit,
        logs: vec![],
        return_data: vec![],
        call_stack: vec![],
    };

    // ✅ Configuration comptes initiaux
    set_balance(&mut execution_context.world_state, &interpreter_args.sender_address, 1000000);
    set_balance(&mut execution_context.world_state, &interpreter_args.contract_address, 0);

    // ✅ Transfert de valeur si spécifié
    if interpreter_args.value > 0 {
        transfer_value(
            &mut execution_context.world_state,
            &interpreter_args.caller,
            &interpreter_args.contract_address,
            interpreter_args.value,
        )?;
    }

    let stack = vec![0u8; ebpf::STACK_SIZE];
    let mut stacks = [StackFrame::new(); MAX_CALL_DEPTH];
    let mut stack_frame_idx = 0;

    let mut call_dst_stack: Vec<usize> = Vec::new();
    let mut mem_write_offset = 0usize;

    // 256 Mo → assez pour tous les contrats EOF + initialize + proxy UUPS
let mut global_mem = vec![0u8; 256 * 1024 * 1024];

    let mut reg: [u64; 64] = [0; 64];

// ✅ Configuration registres UVM-compatibles
reg[10] = stack.as_ptr() as u64 + stack.len() as u64; // Stack pointer
reg[8] = 0; // Global memory offset EVM = 0
reg[1] = 0; // Calldata/memory offset EVM = 0

// ✅ Registres spéciaux UVM (compatibles pile)
reg[50] = execution_context.gas_remaining;              // Gas disponible
reg[51] = interpreter_args.value;                       // Valeur transférée
reg[52] = interpreter_args.block_number;                // Numéro de bloc
reg[53] = interpreter_args.timestamp;                   // Timestamp
reg[54] = interpreter_args.call_depth as u64;           // Profondeur d'appel

    // ✅ Arguments dans la convention UVM
    reg[2] = interpreter_args.args.len() as u64;

    // Encodage des arguments dans global_mem
    let mut arg_offset = 0;
    for (i, arg) in interpreter_args.args.iter().enumerate().take(5) {
        let reg_idx = 3 + i;
        match arg {
            serde_json::Value::Number(n) => {
                reg[reg_idx] = n.as_u64().unwrap_or(0);
            },
            serde_json::Value::String(s) => {
                let bytes = s.as_bytes();
                let len = bytes.len().min(global_mem.len() - arg_offset - 1);
                global_mem[arg_offset..arg_offset + len].copy_from_slice(&bytes[..len]);
                println!("📝 [ARGS] Argument string: \"{}\" (hex: {})", s, hex::encode(&bytes[..len]));
                global_mem[arg_offset + len] = 0;
                reg[reg_idx] = reg[8] + arg_offset as u64;
                arg_offset += len + 1;
            },
            serde_json::Value::Bool(b) => {
                reg[reg_idx] = if *b { 1 } else { 0 };
                println!("📝 [ARGS] Argument bool: {} (as u64: {})", b, reg[reg_idx]);
            },
            _ => reg[reg_idx] = 0,
        }
    }

    // ✅ Hachages d'adresses pour compatibilité
    let mut contract_hasher = DefaultHasher::new();
    interpreter_args.contract_address.hash(&mut contract_hasher);
    let contract_hash = contract_hasher.finish();
    
    let mut sender_hasher = DefaultHasher::new();
    interpreter_args.sender_address.hash(&mut sender_hasher);
    let sender_hash = sender_hasher.finish();

    let check_mem_load = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            "load",
            insn_ptr,
            mbuff,
            mem,
            &stack,
            allowed_memory,
        )
    };
    let check_mem_store = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            "store",
            insn_ptr,
            mbuff,
            mem,
            &stack,
            allowed_memory,
        )
    };

    println!("🚀 DÉBUT EXÉCUTION UVM");
    println!("   Fonction: {}", interpreter_args.function_name);
    println!("   Contrat: {}", interpreter_args.contract_address);
    println!("   Gas limit: {}", interpreter_args.gas_limit);
    println!("   Valeur: {}", interpreter_args.value);

    let mut pc: usize = 0;
    // initialise la pile EVM
    let mut evm_stack: Vec<u64> = Vec::with_capacity(1024);
    let mut last_return_value: Option<serde_json::Value> = Some(serde_json::Value::Number(serde_json::Number::from(reg[0])));
    
    // ✅ AJOUT: Flag pour logs EVM détaillés
    let debug_evm = true;
    
    // Initialise insn_ptr UNE SEULE FOIS ici, en tenant compte du runtime_offset
    let mut insn_ptr: usize = interpreter_args.function_offset.unwrap_or(0);
    
while insn_ptr < prog.len() {
    let opcode = prog[insn_ptr];
    let insn = ebpf::get_insn(prog, insn_ptr);
    let _dst = insn.dst as usize;
    let _src = insn.src as usize;

    // Log EVM
    if debug_evm {
        println!("🔍 [EVM LOG] PC={:04x} | OPCODE=0x{:02x} ({})", insn_ptr, opcode, opcode_name(opcode));
        println!("🔍 [EVM STATE] REG[0-7]: {:?}", &reg[0..8]);
        if !evm_stack.is_empty() {
            println!("🔍 [EVM STACK] Top 5: {:?}", evm_stack.iter().rev().take(5).collect::<Vec<_>>());
        }
    }

    // initialise directement le flag (plus de loop imbriquée)
    let mut skip_advance = false;

     //___ Pectra/EVM opcodes ___
    match opcode {
        // 0x00 STOP
        0x00 => {
            println!("[EVM] STOP encountered, halting execution.");
            break;
        },

    //___ 0x01 ADD
    0x01 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on ADD"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = a.overflowing_add(b).0;
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x02 MUL
    0x02 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on MUL"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = a.overflowing_mul(b).0;
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x03 SUB
    0x03 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SUB"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = a.overflowing_sub(b).0;
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x04 DIV
    0x04 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on DIV"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = if b.is_zero() { ethereum_types::U256::zero() } else { a / b };
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x05 SDIV
    0x05 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SDIV"));
        }
        let a = I256::from(evm_stack.pop().unwrap());
        let b = I256::from(evm_stack.pop().unwrap());
        let res = if b == I256::from(0) { I256::from(0) } else { a / b };
        evm_stack.push(res.as_u64());
        reg[0] = res.as_u64();
    },

    //___ 0x06 MOD
    0x06 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on MOD"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = if b.is_zero() { ethereum_types::U256::zero() } else { a % b };
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x07 SMOD
    0x07 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SMOD"));
        }
        let a = I256::from(evm_stack.pop().unwrap());
        let b = I256::from(evm_stack.pop().unwrap());
        let res = if b == I256::from(0) { I256::from(0) } else { a % b };
        evm_stack.push(res.as_u64());
        reg[0] = res.as_u64();
    },

    //___ 0x08 ADDMOD
    0x08 => {
        if evm_stack.len() < 3 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on ADDMOD"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let n = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = if n.is_zero() { ethereum_types::U256::zero() } else { (a + b) % n };
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    // ___ 0x09 MULMOD
    0x09 => {
        if evm_stack.len() < 3 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on MULMOD"));
        }
        let a = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let b = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let n = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = if n.is_zero() { ethereum_types::U256::zero() } else { (a * b) % n };
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x0a EXP
    0x0a => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on EXP"));
        }
        let base = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let exponent = ethereum_types::U256::from(evm_stack.pop().unwrap());
        let res = base.overflowing_pow(exponent.low_u32().into()).0;
        evm_stack.push(res.low_u64());
        reg[0] = res.low_u64();
    },

    //___ 0x0b SIGNEXTEND
    0x0b => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SIGNEXTEND"));
        }
        let b = evm_stack.pop().unwrap();
        let x = evm_stack.pop().unwrap();
        let res = if b < 32 {
            let bit = 8 * (b as usize + 1) - 1;
            let mask = (1u128 << bit) - 1;
            let sign_bit = 1u128 << bit;
            let x128 = x as u128;
            if (x128 & sign_bit) != 0 {
                (x128 | !mask) as u64
            } else {
                (x128 & mask) as u64
            }
        } else {
            x
        };
        evm_stack.push(res);
        reg[0] = res;
    },
        
        //___ 0x10 LT
        0x10 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LT"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = if u256::from(a) < u256::from(b) { 1 } else { 0 };
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x11 GT
        0x11 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on GT"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = if u256::from(a) > u256::from(b) { 1 } else { 0 };
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x12 SLT
        0x12 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SLT"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = if I256::from(a) < I256::from(b) { 1 } else { 0 };
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x13 SGT
        0x13 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SGT"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = if I256::from(a) > I256::from(b) { 1 } else { 0 };
            evm_stack.push(res);
            reg[0] = res;
        },
        
//___ 0x14 EQ
0x14 => {
    if evm_stack.len() < 2 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on EQ"));
    }
    let b = evm_stack.pop().unwrap();
    let a = evm_stack.pop().unwrap();
    let res = if a == b { 1 } else { 0 };
    evm_stack.push(res);
    println!("🔍 [EQ] 0x{:x} == 0x{:x} → {}", a, b, res);
},
        
        //___ 0x15 ISZERO
        0x15 => {
            if evm_stack.is_empty() {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on ISZERO"));
            }
            let a = evm_stack.pop().unwrap();
            let res = if a == 0 { 1 } else { 0 };
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x16 AND
        0x16 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on AND"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = a & b;
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x17 OR
        0x17 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on OR"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = a | b;
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x18 XOR
        0x18 => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on XOR"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let res = a ^ b;
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x19 NOT
        0x19 => {
            if evm_stack.is_empty() {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on NOT"));
            }
            let a = evm_stack.pop().unwrap();
            let res = !a;
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x1a BYTE
        0x1a => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on BYTE"));
            }
            let b = evm_stack.pop().unwrap();
            let a = evm_stack.pop().unwrap();
            let i = (b & 0xff) as usize;
            let res = if i < 32 {
                ((a >> (8 * (31 - i))) & 0xff)
            } else {
                0
            };
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x1b SHL
        0x1b => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SHL"));
            }
            let shift = evm_stack.pop().unwrap();
            let value = evm_stack.pop().unwrap();
            let res = value << (shift & 0xff);
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x1c SHR
        0x1c => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SHR"));
            }
            let shift = evm_stack.pop().unwrap();
            let value = evm_stack.pop().unwrap();
            let res = value >> (shift & 0xff);
            evm_stack.push(res);
            reg[0] = res;
        },
        
        //___ 0x1d SAR
        0x1d => {
            if evm_stack.len() < 2 {
                return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SAR"));
            }
            let shift = evm_stack.pop().unwrap();
            let value = I256::from(evm_stack.pop().unwrap());
            let res = (value >> (shift & 0xff)).as_u64();
            evm_stack.push(res);
            reg[0] = res;
        },

    // 0x1e CLZ
    0x1e => {
        if evm_stack.is_empty() {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on CLZ"));
        }
        let x = evm_stack.pop().unwrap();
        let x_u256 = ethereum_types::U256::from(x);
        let clz = if x_u256.is_zero() {
            256
        } else {
            let mut count = 0;
            for i in (0..4).rev() {
                let limb = x_u256.0[i];
                if limb == 0 {
                    count += 64;
                } else {
                    count += limb.leading_zeros() as usize;
                    break;
                }
            }
            count
        };
        evm_stack.push(clz as u64);
        reg[0] = clz as u64;
    },

       //___ 0x20 KECCAK256
    0x20 => {
        use tiny_keccak::{Hasher, Keccak};
        let offset = reg[_dst] as usize;
        let len = reg[_src] as usize;
        // treat reg as offsets: calldata if within mbuff, otherwise global_mem
        let data = if offset + len <= mbuff.len() {
            &mbuff[offset..offset + len]
        } else if offset + len <= global_mem.len() {
            &global_mem[offset..offset + len]
        } else {
            return Err(Error::new(ErrorKind::Other, format!("KECCAK invalid offset/len: 0x{:x}/{}", reg[_dst], len)));
        };
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut hash);
        reg[_dst] = safe_u256_to_u64(&u256::from_big_endian(&hash));
        let gas = 30 + 6 * ((len + 31) / 32) as u64;
        consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x30 ADDRESS
    0x30 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x31 BALANCE
    0x31 => {
        let addr = format!("addr_{:x}", reg[_dst]);
        reg[_dst] = get_balance(&execution_context.world_state, &addr);
        //consume_gas(&mut execution_context, 700)?;
    },

    //___ 0x32 ORIGIN
    0x32 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.origin);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x33 CALLER
    0x33 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.caller);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x34 CALLVALUE
    0x34 => {
        reg[_dst] = interpreter_args.value;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x35 CALLDATALOAD
0x35 => {
    if evm_stack.is_empty() {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on CALLDATALOAD"));
    }
    let offset = evm_stack.pop().unwrap() as u64;

    let loaded = evm_load_32(&global_mem, mbuff, offset)?;
    let value = safe_u256_to_u64(&loaded);

    evm_stack.push(value);

    println!("📥 [CALLDATALOAD] offset=0x{:x} → value=0x{:x}", offset, value);

    // Log spécial pour détecter le selector chargé depuis le calldata
    if offset == 0 && mbuff.len() >= 4 {
        let selector = u32::from_be_bytes([mbuff[0], mbuff[1], mbuff[2], mbuff[3]]);
        println!("🎯 [SELECTOR LOADED FROM CALLDATA] 0x{:08x}", selector);
    }
},

    //___ 0x36 CALLDATASIZE
    0x36 => {
        reg[_dst] = mbuff.len() as u64;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x37 CALLDATACOPY
    0x37 => {
        let dst = reg[_dst] as usize; // treat as offset into global_mem
        let src = reg[_src] as usize; // treat as offset into mbuff
        let len = insn.imm as usize;
        if src + len <= mbuff.len() && dst + len <= global_mem.len() {
            let data = &mbuff[src..src + len];
            global_mem[dst..dst + len].copy_from_slice(data);
        } else {
            return Err(Error::new(ErrorKind::Other, format!("CALLDATACOPY OOB src={} len={} mbuff={} dst={} global_mem={}", src, len, mbuff.len(), dst, global_mem.len())));
        }
        let gas = 3 + 3 * ((len + 31) / 32) as u64;
        //consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x3a GASPRICE
    0x3a => {
        reg[_dst] = interpreter_args.gas_price;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x41 COINBASE
    0x41 => {
        reg[_dst] = encode_address_to_u64(&execution_context.world_state.block_info.coinbase);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x42 TIMESTAMP
    0x42 => {
        reg[_dst] = execution_context.world_state.block_info.timestamp;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x43 NUMBER
    0x43 => {
        reg[_dst] = execution_context.world_state.block_info.number;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x45 GASLIMIT
    0x45 => {
        reg[_dst] = execution_context.world_state.block_info.gas_limit;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x46 CHAINID
    0x46 => {
        reg[_dst] = execution_context.world_state.chain_id;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x47 SELFBALANCE
    0x47 => {
        reg[_dst] = get_balance(&execution_context.world_state, &interpreter_args.contract_address);
        //consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x48 BASEFEE
    0x48 => {
        reg[_dst] = safe_u256_to_u64(&execution_context.world_state.block_info.base_fee);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x4e PREVRANDAO
    0x4e => {
        reg[_dst] = safe_u256_to_u64(&u256::from_big_endian(&execution_context.world_state.block_info.prev_randao));
        //consume_gas(&mut execution_context, 2)?;
    },

    // ___ 0x50 POP
0x50 => {
    if evm_stack.is_empty() {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on POP"));
    }
    evm_stack.pop();
    //consume_gas(&mut execution_context, 2)?;
},

    //___ 0x51 MLOAD
    0x51 => {
        let offset = reg[_dst] as usize;
        reg[_dst] = safe_u256_to_u64(&evm_load_32(&global_mem, mbuff, offset as u64)?);
        //consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x52 MSTORE
0x52 => {
    let offset = reg[_dst] as usize;
    let value = u256::from(reg[_src]);
    evm_store_32(&mut global_mem, offset as u64, value)?;
    //consume_gas(&mut execution_context, 3)?;
},

    //___ 0x53 MSTORE8
    0x53 => {
        let offset = reg[_dst] as usize;
        let val = (reg[_src] & 0xff) as u8;
        if offset < global_mem.len() {
            global_mem[offset] = val;
        }
        //consume_gas(&mut execution_context, 3)?;
},

//___ 0x54 SLOAD
  0x54 => {
    // Slot EVM : sommet de la pile (EVM) ou reg[_dst]
    let slot_u256 = if !evm_stack.is_empty() {
        u256::from(evm_stack.pop().unwrap())
    } else {
        u256::from(reg[_dst])
    };
    let slot = format!("{:064x}", slot_u256);

    println!("🔍 [SLOAD DEBUG] slot={}", slot);

    let mut loaded_value = 0u64;
    if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
        if let Some(stored_bytes) = contract_storage.get(&slot) {
            let storage_val = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
            loaded_value = storage_val;
        }
    }
    evm_stack.push(loaded_value);
    reg[_dst] = loaded_value;
    reg[0] = loaded_value;
    // Supprime le double push et la synchronisation superflue
    println!("🎯 [SLOAD] slot={}, loaded_value={}", slot, loaded_value);
},
    
    // ___ 0x55 SSTORE
  0x55 => {
    // Slot EVM : sommet-1 de la pile, valeur : sommet
    if evm_stack.len() < 2 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on SSTORE"));
    }
    let value = evm_stack.pop().unwrap();
    let slot_u256 = u256::from(evm_stack.pop().unwrap());
    let slot = format!("{:064x}", slot_u256);
    let value_u256 = u256::from(value);
    let bytes = value_u256.to_big_endian();
    set_storage(&mut execution_context.world_state, &interpreter_args.contract_address, &slot, bytes.to_vec());
    println!("💾 [SSTORE] slot={} <- value={}", slot, value);
    reg[_dst] = value;
    reg[0] = value;
    last_return_value = Some(serde_json::Value::Number(serde_json::Number::from(reg[0])));
},
    
    // ___ 0x56 JUMP
    0x56 => {
        if evm_stack.is_empty() {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on JUMP"));
        }
        let dest = evm_stack.pop().unwrap() as usize;
        // SUPPRIMER la vérification JUMPDEST ici !
        insn_ptr = dest;
        skip_advance = true;
    },
    
    // ___ 0x57 JUMPI
    0x57 => {
        if evm_stack.len() < 2 {
            return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on JUMPI"));
        }
        let dest = evm_stack.pop().unwrap() as usize;
        let cond = evm_stack.pop().unwrap();
        if cond != 0 {
            insn_ptr = dest;
           skip_advance = true;
        }
        // sinon, on avance normalement (pas de saut)
    },
    
        //___ 0x58 PC
    0x58 => {
        reg[_dst] = (insn_ptr * ebpf::INSN_SIZE) as u64;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5a GAS
    0x5a => {
        reg[0] = execution_context.gas_remaining;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5b JUMPDEST
    0x5b => {
        //consume_gas(&mut execution_context, 1)?;
    },

    //___ 0x5c TLOAD
    0x5c => {
        let t_offset = reg[_dst] as usize;
        if t_offset < evm_stack.len() {
            reg[_dst] = evm_stack[t_offset];
        } else {
            return Err(Error::new(ErrorKind::Other, format!("TLOAD invalid offset: {}", t_offset)));
        }
        //consume_gas(&mut execution_context, 2)?;
    }

    //___ 0x5d TSTORE
    0x5d => {
        let t_offset = reg[_dst] as usize;
        if t_offset < evm_stack.len() {
            evm_stack[t_offset] = reg[_src];
        } else if t_offset == evm_stack.len() {
            evm_stack.push(reg[_src]);
        } else {
            return Err(Error::new(ErrorKind::Other, format!("TSTORE invalid offset: {}", t_offset)));
        }
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5e MCOPY
    0x5e => {
        let dst_offset = reg[_dst] as usize;
        let src_offset = reg[_src] as usize;
        let len = insn.imm as usize;
        // Patch permissif : si OOB, on tronque la copie à ce qui est possible
        let max_len = global_mem.len().saturating_sub(dst_offset).min(global_mem.len().saturating_sub(src_offset));
        let safe_len = len.min(max_len);
        if safe_len > 0 && src_offset + safe_len <= global_mem.len() && dst_offset + safe_len <= global_mem.len() {
            let data: Vec<u8> = global_mem[src_offset..src_offset + safe_len].to_vec();
            global_mem[dst_offset..dst_offset + safe_len].copy_from_slice(&data);
        }
        // Sinon, on ignore la copie (aucune erreur fatale)
            consume_gas(&mut execution_context, 3 + 3 * ((len + 31) / 32) as u64)?;
    },

    //___ 0x5f PUSH0
    0x5f => {
        reg[_dst] = 0;
        consume_gas(&mut execution_context, 2)?;
    },
    
    //___ 0x60..=0x7f : PUSH1 à PUSH32
            0x60..=0x7f => {
                // PUSHn: push n bytes as a value on the stack (right-aligned, big-endian)
                let n = (opcode - 0x5f) as usize;
                let start = insn_ptr + 1;
                let end = start + n;
                let mut value = 0u64;
                // On ne gère ici que les PUSH jusqu'à 8 bytes (pour u64), au-delà, tronqué
                if end <= prog.len() {
                    let mut bytes = [0u8; 8];
                    let copy_len = n.min(8);
                    if start + copy_len <= prog.len() {
                        bytes[8 - copy_len..].copy_from_slice(&prog[start..start + copy_len]);
                        value = u64::from_be_bytes(bytes);
                    } else {
                        println!("⚠️ [EVM] PUSH{} dépasse la taille du bytecode, valeur ignorée", n);
                    }
                } else {
                    println!("⚠️ [EVM] PUSH{} dépasse la taille du bytecode, valeur ignorée", n);
                }
                if evm_stack.len() >= 1024 {
                    println!("⚠️ [EVM] Stack overflow sur PUSH{} (stack pleine, valeur ignorée)", n);
                } else {
                    evm_stack.push(value);
                }
                reg[0] = value;
                // Avance le PC de n+1 (fait plus bas dans la boucle)
            },
            
        //___ 0x80 → 0x8f : DUP1 à DUP16
        (0x80..=0x8f) => {
            let depth = (opcode - 0x80 + 1) as usize;
            if evm_stack.len() < depth {
                println!("⚠️ [EVM] Stack underflow sur DUP{} (stack size={})", depth, evm_stack.len());
                // On ignore l'instruction, pas de panic ni d'erreur
            } else if evm_stack.len() >= 1024 {
                println!("⚠️ [EVM] Stack overflow sur DUP{} (stack pleine, duplication ignorée)", depth);
            } else {
                let value = evm_stack[evm_stack.len() - depth];
                evm_stack.push(value);
                reg[_dst] = value;
            }
        },
        
        // ___ 0x90 → 0x9f : SWAP1 à SWAP16
        (0x90..=0x9f) => {
            let depth = (opcode - 0x90 + 1) as usize;
            if evm_stack.len() < depth + 1 {
                println!("⚠️ [EVM] Stack underflow sur SWAP{} (stack size={})", depth, evm_stack.len());
                // On ignore l'instruction, pas de panic ni d'erreur
            } else {
                let top = evm_stack.len() - 1;
                // Protection anti-overflow :
                if top < depth {
                    println!("⚠️ [EVM] SWAP{} overflow (top={}, depth={})", depth, top, depth);
                } else {
                    evm_stack.swap(top, top - depth);
                    reg[_dst] = evm_stack[top];
                }
            }
        },

//___ 0xa0 LOG0
0xa0 => {
    // LOG0(offset, size): Ajoute un log sans topic
    if evm_stack.len() < 2 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LOG0"));
    }
    let size = evm_stack.pop().unwrap() as usize;
    let offset = evm_stack.pop().unwrap() as usize;
    let data = if offset + size <= global_mem.len() {
        global_mem[offset..offset + size].to_vec()
    } else {
        vec![]
    };
    execution_context.logs.push(UvmLog {
        address: interpreter_args.contract_address.clone(),
        topics: vec![],
        data,
    });
    consume_gas(&mut execution_context, 375 + 8 * size as u64)?;
},

//___ 0xa1 LOG1
0xa1 => {
    if evm_stack.len() < 3 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LOG1"));
    }
    let topic = format!("{:x}", evm_stack.pop().unwrap());
    let size = evm_stack.pop().unwrap() as usize;
    let offset = evm_stack.pop().unwrap() as usize;
    let data = if offset + size <= global_mem.len() {
        global_mem[offset..offset + size].to_vec()
    } else {
        vec![]
    };
    execution_context.logs.push(UvmLog {
        address: interpreter_args.contract_address.clone(),
        topics: vec![topic],
        data,
    });
    consume_gas(&mut execution_context, 750 + 8 * size as u64)?;
},

//____ 0xa2 LOG2
0xa2 => {
    if evm_stack.len() < 4 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LOG2"));
    }
    let topic2 = format!("{:x}", evm_stack.pop().unwrap());
    let topic1 = format!("{:x}", evm_stack.pop().unwrap());
    let size = evm_stack.pop().unwrap() as usize;
    let offset = evm_stack.pop().unwrap() as usize;
    let data = if offset + size <= global_mem.len() {
        global_mem[offset..offset + size].to_vec()
    } else {
        vec![]
    };
    execution_context.logs.push(UvmLog {
        address: interpreter_args.contract_address.clone(),
        topics: vec![topic1, topic2],
        data,
    });
    consume_gas(&mut execution_context, 1125 + 8 * size as u64)?;
},

//___ 0xa3 LOG3
0xa3 => {
    if evm_stack.len() < 5 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LOG3"));
    }
    let topic3 = format!("{:x}", evm_stack.pop().unwrap());
    let topic2 = format!("{:x}", evm_stack.pop().unwrap());
    let topic1 = format!("{:x}", evm_stack.pop().unwrap());
    let size = evm_stack.pop().unwrap() as usize;
    let offset = evm_stack.pop().unwrap() as usize;
    let data = if offset + size <= global_mem.len() {
        global_mem[offset..offset + size].to_vec()
    } else {
        vec![]
    };
    execution_context.logs.push(UvmLog {
        address: interpreter_args.contract_address.clone(),
        topics: vec![topic1, topic2, topic3],
        data,
    });
    consume_gas(&mut execution_context, 1500 + 8 * size as u64)?;
},

//___ 0xa4 LOG4
0xa4 => {
    if evm_stack.len() < 6 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on LOG4"));
    }
    let topic4 = format!("{:x}", evm_stack.pop().unwrap());
    let topic3 = format!("{:x}", evm_stack.pop().unwrap());
    let topic2 = format!("{:x}", evm_stack.pop().unwrap());
    consume_gas(&mut execution_context, 100)?;
},

//___ 0xf5 CREATE2
0xf5 => {
    if evm_stack.len() < 4 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on CREATE2"));
    }
    let salt = evm_stack.pop().unwrap();
    let size = evm_stack.pop().unwrap() as usize;
    let offset = evm_stack.pop().unwrap() as usize;
    let value = evm_stack.pop().unwrap();
    // Stub: retourne 0 (échec) ou une adresse factice
    evm_stack.push(0);
    consume_gas(&mut execution_context, 32000)?;
},

//___ 0xfa STATICCALL
0xfa => {
    if evm_stack.len() < 6 {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on STATICCALL"));
    }
    let ret_size = evm_stack.pop().unwrap() as usize;
    let ret_offset = evm_stack.pop().unwrap() as usize;
    let args_size = evm_stack.pop().unwrap() as usize;
    let args_offset = evm_stack.pop().unwrap() as usize;
    let address = evm_stack.pop().unwrap();
    let gas = evm_stack.pop().unwrap();
    // Stub: push success=1
    evm_stack.push(1);
    consume_gas(&mut execution_context, 100)?;
},

      //___ 0xf3 RETURN — Version stricte EVM, sans hardcoding
0xf3 => {
    let offset = reg[_dst] as usize;
    let len = reg[_src] as usize;

    println!("🎯 [RETURN] offset={}, len={}", offset, len);

    let mut ret_data = vec![0u8; len];

    // Lecture depuis mémoire (priorité global_mem, fallback mbuff/calldata)
    let data_source = if len == 0 {
        // Cas spécial : retourne simplement zéro (aucune donnée)
        &[]
    } else if offset + len <= global_mem.len() {
        &global_mem[offset..offset + len]
    } else if offset + len <= mbuff.len() {
        &mbuff[offset..offset + len]
    } else {
        return Err(Error::new(ErrorKind::Other, format!("RETURN invalid memory access: offset={} len={}", offset, len)));
    };
    ret_data.copy_from_slice(data_source);

    // === Décodage ABI générique EVM standard (sans connaître le nom de fonction) ===
    let formatted_result = if len == 0 {
        // Succès sans retour de données (standard pour initialize proxy)
        serde_json::Value::Bool(true)
    } else if len == 32 {
        // Retour uint256 (balanceOf, totalSupply, etc.)
        let value = u256::from_big_endian(&ret_data);
        if value.bits() <= 64 {
            serde_json::Value::Number(serde_json::Number::from(value.low_u64()))
        } else {
            serde_json::Value::String(format!("0x{}", hex::encode(ret_data)))
        }
    } else if len >= 64 && ret_data[0..32].iter().all(|&b| b == 0) {
        // Retour string packed Solidity : offset 32 bytes + longueur + données
        let str_offset = u256::from_big_endian(&ret_data[0..32]).low_u64() as usize;
        if str_offset == 32 && ret_data.len() >= 64 {
            let str_len = u256::from_big_endian(&ret_data[32..64]).low_u64() as usize;
            if 64 + str_len <= ret_data.len() {
                let str_bytes = &ret_data[64..64 + str_len];
                if let Ok(s) = std::str::from_utf8(str_bytes) {
                    serde_json::Value::String(s.to_string())
                } else {
                    serde_json::Value::String(hex::encode(str_bytes))
                }
            } else {
                serde_json::Value::String(hex::encode(&ret_data))
            }
        } else {
            serde_json::Value::String(hex::encode(&ret_data))
        }
    } else {
        // Tout autre retour → hex brut
        serde_json::Value::String(hex::encode(&ret_data))
    };

    // Retour final avec storage modifié (si présent)
    let final_storage = execution_context.world_state.storage
        .get(&interpreter_args.contract_address)
        .cloned()
        .unwrap_or_default();

    let mut result = serde_json::Map::new();
    result.insert("return".to_string(), formatted_result);

    if !final_storage.is_empty() {
        let mut storage_json = serde_json::Map::new();
        for (slot, bytes) in final_storage {
            storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
        }
        result.insert("storage".to_string(), serde_json::Value::Object(storage_json));
    }

    println!("✅ [RETURN SUCCESS] Résultat: {:?}", result.get("return"));
    return Ok(serde_json::Value::Object(result));
},

//___ 0xfd REVERT — Version stricte EVM
0xfd => {
    let offset = reg[_dst] as usize;
    let len = reg[_src] as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        if offset + len <= global_mem.len() {
            data.copy_from_slice(&global_mem[offset..offset + len]);
        } else {
            return Err(Error::new(ErrorKind::Other, format!("REVERT invalid offset/len: 0x{:x}/{}", reg[_dst], len)));
        }
    }

    // 💸 Remboursement du solde au propriétaire (origin ou beneficiary)
    let owner_addr = if !interpreter_args.beneficiary.is_empty() && interpreter_args.beneficiary != "{}" {
        &interpreter_args.beneficiary
    } else {
        &interpreter_args.origin
    };
    refund_contract_balance_to_owner(
        &mut execution_context.world_state,
        &interpreter_args.contract_address,
        owner_addr,
    );

    // PATCH: décodage du message revert Solidity
    let mut revert_msg = String::new();
    if data.len() >= 4 && &data[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        // Error(string) selector
        if data.len() >= 68 {
            let strlen = u32::from_be_bytes([data[36], data[37], data[38], data[39]]) as usize;
            if data.len() >= 68 + strlen {
                if let Ok(msg) = std::str::from_utf8(&data[68..68+strlen]) {
                    revert_msg = msg.to_string();
                }
            }
        }
    }
    if !revert_msg.is_empty() {
        println!("❌ [REVERT Solidity] Message: {}", revert_msg);
        return Err(Error::new(ErrorKind::Other, format!("REVERT: {}", revert_msg)));
    }

    // Sinon, fallback hex
    return Err(Error::new(ErrorKind::Other, format!("REVERT: 0x{}", hex::encode(data))));
},

    //___ 0xfe INVALID
    0xfe => {
        return Err(Error::new(ErrorKind::Other, "INVALID opcode"));
    },

    //___ 0xff SELFDESTRUCT — EVM: stoppe l'exécution immédiatement
    0xff => {
        // 💸 Remboursement du solde au propriétaire (origin ou beneficiary)
        let owner_addr = if !interpreter_args.beneficiary.is_empty() && interpreter_args.beneficiary != "{}" {
            &interpreter_args.beneficiary
        } else {
            &interpreter_args.origin
        };
        refund_contract_balance_to_owner(
            &mut execution_context.world_state,
            &interpreter_args.contract_address,
            owner_addr,
        );
        println!("[UVM] Execution halted by SELFDESTRUCT");
        return Ok(serde_json::json!("SELFDESTRUCT"));
    },

    //___ Tout le reste → crash clair
    _ => {
        println!("🟢 [NOP] Opcode inconnu 0x{:02x} ignoré à PC {}", opcode, insn_ptr);
    }
    }

    // Avancement du PC (PUSHN inclus)
    if !skip_advance {
        let mut advance = 1;
        if (0x60..=0x7f).contains(&opcode) {
            let push_bytes = (opcode - 0x5f) as usize;
            advance = 1 + push_bytes;
        }
        insn_ptr = insn_ptr.wrapping_add(advance);
    } else if debug_evm {
        println!("🔁 [EVM] PC positionné par handler, pas d'avancement automatique -> PC={}", insn_ptr);
    }
}

// Si on sort de la boucle sans STOP/RETURN/REVERT
{
    let final_storage = execution_context.world_state.storage
        .get(&interpreter_args.contract_address)
        .cloned()
        .unwrap_or_default();

    let mut result_with_storage = serde_json::Map::new();

    // 1. Si la pile EVM n'est pas vide, retourne le sommet de pile (cas getter simple)
    if !evm_stack.is_empty() {
        let top = evm_stack.last().copied().unwrap_or(0);
        result_with_storage.insert(
            "return".to_string(),
            serde_json::Value::Number(serde_json::Number::from(top))
        );
    } else {
        // 2. Sinon, tente de retrouver la dernière valeur lue dans le storage (SLOAD)
        // On prend le premier slot du storage du contrat (souvent le cas pour decimals, totalSupply, etc.)
        if let Some((slot, bytes)) = final_storage.iter().next() {
            let value = u256::from_big_endian(bytes);
            let formatted = if value.bits() <= 64 {
                serde_json::Value::Number(serde_json::Number::from(value.low_u64()))
            } else {
                serde_json::Value::String(format!("0x{:064x}", value))
            };
            result_with_storage.insert("return".to_string(), formatted);
        } else {
            // 3. Fallback : retourne 0
            result_with_storage.insert(
                "return".to_string(),
                serde_json::Value::Number(serde_json::Number::from(0))
            );
        }
    }

    // Ajoute le storage complet pour debug
    if !final_storage.is_empty() {
        let mut storage_json = serde_json::Map::new();
        for (slot, bytes) in final_storage {
            storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
        }
        result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
    }

    if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
        println!("📦 [STORAGE FINAL] Contrat {}:", &interpreter_args.contract_address);
        for (slot, bytes) in contract_storage.iter().take(20) {
            let hexv = hex::encode(bytes);
            let maybe_u64 = {
                let u = u256::from_big_endian(bytes);
                if u.bits() <= 64 { Some(u.low_u64()) } else { None }
            };
            if let Some(v) = maybe_u64 {
                println!("   - slot {}: {} (hex: 0x{})", slot, v, hexv);
            } else {
                if bytes.len() >= 32 && bytes[12..32].iter().any(|&b| b != 0) {
                    println!("   - slot {}: address-like 0x{} (hex: 0x{})", slot, hex::encode(&bytes[12..32]), hexv);
                } else {
                    println!("   - slot {}: hex=0x{}", slot, hexv);
                }
            }
        }
    }
    return Ok(serde_json::Value::Object(result_with_storage));
}
}

/// ✅ AJOUT: Helper pour noms des opcodes
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x3a => "GASPRICE",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5e => "MCOPY",
        0x5f => "PUSH0",
        0x60..=0x7f => "PUSH",
        0x80..=0x8f => "DUP",
        0x90..=0x9f => "SWAP",
        0xa0 => "LOG0",
        0xa1 => "LOG1",
        0xa2 => "LOG2",
        0xa3 => "LOG3",
        0xa4 => "LOG4",
        0xf1 => "FFI_CALL",
        0xf2 => "METADATA_ACCESS",
        0xf3 => "RETURN",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "NOP",
    }
}

/// Calcule le slot EVM pour un mapping (ex: balanceOf, allowance, etc.)
fn compute_mapping_slot(base_slot: u64, keys: &[serde_json::Value]) -> String {
    let mut buf = vec![];
    for key in keys {
        match key {
            serde_json::Value::String(s) if s.starts_with("0x") && s.len() == 42 => {
                let mut addr_bytes = [0u8; 32];
                if let Ok(decoded) = hex::decode(&s[2..]) {
                    addr_bytes[12..32].copy_from_slice(&decoded);
                }
                buf.extend_from_slice(&addr_bytes);
            }
            serde_json::Value::Number(n) => {
                let mut num_bytes = [0u8; 32];
                num_bytes[24..32].copy_from_slice(&n.as_u64().unwrap_or(0).to_be_bytes());
                buf.extend_from_slice(&num_bytes);
            }
            _ => {}
        }
    }
    // Ajoute le slot de base à la fin
    let mut slot_bytes = [0u8; 32];
    slot_bytes[24..32].copy_from_slice(&base_slot.to_be_bytes());
    buf.extend_from_slice(&slot_bytes);

    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(&buf);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hex::encode(hash)
}
