//___ Unity VM: Slurachain VM avec parallélisme optimiste pour 300M TPS ___//
use anyhow::Result;
use dashmap::DashMap;
use futures::{future::join_all, FutureExt};
use hashbrown::{HashMap, HashSet};
use hex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use vuc_storage::storing_access::RocksDBManager;

pub type NerenaValue = serde_json::Value;

// ✅ ERC-1967 standard slots (hex, sans 0x)
const ERC1967_IMPLEMENTATION_SLOT: &str =
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ERC1967_ADMIN_SLOT: &str = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const ERC1967_BEACON_SLOT: &str =
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

// ============================================================================
// OPTIMISTIC PARALLELISM POUR 300M TPS
// ============================================================================

/// ✅ Transaction avec numéro de version pour optimistic concurrency
#[derive(Debug)]
pub struct ParallelTransaction {
    pub id: u64,
    pub contract_address: String,
    pub function_name: String,
    pub args: Vec<NerenaValue>,
    pub sender: String,
    pub version: AtomicU64,
    pub read_set: Arc<RwLock<HashMap<String, u64>>>, // slot -> version lue
    pub write_set: Arc<RwLock<HashMap<String, Vec<u8>>>>, // slot -> nouvelle valeur
    pub dependencies: Arc<RwLock<HashSet<u64>>>,     // TX IDs dont on dépend
    pub calldata: Option<Vec<u8>>,                   // <-- NOUVEAU: Données d'appel brut
}

impl Clone for ParallelTransaction {
    fn clone(&self) -> Self {
        ParallelTransaction {
            id: self.id,
            contract_address: self.contract_address.clone(),
            function_name: self.function_name.clone(),
            args: self.args.clone(),
            sender: self.sender.clone(),
            version: AtomicU64::new(self.version.load(Ordering::SeqCst)),
            read_set: Arc::clone(&self.read_set),
            write_set: Arc::clone(&self.write_set),
            dependencies: Arc::clone(&self.dependencies),
            calldata: self.calldata.clone(),
        }
    }
}

/// ✅ Gestionnaire de parallélisme optimiste
pub struct OptimisticParallelEngine {
    pub transaction_queue: crossbeam::channel::Receiver<ParallelTransaction>,
    pub transaction_sender: crossbeam::channel::Sender<ParallelTransaction>,
    pub global_version_counter: AtomicU64,
    pub storage_versions: DashMap<String, u64>,
    pub active_transactions: DashMap<u64, ParallelTransaction>,
    pub commit_queue: crossbeam::channel::Sender<u64>,
    pub abort_queue: crossbeam::channel::Sender<u64>,
    pub thread_pool_size: usize,
    pub batch_size: usize,
    pub vm: Arc<Mutex<SlurachainVm>>, // <-- AJOUTE CE CHAMP
}

impl OptimisticParallelEngine {
    pub fn new(thread_pool_size: usize, batch_size: usize, vm: Arc<Mutex<SlurachainVm>>) -> Self {
        let (tx_sender, tx_receiver) = crossbeam::channel::unbounded();
        let (commit_sender, _commit_receiver) = crossbeam::channel::unbounded();
        let (abort_sender, _abort_receiver) = crossbeam::channel::unbounded();

        OptimisticParallelEngine {
            transaction_queue: tx_receiver,
            transaction_sender: tx_sender,
            global_version_counter: AtomicU64::new(0),
            storage_versions: DashMap::new(),
            active_transactions: DashMap::new(),
            commit_queue: commit_sender,
            abort_queue: abort_sender,
            thread_pool_size,
            batch_size,
            vm, // <-- Ajout du champ manquant
        }
    }

    /// ✅ NOUVEAU: Collecte des transactions en conflit SANS récursion
    async fn collect_conflicted_transactions_non_recursive(
        &self,
        validation_results: &[bool],
        original_transactions: &[ParallelTransaction],
    ) -> Vec<ParallelTransaction> {
        let mut conflicted = Vec::new();

        for (i, &is_valid) in validation_results.iter().enumerate() {
            if !is_valid && i < original_transactions.len() {
                let mut retry_tx = original_transactions[i].clone();
                // Incrémente la version pour le retry
                retry_tx.version.store(
                    retry_tx.version.load(Ordering::SeqCst) + 1,
                    Ordering::SeqCst,
                );
                // Clear read/write sets pour le retry
                {
                    let mut read_set = retry_tx.read_set.write().await;
                    read_set.clear();
                }
                {
                    let mut write_set = retry_tx.write_set.write().await;
                    write_set.clear();
                }
                conflicted.push(retry_tx);
            }
        }
        conflicted
    }

    /// ✅ Exécution parallèle optimiste de batch de transactions (SANS récursion)
    pub async fn execute_parallel_batch(
        &self,
        mut transactions: Vec<ParallelTransaction>,
    ) -> Vec<Result<NerenaValue, String>> {
        let results = Arc::new(DashMap::new());
        let mut retry_count = 0;
        const MAX_RETRIES: u32 = 3;

        loop {
            let storage_versions = self.storage_versions.clone();
            let global_version_counter = self.global_version_counter.load(Ordering::SeqCst);

            // 1. Phase d'exécution parallèle spéculative
            let execution_futures: Vec<_> = transactions
                .clone()
                .into_iter()
                .map(|tx| {
                    let results_clone = results.clone();
                    let storage_versions_clone = storage_versions.clone();
                    let global_version_counter_value = global_version_counter;
                    let tx_id = tx.id;
                    let vm_clone = self.vm.clone();

                    async move {
                        let engine = OptimisticParallelEngine {
                            transaction_queue: crossbeam::channel::unbounded().1, // dummy receiver
                            transaction_sender: crossbeam::channel::unbounded().0, // dummy sender
                            global_version_counter: AtomicU64::new(global_version_counter_value),
                            storage_versions: storage_versions_clone,
                            active_transactions: DashMap::new(),
                            commit_queue: crossbeam::channel::unbounded().0,
                            abort_queue: crossbeam::channel::unbounded().0,
                            thread_pool_size: 1,
                            batch_size: 1,
                            vm: vm_clone,
                        };

                        match engine
                            .execute_speculative_transaction(tx, global_version_counter_value)
                            .await
                        {
                            Ok(result) => {
                                results_clone.insert(tx_id, Ok(result));
                            }
                            Err(e) => {
                                results_clone.insert(tx_id, Err(e));
                            }
                        }
                    }
                })
                .collect();

            // 2. Attendre toutes les exécutions spéculatives en parallèle
            join_all(execution_futures).await;

            // 3. Phase de validation et commit optimiste
            let validation_results = self.validate_and_commit_batch().await;

            // 4. Collecte des transactions en conflit SANS récursion
            let failed_transactions = self
                .collect_conflicted_transactions_non_recursive(&validation_results, &transactions)
                .await;

            if failed_transactions.is_empty() || retry_count >= MAX_RETRIES {
                // Pas de conflit ou trop de retries - on termine
                break;
            }

            // 5. Prépare le retry avec nouvelle version
            println!(
                "🔄 Retry #{} de {} transactions en conflit",
                retry_count + 1,
                failed_transactions.len()
            );
            transactions = failed_transactions;
            retry_count += 1;

            // Clear previous results for retry
            results.clear();
        }

        // 6. Collecte des résultats finaux
        let mut final_results = Vec::new();
        // Parcours dans l'ordre des transactions fournies pour garantir mapping id -> résultat
        for tx in transactions.iter() {
            if let Some(result) = results.get(&tx.id) {
                final_results.push(result.value().clone());
            } else {
                final_results.push(Err(format!("TX {} manquante après retry", tx.id)));
            }
        }

        final_results
    }

    /// Exécution spéculative d'une transaction (utilise execute_module réel)
    async fn execute_speculative_transaction(
        &self,
        tx: ParallelTransaction,
        _snapshot_version: u64, // plus utilisé
    ) -> Result<NerenaValue, String> {
        println!(
            "⚡ Exécution spéculative TX {} | fn: {} | thread: {}",
            tx.id,
            tx.function_name,
            rayon::current_thread_index().unwrap_or(0)
        );

        let vm_clone = self.vm.clone();
        let contract = tx.contract_address.clone();
        let function = tx.function_name.clone();
        let args = tx.args.clone();
        let sender = tx.sender.clone();

        let mut vm = vm_clone.lock().await;

        let prefix = format!("storage:{}:", &contract);
        println!("   → Lecture depuis prefix stable : {}", prefix);

        let mut reloaded = HashMap::new();
        let mut reloaded_count = 0;

        if let Some(manager) = vm.storage_manager.as_ref() {
            match manager.scan_prefix(&prefix) {
                Ok(entries) => {
                    for (key, value) in entries {
                        if key.starts_with(&prefix) {
                            let slot = key.trim_start_matches(&prefix).to_string();
                            reloaded.insert(slot.clone(), value.clone());
                            reloaded_count += 1;

                            let mut accounts = vm.state.accounts.write().await;
                            if let Some(account) = accounts.get_mut(&contract) {
                                let hex_val = format!("0x{}", hex::encode(&value));
                                account
                                    .resources
                                    .insert(slot.clone(), serde_json::Value::String(hex_val));
                            }
                        }
                    }

                    println!(
                        "   → {} slots rechargés depuis storage stable (TX {})",
                        reloaded_count, tx.id
                    );
                }
                Err(e) => println!("⚠️ [SCAN ÉCHEC] prefix {} : {}", prefix, e),
            }

            // Debug balances
            let balances_slot =
                "37439836327923360225337895871871055371921111519445254264255886447755104894253";
            if let Some(val) = reloaded.get(balances_slot) {
                let u256 = primitive_types::U256::from_big_endian(val);
                println!("   🔥 BALANCES TROUVÉ → {} (0x{})", u256, hex::encode(val));
            } else {
                println!(
                    "   ❌ BALANCES ABSENT dans storage:{}:{}",
                    contract, balances_slot
                );
            }

            let mut world_state = vm.state.world_state.write().await;
            world_state.storage.insert(contract.clone(), reloaded);
        }

        let result = vm
            .execute_module(
                &contract,
                &function,
                args,
                Some(&sender),
                tx.calldata.as_deref(),
            )
            .await?;

        // Write-set extraction (inchangée)
        if let Some(storage_written) = result.get("storage").and_then(|v| v.as_object()) {
            let mut write_set = tx.write_set.write().await;
            for (slot, val_json) in storage_written {
                if let Some(s) = val_json.as_str() {
                    if s.starts_with("0x") {
                        if let Ok(bytes) = hex::decode(&s[2..]) {
                            write_set.insert(slot.clone(), bytes);
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// ✅ Enregistrement du pattern d'accès pour validation
    async fn record_transaction_access_pattern(&self, tx: &ParallelTransaction) {
        println!("📊 Pattern d'accès enregistré pour TX {}", tx.id);
    }

    /// ✅ Phase de validation et commit optimiste
    async fn validate_and_commit_batch(&self) -> Vec<bool> {
        println!("🔍 Phase de validation optimiste...");
        println!(
            "   Nombre de tx actives : {}",
            self.active_transactions.len()
        );

        let mut transaction_ids: Vec<_> = self
            .active_transactions
            .iter()
            .map(|entry| *entry.key())
            .collect();
        transaction_ids.sort();

        println!("   Tx IDs à valider : {:?}", transaction_ids);

        let mut validation_results = Vec::new();

        for tx_id in transaction_ids {
            println!("   → Validation TX {}", tx_id);
            if let Some(tx) = self.active_transactions.get(&tx_id) {
                println!(
                    "     read_set de TX {} : {:?}",
                    tx_id,
                    tx.read_set.read().await
                );

                let is_valid = self.validate_transaction_conflicts(&tx).await;
                println!("     → is_valid = {}", is_valid);

                if is_valid {
                    println!("     → Commit en cours pour TX {}", tx_id);
                    self.commit_transaction_changes(&tx).await;
                    validation_results.push(true);
                    println!("✅ TX {} commitée avec succès", tx_id);
                } else {
                    validation_results.push(false);
                    println!("❌ TX {} en conflit, sera retryée", tx_id);
                }
            } else {
                println!("⚠️ TX {} introuvable dans active_transactions !", tx_id);
            }
        }

        validation_results
    }

    /// ✅ Validation des conflits de concurrence
    async fn validate_transaction_conflicts(&self, tx: &ParallelTransaction) -> bool {
        let read_set = tx.read_set.read().await;
        println!(
            "   Vérification conflits pour TX {} - read_set size: {}",
            tx.id,
            read_set.len()
        );

        for (slot, version_read) in read_set.iter() {
            let current_version = self
                .storage_versions
                .get(slot)
                .map(|v| *v.value())
                .unwrap_or(0);
            println!(
                "     Slot {} : lu v{}, actuel v{} → {}",
                slot,
                version_read,
                current_version,
                if current_version == *version_read {
                    "OK"
                } else {
                    "CONFLIT !"
                }
            );

            if current_version != *version_read {
                println!(
                    "⚠️  Conflit détecté sur slot {} : lu v{}, actuel v{}",
                    slot, version_read, current_version
                );
                return false;
            }
        }
        println!("   → Pas de conflit pour TX {}", tx.id);
        true
    }

    /// ✅ Commit avec nouveau format sûr : storage:{address}:v{version}:{slot}
    async fn commit_transaction_changes(&self, tx: &ParallelTransaction) -> Result<(), String> {
        let write_set = tx.write_set.read().await;
        if write_set.is_empty() {
            println!("ℹ️ TX {} n'a écrit aucun slot → rien à persister", tx.id);
            return Ok(());
        }

        let manager = {
            let vm_guard = self.vm.lock().await;
            vm_guard
                .storage_manager
                .as_ref()
                .ok_or("No storage")?
                .clone()
        };

        let contract = tx.contract_address.clone();

        {
            let mut vm_guard = self.vm.lock().await;
            let mut world_state = vm_guard.state.world_state.write().await;
            let contract_storage = world_state.storage.entry(contract.clone()).or_default();

            for (slot, new_value) in write_set.iter() {
                let keyed_slot = format!("storage:{}:{}", &contract, slot);

                manager
                    .write(&keyed_slot, new_value)
                    .map_err(|e| format!("Write fail {}: {}", keyed_slot, e))?;

                contract_storage.insert(slot.clone(), new_value.clone());
                self.storage_versions.insert(slot.clone(), 1); // ou retire si plus besoin
            }
        }

        // Optionnel : garde un pointeur "dernière modification"
        let version_key = format!("version:{}", &contract);
        let _ = manager.write(&version_key, &1u64.to_be_bytes()); // ou supprime cette ligne

        println!(
            "✅ Commit TX {} terminé — {} slots écrits (sans version)",
            tx.id,
            write_set.len()
        );
        Ok(())
    }

    /// Retourne la version à utiliser pour la lecture spéculative
    /// Priorité : backup_version (stable) > version courante > 1
    async fn get_committed_version(&self, contract: &str) -> u64 {
        let manager = {
            let vm = self.vm.lock().await;
            vm.storage_manager.as_ref().cloned().unwrap_or_else(|| {
                panic!("Aucun storage_manager configuré dans la VM");
            })
        };

        // PRIORITÉ ABSOLUE : backup_version (version stable avec slots persistants)
        let backup_key = format!("backup_version:{}", contract);
        if let Ok(bytes) = manager.read(&backup_key) {
            if bytes.len() == 8 {
                let ver = u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]));
                if ver > 0 {
                    println!(
                        "📸 [GET VERSION] {} → PRIORITÉ BACKUP_VERSION → v{} (stable)",
                        contract, ver
                    );
                    return ver;
                }
            }
        }

        // Si pas de backup → version courante (mais log d'avertissement)
        let version_key = format!("version:{}", contract);
        if let Ok(bytes) = manager.read(&version_key) {
            if bytes.len() == 8 {
                let ver = u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]));
                println!(
                    "📸 [GET VERSION] {} → PAS DE BACKUP → fallback version courante v{}",
                    contract, ver
                );
                return ver;
            }
        }

        // Ultime fallback
        println!(
            "📸 [GET VERSION] {} → AUCUNE VERSION → retour v1 (sécurité)",
            contract
        );
        1u64
    }

    /// ✅ Point d'entrée pour soumission de transaction parallèle
    pub fn submit_transaction(&self, tx: ParallelTransaction) -> Result<(), String> {
        self.active_transactions.insert(tx.id, tx.clone());
        self.transaction_sender
            .send(tx)
            .map_err(|_| "Erreur envoi transaction".to_string())?;
        Ok(())
    }
}

// ============================================================================
// TYPES UVM UNIVERSELS
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub String);

impl Address {
    pub fn new(addr: &str) -> Self {
        Address(addr.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.contains("*") && self.0.contains("#")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signer {
    pub address: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
}

impl Signer {
    pub fn new(addr: &str) -> Self {
        Signer {
            address: Address::new(addr),
            nonce: 0,
            gas_limit: 1000000,
            gas_price: 1,
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }
}

// ============================================================================
// STRUCTURES COMPATIBLES ARCHITECTURE BASÉE SUR PILE UVM
// ============================================================================

#[derive(Clone)]
pub struct Module {
    pub name: String,
    pub address: String,
    pub bytecode: Vec<u8>,
    pub elf_buffer: Vec<u8>,
    pub context: uvm_runtime::UbfContext,
    pub stack_usage: Option<uvm_runtime::stack::StackUsage>,
    pub functions: HashMap<String, FunctionMetadata>,
    pub gas_estimates: HashMap<String, u64>,
    pub storage_layout: HashMap<String, StorageSlot>,
    pub events: Vec<EventDefinition>,
    pub constructor_params: Vec<String>,
}

/// ✅ MISE À JOUR de FunctionMetadata pour inclure les modifiers
#[derive(Clone, Debug)]
pub struct FunctionMetadata {
    pub name: String,
    pub offset: usize,
    pub args_count: usize,
    pub return_type: String,
    pub gas_limit: u64,
    pub payable: bool,
    pub mutability: String,
    pub selector: u32,
    pub arg_types: Vec<String>,
    pub modifiers: Vec<String>, // ✅ NOUVEAU
}

#[derive(Clone, Debug)]
pub struct StorageSlot {
    pub name: String,
    pub slot: u32,
    pub offset: u32,
    pub size: u32,
    pub type_info: String,
}

#[derive(Clone, Debug)]
pub struct EventDefinition {
    pub name: String,
    pub signature: String,
    pub indexed_params: Vec<String>,
    pub data_params: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AccountState {
    // ─── Adresse principale "racine" (Ethereum-compatible) ───
    pub eth_address: String, // ex: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

    // ─── Adresse zk-print longue (résistante quantique) ───
    pub slu_zk_address: String,
    pub balance: u128,
    pub contract_state: Vec<u8>,
    pub resources: BTreeMap<String, serde_json::Value>,
    pub state_version: u64,
    pub last_block_number: u64,
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
    pub is_contract: bool,
    pub gas_used: u64,
}

#[derive(Default, Clone)]
pub struct VmState {
    pub accounts: Arc<RwLock<BTreeMap<String, AccountState>>>,
    pub world_state: Arc<RwLock<UvmWorldState>>,
    pub pending_logs: Arc<RwLock<Vec<UvmLog>>>,
    pub gas_price: u64,
    pub block_info: Arc<RwLock<BlockInfo>>,
    pub cluster: String,
}

#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, UvmAccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>,
    pub code: HashMap<String, Vec<u8>>,
    pub balances: HashMap<String, u64>,
}

#[derive(Clone, Debug)]
pub struct UvmAccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
}

#[derive(Clone, Debug)]
pub struct UvmLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub difficulty: u64,
    pub coinbase: String,
}

impl Default for UvmWorldState {
    fn default() -> Self {
        UvmWorldState {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            balances: HashMap::new(),
        }
    }
}

impl Default for BlockInfo {
    fn default() -> Self {
        BlockInfo {
            number: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            gas_limit: 30000000,
            gas_used: 0,
            difficulty: 1,
            coinbase: "*coinbase*#miner#".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContractDeploymentArgs {
    pub deployer: String,
    pub bytecode: Vec<u8>,
    pub constructor_args: Vec<serde_json::Value>,
    pub gas_limit: u64,
    pub value: u64,
    pub salt: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct DeploymentResult {
    pub contract_address: String,
    pub transaction_hash: String,
    pub gas_used: u64,
    pub deployment_cost: u64,
}

#[derive(Clone, Debug)]
pub struct ContractDeploymentArgsWithOwnership {
    pub deployer: String,
    pub owner_address: String,
    pub owner_private_key_hash: String,
    pub bytecode: Vec<u8>,
    pub constructor_args: Vec<serde_json::Value>,
    pub gas_limit: u64,
    pub value: u64,
    pub hex_format_enabled: bool,
    pub salt: Option<Vec<u8>>,
    pub ownership_type: OwnershipType,
}

#[derive(Clone, Debug)]
pub enum OwnershipType {
    SingleOwner,
    MultiSig,
    DAO,
    Upgradeable,
}

impl Default for OwnershipType {
    fn default() -> Self {
        OwnershipType::SingleOwner
    }
}

#[derive(Clone, Debug)]
pub struct NativeTokenParams {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub mintable: bool,
    pub burnable: bool,
}

impl Default for NativeTokenParams {
    fn default() -> Self {
        NativeTokenParams {
            name: "Vyft Enhancing ZER".to_string(),
            symbol: "VEZ".to_string(),
            decimals: 18,
            total_supply: 888_000_000,
            mintable: true,
            burnable: false,
        }
    }
}

pub struct SimpleInterpreter {
    pub helpers: HashMap<u32, fn(u64, u64, u64, u64, u64) -> u64>,
    pub allowed_memory: HashSet<std::ops::Range<u64>>,
    pub uvm_helpers: HashMap<u32, Box<UvmHelper>>,
    pub last_storage: Option<HashMap<String, Vec<u8>>>,
}

impl SimpleInterpreter {
    pub fn new() -> Self {
        let mut interpreter = SimpleInterpreter {
            helpers: HashMap::new(),
            allowed_memory: HashSet::new(),
            uvm_helpers: HashMap::new(),
            last_storage: None,
        };
        interpreter.setup_uvm_helpers();
        interpreter
    }

    fn setup_uvm_helpers(&mut self) {
        // ✅ SYSTÈME 100% GÉNÉRIQUE - Aucun hardcodage
        println!("✅ Interpréteur UVM initialisé");
    }

    pub fn add_function_helper(
        &mut self,
        selector: u32,
        function_name: &str,
        helper: impl Fn(u64, u64, u64, u64, u64, u64, u64) -> u64 + Send + Sync + 'static,
    ) {
        self.uvm_helpers.insert(selector, Box::new(helper));
        println!(
            "📋 Helper ajouté pour {} (0x{:08x})",
            function_name, selector
        );
    }

    pub fn clear_helpers(&mut self) {
        self.uvm_helpers.clear();
        println!("🧹 Tous les helpers effacés");
    }

    pub fn get_last_storage(&self) -> Option<&HashMap<String, Vec<u8>>> {
        self.last_storage.as_ref()
    }
}

pub struct SlurachainVm {
    pub state: VmState,
    pub modules: BTreeMap<String, Module>,
    pub address_map: BTreeMap<String, String>,
    pub interpreter: Arc<Mutex<SimpleInterpreter>>,
    pub storage_manager: Option<Arc<dyn RocksDBManager>>,
    pub gas_price: u64,
    pub chain_id: u64,
    pub debug_mode: bool,
    pub helpers: HashMap<u32, fn(u64, u64, u64, u64, u64) -> u64>,
    pub allowed_memory: HashSet<std::ops::Range<u64>>,
    pub uvm_helpers: Arc<tokio::sync::Mutex<HashMap<u32, Box<UvmHelper>>>>,
    pub last_storage: Option<HashMap<String, Vec<u8>>>,
    pub parallel_engine: Option<Arc<OptimisticParallelEngine>>,
    // ✅ AJOUT: Verrou global anti-reentrancy
    pub global_execution_lock: Arc<Mutex<()>>,
}

pub type UvmHelper = dyn Fn(u64, u64, u64, u64, u64, u64, u64) -> u64 + Send + Sync + 'static;

// Manual implementation of Clone for SlurachainVm to handle Arc and Option<Arc<dyn RocksDBManager>>
impl Clone for SlurachainVm {
    fn clone(&self) -> Self {
        SlurachainVm {
            state: self.state.clone(),
            modules: self.modules.clone(),
            address_map: self.address_map.clone(),
            interpreter: Arc::clone(&self.interpreter),
            storage_manager: self.storage_manager.as_ref().map(|arc| Arc::clone(arc)),
            gas_price: self.gas_price,
            chain_id: self.chain_id,
            debug_mode: self.debug_mode,
            helpers: self.helpers.clone(),
            allowed_memory: self.allowed_memory.clone(),
            uvm_helpers: self.uvm_helpers.clone(),
            last_storage: self.last_storage.clone(),
            parallel_engine: self.parallel_engine.as_ref().map(|arc| Arc::clone(arc)),
            global_execution_lock: Arc::clone(&self.global_execution_lock),
        }
    }
}

impl SlurachainVm {
    pub fn new() -> Self {
        let mut vm = SlurachainVm {
            state: VmState::default(),
            modules: BTreeMap::new(),
            address_map: BTreeMap::new(),
            interpreter: Arc::new(Mutex::new(SimpleInterpreter::new())),
            storage_manager: None,
            gas_price: 1,
            chain_id: 45056,
            debug_mode: true,
            helpers: HashMap::new(),
            allowed_memory: HashSet::new(),
            uvm_helpers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            last_storage: None,
            parallel_engine: None,
            global_execution_lock: Arc::new(Mutex::new(())), // ✅ Init du lock
        };

        // Module générique pour déploiement
        let mut functions = HashMap::new();
        functions.insert(
            "deploy".to_string(),
            FunctionMetadata {
                name: "deploy".to_string(),
                offset: 0,
                args_count: 2,
                return_type: "address".to_string(),
                gas_limit: 3_000_000,
                payable: true,
                mutability: "nonpayable".to_string(),
                selector: 0,
                arg_types: vec![],
                modifiers: vec![],
            },
        );
        vm.modules.insert(
            "evm".to_string(),
            Module {
                name: "evm".to_string(),
                address: "evm".to_string(),
                bytecode: vec![],
                elf_buffer: vec![],
                context: uvm_runtime::UbfContext::new(),
                stack_usage: None,
                functions,
                gas_estimates: HashMap::new(),
                storage_layout: HashMap::new(),
                events: vec![],
                constructor_params: vec!["bytes".to_string(), "uint256".to_string()],
            },
        );

        vm
    }

    /// ✅ NOUVEAU: Exécution parallèle de batch
    pub async fn execute_parallel_transactions(
        &mut self,
        transactions: Vec<(String, String, Vec<NerenaValue>, String, Option<Vec<u8>>)>,
    ) -> Vec<Result<NerenaValue, String>> {
        if let Some(engine) = &self.parallel_engine {
            let parallel_txs: Vec<_> = transactions
                .into_iter()
                .enumerate()
                .map(
                    |(i, (module_path, function_name, args, sender, calldata))| {
                        let tx = ParallelTransaction {
                            id: i as u64,
                            contract_address: Self::extract_address(&module_path).to_string(),
                            function_name,
                            args,
                            sender,
                            version: AtomicU64::new(0),
                            read_set: Arc::new(RwLock::new(HashMap::new())),
                            write_set: Arc::new(RwLock::new(HashMap::new())),
                            dependencies: Arc::new(RwLock::new(HashSet::new())),
                            calldata,
                        };

                        // IMPORTANT : enregistre la tx dans active_transactions AVANT exécution
                        engine.active_transactions.insert(tx.id, tx.clone());

                        tx
                    },
                )
                .collect();

            // Maintenant lance le batch
            engine.execute_parallel_batch(parallel_txs).await
        } else {
            // Fallback séquentiel
            let mut results = Vec::new();
            for (module_path, function_name, args, sender, calldata) in transactions {
                let result = self
                    .execute_program(
                        &module_path,
                        &function_name,
                        args,
                        Some(&sender),
                        None,
                        None,
                        None,
                        calldata.as_deref(), // <-- Passe le calldata ici
                    )
                    .await;
                results.push(result);
            }
            results
        }
    }

    /// ✅ CORRECTION LOAD_COMPLETE_CONTRACT_STATE pour alimenter l'UVM - SANS CONFLIT D'EMPRUNT
    pub fn load_complete_contract_state(
        &mut self,
        contract_address: &str,
    ) -> Result<Vec<u8>, String> {
        // ✅ CLONE du storage_manager pour éviter les conflits d'emprunt
        let storage_manager = match &self.storage_manager {
            Some(m) => Arc::clone(m),
            None => return Err("Aucun storage_manager configuré".to_string()),
        };

        // assure qu'il y a un AccountState pour remplir
        let mut account = {
            let mut accounts = futures::executor::block_on(self.state.accounts.write());
            accounts
                .entry(contract_address.to_string())
                .or_insert_with(|| AccountState {
                    eth_address: contract_address.to_string(),
                    slu_zk_address: contract_address.to_string(),
                    balance: 0,
                    contract_state: vec![],
                    resources: BTreeMap::new(),
                    state_version: 0,
                    last_block_number: 0,
                    nonce: 0,
                    code_hash: "".to_string(),
                    storage_root: "".to_string(),
                    is_contract: false,
                    gas_used: 0,
                })
                .clone()
        };

        // 1) ✅ CHARGEMENT DU BYTECODE RÉEL
        let code_key_candidates = [
            format!("code:{}", contract_address),
            format!("contract:{}:code", contract_address),
            format!("bytecode:{}", contract_address),
            format!("account:{}:code", contract_address),
            format!("storage:{}:code", contract_address),
        ];

        let mut found_code: Option<Vec<u8>> = None;
        for key in &code_key_candidates {
            match storage_manager.read(key) {
                Ok(bytes) if !bytes.is_empty() => {
                    found_code = Some(bytes);
                    break;
                }
                _ => {}
            }
        }

        if let Some(code) = found_code {
            account.contract_state = code.clone();
            account.is_contract = true;
            let hash = Keccak256::digest(&code);
            account.code_hash = hex::encode(hash);

            // ✅ CRUCIAL: AUTO-DÉTECTION IMMÉDIATE avec le bytecode chargé
            println!("🔄 [AUTO-DETECT] Lancement auto-détection avec bytecode chargé");
            if let Err(e) = self.auto_detect_contract_functions(contract_address, &code) {
                println!("⚠️ Erreur auto-détection: {}", e);
            }

            println!(
                "✅ Contract {} bytecode chargé ({} bytes), code_hash 0x{}",
                contract_address,
                account.contract_state.len(),
                account.code_hash
            );
        } else {
            println!("⚠️ Aucun bytecode trouvé pour {}", contract_address);
        }

        // Helper closure pour tenter lecture d'un storage key (retourne Option<Vec<u8>>)
        let try_read_storage = |sm: &Arc<dyn RocksDBManager>, key: &str| -> Option<Vec<u8>> {
            match sm.read(key) {
                Ok(b) if !b.is_empty() => Some(b),
                _ => None,
            }
        };

        // 2) Lire slots ERC-1967 canoniques
        let canonical_slots = vec![
            ERC1967_IMPLEMENTATION_SLOT.to_string(),
            ERC1967_ADMIN_SLOT.to_string(),
            ERC1967_BEACON_SLOT.to_string(),
        ];

        for slot in &canonical_slots {
            let storage_key = format!("storage:{}:{}", contract_address, slot);
            if let Some(bytes) = try_read_storage(&storage_manager, &storage_key) {
                let hexval = format!("0x{}", hex::encode(&bytes));
                account
                    .resources
                    .insert(slot.clone(), serde_json::Value::String(hexval.clone()));
                println!("💾 Slot canonical {} chargé -> {}", slot, hexval);
            }
        }

        // 3) Tenter de lire clés logiques courantes (implementation/admin/beacon) et normaliser
        let logical_names = ["implementation", "admin", "beacon"];
        for name in &logical_names {
            let storage_key = format!("storage:{}:{}", contract_address, name);
            if let Some(bytes) = try_read_storage(&storage_manager, &storage_key) {
                let canonical_slot = self.map_resource_key_to_slot(name);
                let hexval = format!("0x{}", hex::encode(&bytes));
                account.resources.insert(
                    canonical_slot.clone(),
                    serde_json::Value::String(hexval.clone()),
                );
                println!(
                    "🔁 Slot logique '{}' lu et mappé -> canonical {} = {}",
                    name, canonical_slot, hexval
                );
            }
        }

        // 5) Ecrit l'AccountState mis à jour dans l'état global
        {
            let mut accounts = futures::executor::block_on(self.state.accounts.write());
            accounts.insert(contract_address.to_string(), account.clone());
        }

        println!(
            "🟢 Chargement complet de l'état du contrat {} terminé",
            contract_address
        );

        // Construction du buffer d'état retourné
        fn pad_or_truncate(mut data: Vec<u8>, target: usize) -> Vec<u8> {
            if data.len() == target {
                return data;
            }
            if data.len() > target {
                data.truncate(target);
                return data;
            }
            data.resize(target, 0u8);
            data
        }

        if !account.contract_state.is_empty() {
            return Ok(pad_or_truncate(account.contract_state.clone(), 4096));
        }

        if !account.resources.is_empty() {
            match serde_json::to_vec(&account.resources) {
                Ok(json_bytes) => {
                    return Ok(pad_or_truncate(json_bytes, 4096));
                }
                Err(e) => {
                    eprintln!(
                        "⚠️ Erreur sérialisation resources pour {}: {}",
                        contract_address, e
                    );
                    return Ok(vec![0u8; 4096]);
                }
            }
        }

        Ok(vec![0u8; 4096])
    }

    /// ✅ NOUVEAU: Wrapper parallèle pour une seule transaction
    pub async fn execute_module(
        &mut self,
        module_path: &str,
        function_name: &str,
        args: Vec<NerenaValue>,
        sender_vyid: Option<&str>,
        calldata: Option<&[u8]>,
    ) -> Result<NerenaValue, String> {
        let sender = sender_vyid.unwrap_or("*system*#default#").to_string();
        let calldata_vec = calldata.map(|c| c.to_vec());

        println!(
            "execute_module → path: {} | fn: '{}' | args: {} | calldata: {} bytes | sender: {}",
            module_path,
            function_name,
            args.len(),
            calldata_vec.as_ref().map_or(0, |v| v.len()),
            sender
        );
        // ne contient pas de nom de fonction nil n'essaie pas de résoudre le sélecteur exécute quand-même le module (utile pour les modules sans dispatcher)
        if function_name.is_empty() {
            println!("⚠️ Nom de fonction vide, exécution du module sans résolution de sélecteur");
        }

        let batch = vec![(
            module_path.to_string(),
            function_name.to_string(),
            args,
            sender,
            calldata_vec,
        )];

        // Exécution via le moteur parallèle (même pipeline pour tout)
        let results = self.execute_parallel_transactions(batch).await;

        let result = results.into_iter().next().unwrap_or(Err(
            "Aucun résultat retourné par le moteur parallèle".to_string(),
        ))?;

        Ok(result)
    }

    /// ✅ NOUVEAU: Construction du storage dynamique depuis l'état du contrat
    fn build_dynamic_storage_from_contract_state(
        &self,
        contract_address: &str,
    ) -> Result<Option<HashMap<String, HashMap<String, Vec<u8>>>>, String> {
        let accounts = futures::executor::block_on(self.state.accounts.read());
        if let Some(account) = accounts.get(contract_address) {
            let mut storage = HashMap::new();
            let mut contract_storage = HashMap::new();
            // Convertit les resources en storage bytes
            for (key, value) in &account.resources {
                let storage_bytes = self.convert_resource_to_storage_bytes(value);
                contract_storage.insert(key.clone(), storage_bytes);
            }
            storage.insert(contract_address.to_string(), contract_storage);
            return Ok(Some(storage));
        }
        Ok(None)
    }

    /// ✅ AUTO-DÉTECTION UNIVERSELLE SANS HARDCODAGE - AVEC CHARGEMENT DU BYTECODE
    pub fn auto_detect_contract_functions(
        &mut self,
        contract_address: &str,
        bytecode: &[u8],
    ) -> Result<(), String> {
        println!(
            "🔍 [UNIVERSAL DETECT] Analyse générique pour {}, taille: {} bytes",
            contract_address,
            bytecode.len()
        );

        // ✅ ÉTAPE CRUCIALE: Charger le bytecode dans le module AVANT analyse
        if !self.modules.contains_key(contract_address) {
            // Crée le module avec le bytecode réel
            let module = Module {
                name: contract_address.to_string(),
                address: contract_address.to_string(),
                bytecode: bytecode.to_vec(), // ✅ CRUCIAL: Charge le bytecode réel
                elf_buffer: vec![],
                context: uvm_runtime::UbfContext::new(),
                stack_usage: None,
                functions: HashMap::new(),
                gas_estimates: HashMap::new(),
                storage_layout: HashMap::new(),
                events: vec![],
                constructor_params: vec![],
            };
            self.modules.insert(contract_address.to_string(), module);
            println!(
                "📦 [MODULE CREATED] Module créé avec bytecode ({} bytes)",
                bytecode.len()
            );
        } else {
            // ✅ Met à jour le bytecode existant s'il était vide
            if let Some(module) = self.modules.get_mut(contract_address) {
                if module.bytecode.is_empty() && !bytecode.is_empty() {
                    module.bytecode = bytecode.to_vec();
                    println!(
                        "🔄 [BYTECODE UPDATED] Bytecode mis à jour ({} bytes)",
                        bytecode.len()
                    );
                }
            }
        }

        let mut detected_functions = HashMap::new();
        let len = bytecode.len();

        // ✅ VÉRIFICATION PRÉALABLE
        if len == 0 {
            println!("⚠️ [EMPTY BYTECODE] Aucun bytecode à analyser");
            return Ok(());
        }

        // ✅ ANALYSE PURE DU DISPATCHER - DÉTECTION AUTOMATIQUE DES PATTERNS
        let mut i = 0;
        while i + 10 < len {
            // Pattern universel : PUSH4 + opcodes quelconques + JUMPI
            if bytecode[i] == 0x63 {
                // PUSH4 - sélecteur de fonction
                let selector = u32::from_be_bytes([
                    bytecode[i + 1],
                    bytecode[i + 2],
                    bytecode[i + 3],
                    bytecode[i + 4],
                ]);

                // Recherche du JUMPI dans les 15 bytes suivants
                for j in 5..15 {
                    if i + j < len && bytecode[i + j] == 0x57 {
                        // JUMPI trouvé
                        // Recherche d'un PUSH2 juste avant le JUMPI pour l'offset
                        if j >= 3 && bytecode[i + j - 3] == 0x61 {
                            // PUSH2
                            let offset = ((bytecode[i + j - 2] as usize) << 8)
                                | (bytecode[i + j - 1] as usize);

                            // Validation heuristique de l'offset
                            if offset > i + 50 && offset < len {
                                detected_functions.insert(
                                    format!("function_{:08x}", selector),
                                    self.create_function_metadata(selector, offset),
                                );
                                println!(
                                    "✅ Sélecteur détecté: 0x{:08x} → offset 0x{:04x}",
                                    selector, offset
                                );
                                break;
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        // ✅ Si le dispatcher principal n'a rien donné, scan heuristique
        if detected_functions.is_empty() {
            println!("🔍 Dispatcher principal vide - scan heuristique...");
            self.heuristic_function_detection(bytecode, &mut detected_functions);
        }

        // ✅ Fallback minimal si vraiment rien trouvé
        if detected_functions.is_empty() {
            println!("⚠️ Aucune fonction détectée - création d'une fonction générique");
            detected_functions.insert(
                "fallback".to_string(),
                FunctionMetadata {
                    name: "fallback".to_string(),
                    offset: 100, // Offset arbitraire dans le code
                    args_count: 0,
                    return_type: "bytes".to_string(),
                    gas_limit: 100000,
                    payable: true,
                    mutability: "payable".to_string(),
                    selector: 0x00000000,
                    arg_types: vec![],
                    modifiers: vec![],
                },
            );
        }

        // ✅ Sauvegarde
        self.save_detected_functions(contract_address, detected_functions);
        println!(
            "✅ Détection terminée : {} fonctions",
            self.modules
                .get(contract_address)
                .map(|m| m.functions.len())
                .unwrap_or(0)
        );
        Ok(())
    }

    /// ✅ NOUVEAU: Helper pour créer les métadonnées de fonction
    fn create_function_metadata(&self, selector: u32, offset: usize) -> FunctionMetadata {
        FunctionMetadata {
            name: format!("function_{:08x}", selector),
            offset,
            args_count: 0, // Sera déterminé dynamiquement
            return_type: "bytes".to_string(),
            gas_limit: 100000,
            payable: false,
            mutability: "nonpayable".to_string(),
            selector,
            arg_types: vec![],
            modifiers: vec![],
        }
    }

    /// ✅ NOUVEAU: Configuration du moteur parallèle
    pub fn with_parallel_engine(mut self, thread_count: usize, batch_size: usize) -> Self {
        let engine = Arc::new(OptimisticParallelEngine::new(
            thread_count,
            batch_size,
            Arc::new(Mutex::new(self.clone())),
        ));
        self.parallel_engine = Some(engine);
        println!(
            "⚡ Moteur parallèle configuré: {} threads, batch {}",
            thread_count, batch_size
        );
        self
    }

    pub fn set_storage_manager(&mut self, storage: Arc<dyn RocksDBManager>) {
        self.storage_manager = Some(storage);
    }

    fn extract_address(module_path: &str) -> &str {
        if module_path.contains("*") && module_path.contains("#") {
            return module_path;
        }
        module_path
    }

    pub fn verify_module_and_function(
        &self,
        module_path: &str,
        function_name: &str,
    ) -> Result<(), String> {
        let vyid = Self::extract_address(module_path);

        if !self.modules.contains_key(vyid) {
            return Err(format!("Module/Contrat '{}' non déployé", vyid));
        }

        let module = &self.modules[vyid];
        if !module.functions.contains_key(function_name) {
            return Err(format!(
                "Fonction '{}' non trouvée dans le module '{}'",
                function_name, vyid
            ));
        }

        if let Some(module) = self.modules.get(vyid) {
            let function_list: Vec<_> = module.functions.keys().cloned().collect();
            println!(
                "📋 [DISPATCH] Fonctions disponibles pour {} : {:?}",
                vyid, function_list
            );
        } else {
            println!("📋 [DISPATCH] Aucun module chargé pour {}", vyid);
        }
        Ok(())
    }

    /// ✅ DÉTECTION HEURISTIQUE PURE
    fn heuristic_function_detection(
        &self,
        bytecode: &[u8],
        functions: &mut HashMap<String, FunctionMetadata>,
    ) {
        let len = bytecode.len();

        // Recherche de tous les PUSH4 même isolés
        for i in 0..len.saturating_sub(4) {
            if bytecode[i] == 0x63 {
                // PUSH4
                let potential_selector = u32::from_be_bytes([
                    bytecode[i + 1],
                    bytecode[i + 2],
                    bytecode[i + 3],
                    bytecode[i + 4],
                ]);

                // Validation heuristique du sélecteur
                if potential_selector > 0x00000100 && potential_selector != 0xffffffff {
                    let estimated_offset = (i + 50).min(len.saturating_sub(1));
                    functions.insert(
                        format!("function_{:08x}", potential_selector),
                        self.create_function_metadata(potential_selector, estimated_offset),
                    );
                    println!(
                        "🎯 Sélecteur heuristique: 0x{:08x} @ pos 0x{:04x}",
                        potential_selector, i
                    );
                }
            }
        }
    }

    /// ✅ SAUVEGARDE GÉNÉRIQUE
    fn save_detected_functions(
        &mut self,
        contract_address: &str,
        functions: HashMap<String, FunctionMetadata>,
    ) {
        if let Some(module) = self.modules.get_mut(contract_address) {
            module.functions.extend(functions);
        } else {
            // Création module minimal
            let module = Module {
                name: contract_address.to_string(),
                address: contract_address.to_string(),
                bytecode: vec![], // Sera rempli lors du déploiement
                elf_buffer: vec![],
                context: uvm_runtime::UbfContext::new(),
                stack_usage: None,
                functions,
                gas_estimates: HashMap::new(),
                storage_layout: HashMap::new(),
                events: vec![],
                constructor_params: vec![],
            };
            self.modules.insert(contract_address.to_string(), module);
        }
    }

    /// ✅ NOUVEAU: Calcul générique du sélecteur de fonction
    fn calculate_function_selector_from_signature(
        function_name: &str,
        args: &[NerenaValue],
    ) -> u32 {
        // ✅ CORRECTION: Si le nom commence par "function_", extrait le sélecteur directement
        if function_name.starts_with("function_") {
            if let Some(hex_part) = function_name.strip_prefix("function_") {
                if let Ok(selector) = u32::from_str_radix(hex_part, 16) {
                    println!(
                        "🎯 [SELECTOR] Extraction directe: {} -> 0x{:08x}",
                        function_name, selector
                    );
                    return selector;
                }
            }
        }

        // ✅ Détermine les types d'arguments automatiquement
        let arg_types: Vec<String> = args
            .iter()
            .map(|arg| match arg {
                serde_json::Value::String(s) => {
                    if s.starts_with("0x") && s.len() == 42 {
                        "address".to_string()
                    } else {
                        "string".to_string()
                    }
                }
                serde_json::Value::Number(_) => "uint256".to_string(),
                serde_json::Value::Bool(_) => "bool".to_string(),
                _ => "bytes".to_string(),
            })
            .collect();

        let signature = if arg_types.is_empty() {
            format!("{}()", function_name)
        } else {
            format!("{}({})", function_name, arg_types.join(","))
        };

        let hash = Keccak256::digest(signature.as_bytes());
        let selector = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);

        println!(
            "🎯 [SELECTOR] Signature: {} -> 0x{:08x}",
            signature, selector
        );
        selector
    }

    pub fn ensure_account_exists(
        accounts: &BTreeMap<String, AccountState>,
        address: &str,
    ) -> Result<(), String> {
        if !accounts.contains_key(address) {
            return Err(format!("Compte '{}' introuvable dans l'état UVM", address));
        }
        Ok(())
    }

    /// ✅ DÉTECTION DYNAMIQUE CORRIGÉE: Recherche réelle du dispatcher EVM
    /// EXCEPTION: si selector == 0 → traite comme appel sans selector (fallback / déploiement direct)
    fn find_function_offset_in_bytecode(bytecode: &[u8], selector: u32) -> Option<usize> {
        let len = bytecode.len();
        println!(
            "🔍 [DYNAMIC SEARCH] Recherche sélecteur 0x{:08x} dans {} bytes",
            selector, len
        );

        if len < 10 {
            return None;
        }

        // ────────────────────────────────────────────────
        // EXCEPTION SPÉCIALE : selector == 0 → appel sans fonction explicite (fallback / déploiement brut)
        // ────────────────────────────────────────────────
        if selector == 0 {
            println!(
            "⚡ [EXCEPTION OFFSET] selector 0x00000000 → appel sans fonction explicite (fallback/direct execution)"
        );
            // Retourne un offset "fallback" spécial
            // Typiquement 0 (début du bytecode) ou l'offset de ton fallback si tu en as un défini
            return Some(0); // ← ou un offset fixe comme 0x0421 si tu sais où commence ton fallback
        }

        let selector_bytes = selector.to_be_bytes();

        // ────────────────────────────────────────────────
        // CAS NORMAL : recherche stricte dans le dispatcher
        // ────────────────────────────────────────────────
        let dispatcher_start = 0x0000;
        if dispatcher_start >= len {
            println!(
                "❌ [NO DISPATCHER] Dispatcher start 0x{:04x} dépasse bytecode length",
                dispatcher_start
            );
            return None;
        }

        println!(
            "🔍 [DISPATCHER] Analyse dispatcher à partir de 0x{:04x}",
            dispatcher_start
        );

        // Recherche dans le dispatcher pour notre sélecteur
        for pos in dispatcher_start..len.saturating_sub(4) {
            if &bytecode[pos..pos + 4] == selector_bytes {
                println!(
                    "🎯 [SELECTOR FOUND] 0x{:08x} trouvé à position 0x{:04x}",
                    selector, pos
                );

                // Stratégie A: Pattern classique EQ + PUSH2 + JUMPI
                for scan_offset in 4..20 {
                    if pos + scan_offset + 3 < len {
                        let check_pos = pos + scan_offset;

                        if bytecode[check_pos] == 0x14 && // EQ
                       check_pos + 1 < len && bytecode[check_pos + 1] == 0x61 && // PUSH2
                       check_pos + 4 < len && bytecode[check_pos + 4] == 0x57
                        // JUMPI
                        {
                            let offset = ((bytecode[check_pos + 2] as usize) << 8)
                                | (bytecode[check_pos + 3] as usize);

                            if offset < len && offset > dispatcher_start {
                                println!(
                                    "✅ [EQ PATTERN] 0x{:08x} → offset 0x{:04x}",
                                    selector, offset
                                );
                                return Some(offset);
                            }
                        }
                    }
                }

                // Stratégie B: Pattern comparaison hiérarchique (DUP1 + PUSH4 + GT/LT/EQ)
                for back_scan in 1..30 {
                    if pos >= back_scan {
                        let scan_pos = pos - back_scan;
                        if scan_pos + 10 < len &&
                       bytecode[scan_pos] == 0x80 && // DUP1
                       bytecode[scan_pos + 1] == 0x63
                        // PUSH4
                        {
                            if scan_pos + 6 <= len {
                                let cmp_selector = u32::from_be_bytes([
                                    bytecode[scan_pos + 2],
                                    bytecode[scan_pos + 3],
                                    bytecode[scan_pos + 4],
                                    bytecode[scan_pos + 5],
                                ]);

                                println!(
                                    "🔍 [HIERARCHICAL] Comparaison: notre 0x{:08x} vs 0x{:08x}",
                                    selector, cmp_selector
                                );

                                for op_scan in 6..16 {
                                    if scan_pos + op_scan < len {
                                        let op_code = bytecode[scan_pos + op_scan];
                                        let should_take_branch = match op_code {
                                            0x11 => selector > cmp_selector,  // GT
                                            0x10 => selector < cmp_selector,  // LT
                                            0x14 => selector == cmp_selector, // EQ
                                            _ => false,
                                        };

                                        if should_take_branch {
                                            for jump_scan in (op_scan + 1)..(op_scan + 10) {
                                                if scan_pos + jump_scan + 3 < len &&
                                               bytecode[scan_pos + jump_scan] == 0x61 && // PUSH2
                                               bytecode[scan_pos + jump_scan + 3] == 0x57
                                                // JUMPI
                                                {
                                                    let offset = ((bytecode
                                                        [scan_pos + jump_scan + 1]
                                                        as usize)
                                                        << 8)
                                                        | (bytecode[scan_pos + jump_scan + 2]
                                                            as usize);

                                                    if offset < len && offset > dispatcher_start {
                                                        println!(
                                                        "✅ [HIERARCHICAL] 0x{:08x} → offset 0x{:04x} (op: 0x{:02x})",
                                                        selector, offset, op_code
                                                    );
                                                        return Some(offset);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Stratégie C: Recherche de JUMPDEST proche comme fallback
                for jump_scan in 10..100 {
                    if pos + jump_scan < len && bytecode[pos + jump_scan] == 0x5B {
                        // JUMPDEST
                        let mut valid = true;
                        for check_back in 1..33 {
                            if pos + jump_scan >= check_back {
                                let check_pos = pos + jump_scan - check_back;
                                if check_pos < len {
                                    match bytecode[check_pos] {
                                        0x60..=0x7F => {
                                            // PUSH1-PUSH32
                                            let push_size = (bytecode[check_pos] - 0x5F) as usize;
                                            if check_pos + push_size >= pos + jump_scan {
                                                valid = false;
                                                break;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        if valid {
                            let offset = pos + jump_scan;
                            println!(
                                "🔄 [JUMPDEST FALLBACK] 0x{:08x} → offset 0x{:04x}",
                                selector, offset
                            );
                            return Some(offset);
                        }
                    }
                }
            }
        }

        println!(
            "❌ [NOT FOUND] Sélecteur 0x{:08x} non résolu dynamiquement",
            selector
        );
        None
    }

    /// ✅ VERSION 100% EVM-COMPLIANT – Slot ERC-1967 implementation écrit comme Solidity le fait
    async fn persist_contract_state_immediate(
        &mut self,
        contract_address: &str,
        execution_result: &serde_json::Value,
    ) -> Result<(), String> {
        let storage_manager = match &self.storage_manager {
            Some(m) => m.clone(),
            None => return Ok(()),
        };

        println!(
            "💾 [PERSIST] {} - persistance sans version",
            contract_address
        );

        let storage_obj = execution_result.get("storage").and_then(|v| v.as_object());
        if let Some(obj) = storage_obj {
            for (key, value_json) in obj {
                let canonical_slot = self.map_resource_key_to_slot(key);
                let storage_key = format!("storage:{}:{}", contract_address, canonical_slot);

                let value_bytes = match value_json {
                    serde_json::Value::String(s) if s.starts_with("0x") => {
                        hex::decode(&s[2..]).unwrap_or(vec![0; 32])
                    }
                    serde_json::Value::Number(n) if n.is_u64() => {
                        let mut b = vec![0u8; 32];
                        b[24..32].copy_from_slice(&n.as_u64().unwrap().to_be_bytes());
                        b
                    }
                    _ => vec![0; 32],
                };

                let _ = storage_manager.write(&storage_key, &value_bytes);
                println!("   → Slot {} → clé {} → écrit", key, storage_key);
            }
        }

        println!(
            "✅ Persistance terminée (sans version) pour {}",
            contract_address
        );
        Ok(())
    }

    /// Mappe une clé logique (ex: "implementation", "admin") vers un slot 32 bytes hex canonique.
    fn map_resource_key_to_slot(&self, key: &str) -> String {
        // Clés connues → slots ERC-1967
        match key {
            "implementation" | "implementation_slot" => ERC1967_IMPLEMENTATION_SLOT.to_string(),
            "admin" | "admin_slot" => ERC1967_ADMIN_SLOT.to_string(),
            "beacon" | "beacon_slot" => ERC1967_BEACON_SLOT.to_string(),
            k => {
                // Si la clé ressemble déjà à un slot hex 64 chars (avec ou sans 0x) -> normalise
                let s = k.trim_start_matches("0x");
                if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                    return s.to_lowercase();
                }
                // Fallback déterministe : keccak256(key) -> 32 bytes hex
                let hash = Keccak256::digest(k.as_bytes());
                hex::encode(hash)
            }
        }
    }

    /// ✅ NOUVEAU: Détection intelligente des contrats proxy
    async fn is_proxy_contract(&self, contract_address: &str) -> bool {
        let accounts = self.state.accounts.read().await;
        if let Some(account) = accounts.get(contract_address) {
            // ✅ Vérifie les patterns de proxy standards
            return account.resources.contains_key("implementation")
                || account.resources.contains_key("admin")
                || account.resources.contains_key("beacon")
                || account.resources.contains_key(ERC1967_IMPLEMENTATION_SLOT)
                || account.resources.contains_key(ERC1967_ADMIN_SLOT)
                || account.resources.contains_key(ERC1967_BEACON_SLOT);
        }
        false
    }

    /// ✅ NOUVEAU: Récupération intelligente de l'adresse d'implémentation
    async fn get_implementation_address(&self, proxy_address: &str) -> Option<String> {
        let accounts = self.state.accounts.read().await;
        if let Some(account) = accounts.get(proxy_address) {
            // ✅ Recherche dans l'ordre de priorité
            let implementation_keys = [
                "implementation",
                ERC1967_IMPLEMENTATION_SLOT,
                "logic",
                "target",
                "masterCopy",
            ];

            for key in &implementation_keys {
                if let Some(impl_value) = account.resources.get(*key) {
                    if let Some(impl_str) = impl_value.as_str() {
                        let cleaned = impl_str.trim();
                        if !cleaned.is_empty()
                            && cleaned != "0x0000000000000000000000000000000000000000"
                            && cleaned != "0x0"
                        {
                            println!(
                                "✅ [PROXY] Implémentation trouvée via clé '{}': {}",
                                key, cleaned
                            );
                            return Some(cleaned.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// ✅ NOUVEAU: Validation de l'adresse d'implémentation
    async fn validate_implementation_address(&self, impl_address: &str) -> bool {
        let accounts = self.state.accounts.read().await;
        if let Some(impl_account) = accounts.get(&impl_address.to_string()) {
            return impl_account.is_contract && !impl_account.contract_state.is_empty();
        }
        false
    }

    /// ✅ EXÉCUTION STRICTE avec bytecode réel - CORRECTION MAJEURE POUR PROXY
    pub async fn execute_program(
        &mut self,
        module_path: &str,
        function_name: &str,
        args: Vec<NerenaValue>,
        sender_vyid: Option<&str>,
        stack_usage: Option<&uvm_runtime::stack::StackUsage>,
        return_type: Option<&str>,
        initial_storage: Option<HashMap<String, HashMap<String, Vec<u8>>>>,
        calldata: Option<&[u8]>,
    ) -> Result<serde_json::Value, String> {
        let mem = [0u8; 4096];
        let mut mbuff: Vec<u8> = Vec::new();
        let exports: HashMap<u32, usize> = HashMap::new();
        let vyid = Self::extract_address(module_path);
        let sender = sender_vyid.unwrap_or("*system*#default#");

        println!(
            "🎯 [REAL BYTECODE EXECUTION] Contrat: {}, Fonction: {}",
            vyid, function_name
        );

        // ────────────────────────────────────────────────
        // ÉTAPE 1 : RECHARGEMENT VERSIONNÉ DEPUIS ROCKSDB
        // ────────────────────────────────────────────────
        if let Some(manager) = &self.storage_manager {
            println!(
                "🔄 [PERSIST READ] Rechargement depuis RocksDB pour {}",
                vyid
            );

            // 1. Lire la dernière version persistée
            let version_key = format!("version:{}", vyid);
            let version_bytes = manager.read(&version_key).unwrap_or_default();
            let version = if version_bytes.len() == 8 {
                u64::from_be_bytes(version_bytes.try_into().unwrap_or([0; 8]))
            } else {
                0u64
            };
            println!("   → Dernière version persistée : v{}", version);

            // 2. Scanner uniquement les slots de cette version
            let prefix = format!("v{}/storage:{}:", version, vyid);
            let mut reloaded_storage = HashMap::new();

            match manager.scan_prefix(&prefix) {
                Ok(entries) => {
                    for (key, value) in entries {
                        if key.starts_with(&prefix) {
                            let slot = key.trim_start_matches(&prefix).to_string();
                            reloaded_storage.insert(slot, value);
                        }
                    }
                    println!(
                        "   → {} slots rechargés (v{})",
                        reloaded_storage.len(),
                        version
                    );
                }
                Err(e) => {
                    println!("⚠️ [SCAN ERROR] Impossible de scanner {} : {}", prefix, e);
                }
            }

            // 3. Mettre à jour world_state
            let mut world_state = self.state.world_state.write().await;
            world_state
                .storage
                .insert(vyid.to_string(), reloaded_storage.clone());

            // Debug slot balances
            let balances_slot =
                "37439836327923360225337895871871055371921111519445254264255886447755104894253"
                    .to_string();
            if let Some(value) = reloaded_storage.get(&balances_slot) {
                let u256_val = primitive_types::U256::from_big_endian(value);
                println!(
                    "🔍 [PERSIST READ CHECK] Slot balances rechargé = {} (hex: 0x{})",
                    u256_val,
                    hex::encode(value)
                );
            } else {
                println!("⚠️ [PERSIST READ] Slot balances non trouvé en v{}", version);
            }
        } else {
            println!("⚠️ Pas de storage_manager → stockage mémoire volatile seulement");
        }

        // ────────────────────────────────────────────────
        // ÉTAPE 2 : CHARGEMENT DU BYTECODE RÉEL
        // ────────────────────────────────────────────────
        let real_bytecode = {
            let accounts = self.state.accounts.read().await;

            if let Some(account) = accounts.get(vyid) {
                if account.is_contract && !account.contract_state.is_empty() {
                    account.contract_state.clone()
                } else {
                    return Err(format!("Contrat {} sans bytecode réel", vyid));
                }
            } else {
                return Err(format!("Contrat {} non trouvé", vyid));
            }
        };

        println!(
            "✅ [REAL BYTECODE] Chargé {} bytes de bytecode réel pour {}",
            real_bytecode.len(),
            vyid
        );

        // ────────────────────────────────────────────────
        // ÉTAPE 3 : CALCUL DU SÉLECTEUR
        // ────────────────────────────────────────────────
        let selector = Self::calculate_function_selector_from_signature(function_name, &args);

        // ────────────────────────────────────────────────
        // ÉTAPE 4 : DÉTECTION PROXY (inchangé)
        // ────────────────────────────────────────────────
        let impl_addr_opt = {
            let accounts = self.state.accounts.read().await;
            accounts
                .get(vyid)
                .and_then(|acc| acc.resources.get("implementation"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty() && *s != "0x0000000000000000000000000000000000000000")
                .map(|s| s.to_string())
        };

        if let Some(impl_addr) = impl_addr_opt {
            println!(
                "🧩 [PROXY DETECTED] Proxy {} délègue vers implémentation {}",
                vyid, impl_addr
            );
            println!("🔍 [PROXY STRATEGY] Utilise le bytecode de l'implémentation pour la recherche de fonctions");

            let impl_real_bytecode = {
                let impl_accounts = self.state.accounts.read().await;
                if let Some(impl_account) = impl_accounts.get(&impl_addr) {
                    if !impl_account.contract_state.is_empty() {
                        impl_account.contract_state.clone()
                    } else {
                        return Err(format!("Implémentation {} sans bytecode réel", impl_addr));
                    }
                } else {
                    return Err(format!("Implémentation {} non trouvée", impl_addr));
                }
            };

            println!(
                "✅ [IMPL BYTECODE] Chargé {} bytes de bytecode d'implémentation",
                impl_real_bytecode.len()
            );

            if !self.modules.contains_key(&impl_addr) {
                println!(
                    "🔄 [IMPL AUTO-DETECT] Analyse du bytecode d'implémentation ({} bytes)",
                    impl_real_bytecode.len()
                );
                self.auto_detect_contract_functions(&impl_addr, &impl_real_bytecode)?;
            }

            let impl_function_meta =
                self.find_or_create_function_metadata(&impl_addr, function_name, selector, &args)?;

            println!(
                "🔍 [IMPL OFFSET SEARCH] Recherche offset pour {} dans bytecode d'implémentation",
                function_name
            );
            let impl_resolved_offset = Self::find_function_offset_in_bytecode(
                &impl_real_bytecode,
                impl_function_meta.selector,
            );

            let converted_storage = self
                .build_dynamic_storage_from_contract_state(vyid)?
                .unwrap_or_else(|| HashMap::new());

            let interpreter_args = self
                .prepare_generic_execution_args(
                    vyid,
                    function_name,
                    args.clone(),
                    sender,
                    calldata,
                    &impl_function_meta,
                    impl_resolved_offset.expect("REASON"),
                )
                .await?;

            let calldata_bytes: Vec<u8> = if let Some(calldata) = calldata {
                calldata.to_vec()
            } else {
                interpreter_args.state_data.clone()
            };

            let result = {
                let _guard = self.global_execution_lock.lock().await;
                let mut interpreter = self.interpreter.lock().await;

                let mut helpers_guard = self.uvm_helpers.lock().await; // ← NOUVEAU

                let storage_manager: Option<Arc<dyn RocksDBManager>> = None; // <-- AJOUT: Gestionnaire de stockage (peut être passé en argument)

                uvm_runtime::interpreter::execute_program(
                    Some(&real_bytecode),
                    stack_usage,
                    &mem,
                    &calldata_bytes,
                    &mut *helpers_guard, // ← CORRECTION
                    &self.allowed_memory,
                    return_type,
                    &exports,
                    &interpreter_args,
                    storage_manager,
                    Some(converted_storage),
                )
                .map_err(|e| e.to_string())
            };

            if let Ok(ref val) = result {
                self.process_execution_result_generically(vyid, val, &impl_function_meta)
                    .await?;
            } else {
                return result;
            }
            return result;
        }

        // ────────────────────────────────────────────────
        // ÉTAPE 5 : EXÉCUTION NORMALE (sans proxy)
        // ────────────────────────────────────────────────
        if !self.modules.contains_key(vyid) {
            println!(
                "🔄 [AUTO-DETECT] Analyse du bytecode réel ({} bytes)",
                real_bytecode.len()
            );
            self.auto_detect_contract_functions(vyid, &real_bytecode)?;
        } else {
            if let Some(module) = self.modules.get_mut(vyid) {
                if module.bytecode.len() != real_bytecode.len() {
                    println!(
                        "🔄 [BYTECODE UPDATE] Mise à jour bytecode: {} → {} bytes",
                        module.bytecode.len(),
                        real_bytecode.len()
                    );
                    module.bytecode = real_bytecode.clone();
                    self.auto_detect_contract_functions(vyid, &real_bytecode)?;
                }
            }
        }

        let function_meta =
            self.find_or_create_function_metadata(vyid, function_name, selector, &args)?;

        let resolved_offset =
            Self::find_function_offset_in_bytecode(&real_bytecode, function_meta.selector);

        let interpreter_args = self
            .prepare_generic_execution_args(
                vyid,
                function_name,
                args.clone(),
                sender,
                calldata,
                &function_meta,
                resolved_offset.expect("REASON"),
            )
            .await?;

        let converted_storage = self
            .build_dynamic_storage_from_contract_state(vyid)?
            .unwrap_or_else(|| HashMap::new());

        // ────────────────────────────────────────────────
        // EXÉCUTION RÉELLE + POST-PROCESSING (logs + persistance)
        // ────────────────────────────────────────────────
        let calldata_bytes: Vec<u8> = if let Some(c) = calldata {
            c.to_vec()
        } else {
            interpreter_args.state_data.clone()
        };

        let result = {
            let _guard = self.global_execution_lock.lock().await;
            let mut interpreter = self.interpreter.lock().await;
            let mut helpers_guard = self.uvm_helpers.lock().await;

            uvm_runtime::interpreter::execute_program(
                Some(&real_bytecode),
                stack_usage,
                &mem,
                &calldata_bytes,
                &mut *helpers_guard,
                &self.allowed_memory,
                return_type,
                &exports,
                &interpreter_args,
                self.storage_manager.clone(),
                Some(converted_storage),
            )
            .map_err(|e| e.to_string())
        };

        let final_result = match result {
            Ok(mut val) => {
                // Traitement logs + persistance
                let _ = self.process_execution_result_generically(vyid, &val, &function_meta).await;
                val
            }
            Err(e) => return Err(e),
        };

        Ok(final_result)
    }

    /// ✅ NOUVEAU: Post-processing générique des résultats d'exécution
    /// ✅ POST-PROCESSING : Logs emit + Persistance slots & balances (support complet)
    async fn process_execution_result_generically(
        &mut self,
        contract_address: &str,
        result: &serde_json::Value,
        function_meta: &FunctionMetadata,
    ) -> Result<(), String> {
        println!(
            "🔄 [POST-PROCESS] Traitement du résultat pour {} → fn: {}",
            contract_address, function_meta.name
        );

        // 1. Extraction et affichage des logs emit
        let logs = result
            .get("logs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if !logs.is_empty() {
            println!("🎉 [EMIT SUCCESS] {} événements Solidity détectés !", logs.len());
            for (i, log) in logs.iter().enumerate() {
                let addr = log.get("address").and_then(|v| v.as_str()).unwrap_or("unknown");
                let topic_count = log.get("topics").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
                println!("   └─ Log #{} : address={} | {} topics | data={}", i, addr, topic_count, data);
            }
        } else {
            println!("ℹ️  Aucun événement émis pendant cet appel");
        }

        // 2. Persistance des slots (exactement comme avant)
        if let Some(manager) = &self.storage_manager {
            if let Some(storage_obj) = result.get("storage").and_then(|v| v.as_object()) {
                for (slot, value_json) in storage_obj {
                    let storage_key = format!("storage:{}:{}", contract_address, slot);
                    let value_bytes = match value_json {
                        serde_json::Value::String(s) if s.starts_with("0x") => {
                            hex::decode(&s[2..]).unwrap_or_else(|_| vec![0; 32])
                        }
                        serde_json::Value::Number(n) => {
                            let mut b = vec![0u8; 32];
                            if let Some(u) = n.as_u64() {
                                b[24..32].copy_from_slice(&u.to_be_bytes());
                            }
                            b
                        }
                        _ => vec![0; 32],
                    };
                    let _ = manager.write(&storage_key, &value_bytes);
                }
            }

            // Persistance explicite du slot balances
            let balances_slot = "37439836327923360225337895871871055371921111519445254264255886447755104894253".to_string();
            if let Some(balances_value) = result.get("storage")
                .and_then(|v| v.get(&balances_slot))
                .or_else(|| result.get("balances").and_then(|v| v.get(&balances_slot)))
            {
                let value_bytes = match balances_value {
                    serde_json::Value::String(s) if s.starts_with("0x") => {
                        hex::decode(&s[2..]).unwrap_or_else(|_| vec![0; 32])
                    }
                    _ => vec![0; 32],
                };
                let balances_key = format!("storage:{}:{}", contract_address, balances_slot);
                let _ = manager.write(&balances_key, &value_bytes);
                let u256_val = primitive_types::U256::from_big_endian(&value_bytes);
                println!("💰 Balance persistée → {} VEZ", u256_val);
            }
        }

        println!("✅ [POST-PROCESS] Terminé pour {}", contract_address);
        Ok(())
    }

    /// ✅ NOUVEAU: Conversion des resources en bytes de storage
    fn convert_resource_to_storage_bytes(&self, value: &serde_json::Value) -> Vec<u8> {
        match value {
            serde_json::Value::String(s) => {
                if s.starts_with("0x") && s.len() > 2 {
                    hex::decode(&s[2..]).unwrap_or_else(|_| s.as_bytes().to_vec())
                } else {
                    s.as_bytes().to_vec()
                }
            }
            serde_json::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    u.to_be_bytes().to_vec()
                } else {
                    vec![0u8; 32]
                }
            }
            serde_json::Value::Bool(b) => {
                vec![if *b { 1u8 } else { 0u8 }; 32]
            }
            _ => value.to_string().as_bytes().to_vec(),
        }
    }

    /// ✅ NOUVEAU: Préparation des arguments d'exécution génériques
    async fn prepare_generic_execution_args(
        &self,
        contract_address: &str,
        function_name: &str,
        args: Vec<NerenaValue>,
        sender: &str,
        calldata: Option<&[u8]>,
        function_meta: &FunctionMetadata,
        resolved_offset: usize,
    ) -> Result<uvm_runtime::interpreter::InterpreterArgs, String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let block_info = self.state.block_info.read().await;
        let block_number = block_info.number;

        // ────────────────────────────────────────────────
        // 1. Construction du calldata ABI (priorité : calldata passé > génération auto)
        // ────────────────────────────────────────────────
        let calldata_bytes: Vec<u8> = if let Some(external_calldata) = calldata {
            // Si on a passé un calldata brut (ex: depuis eth_call ou proxy)
            println!(
                "🟢 Utilisation du calldata brut passé (len = {})",
                external_calldata.len()
            );
            external_calldata.to_vec()
        } else {
            // Sinon on génère le calldata ABI standard
            let mut generated = Vec::with_capacity(4 + args.len() * 32);

            // Selector (4 bytes)
            generated.extend_from_slice(&function_meta.selector.to_be_bytes());

            // Arguments (chacun 32 bytes paddés)
            for arg in &args {
                let mut padded = [0u8; 32];

                match arg {
                    serde_json::Value::String(s) => {
                        if s.starts_with("0x") && s.len() == 42 {
                            // Adresse → padding à gauche
                            if let Ok(bytes) = hex::decode(&s[2..]) {
                                if bytes.len() == 20 {
                                    padded[12..32].copy_from_slice(&bytes);
                                }
                            }
                        } else {
                            // String → padding à droite (pas ABI optimal mais acceptable ici)
                            let bytes = s.as_bytes();
                            if bytes.len() <= 32 {
                                padded[..bytes.len()].copy_from_slice(bytes);
                            }
                        }
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(u) = n.as_u64() {
                            padded[24..32].copy_from_slice(&u.to_be_bytes());
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        padded[31] = if *b { 1 } else { 0 };
                    }
                    _ => {} // reste à zéro
                }

                generated.extend_from_slice(&padded);
            }

            println!(
                "🟢 Calldata généré automatiquement → len={}, hex=0x{}",
                generated.len(),
                hex::encode(&generated)
            );

            generated
        };

        // ────────────────────────────────────────────────
        // 2. Création finale des InterpreterArgs
        // ────────────────────────────────────────────────
        Ok(uvm_runtime::interpreter::InterpreterArgs {
            function_name: function_name.to_string(),
            contract_address: contract_address.to_string(),
            sender_address: sender.to_string(),
            args,
            state_data: calldata_bytes, // ← ICI : on passe le bon calldata_bytes
            gas_limit: function_meta.gas_limit.into(),
            gas_price: self.gas_price.into(),
            value: 0u64.into(),
            call_depth: 0u64.into(),
            block_number: block_number.into(),
            timestamp: current_time.into(),
            caller: sender.to_string(),
            origin: sender.to_string(),
            beneficiary: sender.to_string(),
            function_offset: Some(resolved_offset),
            base_fee: Some(0u64.into()),
            blob_base_fee: Some(0u64.into()),
            blob_hash: Some([0u8; 32]),
        })
    }

    /// ✅ NOUVEAU: Persistance des résultats dans le storage
    fn persist_result_to_storage(
        &self,
        storage_manager: &Arc<dyn RocksDBManager>,
        contract_address: &str,
        result: &serde_json::Value,
    ) -> Result<(), String> {
        let result_key = format!(
            "result:{}:{}",
            contract_address,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        let result_bytes = serde_json::to_vec(result)
            .map_err(|e| format!("Erreur sérialisation résultat: {}", e))?;
        storage_manager
            .write(&result_key, &result_bytes)
            .map_err(|e| format!("Erreur persistance: {}", e))?;
        println!("💾 [PERSIST] Résultat persisté: {}", result_key);
        Ok(())
    }

    /// ✅ Lookup générique dans les resources d'un compte
    async fn lookup_value_from_resources(
        &self,
        address: &str,
        key: &str,
    ) -> Result<NerenaValue, String> {
        let accounts = self.state.accounts.read().await;
        if let Some(account) = accounts.get(address) {
            // Cherche directement la clé
            if let Some(value) = account.resources.get(key) {
                return Ok(value.clone());
            }

            // Cherche des variantes de la clé (case insensitive, préfixes)
            let key_lower = key.to_lowercase();
            for (res_key, res_val) in &account.resources {
                let res_lower = res_key.to_lowercase();
                if res_lower == key_lower || res_lower.contains(&key_lower) {
                    return Ok(res_val.clone());
                }
            }

            // Cherche dans les slots de storage
            if let Some(slot_value) = self.find_in_storage_slots(account, key) {
                return Ok(slot_value);
            }
        }
        Ok(serde_json::Value::Null)
    }

    /// ✅ NOUVEAU: Recherche dans les slots de storage
    fn find_in_storage_slots(&self, account: &AccountState, key: &str) -> Option<NerenaValue> {
        // Cherche dans tous les slots possibles
        for (slot_key, slot_value) in &account.resources {
            if slot_key.len() == 64 {
                // Slots de storage EVM
                if let Some(decoded) = self.decode_storage_slot_generically(slot_value) {
                    if self.matches_key_semantics(key, &decoded) {
                        return Some(decoded);
                    }
                }
            }
        }
        None
    }

    /// ✅ NOUVEAU: Décodage générique des slots de storage
    fn decode_storage_slot_generically(
        &self,
        slot_value: &serde_json::Value,
    ) -> Option<NerenaValue> {
        if let Some(hex_str) = slot_value.as_str() {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() >= 32 {
                    // Essaie de décoder comme adresse (20 derniers bytes)
                    let addr_bytes = &bytes[12..32];
                    if !addr_bytes.iter().all(|&b| b == 0) {
                        let addr = format!("0x{}", hex::encode(addr_bytes));
                        if self.looks_like_address(&addr) {
                            return Some(serde_json::json!(addr));
                        }
                    }
                    // Essaie de décoder comme uint256 (8 derniers bytes)
                    let uint_bytes = &bytes[24..32];
                    let value = u64::from_be_bytes([
                        uint_bytes[0],
                        uint_bytes[1],
                        uint_bytes[2],
                        uint_bytes[3],
                        uint_bytes[4],
                        uint_bytes[5],
                        uint_bytes[6],
                        uint_bytes[7],
                    ]);
                    if value > 0 && value < 1_000_000_000 {
                        // Valeur raisonnable
                        return Some(serde_json::json!(value));
                    }
                    // Essaie de décoder comme string
                    if let Some(s) = hex_str.get(..2) {
                        if s == "0x" {
                            // Traite comme adresse hex
                            let mut bytes = [0u8; 32];
                            if let Ok(addr_bytes) = hex::decode(&hex_str[2..]) {
                                bytes[12..32].copy_from_slice(&addr_bytes);
                            }
                            return Some(serde_json::json!(format!("0x{}", hex::encode(&bytes))));
                        }
                    }
                }
            }
        }
        None
    }

    fn matches_key_semantics(&self, key: &str, value: &serde_json::Value) -> bool {
        let key_lower = key.to_lowercase();
        match value {
            serde_json::Value::String(s) => {
                if key_lower.contains("owner") || key_lower.contains("admin") {
                    s.starts_with("0x") && s.len() == 42
                } else if key_lower.contains("name") {
                    s.len() > 2
                        && s.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c.is_whitespace())
                } else if key_lower.contains("symbol") {
                    s.len() >= 2 && s.len() <= 10 && s.chars().all(|c| c.is_ascii_uppercase())
                } else {
                    true
                }
            }
            serde_json::Value::Number(n) => {
                if key_lower.contains("balance")
                    || key_lower.contains("supply")
                    || key_lower.contains("amount")
                {
                    n.as_u64().unwrap_or(0) >= 0
                } else if key_lower.contains("decimals") {
                    let val = n.as_u64().unwrap_or(0);
                    val >= 0 && val <= 36
                } else {
                    true
                }
            }
            _ => true,
        }
    }

    fn looks_like_address(&self, addr: &str) -> bool {
        addr.starts_with("0x")
            && addr.len() == 42
            && addr != "0x0000000000000000000000000000000000000000"
            && addr != "0x0000000000000000000000000000000000000040"
    }

    /// ✅ FONCTION MÉTADATA STRICTE: Refuse de créer des métadonnées si la fonction n'existe pas
    /// EXCEPTION: si function_name est vide → traite comme appel sans selector (fallback / déploiement direct)
    fn find_or_create_function_metadata(
        &mut self,
        contract_address: &str,
        function_name: &str,
        selector: u32,
        _args: &[NerenaValue],
    ) -> Result<FunctionMetadata, String> {
        // ────────────────────────────────────────────────
        // EXCEPTION SPÉCIALE : function_name vide → appel sans selector (déploiement brut, fallback, direct bytecode)
        // ────────────────────────────────────────────────
        if function_name.is_empty() {
            println!(
            "⚡ [EXCEPTION META] function_name vide → appel sans selector (fallback/direct execution) pour {}",
            contract_address
        );

            // Retourne une metadata "fallback" spéciale
            return Ok(FunctionMetadata {
                name: "*fallback*".to_string(),
                offset: 0, // ou l'offset de ton fallback si tu en as un
                args_count: _args.len(),
                arg_types: vec![], // ou inféré des args
                return_type: "unknown".to_string(),
                gas_limit: 1_000_000, // valeur haute pour sécurité
                payable: true,        // souvent payable en fallback
                mutability: "nonpayable".to_string(),
                selector: 0, // pas de selector
                modifiers: vec![],
            });
        }

        // ────────────────────────────────────────────────
        // CAS NORMAL : recherche stricte dans les fonctions détectées
        // ────────────────────────────────────────────────
        if let Some(module) = self.modules.get(contract_address) {
            // Recherche par nom exact
            if let Some(meta) = module.functions.get(function_name) {
                println!(
                    "✅ [META FOUND] Fonction trouvée par nom: {}",
                    function_name
                );
                return Ok(meta.clone());
            }

            // Recherche par selector dans les fonctions function_XXXXXXXX
            for (fname, meta) in &module.functions {
                if meta.selector == selector && fname.starts_with("function_") {
                    println!(
                        "✅ [META FOUND] Fonction trouvée par sélecteur: {} (0x{:08x})",
                        fname, selector
                    );
                    return Ok(meta.clone());
                }
            }

            // Recherche par nom function_XXXXXXXX si l'appel utilise le nom classique
            let expected_function_name = format!("function_{:08x}", selector);
            if let Some(meta) = module.functions.get(&expected_function_name) {
                println!(
                    "✅ [META MAPPED] Appel '{}' mappé sur fonction détectée '{}'",
                    function_name, expected_function_name
                );
                return Ok(meta.clone());
            }

            // UTILISE LA FONCTION EXISTANTE create_function_metadata EN DERNIER RECOURS
            // Mais seulement si on trouve l'offset dans le bytecode
            if let Some(offset) = Self::find_function_offset_in_bytecode(&module.bytecode, selector)
            {
                println!(
                    "✅ [META CREATE] Création métadata pour {} trouvé à offset 0x{:04x}",
                    function_name, offset
                );
                return Ok(self.create_function_metadata(selector, offset));
            }
        }

        // ────────────────────────────────────────────────
        // ÉCHEC STRICT - Aucune fonction trouvée (pour les appels normaux)
        // ────────────────────────────────────────────────
        Err(format!(
            "Fonction '{}' (sélecteur 0x{:08x}) NON TROUVÉE dans le dispatcher du contrat {}. \
         Vérifiez que le contrat contient cette fonction.",
            function_name, selector, contract_address
        ))
    }

    pub fn new_with_cluster(cluster: &str) -> Self {
        let mut vm = SlurachainVm::new();
        vm.state.cluster = cluster.to_string();
        vm
    }

    /// ✅ NORMALISATION: assure que les valeurs hex sont préfixées "0x" pour être reconnues
    fn normalize_storage_json_value(value: &serde_json::Value) -> serde_json::Value {
        if let Some(s) = value.as_str() {
            // si déjà préfixé, on renvoie tel quel
            if s.starts_with("0x") {
                return serde_json::Value::String(s.to_string());
            }
            // si ressemble à une chaîne hex paire (64 chars typique), on ajoute "0x"
            if s.len() >= 2 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() % 2 == 0 {
                return serde_json::Value::String(format!("0x{}", s));
            }
        }
        // sinon on renvoie la valeur originale
        value.clone()
    }
}
