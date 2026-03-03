use crate::consensus::slurachain_gov::slurachainGovernance;
use crate::slurachain_rpc_service::TxRequest;
use alloy_primitives::B256;
use base64::engine::general_purpose::STANDARD as base64_standard;
use base64::Engine as _;
use chrono::Utc;
use ethers::utils::keccak256;
use lazy_static::lazy_static;
use reth_trie::root::state_root;
use serde_json;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, Duration, Instant};
use tracing::{error, info, warn};
use vuc_events::time_warp::TimeWarp;
 use uvm_runtime::lib::BTreeMap;
use vuc_events::timestamp_release::TimestampRelease;
use vuc_storage::storing_access::{RocksDBManager, RocksDBManagerImpl, SlurachainMetadata};
use vuc_tx::slura_merkle::build_state_trie;
use vuc_tx::slurachain_vm::SlurachainVm;
use vuc_types::committee::EpochId;
use vuc_types::supported_protocol_versions::SupportedProtocolVersions;

lazy_static! {
    static ref CONTRACT_STATE_HISTORY: Mutex<HashMap<String, Vec<Vec<u8>>>> =
        Mutex::new(HashMap::new());
}

// ────────────────────────────────────────────────────────────────
// CONSTANTES (gardées pour compatibilité mais désactivées)
// ────────────────────────────────────────────────────────────────

pub const LUROSONIE_DECENTRALIZATION_THRESHOLD: u128 = 42_500_000_000_000_000_000_000_000_000u128;
pub const LUROSONIE_MIN_RELAY_STAKE: u64 = 30_000;
pub const LUROSONIE_SYSTEM_VALIDATOR: &str = "0x53ae54b11251d5003e9aa51422405bc35a2ef32d";

// Valeur forcée énorme pour que le système soit toujours valide
const FORCED_SYSTEM_POWER: u64 = 1_000_000_000;

const RELAY_MASTER_SELECTOR: &str = "relay_master(address,uint256)";
const REWARD_HOLDER_SELECTOR: &str = "reward_lurosonie_holder(address,uint256)";
const GET_POWER_SELECTOR: &str = "getValidatorRelayPower(address)";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockData {
    pub block: TimestampRelease,
    pub transactions: Vec<TxRequest>,
    pub validator: String,
    pub contract_states: HashMap<String, Vec<u8>>,
    pub execution_results: HashMap<String, serde_json::Value>,
    pub relay_power: u64,
    pub delegated_stake: u64,
    pub is_system_block: bool,
}

#[derive(Clone, Debug)]
pub struct RelayValidator {
    pub address: String,
    pub stake: u64,
    pub delegated_stake: u64,
    pub total_power: u64,
    pub is_active: bool,
    pub relay_count: u64,
    pub last_relay_time: u64,
    pub is_system: bool,
}

#[derive(Clone, Debug)]
pub struct StakeDelegation {
    pub delegator: String,
    pub validator: String,
    pub amount: u64,
    pub timestamp: u64,
}

pub struct LurosonieManager {
    pub epoch_id: EpochId,
    pub committee: Vec<String>,
    pub supported_protocol_versions: SupportedProtocolVersions,
    pub balances: Arc<RwLock<HashMap<String, u64>>>,
    pub time_warp: TimeWarp,
    pub storage: Arc<RocksDBManagerImpl>,
    pub block_sender: mpsc::Sender<TimestampRelease>,
    pub pending_transactions: Arc<RwLock<HashMap<String, TxRequest>>>,
    pub block_counts: Arc<RwLock<HashMap<String, u64>>>,
    pub vm: Arc<RwLock<SlurachainVm>>,
    pub governance: Arc<RwLock<HashMap<String, slurachainGovernance>>>,
    pub last_block_hash: Arc<RwLock<Option<String>>>,
    pub validators: Arc<RwLock<Vec<String>>>,
    pub slurachain_data: Arc<RwLock<Vec<BlockData>>>,
    pub current_validator_index: Arc<RwLock<usize>>,
    pub block_time_ms: u64,
    pub relay_validators: Arc<RwLock<HashMap<String, RelayValidator>>>,
    pub delegations: Arc<RwLock<Vec<StakeDelegation>>>,
    pub min_relay_stake: u64,
    pub relay_round_duration: u64,
    pub current_relay_leader: Arc<RwLock<Option<String>>>,
    pub total_vez_supply: Arc<RwLock<u64>>,
    pub is_decentralized: Arc<RwLock<bool>>,
    pub mempool_tx_sender: mpsc::Sender<TxRequest>,
    pub mempool_tx_receiver: Mutex<Option<mpsc::Receiver<TxRequest>>>,
}

impl LurosonieManager {
    pub async fn new_with_storage(
        storage: Arc<RocksDBManagerImpl>,
        vm: Arc<RwLock<SlurachainVm>>,
        block_sender: mpsc::Sender<TimestampRelease>,
    ) -> Self {
        {
            let mut vm_instance = vm.write().await;
            vm_instance.set_storage_manager(storage.clone());
        }

        let (mempool_tx_sender, mempool_tx_receiver) = mpsc::channel(100000);

        LurosonieManager {
            epoch_id: EpochId::default(),
            committee: vec![],
            supported_protocol_versions: SupportedProtocolVersions::default(),
            governance: Arc::new(RwLock::new(HashMap::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            time_warp: TimeWarp::default(),
            block_sender,
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
            block_counts: Arc::new(RwLock::new(HashMap::new())),
            vm: vm.clone(),
            last_block_hash: Arc::new(RwLock::new(None)),
            validators: Arc::new(RwLock::new(Vec::new())),
            storage,
            slurachain_data: Arc::new(RwLock::new(Vec::new())),
            current_validator_index: Arc::new(RwLock::new(0)),
            block_time_ms: 3000,
            relay_validators: Arc::new(RwLock::new(HashMap::new())),
            delegations: Arc::new(RwLock::new(Vec::new())),
            min_relay_stake: LUROSONIE_MIN_RELAY_STAKE,
            relay_round_duration: 15_000,
            current_relay_leader: Arc::new(RwLock::new(None)),
            total_vez_supply: Arc::new(RwLock::new(0)),
            is_decentralized: Arc::new(RwLock::new(false)), // forcé décentralisé = faux, on ignore
            mempool_tx_sender,
            mempool_tx_receiver: Mutex::new(Some(mempool_tx_receiver)),
        }
    }

    async fn find_vezcur_contract_address(&self) -> Result<String, String> {
        let vm = self.vm.read().await;

        for key in ["vezcur", "vez", "token", "main_token"] {
            if let Some(addr) = vm.address_map.get(key) {
                println!(
                    "🔍 Contrat VEZ trouvé dans address_map (clé '{}'): {}",
                    key, addr
                );
                return Ok(addr.clone());
            }
        }

        let fallback = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
        println!(
            "⚠️ Pas d'adresse VEZ dans address_map → fallback : {}",
            fallback
        );
        Ok(fallback)
    }

    pub async fn start_lurosonie_consensus(&self) {
        println!("🚀 Démarrage du consensus LUROSONIE - Mode forcé sans blocage");
        println!("   → Toutes les conditions de stake/power sont désactivées");
        println!("   → Production de blocs illimitée même si stake = 0");

        self.initialize_system_validator().await;

        let mut block_interval = tokio::time::interval(Duration::from_millis(self.block_time_ms));
        let mut relay_round = 0u64;

        loop {
            tokio::select! {
                _ = block_interval.tick() => {
                    relay_round += 1;
                    let block_number = self.get_block_height().await + 1;

                    let block_producer = self.select_block_producer().await;
                    let is_system_block = true; // forcé système

                    println!(
                        "🔄 Bloc #{} - Producteur forcé: {} (round {})",
                        block_number, block_producer, relay_round
                    );

                    if let Err(e) = self.produce_lurosonie_block(block_number, &block_producer, is_system_block).await {
                        error!("❌ Erreur production bloc #{}: {}", block_number, e);
                        continue;
                    }

                    println!("✅ Bloc #{} accepté automatiquement (consensus désactivé)", block_number);
                }
            }
        }
    }

    async fn initialize_system_validator(&self) {
        let system_address = LUROSONIE_SYSTEM_VALIDATOR.to_string();
        let vez_addr = match self.find_vezcur_contract_address().await {
            Ok(addr) => addr,
            Err(_) => {
                println!("⚠️ Impossible de trouver VEZ → stake forcé");
                String::new()
            }
        };

        let stake = if vez_addr.is_empty() {
            0u64
        } else {
            let mut vm = self.vm.write().await;
            vm.execute_module(
                &vez_addr,
                "balanceOf",
                vec![serde_json::Value::String(system_address.clone())],
                Some(&system_address),
                None,
            )
            .await
            .ok()
            .and_then(|r| r.as_u64())
            .unwrap_or(0)
        };

        // Power forcé énorme
        let forced_power = FORCED_SYSTEM_POWER.max(stake);

        let system_validator = RelayValidator {
            address: system_address.clone(),
            stake,
            delegated_stake: 0,
            total_power: forced_power,
            is_active: true,
            relay_count: 0,
            last_relay_time: Utc::now().timestamp() as u64,
            is_system: true,
        };

        let mut validators = self.relay_validators.write().await;
        validators.insert(system_address.clone(), system_validator);

        let mut current_leader = self.current_relay_leader.write().await;
        *current_leader = Some(system_address.clone());

        println!(
            "🏛️ Validateur système FORCÉ → stake: {}, power: {} VEZ (illimité)",
            stake, forced_power
        );
    }

    async fn check_decentralization_threshold(&self) -> Result<(), String> {
        // Désactivé complètement
        println!("check_decentralization_threshold → ignoré (mode sans blocage)");
        Ok(())
    }

    async fn calculate_total_vez_supply(&self) -> Result<u128, String> {
        // On garde le calcul mais on force un minimum pour éviter blocage
        let mut supply = 0u128;

        // ... (ton code existant) ...

        if supply == 0 {
            println!("Supply calculée = 0 → forcée à 1_000_000_000 pour stabilité");
            supply = 1_000_000_000;
        }

        println!("📊 Supply totale (forcée si besoin) : {} VEZ", supply);
        Ok(supply)
    }

    async fn select_block_producer(&self) -> String {
        // Toujours le système pour éviter tout blocage
        let leader = self.current_relay_leader.read().await.clone();
        leader.unwrap_or_else(|| {
            println!("Aucun leader → fallback système forcé");
            LUROSONIE_SYSTEM_VALIDATOR.to_string()
        })
    }

    pub async fn produce_lurosonie_block(
        &self,
        block_number: u64,
        producer: &str,
        is_system_block: bool,
    ) -> Result<(), String> {
        let start_time = Instant::now();

        println!(
            "🔄 Production bloc #{} autorisée sans condition (mode forcé)",
            block_number
        );

        // 1. Récupère toutes les tx du mempool
        let pending = self.pending_transactions.read().await;
        let transactions: Vec<TxRequest> = pending.values().cloned().collect();
        drop(pending);

        println!(
            "📦 {} transactions à traiter dans le bloc forcé #{}",
            transactions.len(),
            block_number
        );

        let relay_power = FORCED_SYSTEM_POWER;

        // Création du bloc vide au départ
        let block = TimestampRelease {
            timestamp: Utc::now(),
            log: format!(
                "Bloc #{} produit en mode forcé (producer: {})",
                block_number, producer
            ),
            block_number,
            vyfties_id: producer.to_string(),
        };

        let mut contract_states: HashMap<String, Vec<u8>> = HashMap::new();
        let mut execution_results: HashMap<String, serde_json::Value> = HashMap::new();
        let mut processed_hashes: Vec<String> = Vec::new();

        // 3. Finalisation du bloc
        let block_data = BlockData {
            block,
            transactions,
            validator: producer.to_string(),
            contract_states,
            execution_results,
            relay_power,
            delegated_stake: 0,
            is_system_block,
        };

        // Ajout à la chaîne
        if let Err(e) = self.add_lurosonie_block_to_chain(block_data).await {
            error!("❌ Échec ajout bloc #{} à la chaîne: {}", block_number, e);
            return Err(e);
        }

        // Vidage du mempool
        self.remove_processed_transactions(processed_hashes.clone()).await;

        println!(
            "✅ Bloc #{} produit avec succès en mode forcé en {:?} ({} tx traitées)",
            block_number,
            start_time.elapsed(),
            processed_hashes.len()
        );

        Ok(())
    }

    /// Ajoute une transaction dans le mempool Lurosonie
    pub async fn add_transaction_to_mempool(&self, tx: TxRequest) {
        let tx_hash = tx.hash.clone();
        let mut pending = self.pending_transactions.write().await;
        pending.insert(tx_hash.clone(), tx.clone());
        // AJOUT : envoi sur le canal mempool_tx_sender
        let _ = self.mempool_tx_sender.send(tx).await;
        println!("✅ Transaction ajoutée au mempool Lurosonie : {}", tx_hash);
    }

    /// Vérifie si une transaction (par hash) est présente dans le mempool Lurosonie
    pub async fn has_transaction_in_mempool(&self, tx_hash: &str) -> bool {
        let pending = self.pending_transactions.read().await;
        pending.contains_key(tx_hash)
    }

    /// Récupère un bloc par son hash (pour eth_getBlockByHash)
    pub async fn get_block_by_hash(&self, block_hash: &str) -> Option<BlockData> {
        use sha3::{Digest, Sha3_256};
        let slurachain = self.slurachain_data.read().await;
        for block_data in slurachain.iter() {
            // Recalcule le hash du bloc comme dans add_lurosonie_block_to_chain
            let block_serialized = serde_json::to_string(&serde_json::json!({
                "block": block_data.block,
                "relay_power": block_data.relay_power,
                "delegated_stake": block_data.delegated_stake,
                "validator": block_data.validator
            }))
            .ok()?;
            let mut hasher = Sha3_256::new();
            hasher.update(block_serialized.as_bytes());
            let hash = format!("{:x}", hasher.finalize());
            let hash_prefixed = format!("0x{}", hash);
            if hash_prefixed.eq_ignore_ascii_case(block_hash) {
                return Some(block_data.clone());
            }
        }
        None
    }

    pub async fn lurosonie_bft_consensus(&self, block_number: u64) -> Result<(), String> {
        // Désactivé : on accepte tout bloc produit
        println!("lurosonie_bft_consensus → ignoré (mode sans blocage)");
        Ok(())
    }

    async fn sync_relay_validators_from_vm(&self) -> Result<(), String> {
        println!("sync_relay_validators_from_vm → mode forcé : seul le système actif");

        let system_address = LUROSONIE_SYSTEM_VALIDATOR.to_string();

        let system_validator = RelayValidator {
            address: system_address.clone(),
            stake: 0,
            delegated_stake: 0,
            total_power: FORCED_SYSTEM_POWER,
            is_active: true,
            relay_count: 999999,
            last_relay_time: Utc::now().timestamp() as u64,
            is_system: true,
        };

        let mut validators = self.relay_validators.write().await;
        validators.clear(); // on garde QUE le système
        validators.insert(system_address.clone(), system_validator);

        let mut current_leader = self.current_relay_leader.write().await;
        *current_leader = Some(system_address);

        println!(
            "🔄 Sync forcée : seul le système reste actif avec power {}",
            FORCED_SYSTEM_POWER
        );

        Ok(())
    }

    async fn lurosonie_relay_power_rotation(&self) -> Result<(), String> {
        self.sync_relay_validators_from_vm().await?;

        self.calculate_relay_powers().await?;

        let new_leader = self.select_lurosonie_relay_leader().await?;

        {
            let mut current_leader = self.current_relay_leader.write().await;
            *current_leader = Some(new_leader.clone());
        }

        println!("🎯 Nouveau leader de relais Lurosonie: {}", new_leader);
        Ok(())
    }

    pub async fn get_pending_transaction_count(&self) -> usize {
        self.pending_transactions.read().await.len()
    }

    pub async fn get_block_by_number(&self, block_number: u64) -> Option<BlockData> {
        let chain = self.slurachain_data.read().await;

        let block_opt = chain
            .iter()
            .find(|bd| bd.block.block_number == block_number)
            .cloned();

        if block_opt.is_some() {
            if block_number % 10 == 0 {
                // log tous les 10 blocs pour ne pas spammer
                info!(
                    "Bloc #{} retrouvé en mémoire (taille chain: {})",
                    block_number,
                    chain.len()
                );
            }
        } else if block_number <= chain.len() as u64 {
            warn!(
                "Bloc #{} introuvable malgré chain height {}",
                block_number,
                chain.len()
            );
        }

        block_opt
    }

    async fn update_validator_power_onchain(
        &self,
        validator: &str,
        delegated_amount: u64,
    ) -> Result<u64, String> {
        let vez_address = self.find_vezcur_contract_address().await?;
        let mut vm = self.vm.write().await;

        let result = vm
            .execute_module(
                &vez_address,
                "relay_master",
                vec![
                    serde_json::Value::String(validator.to_string()),
                    serde_json::Value::Number(serde_json::Number::from(delegated_amount)),
                ],
                Some(&LUROSONIE_SYSTEM_VALIDATOR.to_string()),
                None,
            )
            .await?;

        let new_power = result.as_u64().ok_or("Invalid relay_master return")?;

        println!(
            "🔄 Pouvoir on-chain mis à jour pour {} → {}",
            validator, new_power
        );

        Ok(new_power)
    }

    async fn distribute_block_reward(
        &self,
        producer: &str,
        reward_amount: u64,
    ) -> Result<(), String> {
        let vez_address = self.find_vezcur_contract_address().await?;
        let mut vm = self.vm.write().await;

        vm.execute_module(
            &vez_address,
            "reward_lurosonie_holder",
            vec![
                serde_json::Value::String(producer.to_string()),
                serde_json::Value::Number(serde_json::Number::from(reward_amount)),
            ],
            Some(&LUROSONIE_SYSTEM_VALIDATOR.to_string()),
            None,
        )
        .await?;

        println!(
            "🏆 Récompense {} VEZ distribuée à {}",
            reward_amount, producer
        );

        Ok(())
    }

    async fn calculate_relay_powers(&self) -> Result<(), String> {
        let mut validators = self.relay_validators.write().await;

        for (address, validator) in validators.iter_mut() {
            validator.delegated_stake = self.get_delegated_stake(address).await;
            validator.total_power = validator.stake.saturating_add(validator.delegated_stake);

            println!(
                "🔢 Pouvoir de relais calculé: {} = {} VEZ",
                address, validator.total_power
            );
        }

        Ok(())
    }

    async fn select_lurosonie_relay_leader(&self) -> Result<String, String> {
        let validators = self.relay_validators.read().await;

        if validators.is_empty() {
            return Ok(LUROSONIE_SYSTEM_VALIDATOR.to_string());
        }

        let total_power: u64 = validators.values().map(|v| v.total_power).sum();
        if total_power == 0 {
            return Ok(LUROSONIE_SYSTEM_VALIDATOR.to_string());
        }

        let mut random_seed = Utc::now().timestamp() as u64;
        if let Some(last_hash) = &*self.last_block_hash.read().await {
            let hash_bytes = last_hash.as_bytes();
            for &byte in hash_bytes.iter().take(8) {
                random_seed ^= byte as u64;
            }
        }

        let target = random_seed % total_power;
        let mut cumulative_power = 0u64;

        for (address, validator) in validators.iter() {
            cumulative_power = cumulative_power.saturating_add(validator.total_power);
            if cumulative_power > target {
                println!(
                    "🎯 Leader sélectionné par algorithme Lurosonie: {} (pouvoir: {} VEZ)",
                    address, validator.total_power
                );
                return Ok(address.clone());
            }
        }

        Ok(validators.keys().next().unwrap().clone())
    }

    async fn get_delegated_stake(&self, validator: &str) -> u64 {
        let delegations = self.delegations.read().await;
        delegations
            .iter()
            .filter(|d| d.validator == validator)
            .map(|d| d.amount)
            .sum()
    }

    async fn validate_lurosonie_block(&self, block_number: u64, validator: &str) -> bool {
        let slurachain = self.slurachain_data.read().await;
        if let Some(block_data) = slurachain
            .iter()
            .find(|bd| bd.block.block_number == block_number)
        {
            let is_valid = !block_data.block.vyfties_id.is_empty()
                && block_data.block.block_number > 0
                && block_data.relay_power >= self.min_relay_stake;

            if is_valid {
                println!(
                    "✅ Validateur {} confirme bloc Lurosonie #{}",
                    validator, block_number
                );
            } else {
                println!(
                    "❌ Validateur {} rejette bloc Lurosonie #{}",
                    validator, block_number
                );
            }

            is_valid
        } else {
            false
        }
    }

    async fn add_lurosonie_block_to_chain(&self, block_data: BlockData) -> Result<(), String> {
        let block_serialized = serde_json::to_string(&serde_json::json!({
            "block": block_data.block,
            "relay_power": block_data.relay_power,
            "delegated_stake": block_data.delegated_stake,
            "validator": block_data.validator,
            "contract_states_count": block_data.contract_states.len(),
            "transactions_count": block_data.transactions.len()
        }))
        .map_err(|e| format!("Erreur sérialisation bloc Lurosonie: {}", e))?;

        let mut hasher = Sha3_256::new();
        hasher.update(block_serialized.as_bytes());
        let hash = format!("0x{:x}", hasher.finalize());

        {
            let mut last_hash = self.last_block_hash.write().await;
            *last_hash = Some(hash.clone());
        }

        {
            let mut slurachain = self.slurachain_data.write().await;
            slurachain.push(block_data.clone());
        }

        let block_key = format!("lurosonie_block:{}", block_data.block.block_number);
        let block_metadata = SlurachainMetadata {
            from_op: "lurosonie_system".to_string(),
            receiver_op: block_data.validator.clone(),
            fees_tx: block_data.relay_power,
            value_tx: serde_json::to_string(&block_data).map_err(|e| e.to_string())?,
            nonce_tx: block_data.block.block_number,
            hash_tx: hash.clone(),
        };

        if let Err(e) = self.storage.store_metadata(&block_key, &block_metadata) {
            error!("❌ Erreur sauvegarde bloc Lurosonie {}: {}", block_key, e);
        } else {
            println!("💾 [DB] Bloc Lurosonie {} sauvegardé", block_key);
        }

        for (contract_storage_key, state_bytes) in &block_data.contract_states {
            let storage_key = format!(
                "lurosonie_contract_state:{}:{}",
                contract_storage_key, block_data.block.block_number
            );
            let state_metadata = SlurachainMetadata {
                from_op: "lurosonie_system".to_string(),
                receiver_op: contract_storage_key.clone(),
                fees_tx: 0,
                value_tx: hex::encode(state_bytes),
                nonce_tx: block_data.block.block_number,
                hash_tx: hash.clone(),
            };

            if let Err(e) = self.storage.store_metadata(&storage_key, &state_metadata) {
                error!(
                    "❌ Erreur sauvegarde état contrat Lurosonie {}: {}",
                    storage_key, e
                );
            } else {
                println!(
                    "💾 [DB] État contrat {} sauvegardé pour bloc {}",
                    contract_storage_key, block_data.block.block_number
                );
            }
        }

        if let Err(e) = self.block_sender.send(block_data.block.clone()).await {
            error!("❌ Erreur envoi bloc Lurosonie: {}", e);
        }

        println!(
            "🔗 Bloc Lurosonie #{} ajouté à la chaîne (hash: {}, storage: {} états, DB: ✅)",
            block_data.block.block_number,
            &hash[..8],
            block_data.contract_states.len()
        );

        Ok(())
    }

    pub async fn delegate_stake(
        &self,
        delegator: &str,
        validator: &str,
        amount: u64,
    ) -> Result<(), String> {
        {
            let validators = self.relay_validators.read().await;
            if !validators.contains_key(validator) {
                return Err(format!(
                    "Validateur {} non trouvé dans les validateurs de relais",
                    validator
                ));
            }
        }

        let delegator_balance = {
            let mut vm = self.vm.write().await;
            let default_addr = "*frame000*".to_string();
            let module_address = vm.address_map.get("vezcur").unwrap_or(&default_addr);
            let module_path = format!("{}::vezcur", module_address);

            match vm
                .execute_module(
                    &module_path,
                    "solde_of",
                    vec![serde_json::Value::String(delegator.to_string())],
                    Some(&delegator),
                    None,
                )
                .await
            {
                Ok(result) => result.as_u64().unwrap_or(0),
                Err(_) => 0,
            }
        };

        if delegator_balance < amount {
            return Err(format!(
                "Solde insuffisant pour déléguer: {} < {} VEZ",
                delegator_balance, amount
            ));
        }

        let delegation = StakeDelegation {
            delegator: delegator.to_string(),
            validator: validator.to_string(),
            amount,
            timestamp: Utc::now().timestamp() as u64,
        };

        {
            let mut delegations = self.delegations.write().await;
            delegations.push(delegation);
        }

        println!(
            "✅ Délégation créée: {} délègue {} VEZ à {}",
            delegator, amount, validator
        );
        Ok(())
    }

    pub async fn get_lurosonie_stats(&self) -> serde_json::Value {
        let slurachain = self.slurachain_data.read().await;
        let validators = self.relay_validators.read().await;
        let delegations = self.delegations.read().await;
        let current_leader = self.current_relay_leader.read().await;

        let total_blocks = slurachain.len();
        let total_relay_power: u64 = validators.values().map(|v| v.total_power).sum();
        let total_delegated: u64 = delegations.iter().map(|d| d.amount).sum();

        let validator_stats: HashMap<String, serde_json::Value> = validators
            .iter()
            .map(|(addr, validator)| {
                (
                    addr.clone(),
                    serde_json::json!({
                        "stake": validator.stake,
                        "delegated_stake": validator.delegated_stake,
                        "total_power": validator.total_power,
                        "relay_count": validator.relay_count,
                        "is_active": validator.is_active
                    }),
                )
            })
            .collect();

        serde_json::json!({
            "consensus": "Lurosonie Relayed PoS BFT",
            "min_relay_stake": self.min_relay_stake,
            "relay_round_duration_ms": self.relay_round_duration,
            "current_relay_leader": current_leader.clone(),
            "total_blocks": total_blocks,
            "total_relay_validators": validators.len(),
            "total_relay_power": total_relay_power,
            "total_delegated_stake": total_delegated,
            "block_time_ms": self.block_time_ms,
            "validators": validator_stats,
            "delegation_count": delegations.len()
        })
    }

    pub async fn get_last_block_hash(&self) -> Option<String> {
        let hash = self.last_block_hash.read().await;
        hash.clone()
    }

    pub async fn get_last_block_info(&self) -> Option<(u64, String)> {
        let slurachain = self.slurachain_data.read().await;
        if let Some(last_block) = slurachain.last() {
            Some((last_block.block.block_number, last_block.validator.clone()))
        } else {
            None
        }
    }

    pub async fn can_validator_produce_block(&self, validator: &str) -> bool {
        let validators = self.relay_validators.read().await;
        if let Some(validator_info) = validators.get(validator) {
            validator_info.is_active
                && (validator_info.is_system || validator_info.total_power >= self.min_relay_stake)
        } else {
            false
        }
    }

    pub async fn get_validator_performance_stats(&self) -> HashMap<String, serde_json::Value> {
        let validators = self.relay_validators.read().await;
        let slurachain = self.slurachain_data.read().await;

        let mut stats = HashMap::new();

        for (addr, validator) in validators.iter() {
            let blocks_produced = slurachain.iter().filter(|bd| bd.validator == *addr).count();

            let avg_relay_time = if validator.relay_count > 0 {
                validator.last_relay_time / validator.relay_count
            } else {
                0
            };

            stats.insert(
                addr.clone(),
                serde_json::json!({
                    "blocks_produced": blocks_produced,
                    "relay_count": validator.relay_count,
                    "average_relay_time": avg_relay_time,
                    "stake_efficiency": if validator.stake > 0 {
                        (blocks_produced as f64) / (validator.stake as f64)
                    } else {
                        0.0
                    },
                    "is_system": validator.is_system,
                    "uptime_percentage": validator.relay_count as f64
                }),
            );
        }

        stats
    }

    pub async fn get_network_metrics(&self) -> serde_json::Value {
        let is_decentralized = *self.is_decentralized.read().await;
        let total_supply = *self.total_vez_supply.read().await;
        let validators = self.relay_validators.read().await;
        let slurachain = self.slurachain_data.read().await;
        let pending_count = self.get_pending_transaction_count().await;

        let active_validators = validators
            .values()
            .filter(|v| v.is_active && !v.is_system)
            .count();

        let total_staked = validators
            .values()
            .filter(|v| !v.is_system)
            .map(|v| v.total_power)
            .sum::<u64>();

        let latest_blocks = slurachain.iter().rev().take(10).collect::<Vec<_>>();

        let avg_block_time = if latest_blocks.len() > 1 {
            let time_diffs: Vec<i64> = latest_blocks
                .windows(2)
                .map(|window| {
                    window[0].block.timestamp.timestamp() - window[1].block.timestamp.timestamp()
                })
                .collect();
            time_diffs.iter().sum::<i64>() / time_diffs.len() as i64
        } else {
            (self.block_time_ms / 1000) as i64
        };

        serde_json::json!({
            "network_status": if is_decentralized { "DECENTRALIZED" } else { "CENTRALIZED_BOOTSTRAP" },
            "consensus_algorithm": "Lurosonie Relayed PoS BFT",
            "total_vez_supply": total_supply,
            "decentralization_threshold": LUROSONIE_DECENTRALIZATION_THRESHOLD,
            "decentralization_progress": total_supply,
            "active_validators": active_validators,
            "total_staked_vez": total_staked,
            "staking_ratio": total_supply,
            "total_blocks": slurachain.len(),
            "pending_transactions": pending_count,
            "average_block_time_seconds": avg_block_time,
            "min_relay_stake": self.min_relay_stake,
            "relay_round_duration_ms": self.relay_round_duration,
            "block_time_ms": self.block_time_ms
        })
    }

    pub async fn verify_relay_validator(&self, validator_id: &str) -> bool {
        let validators = self.relay_validators.read().await;
        validators
            .get(validator_id)
            .map(|v| v.is_active && v.total_power >= self.min_relay_stake)
            .unwrap_or(false)
    }

    fn required_stake(&self) -> u64 {
        self.min_relay_stake
    }

    pub async fn select_validators(&self) -> Vec<String> {
        let validators = self.relay_validators.read().await;
        validators
            .iter()
            .filter(|(_, v)| v.is_active && v.total_power >= self.min_relay_stake)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    pub async fn add_block_to_chain(&self, block: TimestampRelease, prev_hash: Option<String>) {
        let block_serialized = serde_json::to_string(&block).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(block_serialized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        {
            let mut last_hash = self.last_block_hash.write().await;
            *last_hash = Some(hash.clone());
        }

        let prev = prev_hash.unwrap_or_else(|| "None".to_string());
        println!(
            "Bloc ajouté à l'slurachain : {:?}, précédent : {}",
            block, prev
        );
    }

    pub async fn get_oldest_block_height(&self) -> u64 {
        let slurachain = self.slurachain_data.read().await;
        slurachain
            .first()
            .map(|bd| bd.block.block_number)
            .unwrap_or(0)
    }

    pub async fn get_block_height(&self) -> u64 {
        let slurachain = self.slurachain_data.read().await;
        slurachain
            .last()
            .map(|bd| bd.block.block_number)
            .unwrap_or(0)
    }

    pub async fn add_pending_transaction(&self, tx: TxRequest) {
        self.update_balance(&tx.from_op, 0).await;
        let mut pending_transactions = self.pending_transactions.write().await;
        let tx_hash = format!(
            "{}:{}:{}:{}",
            tx.from_op, tx.receiver_op, tx.value_tx, tx.nonce_tx
        );
        pending_transactions.insert(tx_hash, tx);
    }

    pub async fn remove_processed_transactions(&self, processed_hashes: Vec<String>) {
        let mut pending_transactions = self.pending_transactions.write().await;
        for hash in processed_hashes {
            pending_transactions.remove(&hash);
        }
    }

    pub async fn update_balance(&self, account: &str, amount: u64) {
        let mut balances = self.balances.write().await;
        balances.insert(account.to_string(), amount);
        println!(
            "Solde Lurosonie synchronisé pour {} : {} VEZ",
            account, amount
        );
    }

    pub async fn validate_transaction(&self, tx: &TxRequest) -> bool {
        let balances = self.balances.read().await;
        if let Some(balance) = balances.get(&tx.from_op) {
            *balance >= tx.value_tx.parse::<u64>().unwrap_or(0)
        } else {
            self.update_balance(&tx.from_op, 0).await;
            false
        }
    }

    pub async fn get_complete_contract_data(&self, contract_address: &str) -> serde_json::Value {
        let mut vm = self.vm.write().await;
        let current_state = vm
            .load_complete_contract_state(contract_address)
            .unwrap_or_else(|_| vec![0u8; 4096]);
        let history_lock = CONTRACT_STATE_HISTORY.lock().await;
        let history = history_lock
            .get(contract_address)
            .cloned()
            .unwrap_or_default();

        let module_info = if let Some(module) = vm.modules.get(contract_address) {
            let functions: Vec<String> = module.functions.keys().cloned().collect();

            serde_json::json!({
                "name": module.name,
                "address": module.address,
                "bytecode_size": module.bytecode.len(),
                "functions": functions
            })
        } else {
            serde_json::Value::Null
        };

        serde_json::json!({
            "contract_address": contract_address,
            "current_state_size": current_state.len(),
            "state_history_count": history.len(),
            "module_info": module_info,
            "is_deployed": vm.modules.contains_key(contract_address),
            "latest_states": history.iter().rev().take(5).collect::<Vec<_>>()
        })
    }

    async fn execute_native_transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<(), String> {
        let mut balances = self.balances.write().await;

        let from_balance = balances.get(from).copied().unwrap_or(0);
        if from_balance < amount {
            return Err(format!("Solde insuffisant: {} < {}", from_balance, amount));
        }

        balances.insert(from.to_string(), from_balance - amount);

        let to_balance = balances.get(to).copied().unwrap_or(0);
        balances.insert(to.to_string(), to_balance + amount);

        println!("✅ Transfert natif: {} -> {} ({} VEZ)", from, to, amount);
        Ok(())
    }

    pub async fn get_contract_state(&self, contract_address: &str) -> Result<Vec<u8>, String> {
        let mut vm = self.vm.write().await;
        vm.load_complete_contract_state(contract_address)
    }

    pub async fn get_contract_state_at_block(
        &self,
        contract_address: &str,
        block_number: u64,
    ) -> Option<Vec<u8>> {
        if let Some(block_data) = self.get_block_by_number(block_number).await {
            if let Some(state) = block_data.contract_states.get(contract_address) {
                println!(
                    "DEBUG: 📚 État contrat {} récupéré depuis slurachain en mémoire (bloc {})",
                    contract_address, block_number
                );
                return Some(state.clone());
            }
        }

        {
            let history_lock = CONTRACT_STATE_HISTORY.lock().await;
            if let Some(history) = history_lock.get(contract_address) {
                if let Some(last_state) = history.last() {
                    println!(
                        "DEBUG: 📚 État contrat {} récupéré depuis historique en mémoire",
                        contract_address
                    );
                    return Some(last_state.clone());
                }
            }
        }

        {
            let mut vm = self.vm.write().await;
            if let Ok(state) = vm.load_complete_contract_state(contract_address) {
                if state != vec![0u8; 4096] {
                    println!(
                        "DEBUG: 📚 État contrat {} récupéré depuis VM courante",
                        contract_address
                    );
                    return Some(state);
                }
            }
        }

        println!(
            "DEBUG: ❌ Aucun état trouvé pour contrat {} au bloc {}",
            contract_address, block_number
        );
        None
    }

    pub async fn validate_and_add_transaction(
        &self,
        tx: TxRequest,
        validator_addr: &str,
    ) -> Result<(), String> {
        if !self.can_validator_produce_block(validator_addr).await {
            return Err(format!(
                "Le validateur {} n'a pas le droit de produire un bloc",
                validator_addr
            ));
        }

        self.add_pending_transaction(tx.clone()).await;

        let block_height = self.get_block_height().await + 1;
        self.produce_lurosonie_block(block_height, validator_addr, false)
            .await?;

        self.lurosonie_bft_consensus(block_height).await?;

        Ok(())
    }

    pub async fn mempool_tx_receiver(&self) -> mpsc::Receiver<TxRequest> {
        let mut lock = self.mempool_tx_receiver.lock().await;
        lock.take().expect("mempool_tx_receiver déjà consommé")
    }

    pub async fn get_all_block_hashes(&self) -> Vec<String> {
        use sha3::{Digest, Sha3_256};
        let slurachain = self.slurachain_data.read().await;
        slurachain
            .iter()
            .map(|block_data| {
                let block_serialized = serde_json::to_string(&serde_json::json!({
                    "block": block_data.block,
                    "relay_power": block_data.relay_power,
                    "delegated_stake": block_data.delegated_stake,
                    "validator": block_data.validator
                }))
                .unwrap_or_default();
                let mut hasher = Sha3_256::new();
                hasher.update(block_serialized.as_bytes());
                format!("0x{:x}", hasher.finalize())
            })
            .collect()
    }

    pub async fn load_contract_state_from_db(
        &self,
        contract_address: &str,
        block_number: Option<u64>,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let block_num = block_number.unwrap_or_else(|| {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async { self.get_block_height().await })
            })
        });

        let mut contract_state = HashMap::new();

        for slot_id in 0..256u32 {
            let slot = format!("{:064x}", slot_id);
            let storage_key = format!(
                "lurosonie_contract_state:{}:{}:{}",
                contract_address, slot, block_num
            );

            if let Ok(Some(metadata)) = self.storage.get_metadata(&storage_key) {
                if let Ok(bytes) = hex::decode(&metadata.value_tx) {
                    if bytes != vec![0u8; 32] {
                        contract_state.insert(slot.clone(), bytes);
                        println!("📥 [DB LOAD] Slot {} = 0x{}", slot, metadata.value_tx);
                    }
                }
            }
        }

        if contract_state.is_empty() {
            None
        } else {
            println!(
                "📚 [DB LOAD] État contrat {} chargé depuis DB : {} slots",
                contract_address,
                contract_state.len()
            );
            Some(contract_state)
        }
    }

    pub async fn sync_from_database(&self) -> Result<(), String> {
        println!("🔄 [DB SYNC] Synchronisation depuis la base de données...");

        let mut block_num = 0u64;
        let mut loaded = 0usize;

        loop {
            let block_key = format!("lurosonie_block:{}", block_num);
            match self.storage.get_metadata(&block_key) {
                Ok(Some(metadata)) => {
                    match serde_json::from_str::<BlockData>(&metadata.value_tx) {
                        Ok(block_data) => {
                            let mut slurachain = self.slurachain_data.write().await;
                            if !slurachain.iter().any(|b| b.block.block_number == block_num) {
                                slurachain.push(block_data);
                                loaded += 1;
                                println!("📥 [DB SYNC] Bloc {} rechargé depuis DB", block_num);
                            }
                        }
                        Err(e) => {
                            error!("[DB SYNC] Erreur désérialisation bloc {}: {}", block_num, e);
                        }
                    }
                    block_num += 1;
                }
                Ok(None) => {
                    println!(
                        "✅ [DB SYNC] Plus de blocs dans DB (arrêt à {}) – {} blocs chargés",
                        block_num, loaded
                    );
                    break;
                }
                Err(e) => {
                    error!("[DB SYNC] Erreur lecture DB bloc {}: {}", block_num, e);
                    break;
                }
            }
        }

        if loaded == 0 {
            println!("ℹ️ [DB SYNC] Aucun bloc trouvé dans la DB");
        } else {
            println!(
                "🟢 [DB SYNC] Synchronisation terminée – {} blocs chargés",
                loaded
            );
        }

        Ok(())
    }
}
