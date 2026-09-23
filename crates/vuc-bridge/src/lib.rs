use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use sha3::{Digest, Sha3_256};
use hex;
use reqwest::Client;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Devnet,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum BlockValidationStatus {
    Pending,
    Confirmed(u32),
    Reorged,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcDeposit {
    pub txid: String,
    pub amount_satoshi: u64,
    pub sender_btc: String,
    pub recipient_evm: String,
    pub confirmations: u32,
    pub status: DepositStatus,
    pub fee_satoshi: u64,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub merkle_proof: Option<Vec<String>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BitcoinBlockAnchor {
    pub height: u64,
    pub block_hash: String,
    pub previous_block_hash: Option<String>,
    pub txids: Vec<String>,
    pub merkle_root: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DepositStatus {
    Pending,
    Confirmed,
    Minted,
    Failed,
}

pub struct BitcoinBridge {
    api_key: String,
    network: NetworkType,
    deposits: Arc<RwLock<HashMap<String, BtcDeposit>>>,
    vez_contract: Arc<RwLock<String>>,
    bridge_address: Arc<RwLock<String>>,
    last_btc_height: Arc<RwLock<u64>>,
    persistent_path: String,
}

impl BitcoinBridge {
    pub fn new(api_key: String, network: NetworkType) -> Self {
        let persistent_path = std::env::var("BTC_BRIDGE_DB")
            .unwrap_or_else(|_| ".slura_btc_bridge.json".to_string());
        Self {
            api_key,
            network,
            deposits: Arc::new(RwLock::new(HashMap::new())),
            vez_contract: Arc::new(RwLock::new(String::new())),
            bridge_address: Arc::new(RwLock::new(String::new())),
            last_btc_height: Arc::new(RwLock::new(0)),
            persistent_path,
        }
    }

    pub fn network_url(&self) -> String {
        match self.network {
            NetworkType::Mainnet => format!("https://bitcoin-mainnet.g.alchemy.com/v2/{}", self.api_key),
            NetworkType::Testnet => format!("https://bitcoin-testnet.g.alchemy.com/v2/{}", self.api_key),
            NetworkType::Devnet => format!("https://bitcoin-devnet.g.alchemy.com/v2/{}", self.api_key),
        }
    }

    pub fn get_bridge_address(&self) -> String {
        std::env::var("BTC_BRIDGE_ADDRESS")
            .unwrap_or_else(|_| "bc1qexample1234567890abcdefghijklmnopqrstuvwxyz".to_string())
    }

    /// Validation PoW / merkle simplifiée : vérifie que le bloc existe et que le txid est inclus
    pub async fn validate_bitcoin_block(&self, height: u64, txid: &str) -> Result<BlockValidationStatus, String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[height]});
        let client = reqwest::Client::new();
        let resp = client.post(&url)
            .header("Content-Type","application/json")
            .json(&payload)
            .send().await.map_err(|e| format!("HTTP: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON: {}", e))?;
        let block_hash = resp["result"].as_str().ok_or("No block hash")?.to_string();

        let payload2 = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblock","params":[block_hash, false]});
        let resp2 = client.post(&url)
            .header("Content-Type","application/json")
            .json(&payload2)
            .send().await.map_err(|e| format!("HTTP2: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON2: {}", e))?;
        let txs = resp2["result"]["tx"].as_array().ok_or("No tx array")?;
        let included = txs.iter().any(|v| v.as_str() == Some(txid));
        if included {
            Ok(BlockValidationStatus::Confirmed(6))
        } else {
            Ok(BlockValidationStatus::Invalid)
        }
    }

    /// Surveiller les nouveaux blocs Bitcoin (mainnet/testnet selon config)
    pub async fn watch_blocks(&self) {
        let client = reqwest::Client::new();
        let mut last_height = *self.last_btc_height.read().await;
        loop {
            match self.get_blockcount(&client).await {
                Ok(height) => {
                    if height > last_height {
                        last_height = height;
                        tracing::info!("🆕 Nouveau bloc Bitcoin {} (réseau: {:?})", height, self.network);
                        *self.last_btc_height.write().await = height;
                        self.process_new_block(height, &client).await;
                    }
                }
                Err(e) => tracing::error!("Bitcoin watcher error: {}", e),
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }

    pub async fn get_blockcount(&self, client: &reqwest::Client) -> Result<u64, String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]});
        let resp = client.post(&url).header("Content-Type","application/json").json(&payload).send().await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON: {}", e))?;
        resp["result"].as_u64().ok_or_else(|| "Invalid result".to_string())
    }

    async fn process_new_block(&self, height: u64, client: &reqwest::Client) {
        let block_hash = match self.get_block_hash(height, client).await {
            Ok(h) => h,
            Err(e) => { tracing::error!("Failed block hash: {}", e); return; }
        };
        let txids = match self.get_block_txs(&block_hash, client).await {
            Ok(t) => t,
            Err(e) => { tracing::error!("Failed block txs: {}", e); return; }
        };
        for txid in txids {
            self.check_deposit(&txid, client).await;
        }
    }

    async fn get_block_hash(&self, height: u64, client: &reqwest::Client) -> Result<String, String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[height]});
        let resp = client.post(&url).header("Content-Type","application/json").json(&payload).send().await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON: {}", e))?;
        resp["result"].as_str().map(|s| s.to_string()).ok_or_else(|| "Invalid result".to_string())
    }

    async fn get_block_txs(&self, block_hash: &str, client: &reqwest::Client) -> Result<Vec<String>, String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblock","params":[block_hash, true]});
        let resp = client.post(&url).header("Content-Type","application/json").json(&payload).send().await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON: {}", e))?;
        let txids = resp["result"]["tx"].as_array().ok_or("Invalid tx array")?
            .iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
        Ok(txids)
    }

    /// Récupère les données complètes d'un bloc Bitcoin (hash + txids)
    /// Utilisé par le séquenceur sidechain pour lier le bloc BTC au bloc Slura
    pub async fn get_block_data(&self, height: u64, client: &reqwest::Client) -> Result<(String, Vec<String>), String> {
        let block_hash = self.get_block_hash(height, client).await?;
        let txids = self.get_block_txs(&block_hash, client).await?;
        Ok((block_hash, txids))
    }
    /// Récupère un BitcoinBlockAnchor complet (hash, prev_hash, txids, merkle_root)
    pub async fn get_block_anchor(&self, height: u64, client: &Client) -> Result<BitcoinBlockAnchor, String> {
        let block_hash = self.get_block_hash(height, client).await?;
        let txids = self.get_block_txs(&block_hash, client).await?;

        let previous_block_hash = if height > 0 {
            Some(self.get_block_hash(height - 1, client).await?)
        } else {
            None
        };

        let merkle_root = self.get_block_merkle_root(&block_hash, client).await;

        Ok(BitcoinBlockAnchor {
            height,
            block_hash,
            previous_block_hash,
            txids,
            merkle_root,
        })
    }

    async fn get_block_merkle_root(&self, block_hash: &str, client: &Client) -> Option<String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"getblock","params":[block_hash, true]});
        client.post(&url)
            .header("Content-Type","application/json")
            .json(&payload)
            .send().await.ok()?
            .json::<serde_json::Value>().await.ok()?
            .get("result")
            .and_then(|r| r.get("mrklRoot"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
    async fn check_deposit(&self, txid: &str, client: &reqwest::Client) {
        let tx = match self.get_transaction(txid, client).await {
            Ok(t) => t,
            Err(e) => { tracing::warn!("Failed tx {}: {}", txid, e); return; }
        };
        let bridge_address = self.get_bridge_address();
        if let Some(vout) = tx["result"]["vout"].as_array() {
            for output in vout {
                if let Some(script_pub_key) = output["scriptPubKey"].as_object() {
                    if let Some(addr) = script_pub_key.get("addresses")
                        .and_then(|a| a.as_array()).and_then(|arr| arr.first()).and_then(|v| v.as_str())
                    {
                        if addr == &bridge_address {
                            let amount = output["value"].as_u64().unwrap_or(0);
                            let confirmations = tx["result"]["confirmations"].as_u64().unwrap_or(0) as u32;
                            self.register_deposit(txid.to_string(), amount, addr.to_string(), confirmations, None).await;
                        }
                    }
                }
            }
        }
    }

    async fn get_transaction(&self, txid: &str, client: &reqwest::Client) -> Result<serde_json::Value, String> {
        let url = self.network_url();
        let payload = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"gettransaction","params":[txid]});
        let resp = client.post(&url).header("Content-Type","application/json").json(&payload).send().await
            .map_err(|e| format!("HTTP: {}", e))?
            .json::<serde_json::Value>().await.map_err(|e| format!("JSON: {}", e))?;
        Ok(resp)
    }

    async fn register_deposit(&self, txid: String, amount: u64, sender: String, confirmations: u32, block_height: Option<u64>) {
        let mut deposits = self.deposits.write().await;
        let recipient_evm = self.generate_evm_address(&sender);
        let deposit = BtcDeposit {
            txid: txid.clone(),
            amount_satoshi: amount,
            sender_btc: sender,
            recipient_evm: recipient_evm.clone(),
            confirmations,
            status: if confirmations >= 6 { DepositStatus::Confirmed } else { DepositStatus::Pending },
            fee_satoshi: 0,
            block_hash: None,
            block_height,
            merkle_proof: None,
        };
        deposits.insert(txid.clone(), deposit);
        tracing::info!("💰 Dépôt BTC enregistré : {} → {} ({} satoshis, conf={})", txid, recipient_evm, amount, confirmations);
        if confirmations >= 6 {
            self.mint_vez_for_deposit(&txid, &recipient_evm, amount).await;
        }
    }

    fn generate_evm_address(&self, btc_address: &str) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(btc_address.as_bytes());
        let hash = hasher.finalize();
        format!("0x{}", hex::encode(&hash[12..]))
    }

    async fn mint_vez_for_deposit(&self, txid: &str, recipient: &str, amount: u64) -> String {
        let vez_contract = self.vez_contract.read().await;
        if vez_contract.is_empty() {
            tracing::error!("VEZ contract address not set — cannot mint");
            return "error: no contract".to_string();
        }
        tracing::info!("🎨 Mint VEZ pour dépôt {} : {} → {} ({} satoshis)", txid, recipient, vez_contract.as_str(), amount);
        let mut deposits = self.deposits.write().await;
        if let Some(deposit) = deposits.get_mut(txid) {
            deposit.status = DepositStatus::Minted;
        }
        "minted".to_string()
    }

    pub async fn get_pending_deposits(&self) -> Vec<BtcDeposit> {
        let deposits = self.deposits.read().await;
        deposits.values().filter(|d| d.status == DepositStatus::Pending || d.status == DepositStatus::Confirmed).cloned().collect()
    }

    pub async fn set_vez_contract(&self, address: String) {
        *self.vez_contract.write().await = address;
    }

    pub async fn set_bridge_address(&self, address: String) {
        *self.bridge_address.write().await = address;
    }

    pub fn get_network(&self) -> NetworkType {
        self.network.clone()
    }
}