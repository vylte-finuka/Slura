use tokio::sync::Mutex;
use vuc_types::tx_op::TxOpPart;
use std::sync::Arc;
use tracing::info;
use hashbrown::HashMap;
use std::fmt;

/// Service global adapté pour endpoints Ethereum
#[derive(Clone)]
pub struct SlurEthService {
    pub accounts:   Arc<Mutex<HashMap<String, u64>>>,
    pub last_nonce: Arc<Mutex<HashMap<String, u64>>>,
}

impl SlurEthService {
    pub fn new() -> Self {
        SlurEthService {
            accounts:   Arc::new(Mutex::new(HashMap::new())),
            last_nonce: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn set_balance(&self, address: &str, balance: u64) {
        let mut accounts: tokio::sync::MutexGuard<'_, HashMap<String, u64>> =
            self.accounts.lock().await;
        accounts.insert(address.to_lowercase(), balance);
    }

    pub async fn get_balance(&self, address: &str) -> u64 {
        let accounts: tokio::sync::MutexGuard<'_, HashMap<String, u64>> =
            self.accounts.lock().await;
        accounts.get(&address.to_lowercase()).copied().unwrap_or(0)
    }

    pub async fn set_nonce(&self, address: &str, nonce: u64) {
        let mut nonces: tokio::sync::MutexGuard<'_, HashMap<String, u64>> =
            self.last_nonce.lock().await;
        nonces.insert(address.to_lowercase(), nonce);
    }

    pub async fn get_nonce(&self, address: &str) -> u64 {
        let nonces: tokio::sync::MutexGuard<'_, HashMap<String, u64>> =
            self.last_nonce.lock().await;
        nonces.get(&address.to_lowercase()).copied().unwrap_or(0)
    }

    pub async fn log_eth_status(&self) {
        let accounts: tokio::sync::MutexGuard<'_, HashMap<String, u64>> =
            self.accounts.lock().await;
        info!("Ethereum accounts: {:?}", accounts.keys().collect::<Vec<_>>());
    }
}

impl fmt::Display for SlurEthService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlurEthService {{ accounts: {}, nonces: {} }}",
            self.accounts.blocking_lock().len(),
            self.last_nonce.blocking_lock().len()
        )
    }
}

#[derive(Clone)]
pub struct SlurachainService {
    pub sign_op:    String,
    pub tx_op:      Vec<TxOpPart>,
    pub nonce_tx:   u64,
    pub creator_id: String,
}

impl SlurachainService {
    pub async fn lurosonie_process(_mutex: Arc<Mutex<HashMap<String, String>>>) {
        info!("Le consensus Lurosonie est démarré.");
    }

    pub async fn slurachain_process(&self, _mutex: Arc<Mutex<HashMap<String, String>>>) {}
}

impl fmt::Display for SlurachainService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlurachainService {{ tx_op: {:?}, nonce_tx: {}, sign_op: {}, creator_id: {} }}",
               self.tx_op, self.nonce_tx, self.sign_op, self.creator_id)
    }
}
