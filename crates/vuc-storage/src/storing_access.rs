use anyhow::{Result, Context};
use rocksdb::{DB, Options, IteratorMode, Direction};
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlurachainMetadata {
    pub from_op: String,
    pub receiver_op: String,
    pub fees_tx: u64,
    pub value_tx: String,
    pub nonce_tx: u64,
    pub hash_tx: String,
}

pub trait RocksDBManager: Send + Sync + 'static {
    fn read(&self, key: &str) -> Result<Vec<u8>>;
    fn write(&self, key: &str, value: &[u8]) -> Result<()>;
    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>>;

    // Helpers spécifiques metadata (sérialisation JSON)
    fn store_metadata(&self, key: &str, metadata: &SlurachainMetadata) -> Result<()>;
    fn get_metadata(&self, key: &str) -> Result<Option<SlurachainMetadata>>;
}

#[derive(Clone)]
pub struct RocksDBManagerImpl {
    db: Arc<DB>,
}

impl RocksDBManagerImpl {
    /// Ouvre ou crée une base RocksDB au chemin spécifié
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let db = DB::open(&opts, path.as_ref())
            .with_context(|| format!("Échec ouverture RocksDB à {:?}", path.as_ref()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Pour les tests ou cas où on veut une DB temporaire en mémoire
    #[cfg(test)]
    pub fn new_temp() -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, tempfile::tempdir()?.path())
            .context("Échec ouverture RocksDB temporaire")?;
        Ok(Self { db: Arc::new(db) })
    }
}

#[async_trait::async_trait]
impl RocksDBManager for RocksDBManagerImpl {
    fn read(&self, key: &str) -> Result<Vec<u8>> {
        self.db
            .get(key.as_bytes())
            .context("Erreur lecture RocksDB")?
            .ok_or_else(|| anyhow::anyhow!("Clé non trouvée: {}", key))
            .map(|v| v.to_vec())
    }

    fn write(&self, key: &str, value: &[u8]) -> Result<()> {
        self.db
            .put(key.as_bytes(), value)
            .context("Erreur écriture RocksDB")
    }

    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut results = Vec::new();
        let iter = self.db.iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward));

        for item in iter {
            let (k, v) = item.context("Erreur itération RocksDB")?;
            let key_str = String::from_utf8(k.to_vec())
                .context("Clé non-UTF8 dans scan")?;

            if !key_str.starts_with(prefix) {
                break;
            }

            results.push((key_str, v.to_vec()));
        }

        Ok(results)
    }

    fn store_metadata(&self, key: &str, metadata: &SlurachainMetadata) -> Result<()> {
        let bytes = serde_json::to_vec(metadata)
            .context("Échec sérialisation JSON metadata")?;
        self.write(key, &bytes)
    }

    fn get_metadata(&self, key: &str) -> Result<Option<SlurachainMetadata>> {
        match self.read(key) {
            Ok(bytes) => {
                let meta = serde_json::from_slice(&bytes)
                    .context("Échec désérialisation metadata")?;
                Ok(Some(meta))
            }
            Err(e) if e.to_string().contains("Clé non trouvée") => Ok(None),
            Err(e) => Err(e),
        }
    }
}