//___  Vyft Ltd __  (c) 2026  ___
// ___ Lunée Kernel — Platform Bridge ___
//
//! Types partagés entre le kernel et le runtime OS (platform engine).
//! Définit les structures de configuration RPC, les erreurs de plateforme,
//! les commandes CLI et les réponses associées.
//!
//! Ce module sert d'interface entre le kernel UEFI (no_std) et le moteur
//! blockchain complet (std/tokio). Il définit les types de communication
//! pour le démarrage asynchrone de la blockchain.

use alloc::string::String;
use alloc::vec::Vec;

// ── Erreurs de plateforme ─────────────────────────────────────────────────────
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    InvalidBinary,
    ExecutionFailed(i32),
    NotInitialized,
    Network(String),
    Storage(String),
    Contract(String),
    Rpc(String),
    Cli(String),
    BlockchainInit(String),
    TokioRuntime(String),
    StorageManager(String),
}

impl core::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlatformError::InvalidBinary => write!(f, "Binaire invalide"),
            PlatformError::ExecutionFailed(code) => write!(f, "Exécution échouée: code {}", code),
            PlatformError::NotInitialized => write!(f, "Moteur non initialisé"),
            PlatformError::Network(msg) => write!(f, "Erreur réseau: {}", msg),
            PlatformError::Storage(msg) => write!(f, "Erreur stockage: {}", msg),
            PlatformError::Contract(msg) => write!(f, "Erreur contrat: {}", msg),
            PlatformError::Rpc(msg) => write!(f, "Erreur RPC: {}", msg),
            PlatformError::Cli(msg) => write!(f, "Erreur CLI: {}", msg),
            PlatformError::BlockchainInit(msg) => write!(f, "Erreur init blockchain: {}", msg),
            PlatformError::TokioRuntime(msg) => write!(f, "Erreur runtime tokio: {}", msg),
            PlatformError::StorageManager(msg) => write!(f, "Erreur gestionnaire stockage: {}", msg),
        }
    }
}

// ── Configuration du nœud RPC ─────────────────────────────────────────────────

/// Configuration du nœud RPC pour le platform engine EFI.
#[derive(Debug, Clone)]
pub struct RpcNodeConfig {
    pub listen_addr: String,
    pub chain_id:    u64,
    pub network:     String,
    pub port:        u16,
}

impl Default for RpcNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8082".into(),
            chain_id:    0x534C_0003,
            network:     "devnet".into(),
            port:        8082,
        }
    }
}

// ── Commandes CLI ─────────────────────────────────────────────────────────────

/// Représente une commande CLI parsée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Affiche l'aide
    Help,
    /// Affiche l'état du nœud
    Status,
    /// Affiche le nombre de blocs
    Blocks,
    /// Affiche les infos de la chaîne
    Chain,
    /// Solde d'une adresse
    Balance { address: String },
    /// Envoie une transaction
    Send { to: String, amount: String },
    /// Déploie un contrat
    Deploy { name: String },
    /// Appelle une fonction contrat
    Call { contract: String, function: String, args: Vec<String> },
    /// Envoie une requête RPC brute
    Rpc { request: String },
    /// Affiche les pairs
    Peers,
    /// Efface l'écran
    Clear,
    /// Quitte le moteur
    Exit,
}

/// Réponse à une commande CLI.
#[derive(Debug, Clone)]
pub struct CliResponse {
    pub success: bool,
    pub message: String,
    pub data:    Option<String>,
}

impl CliResponse {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self { success: true, message: msg.into(), data: None }
    }
    pub fn ok_with_data(msg: impl Into<String>, data: impl Into<String>) -> Self {
        Self { success: true, message: msg.into(), data: Some(data.into()) }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { success: false, message: msg.into(), data: None }
    }
}

// ── Configuration du validateur système ────────────────────────────────────────

/// Configuration du validateur système pour le démarrage de la blockchain.
///
/// # Sécurité
/// La clé privée n'est JAMAIS hardcodée ici. Elle est soit :
/// - Générée aléatoirement dans `kernel_runtime.rs` (mode EFI natif)
/// - Lue depuis la variable d'env `PRIMARY_VALIDATOR_PRIVKEY` (mode engine_platform)
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Clé privée du validateur (hex, 64 chars ou 0x + 64 chars)
    /// Laisser vide ("") pour forcer la génération aléatoire côté appelant.
    pub private_key: String,
    /// Adresse du validateur dérivée (laisser vide pour calcul automatique)
    pub address: String,
    /// Allocation initiale en VEZ (en wei)
    pub initial_balance: u64,
}

impl Default for ValidatorConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(), // Clé vide → génération aléatoire obligatoire
            address: String::new(),     // Adresse vide → calcul automatique depuis la clé
            // 400_000 VEZ en wei (échelle 10^9 pour rester dans u64)
            initial_balance: 400_000_000_000_000_u64,
        }
    }
}

// ── Configuration de la blockchain ───────────────────────────────────────────

/// Configuration pour le démarrage de la blockchain Slura.
#[derive(Debug, Clone)]
pub struct BlockchainConfig {
    /// Réseau (mainnet, testnet, devnet)
    pub network: String,
    /// ID de la chaîne
    pub chain_id: u64,
    /// Port RPC
    pub rpc_port: u16,
    /// Adresse du validateur
    pub validator: ValidatorConfig,
    /// Comptes initiaux avec allocations
    pub initial_accounts: Vec<InitialAccount>,
    /// Module VEZ bytecode (hex)
    pub vez_bytecode: Option<String>,
}

/// Compte initial avec allocation VEZ.
#[derive(Debug, Clone)]
pub struct InitialAccount {
    pub address: String,
    pub balance: u64,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            network: "devnet".into(),
            chain_id: 0x534C_0003,
            rpc_port: 8082,
            validator: ValidatorConfig::default(),
            initial_accounts: alloc::vec![
                // 10_000_000 VEZ en wei (échelle 10^9 pour rester dans u64)
                InitialAccount { address: "0x0000000000000000000000000000000000000001".into(), balance: 10_000_000_000_000_u64 },
                // 5_000_000 VEZ en wei (échelle 10^9 pour rester dans u64)
                InitialAccount { address: "0x0000000000000000000000000000000000000002".into(), balance: 5_000_000_000_000_u64 },
            ],
            vez_bytecode: None,
        }
    }
}

// ── État de la blockchain ────────────────────────────────────────────────────

/// État de la blockchain pour le suivi.
#[derive(Debug, Clone, Default)]
pub struct BlockchainState {
    /// Nombre de blocs
    pub block_number: u64,
    /// État synchronisé
    pub synced: bool,
    /// Nombre de transactions
    pub tx_count: u64,
    /// Liste des adresses de contrats déployés
    pub contracts: Vec<String>,
}

// ── Interface de démarrage blockchain ───────────────────────────────────────

/// Interface pour démarrer la blockchain depuis le kernel EFI.
/// 
/// Cette interface permet au kernel UEFI (no_std) de déclencher le démarrage
/// du moteur blockchain complet via une série d'appels FFI/async.
pub trait BlockchainStarter {
    /// Initialise le runtime tokio et le moteur blockchain.
    fn init_blockchain(&mut self, config: &BlockchainConfig) -> Result<(), PlatformError>;
    
    /// Démarre le serveur RPC sur le port configuré.
    fn start_rpc(&mut self) -> Result<(), PlatformError>;
    
    /// Retourne l'état actuel de la blockchain.
    fn get_state(&self) -> BlockchainState;
    
    /// Arrête la blockchain (pour le shutdown).
    fn shutdown(&mut self) -> Result<(), PlatformError>;
}
