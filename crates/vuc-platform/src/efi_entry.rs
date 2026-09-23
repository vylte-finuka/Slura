//! efi_entry.rs — Point d'entrée UEFI + hôte pour vuc-platform (engine_platform).
//!
//! Deux modes d'utilisation :
//!   A) Binaire natif (cargo run / vuc-platform-engine.exe) : fn main() ci-dessous.
//!   B) Chargé par lunee-ker via LoadImage UEFI : platform_efi_start (C-ABI).
//!
//! Variables d'environnement reconnues (injectées par SluEnvSys.slul ou CLI) :
//!   PRIMARY_VALIDATOR_PRIVKEY   — clé privée du validateur (hex 64 chars)
//!   SLURACHAIN_NETWORK          — testnet | devnet | mainnet (défaut : testnet)
//!   SLURACHAIN_RPC_PORT         — port JSON-RPC (défaut : 8545)
//!   SLURACHAIN_P2P_PORT         — port P2P (défaut : 30303)
//!   SLURACHAIN_DATA_DIR         — répertoire RocksDB (défaut : ./slura_data)
//!
//! Build : cargo build -p vuc-platform --bin vuc-platform-engine --target x86_64-pc-windows-msvc

use std::ffi::CStr;
use std::os::raw::c_char;

use vuc_platform::platform_engine;

// ── Valeurs par défaut (overridées par env vars ou CLI) ───────────────────────
const DEFAULT_NETWORK:  &str = "testnet";
const DEFAULT_RPC_PORT: &str = "8545";
const DEFAULT_P2P_PORT: &str = "30303";
const DEFAULT_DATA_DIR: &str = "./slura_data";
const DEFAULT_VALIDATOR_KEY: &str =
    "024ed470c9bbb52a1f002540b446b634840789ccc1ed0d6699b24edbd358863b";

/// Point d'entrée C-ABI — appelé par lunee-ker après LoadImage.
///
/// `args` : liste d'arguments null-separated (ex. "--network devnet\0")
/// `len`  : nombre d'arguments
#[no_mangle]
pub unsafe extern "C" fn platform_efi_start(
    args: *const *const c_char,
    len:  usize,
) -> i32 {
    // Convertir les arguments C → Vec<String> pour clap
    let argv: Vec<String> = if args.is_null() || len == 0 {
        vec!["vuc-platform".to_string()]
    } else {
        (0..len)
            .map(|i| {
                let ptr = *args.add(i);
                if ptr.is_null() { String::new() }
                else { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
            })
            .collect()
    };

    // Lance le node dans un tokio current-thread runtime (single-threaded).
    // current-thread est portable sur toute plateforme supportant POSIX threads.
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            rt.block_on(engine_start(argv));
            0
        }
        Err(e) => {
            eprintln!("[PLATFORM] Tokio runtime error: {}", e);
            -1
        }
    }
}

/// Lance engine_platform avec les arguments donnés.
async fn engine_start(argv: Vec<String>) {
    // Simuler std::env::args() pour clap
    // (engine_platform.rs utilise clap::Parser qui lit std::env::args)
    // On remplace les args process avec les nôtres via une variable globale.
    unsafe {
        // Note : set_var est deprecated depuis Rust 1.81 mais fonctionnel ici.
        #[allow(deprecated)]
        if argv.iter().any(|a| a.contains("devnet")) {
            std::env::set_var("SLURACHAIN_NETWORK", "devnet");
        } else if argv.iter().any(|a| a.contains("testnet")) {
            std::env::set_var("SLURACHAIN_NETWORK", "testnet");
        } else if argv.iter().any(|a| a.contains("mainnet")) {
            std::env::set_var("SLURACHAIN_NETWORK", "mainnet");
        }
    }

    tracing::info!("[PLATFORM] Slura chain démarré depuis le noyau Lunée");
    // La logique principale est dans engine_platform::main — on la réutilise
    // via le module platform_engine exposé par lib.rs.
    platform_engine::run().await;
}

// ── Point d'entrée natif (binaire hôte Windows/Linux) ─────────────────────────
//
// Utilisé quand on lance `vuc-platform-engine.exe` directement.
// Lit les variables d'environnement (ou défauts) et démarre le full node.
fn main() {
    // Initialisation du logger tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info,vuc_platform=debug".to_string())
        )
        .init();

    // Injection des variables d'environnement par défaut si absentes
    inject_env_defaults();

    let network = std::env::var("SLURACHAIN_NETWORK")
        .unwrap_or_else(|_| DEFAULT_NETWORK.to_string());
    let rpc_port = std::env::var("SLURACHAIN_RPC_PORT")
        .unwrap_or_else(|_| DEFAULT_RPC_PORT.to_string());
    let p2p_port = std::env::var("SLURACHAIN_P2P_PORT")
        .unwrap_or_else(|_| DEFAULT_P2P_PORT.to_string());
    let data_dir = std::env::var("SLURACHAIN_DATA_DIR")
        .unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string());
    let validator_key = std::env::var("PRIMARY_VALIDATOR_PRIVKEY")
        .unwrap_or_else(|_| DEFAULT_VALIDATOR_KEY.to_string());

    tracing::info!(
        "[PLATFORM] Démarrage vuc-platform-engine\n\
         ├── Network  : {}\n\
         ├── RPC port : {}\n\
         ├── P2P port : {}\n\
         ├── Data dir : {}\n\
         └── Validator: {}...",
        network, rpc_port, p2p_port, data_dir,
        &validator_key[..8.min(validator_key.len())]
    );

    let argv = vec![
        "vuc-platform-engine".to_string(),
        format!("--network={}", network),
        format!("--rpc-port={}", rpc_port),
        format!("--p2p-port={}", p2p_port),
        format!("--data-dir={}", data_dir),
    ];

    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            rt.block_on(engine_start(argv));
        }
        Err(e) => {
            eprintln!("[PLATFORM] Tokio runtime error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Injecte les valeurs par défaut dans l'environnement si la variable est absente.
fn inject_env_defaults() {
    #[allow(deprecated)]
    let set = |k: &str, v: &str| {
        if std::env::var(k).is_err() {
            unsafe { std::env::set_var(k, v); }
        }
    };
    set("SLURACHAIN_NETWORK",        DEFAULT_NETWORK);
    set("SLURACHAIN_RPC_PORT",       DEFAULT_RPC_PORT);
    set("SLURACHAIN_P2P_PORT",       DEFAULT_P2P_PORT);
    set("SLURACHAIN_DATA_DIR",       DEFAULT_DATA_DIR);
    set("PRIMARY_VALIDATOR_PRIVKEY", DEFAULT_VALIDATOR_KEY);
}
