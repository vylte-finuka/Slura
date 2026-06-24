//! efi_entry.rs — Point d'entrée UEFI pour vuc-platform (engine_platform).
//!
//! Ce fichier est la "colle" entre UEFI et engine_platform.rs :
//!   1. UEFI appelle platform_efi_start (chargé par lunee-ker via LoadImage)
//!   2. platform_efi_start initialise tokio + lance engine_platform::start()
//!   3. engine_platform gère le full node RPC SluraChain
//!
//! Build : cargo build -p vuc-platform --bin vuc-platform-engine --target x86_64-pc-windows-msvc
//! L'EFI est obtenu en cross-compilant ou en utilisant un PE64 wrapper.

use std::ffi::CStr;
use std::os::raw::c_char;

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

    tracing::info!("[PLATFORM] engine_platform démarré depuis le noyau Lunée");
    // La logique principale est dans engine_platform::main — on la réutilise
    // via le module platform_engine exposé par lib.rs.
    crate::platform_engine::run().await;
}
