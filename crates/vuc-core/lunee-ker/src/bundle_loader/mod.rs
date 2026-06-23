//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — Maratine bundle loader ___
//
//! Charge les bundles Maratine (.slul drivers, .marep apps) depuis la
//! partition ESP et les exécute dans l'espace adresse du kernel.
//!
//! ## Format des bundles
//! Les bundles sont des archives ZIP **non compressées** (méthode 0 — stored).
//! `marai build --no-compress` produit ce format.
//!
//! | Bundle | Contenu attendu     | Rôle                              |
//! |--------|---------------------|-----------------------------------|
//! | .slul  | `native.efi`        | Driver UEFI PE32+ (LoadImage)     |
//! | .marep | `native.bin`        | Binaire PIC flat, OEntry offset 0 |
//!
//! ## Layout ESP
//! ```
//! EFI\SLURA\DRIVERS\sys.slul   ← drivers système
//! EFI\SLURA\DRIVERS\gpu.slul
//! EFI\SLURA\DRIVERS\io.slul
//! EFI\SLURA\HOME\home.marep    ← application de démarrage
//! ```

extern crate alloc;

pub mod zip_reader;
pub mod slul_loader;
pub mod marep_loader;

/// Erreurs pouvant survenir lors du chargement d'un bundle Maratine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// Volume ou fichier introuvable sur l'ESP.
    FileNotFound,
    /// Signature ou structure ZIP invalide.
    InvalidZip,
    /// Méthode de compression non supportée (seul stored/0 est accepté).
    CompressedNotSupported,
    /// Erreur de protocole UEFI (LoadImage, StartImage, FS…).
    UefiError,
    /// Impossible d'allouer des pages exécutables.
    AllocationFailed,
    /// Le binaire natif extrait du bundle est vide.
    EmptyBinary,
    /// Le runtime UVM n'est pas encore disponible (stub UEFI = -2).
    NotInitialized,
    /// execute_program a retourné un code d'erreur négatif.
    ExecutionFailed(i32),
}

// ── Signatures C-ABI des entry-points Maratine ───────────────────────────────
//
// Le compilateur Maratine émet les fonctions `rel cl` au niveau module avec
// ExternalLinkage, ce qui les rend accessibles depuis le kernel via un cast
// de pointeur C-ABI.
//
// Pour les binaires flat (.marep → native.bin), OEntry est à l'offset 0.

/// Point d'entrée principal (`rel cl OEntry` dans Mara).
pub type FnOEntry    = unsafe extern "C" fn() -> i32;

/// Événement de cycle de vie driver (`rel op APrevent` dans Mara).
/// `event` : 0 = Start, 1 = Stop.
pub type FnAPrevent  = unsafe extern "C" fn(event: u32) -> i32;

/// Événement de cycle de vie application (`rel op LAPrevent` dans Mara).
/// `event` : 0 = Create, 1 = Resume, 2 = Pause, 3 = Destroy.
/// `ctx`   : pointeur opaque passé par le runtime Slura.
pub type FnLAPrevent = unsafe extern "C" fn(event: u32, ctx: *mut u8) -> i32;
