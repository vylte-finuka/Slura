//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee — HAL AArch64/ARM64 backend ___
// crates\vuc-core\lunee-ker\src\hal_manager\arm64.rs
//
// Équivalent AArch64 de amd64.rs. AArch64 n'a pas d'instruction CPUID.
// Les capacités optionnelles sont découvertes par SluraBSD: un chargeur UEFI
// ne doit pas supposer son niveau d'exception ni lire directement des
// registres système qui peuvent être interceptés par le firmware ou un
// hyperviseur. Les constantes `cpuid::*` sont conservées pour l'API commune.
//
// Le mapping ci-dessous rapproche chaque bit x86 de son équivalent
// fonctionnel AArch64 le plus proche (ex. AES_BIT ← FEAT_AES, POPCNT_BIT ←
// toujours disponible en base AArch64). Ce n'est pas une correspondance
// bit-à-bit CPUID, juste une réutilisation du même bit-field pour piloter
// la même logique de détection matérielle.

/* --------------------------------------------------------------------- */
/*  Masques de bits « features » – mêmes noms/valeurs que amd64.rs        */
/*  pour que hal_manager.rs reste identique entre architectures.          */
/* --------------------------------------------------------------------- */
pub mod cpuid {
    pub const SSE3_BIT:      u32 = 1 << 0;   // ← toujours actif (NEON de base)
    pub const SSSE3_BIT:     u32 = 1 << 9;
    pub const SSE41_BIT:     u32 = 1 << 19;
    pub const SSE42_BIT:     u32 = 1 << 20;
    pub const AES_BIT:       u32 = 1 << 25;  // ← FEAT_AES
    pub const AVX_BIT:       u32 = 1 << 28;  // ← FEAT_SVE
    pub const FMA_BIT:       u32 = 1 << 12;
    pub const RDRAND_BIT:    u32 = 1 << 30;  // ← FEAT_RNG
    pub const VMX_BIT:       u32 = 1 << 5;   // ← EL2 (virtualisation) présent

    pub const AVX2_BIT:      u32 = 1 << 5;   // ← FEAT_SVE2
    pub const BMI1_BIT:      u32 = 1 << 3;
    pub const BMI2_BIT:      u32 = 1 << 8;
    pub const ADX_BIT:       u32 = 1 << 19;
    pub const SHA_BIT:       u32 = 1 << 29;  // ← FEAT_SHA1/FEAT_SHA256
    pub const SMEP_BIT:      u32 = 1 << 7;
    pub const SMAP_BIT7:     u32 = 1 << 20;
    pub const MPX_BIT:       u32 = 1 << 14;
    pub const CET_SS_BIT:    u32 = 1 << 7;   // ← FEAT_BTI/FEAT_PAuth

    pub const SSE4A_BIT:     u32 = 1 << 6;
    pub const XOP_BIT:       u32 = 1 << 11;
    pub const FMA4_BIT:      u32 = 1 << 16;
    pub const SVM_BIT:       u32 = 1 << 2;
    pub const ABM_BIT:       u32 = 1 << 5;
    pub const TBM_BIT:       u32 = 1 << 21;
    pub const LZCNT_BIT:     u32 = 1 << 31;  // ← CLZ toujours dispo (base AArch64)
    pub const SYSCALL_BIT:   u32 = 1 << 11;  // ← SVC toujours dispo (base AArch64)
    pub const NX_BIT:        u32 = 1 << 20;  // ← XN toujours dispo (MMU AArch64)
    pub const RDTSCP_BIT:    u32 = 1 << 27;  // ← CNTVCT_EL0 (compteur générique)
    pub const POPCNT_BIT:    u32 = 1 << 23;  // ← FEAT_CSSC / toujours via NEON
}

/* --------------------------------------------------------------------- */
/*  Profil CPU sûr utilisable avant le transfert à SluraBSD                 */
/* --------------------------------------------------------------------- */
pub fn query_cpu_features() -> u32 {
    // AArch64 garantit le jeu de base, mais pas AES, SHA, RNDR, SVE ou PAuth.
    // Ces extensions sont publiées par SluraBSD après son initialisation.
    cpuid::SSE3_BIT
        | cpuid::LZCNT_BIT
        | cpuid::SYSCALL_BIT
        | cpuid::NX_BIT
        | cpuid::POPCNT_BIT
}
