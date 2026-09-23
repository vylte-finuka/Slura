//___  Vyft Ltd __  (c) 2026  ___  All Rights Reserved  ___
// ___ Kernel core named Lunee — HAL x86_64/AMD64 backend ___
// crates\vuc-core\lunee-ker\src\hal_manager\amd64.rs
//
// Détection des extensions CPU via CPUID (x86_64 uniquement). Extrait de
// hal_manager.rs pour séparer le backend par architecture — voir arm64.rs
// pour l'équivalent AArch64 (MIDR_EL1/ID_AA64*), qui n'a pas de CPUID.

use core::arch::x86_64::{__cpuid, __cpuid_count};

/* --------------------------------------------------------------------- */
/*  Masques de bits CPUID – extensions AMD64 / Intel                     */
/* --------------------------------------------------------------------- */
pub mod cpuid {
    pub const SSE3_BIT:      u32 = 1 << 0;
    pub const SSSE3_BIT:     u32 = 1 << 9;
    pub const SSE41_BIT:     u32 = 1 << 19;
    pub const SSE42_BIT:     u32 = 1 << 20;
    pub const AES_BIT:       u32 = 1 << 25;
    pub const AVX_BIT:       u32 = 1 << 28;
    pub const FMA_BIT:       u32 = 1 << 12;
    pub const RDRAND_BIT:    u32 = 1 << 30;
    pub const VMX_BIT:       u32 = 1 << 5;

    pub const AVX2_BIT:      u32 = 1 << 5;
    pub const BMI1_BIT:      u32 = 1 << 3;
    pub const BMI2_BIT:      u32 = 1 << 8;
    pub const ADX_BIT:       u32 = 1 << 19;
    pub const SHA_BIT:       u32 = 1 << 29;
    pub const SMEP_BIT:      u32 = 1 << 7;
    pub const SMAP_BIT7:     u32 = 1 << 20;
    pub const MPX_BIT:       u32 = 1 << 14;
    pub const CET_SS_BIT:    u32 = 1 << 7;

    pub const SSE4A_BIT:     u32 = 1 << 6;
    pub const XOP_BIT:       u32 = 1 << 11;
    pub const FMA4_BIT:      u32 = 1 << 16;
    pub const SVM_BIT:       u32 = 1 << 2;
    pub const ABM_BIT:       u32 = 1 << 5;
    pub const TBM_BIT:       u32 = 1 << 21;
    pub const LZCNT_BIT:     u32 = 1 << 31;
    pub const SYSCALL_BIT:   u32 = 1 << 11;
    pub const NX_BIT:        u32 = 1 << 20;
    pub const RDTSCP_BIT:    u32 = 1 << 27;
    pub const POPCNT_BIT:    u32 = 1 << 23;
}

/* --------------------------------------------------------------------- */
/*  Fonction utilitaire – retourne un bit‑field décrivant les extensions AMD64 */
/* --------------------------------------------------------------------- */
pub fn query_cpu_features() -> u32 {
    let max_basic = unsafe { __cpuid(0).eax };
    let mut features: u32 = 0;

    if max_basic >= 1 {
        let cpuid1 = unsafe { __cpuid(1) };
        let ecx = cpuid1.ecx;
        if (ecx & cpuid::SSE3_BIT) != 0 { features |= cpuid::SSE3_BIT; }
        if (ecx & cpuid::SSSE3_BIT) != 0 { features |= cpuid::SSSE3_BIT; }
        if (ecx & cpuid::SSE41_BIT) != 0 { features |= cpuid::SSE41_BIT; }
        if (ecx & cpuid::SSE42_BIT) != 0 { features |= cpuid::SSE42_BIT; }
        if (ecx & cpuid::AES_BIT) != 0 { features |= cpuid::AES_BIT; }
        if (ecx & cpuid::AVX_BIT) != 0 { features |= cpuid::AVX_BIT; }
        if (ecx & cpuid::FMA_BIT) != 0 { features |= cpuid::FMA_BIT; }
        if (ecx & cpuid::RDRAND_BIT) != 0 { features |= cpuid::RDRAND_BIT; }
        if (ecx & cpuid::VMX_BIT) != 0 { features |= cpuid::VMX_BIT; }
    }

    if max_basic >= 7 {
        let cpuid7 = unsafe { __cpuid_count(7, 0) };
        let ebx = cpuid7.ebx;
        let ecx = cpuid7.ecx;
        if (ebx & cpuid::AVX2_BIT) != 0 { features |= cpuid::AVX2_BIT; }
        if (ebx & cpuid::BMI1_BIT) != 0 { features |= cpuid::BMI1_BIT; }
        if (ebx & cpuid::BMI2_BIT) != 0 { features |= cpuid::BMI2_BIT; }
        if (ebx & cpuid::ADX_BIT) != 0 { features |= cpuid::ADX_BIT; }
        if (ebx & cpuid::SHA_BIT) != 0 { features |= cpuid::SHA_BIT; }
        if (ebx & cpuid::SMEP_BIT) != 0 { features |= cpuid::SMEP_BIT; }
        if (ebx & cpuid::SMAP_BIT7) != 0 { features |= cpuid::SMAP_BIT7; }
        if (ebx & cpuid::MPX_BIT) != 0 { features |= cpuid::MPX_BIT; }
        if (ecx & cpuid::CET_SS_BIT) != 0 { features |= cpuid::CET_SS_BIT; }
    }

    let max_extended = unsafe { __cpuid(0x8000_0000).eax };
    if max_extended >= 0x8000_0001 {
        let cpuid_ext = unsafe { __cpuid(0x8000_0001) };
        let ecx = cpuid_ext.ecx;
        if (ecx & cpuid::SSE4A_BIT) != 0 { features |= cpuid::SSE4A_BIT; }
        if (ecx & cpuid::XOP_BIT) != 0 { features |= cpuid::XOP_BIT; }
        if (ecx & cpuid::FMA4_BIT) != 0 { features |= cpuid::FMA4_BIT; }
        if (ecx & cpuid::SVM_BIT) != 0 { features |= cpuid::SVM_BIT; }
        if (ecx & cpuid::ABM_BIT) != 0 { features |= cpuid::ABM_BIT; }
        if (ecx & cpuid::TBM_BIT) != 0 { features |= cpuid::TBM_BIT; }
        if (ecx & cpuid::LZCNT_BIT) != 0 { features |= cpuid::LZCNT_BIT; }
        if (ecx & cpuid::SYSCALL_BIT) != 0 { features |= cpuid::SYSCALL_BIT; }
        if (ecx & cpuid::NX_BIT) != 0 { features |= cpuid::NX_BIT; }
        if (ecx & cpuid::RDTSCP_BIT) != 0 { features |= cpuid::RDTSCP_BIT; }
        if (ecx & cpuid::POPCNT_BIT) != 0 { features |= cpuid::POPCNT_BIT; }
    }

    features
}
