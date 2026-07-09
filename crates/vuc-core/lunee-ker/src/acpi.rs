//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — lecture directe des tables ACPI (ACPI Spec 6.4, §5) ___

//! Complément à `pci.rs` : au lieu de s'appuyer uniquement sur l'abstraction
//! `EFI_PCI_IO_PROTOCOL`, ce module lit les VRAIES tables système ACPI —
//! RSDP → XSDT → MCFG — comme le décrit la spec ACPI 6.4 §5.2.5 (localisation
//! du RSDP sur systèmes UEFI, via l'EFI Configuration Table) et §5.2.6
//! (en-tête commun DESCRIPTION_HEADER de toutes les tables système).
//!
//! Le format de la table MCFG lui-même n'est pas dans le corps de la spec
//! ACPI (il est défini dans la "PCI Firmware Specification", à laquelle
//! l'ACPI Spec renvoie) mais est stable et documenté depuis PCI Firmware
//! Spec 3.0 — inchangé depuis.
//!
//! Lecture seule uniquement : aucune écriture, aucun accès MMIO ici. Sert à
//! vérifier/recouper les informations déjà obtenues via `pci.rs`, pas à les
//! remplacer (EFI_PCI_IO_PROTOCOL reste l'API utilisée pour l'accès réel).

use crate::ovc_exec::serial_log;
use uefi::table::{cfg, Boot, SystemTable};

unsafe fn read_u8(base: *const u8, off: usize) -> u8 { base.add(off).read_unaligned() }
unsafe fn read_u16(base: *const u8, off: usize) -> u16 { base.add(off).cast::<u16>().read_unaligned() }
unsafe fn read_u32(base: *const u8, off: usize) -> u32 { base.add(off).cast::<u32>().read_unaligned() }
unsafe fn read_u64(base: *const u8, off: usize) -> u64 { base.add(off).cast::<u64>().read_unaligned() }

/// Table 5.3 (RSDP Structure) — recherche l'entrée ACPI dans l'EFI Configuration
/// Table (§5.2.5.2 "Finding the RSDP on UEFI Enabled Systems") puis valide la
/// signature "RSD PTR ". Retourne (rsdt_address, xsdt_address, revision).
fn locate_and_parse_rsdp(st: &SystemTable<Boot>) -> Option<(u32, u64, u8)> {
    let entries = st.config_table();
    let ptr = entries.iter()
        .find(|e| e.guid == cfg::ACPI2_GUID)
        .or_else(|| entries.iter().find(|e| e.guid == cfg::ACPI_GUID))
        .map(|e| e.address as *const u8)?;

    let sig = unsafe { core::slice::from_raw_parts(ptr, 8) };
    if sig != b"RSD PTR " { return None; }

    let revision = unsafe { read_u8(ptr, 15) };
    let rsdt_address = unsafe { read_u32(ptr, 16) };
    // XsdtAddress (offset 24, 8 octets) n'est valide que si revision >= 2
    // (ACPI 2.0+) — cf. note "* These fields are only valid when the
    // Revision value is 2 or above" sous la Table 5.3.
    let xsdt_address = if revision >= 2 { unsafe { read_u64(ptr, 24) } } else { 0 };
    Some((rsdt_address, xsdt_address, revision))
}

/// (signature 4 octets, adresse physique de la table)
struct TableRef {
    signature: [u8; 4],
    address: u64,
}

/// Table 5.4 (DESCRIPTION_HEADER Fields) : Signature[4]@0, Length(u32)@4 —
/// commun à toutes les tables système ACPI, y compris XSDT/RSDT elles-mêmes.
const HEADER_LEN: usize = 36;

/// Parcourt le XSDT (pointeurs 64-bit, ACPI 2.0+) ou RSDT (pointeurs 32-bit,
/// repli ACPI 1.0) et retourne la liste des tables référencées.
fn enumerate_tables(rsdt_addr: u32, xsdt_addr: u64) -> alloc::vec::Vec<TableRef> {
    let (base, entry_size, is_xsdt): (u64, usize, bool) = if xsdt_addr != 0 {
        (xsdt_addr, 8, true)
    } else {
        (rsdt_addr as u64, 4, false)
    };
    if base == 0 { return alloc::vec::Vec::new(); }

    let header_ptr = base as *const u8;
    let sig = unsafe { core::slice::from_raw_parts(header_ptr, 4) };
    let expected = if is_xsdt { b"XSDT" as &[u8] } else { b"RSDT" as &[u8] };
    if sig != expected { return alloc::vec::Vec::new(); }

    let length = unsafe { read_u32(header_ptr, 4) } as usize;
    if length < HEADER_LEN { return alloc::vec::Vec::new(); }
    let count = (length - HEADER_LEN) / entry_size;

    let mut out = alloc::vec::Vec::new();
    for i in 0..count {
        let off = HEADER_LEN + i * entry_size;
        let table_addr: u64 = if is_xsdt {
            unsafe { read_u64(header_ptr, off) }
        } else {
            unsafe { read_u32(header_ptr, off) as u64 }
        };
        if table_addr == 0 { continue; }
        let tsig = unsafe { core::slice::from_raw_parts(table_addr as *const u8, 4) };
        let mut signature = [0u8; 4];
        signature.copy_from_slice(tsig);
        out.push(TableRef { signature, address: table_addr });
    }
    out
}

/// Une entrée "Configuration Space Base Address Allocation Structure" de la
/// table MCFG (PCI Firmware Spec) — 16 octets : base ECAM, groupe de segment
/// PCI, bus de début/fin couverts par cette plage mémoire.
pub struct McfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// Localise et logue les tables ACPI de haut niveau (RSDP, XSDT/RSDT, toutes
/// les tables référencées), puis parse la MCFG si présente — donne la vraie
/// adresse ECAM (config space PCIe mappé en mémoire) par segment/plage de bus,
/// en complément de l'accès via EFI_PCI_IO_PROTOCOL déjà utilisé dans pci.rs.
pub fn scan_acpi_tables(st: &SystemTable<Boot>) -> alloc::vec::Vec<McfgEntry> {
    let Some((rsdt_addr, xsdt_addr, revision)) = locate_and_parse_rsdp(st) else {
        serial_log(b"[ACPI] RSDP introuvable dans l'EFI Configuration Table\r\n");
        return alloc::vec::Vec::new();
    };
    serial_log(alloc::format!(
        "[ACPI] RSDP trouve : revision={} rsdt={:#x} xsdt={:#x}\r\n",
        revision, rsdt_addr, xsdt_addr
    ).as_bytes());

    let tables = enumerate_tables(rsdt_addr, xsdt_addr);
    serial_log(alloc::format!("[ACPI] {} table(s) systeme referencee(s)\r\n", tables.len()).as_bytes());

    let mut mcfg_entries = alloc::vec::Vec::new();
    for t in &tables {
        let sig_str = core::str::from_utf8(&t.signature).unwrap_or("????");
        serial_log(alloc::format!("[ACPI] table '{}' @ {:#x}\r\n", sig_str, t.address).as_bytes());

        if &t.signature == b"MCFG" {
            let header_ptr = t.address as *const u8;
            let length = unsafe { read_u32(header_ptr, 4) } as usize;
            // En-tête DESCRIPTION_HEADER (36) + 8 octets réservés avant le
            // tableau d'entrées de 16 octets chacune (PCI Firmware Spec).
            const MCFG_RESERVED: usize = 8;
            const ENTRY_LEN: usize = 16;
            if length > HEADER_LEN + MCFG_RESERVED {
                let n = (length - HEADER_LEN - MCFG_RESERVED) / ENTRY_LEN;
                for i in 0..n {
                    let off = HEADER_LEN + MCFG_RESERVED + i * ENTRY_LEN;
                    let base_address = unsafe { read_u64(header_ptr, off) };
                    let segment_group = unsafe { read_u16(header_ptr, off + 8) };
                    let start_bus = unsafe { read_u8(header_ptr, off + 10) };
                    let end_bus = unsafe { read_u8(header_ptr, off + 11) };
                    serial_log(alloc::format!(
                        "[ACPI] MCFG: segment={} bus={:#x}-{:#x} ECAM_base={:#x}\r\n",
                        segment_group, start_bus, end_bus, base_address
                    ).as_bytes());
                    mcfg_entries.push(McfgEntry { base_address, segment_group, start_bus, end_bus });
                }
            }
        }
    }

    if mcfg_entries.is_empty() {
        serial_log(b"[ACPI] Pas de table MCFG (pas de PCIe ECAM decrit par ACPI)\r\n");
    }
    mcfg_entries
}
