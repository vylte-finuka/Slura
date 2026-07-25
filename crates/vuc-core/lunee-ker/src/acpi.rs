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

/// Registres/valeurs réellement nécessaires pour déclencher une entrée ACPI
/// S3 (mise en veille RAM) "à la main", sans interpréteur AML complet — ACPI
/// Spec 6.4 §7 ("Power and Performance Management"), en particulier §7.3
/// (PM1 Control Registers, bits SLP_TYPx/SLP_EN) et §7.4 (transition de state
/// via écriture du registre PM1_CNT). Port I/O uniquement (GAS en espace
/// System I/O — le seul cas géré ici ; un GAS en System Memory ferait planter
/// silencieusement, donc explicitement rejeté dans `scan_power_management`).
#[derive(Clone, Copy)]
pub struct PowerMgmt {
    pub pm1a_cnt_port: u16,
    pub pm1b_cnt_port: u16,   // 0 si absent (beaucoup de systèmes, dont QEMU/OVMF, n'ont pas de PM1b)
    pub slp_typ_a: u16,       // valeur SLP_TYP (3 bits) à placer aux bits 10-12 du PM1a_CNT pour \_S3
    pub slp_typ_b: u16,       // idem PM1b, 0 si non applicable
    pub smi_cmd_port: u16,    // 0 si absent (mode ACPI déjà actif nativement, cas UEFI courant)
    pub acpi_enable_val: u8,
}

/// Encodage AML "PkgLength" (spec ACPI 6.4 §20.2.4) : lit la longueur totale
/// du Package et retourne (nombre d'octets occupés par PkgLength lui-même).
/// On n'a besoin que de savoir combien d'octets sauter pour atteindre
/// NumElements — la valeur de longueur elle-même n'est pas utilisée.
fn aml_pkglength_byte_count(data: &[u8]) -> Option<usize> {
    let b0 = *data.first()?;
    let lead_bytes = (b0 >> 6) & 0x3;
    Some(1 + lead_bytes as usize)
}

/// Cherche l'objet `\_S3` (NameSeg AML "_S3_", 4 octets ASCII fixes — un nom
/// AML est toujours encodé sur 4 caractères, complété par '_') dans les
/// octets bruts d'une table (DSDT ou SSDT), puis décode le PackageOp (0x12)
/// qui le suit pour en extraire les 2 premiers éléments (SLP_TYPa, SLP_TYPb).
/// Technique volontairement bornée (PAS un interpréteur AML général) — même
/// principe que la recherche "_S3_" documentée sur wiki.osdev.org/ACPI,
/// fiable sur les DSDT standard générés par QEMU/OVMF et VMware.
fn find_s3_sleep_type(table_bytes: &[u8]) -> Option<(u16, u16)> {
    let needle = b"_S3_";
    let mut i = 0usize;
    while i + 4 <= table_bytes.len() {
        if &table_bytes[i..i + 4] == needle {
            let mut p = i + 4;
            if table_bytes.get(p) != Some(&0x12) { i += 1; continue; } // PackageOp
            p += 1;
            let skip = aml_pkglength_byte_count(&table_bytes[p..])?;
            p += skip;
            let _num_elements = *table_bytes.get(p)?;
            p += 1;

            let mut values = [0u16; 2];
            for slot in values.iter_mut() {
                let op = *table_bytes.get(p)?;
                match op {
                    0x00 => { *slot = 0; p += 1; }                                   // ZeroOp
                    0x01 => { *slot = 1; p += 1; }                                   // OneOp
                    0x0A => { *slot = *table_bytes.get(p + 1)? as u16; p += 2; }      // BytePrefix
                    0x0B => {                                                        // WordPrefix
                        let lo = *table_bytes.get(p + 1)? as u16;
                        let hi = *table_bytes.get(p + 2)? as u16;
                        *slot = lo | (hi << 8);
                        p += 3;
                    }
                    _ => return None, // encodage inattendu — repli honnête, pas de valeur devinée
                }
            }
            return Some((values[0], values[1]));
        }
        i += 1;
    }
    None
}

/// Localise et parse la FADT ("FACP") pour en extraire les registres PM1
/// (System I/O uniquement — voir `PowerMgmt`), puis le DSDT référencé pour y
/// chercher `\_S3` via `find_s3_sleep_type`. Retourne `None` honnêtement si
/// un des éléments nécessaires est absent/non supporté (ex: GAS en System
/// Memory, PM1_CNT_LEN suspect, `\_S3` introuvable) plutôt que d'inventer une
/// valeur — dans ce cas `SluPwMan` refusera la mise en veille (voir ovc_exec.rs).
pub fn scan_power_management(st: &SystemTable<Boot>) -> Option<PowerMgmt> {
    let (rsdt_addr, xsdt_addr, _revision) = locate_and_parse_rsdp(st)?;
    let tables = enumerate_tables(rsdt_addr, xsdt_addr);
    let fadt = tables.iter().find(|t| &t.signature == b"FACP")?;

    let hp = fadt.address as *const u8;
    let length = unsafe { read_u32(hp, 4) } as usize;
    if length < HEADER_LEN + 116 {
        serial_log(b"[ACPI] FADT trop courte pour les champs PM1 attendus\r\n");
        return None;
    }

    // Champs FADT (ACPI 1.0, tous en System I/O implicite pour ces anciens
    // champs — SMI_CMD@48, PM1a_CNT_BLK@64, PM1b_CNT_BLK@68, PM1_CNT_LEN@89).
    let smi_cmd = unsafe { read_u32(hp, 48) };
    let acpi_enable = unsafe { read_u8(hp, 52) };
    let pm1a_cnt_blk = unsafe { read_u32(hp, 64) };
    let pm1b_cnt_blk = unsafe { read_u32(hp, 68) };
    let pm1_cnt_len = unsafe { read_u8(hp, 89) };
    let dsdt_addr = unsafe { read_u32(hp, 40) };

    // X_PM1a_CNT_BLK (GAS 12 octets @ 172) prioritaire si présent (ACPI 2.0+,
    // longueur FADT suffisante) — on exige System I/O (address_space_id == 1),
    // repli honnête (None) sinon plutôt que de mal interpréter une adresse
    // System Memory comme un port I/O.
    let mut pm1a_port = pm1a_cnt_blk as u16;
    if length >= HEADER_LEN + 184 + 12 {
        let x_off = 172usize;
        let addr_space = unsafe { read_u8(hp, x_off) };
        let x_addr = unsafe { read_u64(hp, x_off + 4) };
        if x_addr != 0 {
            if addr_space != 1 {
                serial_log(b"[ACPI] X_PM1a_CNT_BLK n'est pas en System I/O - mise en veille non geree\r\n");
                return None;
            }
            pm1a_port = x_addr as u16;
        }
    }
    if pm1a_port == 0 || pm1_cnt_len == 0 {
        serial_log(b"[ACPI] FADT sans PM1a_CNT_BLK exploitable - mise en veille non disponible\r\n");
        return None;
    }

    let x_dsdt = if length >= HEADER_LEN + 140 + 8 { unsafe { read_u64(hp, 140) } } else { 0 };
    let dsdt_final = if x_dsdt != 0 { x_dsdt } else { dsdt_addr as u64 };
    if dsdt_final == 0 {
        serial_log(b"[ACPI] FADT sans DSDT reference - mise en veille non disponible\r\n");
        return None;
    }
    let dsdt_hp = dsdt_final as *const u8;
    let dsdt_len = unsafe { read_u32(dsdt_hp, 4) } as usize;
    if dsdt_len < HEADER_LEN || dsdt_len > 1_048_576 {
        serial_log(b"[ACPI] DSDT de longueur suspecte - mise en veille non disponible\r\n");
        return None;
    }
    let dsdt_bytes = unsafe { core::slice::from_raw_parts(dsdt_hp, dsdt_len) };

    let Some((slp_typ_a, slp_typ_b)) = find_s3_sleep_type(dsdt_bytes) else {
        serial_log(b"[ACPI] Objet \\_S3 introuvable dans le DSDT - mise en veille non disponible\r\n");
        return None;
    };

    serial_log(alloc::format!(
        "[ACPI] PM1a_CNT port={:#x} PM1b_CNT port={:#x} SLP_TYPa={} SLP_TYPb={} SMI_CMD={:#x}\r\n",
        pm1a_port, pm1b_cnt_blk as u16, slp_typ_a, slp_typ_b, smi_cmd
    ).as_bytes());

    Some(PowerMgmt {
        pm1a_cnt_port: pm1a_port,
        pm1b_cnt_port: pm1b_cnt_blk as u16,
        slp_typ_a,
        slp_typ_b,
        smi_cmd_port: smi_cmd as u16,
        acpi_enable_val: acpi_enable,
    })
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
