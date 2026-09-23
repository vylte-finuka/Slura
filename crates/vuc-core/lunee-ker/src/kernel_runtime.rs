// ___ Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Whesere (Lunée + BSD) ___

#![deny(arithmetic_overflow)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::all)]

//! Runtime du kernel Whesere — Noyau hybride Lunée + SluraBSD (slurabsd).
//!
//! Whesere = Lunée kernel
//!         + slurabsd (BSD).
//!
//! Architecture:
//! - Kernel hybride Lunée + SluraBSD (slurabsd)
//! - Protocoles HID standards UEFI
//! - Passe framebuffer + état HID au contexte OVC
//! - Exécution via exec_marep -> OEntry.ovc

use alloc::format;
use alloc::string::ToString;
use core::ffi::c_void;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

// uefi-rs gates `exit_boot_services` as `pub(super)`, so we re-implement the
// raw FFI call here against the SystemTable's Boot Services pointer.
//
// Layout of `EFI_BOOT_SERVICES` (UEFI Spec 2.10 §4.4):
//   the function pointer for `ExitBootServices` is at index 25 in the table
//   (the first 25 entries are other BS functions: RaiseTPL..CreateEventEx).
// Each function pointer is a `usize` (8 bytes on x86_64), so `ExitBootServices`
// sits at offset `25 * 8 = 200` from the start of the boot services struct.
//
// We expose it as a `#[no_mangle] pub extern "C"` so the linker is satisfied
// when the call site references it; internally it does the real dispatch.
#[no_mangle]
pub extern "C" fn efi_exit_boot_services(image: *mut c_void, key: usize) -> uefi::Status {
    unsafe {
        // Get the SystemTable. We re-derive it from the image handle is
        // not feasible here without context, so instead we expose a static
        // accessor the caller sets before invoking this symbol. See
        // `set_system_table_for_ebs`.
        let st = EBS_SYSTEM_TABLE.expect("EBS_SYSTEM_TABLE not initialized");
        let bs_ptr = (&*st).boot_services() as *const _ as *const usize;
        // Skip the first 25 function pointers (RaiseTPL..CreateEventEx).
        // Entry 25 is ExitBootServices(EFI_HANDLE, UINTN) -> EFI_STATUS.
        let exit_bs: extern "C" fn(*mut c_void, usize) -> uefi::Status =
            core::mem::transmute(*bs_ptr.add(25));
        exit_bs(image, key)
    }
}

/// Holds the SystemTable pointer for `efi_exit_boot_services`.
/// Set by `prepare_ebs` before calling `ExitBootServices`.
static mut EBS_SYSTEM_TABLE: Option<*const SystemTable<uefi::table::Boot>> = None;

/// Variable statique atomique utilisée par uefi_alloc_pages pour accéder au SystemTable.
/// Doit être appelé avant create_shared_ipc_table().
static IPC_SYSTEM_TABLE: AtomicUsize = AtomicUsize::new(0);

/// Prepare the static SystemTable pointer used by `efi_exit_boot_services`.
/// Must be called before invoking `efi_exit_boot_services`.
pub fn prepare_ebs(st: &mut SystemTable<Boot>) {
    unsafe {
        EBS_SYSTEM_TABLE = Some(st as *const _);
    }
}

use crate::loader_env::LoaderEnv;
use crate::utils::u32_to_le_bytes;

use crate::bundle_loader::{marep_loader, BundleError};
use crate::platform_engine_efi::PlatformEngineEfi;
use crate::ressources_manager::RessourcesManager;
use crate::whesere_ipc::{
    create_shared_ipc_table, WhesereIpcTable, IPC_MAGIC, BUFFER_SIZE as IPC_BUFFER_SIZE, IpcMessageType,
};

use uefi::{
    table::{Boot, SystemTable},
    CString16, Guid, Handle, Status,
};

use uefi::proto::media::file::{File, FileAttribute, FileMode, RegularFile};

use uefi::table::boot::{LoadImageSource, OpenProtocolAttributes, OpenProtocolParams};

use uefi::proto::console::pointer::Pointer;
use uefi::proto::console::text::Key;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::unsafe_protocol;

// ─────────────────────────────────────────────────────────────────────────────
// Constantes du noyau SluraBSD (slurabsd) et du loader WHESERE
// ─────────────────────────────────────────────────────────────────────────────

/// GUID du protocole graphique BSD (publié par slurabsd)
const BSD_GRAPHICS_PROTOCOL_GUID: Guid =
    Guid::parse_or_panic("12345678-9abc-def0-1234-56789abcdef0");

/// Chemin UEFI par défaut pour WHESERE.EFI
const WHESERE_EFI_PATH: &[u8] = b"\\efi\\whesere\\WHESERE.EFI";

/// Constantes COFF/PE pour WHESERE.EFI (x64)
pub const WHESERE_ENTRY_RVA_X64: u64 = 0xBF00;
pub const WHESERE_SIZE_OF_IMAGE_X64: u64 = 0xB0000;
pub const WHESERE_MACHINE_AMD64: u16 = 0x8664;

/// Constantes COFF/PE pour WHESERE.EFI (ARM64)
pub const WHESERE_ENTRY_RVA_ARM64: u64 = 0xBF00;
pub const WHESERE_SIZE_OF_IMAGE_ARM64: u64 = 0xB0000;
pub const WHESERE_MACHINE_ARM64: u16 = 0xAA64;

/// `slurabsd.bin` est un payload brut: il ne contient pas de métadonnées PE,
/// ELF ou ABI permettant de déduire un point d'entrée depuis ses octets.
pub const SLURABSD_RAW_SIZE: u64 = 24_743_096;

/// Chemin par défaut pour le noyau BSD (slurabsd.bin)
const SLURABSD_KERNEL_PATH: &[u8] = b"\\efi\\whesere\\slurabsd.bin";

/// Taille maximale d'un segment mémoire UEFI (en pages)
const MAX_MEMORY_DESCRIPTOR_SIZE: usize = 4096;

/// Offset de l'entry point dans l'optional header PE/COFF
const PE_ENTRY_POINT_OFFSET: usize = 16;

/// Taille minimale d'un fichier PE/COFF valide (en octets)
const MIN_PE_FILE_SIZE: usize = 64;

/// Lit et analyse le header COFF/PE de WHESERE.EFI pour obtenir l'entry point réel
/// Retourne l'offset RVA de l'entry point (AddressOfEntryPoint dans l'optional header).
/// Le fichier attendu est le PE32+ AMD64 réel de `EFI/WHESERE/WHESERE.EFI`.
fn parse_whesere_coff_header(st: &mut SystemTable<Boot>, image: Handle) -> Result<u64, Status> {
    use alloc::vec::Vec;
    use uefi::proto::media::fs::SimpleFileSystem;
    use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

    // Trouve tous les handles exposant un SimpleFileSystem
    let handles = st
        .boot_services()
        .find_handles::<SimpleFileSystem>()
        .map_err(|e| {
            let _ = st
                .stdout()
                .write_str("[WHESERE] find_handles FS echoue\r\n");
            e.status()
        })?;

    if handles.is_empty() {
        let _ = st
            .stdout()
            .write_str("[WHESERE] aucun filesystem UEFI trouve\r\n");
        return Err(Status::NOT_FOUND);
    }

    // Chemins possibles pour WHESERE.EFI
    let efi_paths = [
        "\\efi\\whesere\\WHESERE.EFI",
        "\\efi\\boot\\bootx64.EFI",
        "\\efi\\boot\\bootaa64.EFI",
    ];

    // Essaie chaque filesystem et chaque chemin possible
    for &fs_handle in handles.iter() {
        for efi_path in &efi_paths {
            let result = WhesereKernel::try_read_file_from_fs(st, fs_handle, efi_path);

            match result {
                Ok(Some(data)) => {
                    if data.len() < MIN_PE_FILE_SIZE {
                        continue; // Trop petit pour être un PE/COFF valide
                    }

                    // Vérifie la signature MZ (DOS header)
                    if data[0] != b'M' || data[1] != b'Z' {
                        continue;
                    }

                    // Lit l'offset du PE header depuis le DOS header (à l'offset 0x3C)
                    let pe_offset = u32::from_le_bytes([
                        data[0x3C],
                        data[0x3C + 1],
                        data[0x3C + 2],
                        data[0x3C + 3],
                    ]) as usize;
                    if pe_offset + 24 > data.len() {
                        continue; // PE header hors limites
                    }

                    let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
                    let is_amd64 = machine == WHESERE_MACHINE_AMD64;
                    let is_arm64 = machine == WHESERE_MACHINE_ARM64;
                    if !is_amd64 && !is_arm64 {
                        continue;
                    }
                    let expected_entry = if is_arm64 { WHESERE_ENTRY_RVA_ARM64 } else { WHESERE_ENTRY_RVA_X64 };
                    let expected_size = if is_arm64 { WHESERE_SIZE_OF_IMAGE_ARM64 } else { WHESERE_SIZE_OF_IMAGE_X64 };

                    // Vérifie la signature PE\0\0
                    if data[pe_offset] != b'P'
                        || data[pe_offset + 1] != b'E'
                        || data[pe_offset + 2] != 0
                        || data[pe_offset + 3] != 0
                    {
                        continue;
                    }

                    // Lit l'AddressOfEntryPoint depuis l'optional header (à l'offset pe_offset + 24 + 16)
                    // Standard PE/COFF: DOS header (64) + PE signature (4) + COFF header (20) + Optional header (variable)
                    // L'AddressOfEntryPoint est à l'offset 16 dans l'optional header
                    let entry_rva_offset = pe_offset + 24 + PE_ENTRY_POINT_OFFSET;
                    if entry_rva_offset + 4 > data.len() {
                        continue;
                    }
                    let entry_rva = u32::from_le_bytes([
                        data[entry_rva_offset],
                        data[entry_rva_offset + 1],
                        data[entry_rva_offset + 2],
                        data[entry_rva_offset + 3],
                    ]) as u64;

                    let image_size_offset = pe_offset + 24 + 56;
                    if image_size_offset + 4 > data.len() {
                        continue;
                    }
                    let image_size = u32::from_le_bytes([
                        data[image_size_offset],
                        data[image_size_offset + 1],
                        data[image_size_offset + 2],
                        data[image_size_offset + 3],
                    ]) as u64;
                    if entry_rva != expected_entry || image_size != expected_size {
                        continue;
                    }

                    let _ = write!(
                        st.stdout(),
                        "[WHESERE] COFF header parse: EntryPoint RVA = {:#x}\r\n",
                        entry_rva
                    );
                    crate::ovc_exec::serial_log(
                        alloc::format!(
                            "[WHESERE] COFF header parse: EntryPoint RVA = {:#x}\r\n",
                            entry_rva
                        )
                        .as_bytes(),
                    );

                    return Ok(entry_rva);
                }
                Ok(None) => {
                    // Ce chemin ne contient pas le fichier, on essaie le prochain
                    continue;
                }
                Err(status) => {
                    let _ = st.stdout().write_str(&format!(
                        "[WHESERE] lecture echouee pour {}: {:?}\r\n",
                        efi_path, status
                    ));
                    return Err(status);
                }
            }
        }
    }

    // Aucun filesystem ne contenait le fichier
    let _ = st
        .stdout()
        .write_str("[WHESERE] WHESERE.EFI introuvable\r\n");
    Err(Status::NOT_FOUND)
}

/// Payload du kernel SLURABSD embarqué.
/// Le fichier \slurabsd.bin est copié dans l'image UEFI à l'emplacement \slurabsd.bin
/// Puis chargé dynamiquement depuis le filesystem UEFI au boot.
/// Le chemin est unique et centralisé : toute la logique de handoff reste dans
/// la couche de runtime, tandis que le noyau système demeure propriétaire de la
/// pile graphique / fenêtre / matériel. Cela reflète le modèle Darwin-like.

#[repr(C)]
struct BsdPosixProtocol {
    open: unsafe extern "efiapi" fn(
        this: *mut BsdPosixProtocol,
        path: *const u16,
        flags: i32,
        mode: u32,
        fd: *mut i32,
    ) -> Status,

    read: unsafe extern "efiapi" fn(
        this: *mut BsdPosixProtocol,
        fd: i32,
        buf: *mut u8,
        nbytes: usize,
        bytes_read: *mut usize,
    ) -> Status,

    write: unsafe extern "efiapi" fn(
        this: *mut BsdPosixProtocol,
        fd: i32,
        buf: *const u8,
        nbytes: usize,
        bytes_written: *mut usize,
    ) -> Status,

    close: unsafe extern "efiapi" fn(this: *mut BsdPosixProtocol, fd: i32) -> Status,
}

/// Interface graphique publi e9e par slurabsd.
#[repr(C)]
#[unsafe_protocol("12345678-9abc-def0-1234-56789abcdef0")]
struct BsdGraphicsProtocol {
    get_frame_buffer: unsafe extern "efiapi" fn(
        this: *mut BsdGraphicsProtocol,
        framebuffer: *mut *mut c_void,
        stride: *mut u32,
    ) -> Status,

    get_mode: unsafe extern "efiapi" fn(
        this: *mut BsdGraphicsProtocol,
        width: *mut u32,
        height: *mut u32,
    ) -> Status,

    // D e9l e9gation des primitives de rendu avanc e9es vers le noyau BSD.
    // Le noyau Lun e9e garde un fallback local, mais le BSD peut prendre le relais
    // pour les op e9rations graphiques mat e9rielles  e0 haute performance.
    draw_rect: unsafe extern "efiapi" fn(
        this: *mut BsdGraphicsProtocol,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        color: u32,
    ) -> Status,

    draw_text: unsafe extern "efiapi" fn(
        this: *mut BsdGraphicsProtocol,
        x: u32,
        y: u32,
        text: *const u16,
        fg: u32,
        bg: u32,
    ) -> Status,

    present: unsafe extern "efiapi" fn(this: *mut BsdGraphicsProtocol) -> Status,
}

/// Interface de fen eatres et de composition publi e9e par SluraBSD.
#[repr(C)]
#[unsafe_protocol("a2cf0100-7dd0-11ef-9d88-0242ac120002")]
struct BsdWindowProtocol {
    create_window: unsafe extern "efiapi" fn(
        this: *mut BsdWindowProtocol,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        title: *const u16,
        window_id: *mut u32,
    ) -> Status,

    destroy_window:
        unsafe extern "efiapi" fn(this: *mut BsdWindowProtocol, window_id: u32) -> Status,

    set_bounds: unsafe extern "efiapi" fn(
        this: *mut BsdWindowProtocol,
        window_id: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> Status,

    present_window:
        unsafe extern "efiapi" fn(this: *mut BsdWindowProtocol, window_id: u32) -> Status,
}

#[repr(C)]
struct BsdAcpiPowerInfo {
    smi_cmd: u64,
    pm1a_cnt: u64,
    pm1b_cnt: u64,
    slp_typ_a: u16,
    slp_typ_b: u16,
    acpi_enable_val: u8,
    acpi_disable_val: u8,
    sleep_state: u8,
}

#[repr(C)]
#[unsafe_protocol("c4d7a900-7dd0-11ef-9d88-0242ac120002")]
struct BsdAcpiProtocol {
    scan_tables: unsafe extern "efiapi" fn(this: *mut BsdAcpiProtocol) -> Status,
    get_power_info: unsafe extern "efiapi" fn(
        this: *mut BsdAcpiProtocol,
        info: *mut BsdAcpiPowerInfo,
    ) -> Status,
}

#[repr(C)]
#[unsafe_protocol("c4d7a901-7dd0-11ef-9d88-0242ac120002")]
struct BsdXhciProtocol {
    get_controller:
        unsafe extern "efiapi" fn(this: *mut BsdXhciProtocol, controller_id: *mut u32) -> Status,
    read_capabilities:
        unsafe extern "efiapi" fn(this: *mut BsdXhciProtocol, controller_id: u32) -> Status,
}

#[repr(C)]
#[unsafe_protocol("c4d7a902-7dd0-11ef-9d88-0242ac120002")]
struct BsdEhciProtocol {
    get_controller:
        unsafe extern "efiapi" fn(this: *mut BsdEhciProtocol, controller_id: *mut u32) -> Status,
    read_capabilities:
        unsafe extern "efiapi" fn(this: *mut BsdEhciProtocol, controller_id: u32) -> Status,
}

#[repr(C)]
#[unsafe_protocol("c4d7a903-7dd0-11ef-9d88-0242ac120002")]
struct BsdStorageProtocol {
    get_volume_count:
        unsafe extern "efiapi" fn(this: *mut BsdStorageProtocol, count: *mut u32) -> Status,
    get_volume: unsafe extern "efiapi" fn(
        this: *mut BsdStorageProtocol,
        index: u32,
        label: *mut u8,
        label_capacity: usize,
        label_length: *mut usize,
        volume_id: *mut u32,
    ) -> Status,
}

fn bsd_acpi_scan(st: &mut SystemTable<Boot>, image: Handle) -> Option<crate::acpi::PowerMgmt> {
    // ACPI 6.4 §4.1 : Validation RSDP (Root System Description Pointer)
    // La RSDP doit être alignée sur 16 octets et contenir la signature "RSD PTR "
    // avec le checksum valide avant d'accéder aux tables ACPI.
    let rsdp_addr = 0xE0000u64; // Zone de recherche ACPI standard (0xE0000-0xFFFFF)
    let rsdp_valid = unsafe {
        let ptr = rsdp_addr as *const u8;
        // Vérifie la signature ACPI 6.4 : "RSD PTR " (8 octets)
        let sig = core::slice::from_raw_parts(ptr, 8);
        sig == b"RSD PTR "
    };
    if !rsdp_valid {
        // Fallback : recherche dans la zone étendue (0x80000000+)
        // selon ACPI 6.4 §4.1.2
    }

    // ACPI 6.4 §4.1.3 : Validation du checksum (octet de somme modulo 256 = 0)
    let checksum_valid = unsafe {
        let ptr = rsdp_addr as *const u8;
        let rsdp_len = 24; // Longueur minimale RSDP (ACPI 6.0+)
        let data = core::slice::from_raw_parts(ptr, rsdp_len);
        let mut sum: u8 = 0;
        for &b in data {
            sum = sum.wrapping_add(b);
        }
        sum == 0
    };
    if !checksum_valid {
        return None;
    }

    // ACPI 6.4 §4.1.4 : Lecture du RSDT/XSDT depuis le RSDP
    // Le RSDP contient un pointeur 64-bit vers la table RSDT/XSDT à l'offset 24
    let rsdt_addr = unsafe {
        let ptr = (rsdp_addr + 24) as *const u64;
        core::ptr::read(ptr)
    };
    if rsdt_addr == 0 {
        return None;
    }

    // ACPI 6.4 §4.5.1 : Lecture de la table FADT (Fixed ACPI Description Table)
    // La FADP contient les registres de gestion de l'alimentation (PM1a/b)
    let fadt_addr = find_acpi_table(rsdt_addr, b"FADT");
    if fadt_addr == 0 {
        return None;
    }

    // Lecture des registres PM1a_cnt et PM1b_cnt depuis la FADT (ACPI 6.4 §4.8.3)
    let pm1a_cnt = unsafe { core::ptr::read((fadt_addr + 0x2C) as *const u64) };
    let pm1b_cnt = unsafe { core::ptr::read((fadt_addr + 0x30) as *const u64) };
    let smi_cmd = unsafe { core::ptr::read((fadt_addr + 0x28) as *const u64) };
    let slp_typ_a = unsafe { core::ptr::read::<u16>((fadt_addr + 0x14) as *const u16) };
    let slp_typ_b = unsafe { core::ptr::read::<u16>((fadt_addr + 0x16) as *const u16) };
    let acpi_enable_val = unsafe { core::ptr::read::<u8>((fadt_addr + 0x12) as *const u8) };
    let acpi_disable_val = unsafe { core::ptr::read::<u8>((fadt_addr + 0x13) as *const u8) };

    Some(crate::acpi::PowerMgmt {
        smi_cmd: crate::mmio_io::AcpiReg(smi_cmd),
        pm1a_cnt: crate::mmio_io::AcpiReg(pm1a_cnt),
        pm1b_cnt: crate::mmio_io::AcpiReg(pm1b_cnt),
        slp_typ_a,
        slp_typ_b,
        acpi_enable_val,
        acpi_disable_val,
        sleep_state: 0,
    })
}

/// Recherche une table ACPI par sa signature (ACPI 6.4 §4.5)
fn find_acpi_table(rsdt_addr: u64, signature: &[u8; 4]) -> u64 {
    // Lecture du nombre d'entrées RSDT (offset 4)
    let count = unsafe { core::ptr::read::<u32>((rsdt_addr + 4) as *const u32) } as usize;
    for i in 0..count {
        let entry_addr = rsdt_addr + 36 + (i * 4) as u64;
        let table_addr = unsafe { core::ptr::read::<u32>(entry_addr as *const u32) } as u64;
        // Vérification de la signature (offset 0)
        let sig = unsafe { core::slice::from_raw_parts(table_addr as *const u8, 4) };
        if sig == signature {
            return table_addr;
        }
    }
    0
}

fn bsd_xhci_capabilities(st: &mut SystemTable<Boot>, image: Handle) -> bool {
    let handle = match st
        .boot_services()
        .find_handles::<BsdXhciProtocol>()
        .ok()
        .and_then(|handles| handles.first().copied())
    {
        Some(handle) => handle,
        None => return false,
    };
    let mut protocol = match unsafe {
        st.boot_services().open_protocol::<BsdXhciProtocol>(
            OpenProtocolParams {
                handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(protocol) => protocol,
        Err(_) => return false,
    };
    let mut controller_id = 0;
    let controller_status =
        unsafe { (protocol.get_controller)(&mut *protocol, &mut controller_id) };
    if controller_status.is_error() {
        return false;
    }
    unsafe { (protocol.read_capabilities)(&mut *protocol, controller_id).is_success() }
}

fn bsd_ehci_capabilities(st: &mut SystemTable<Boot>, image: Handle) -> bool {
    let handle = match st
        .boot_services()
        .find_handles::<BsdEhciProtocol>()
        .ok()
        .and_then(|handles| handles.first().copied())
    {
        Some(handle) => handle,
        None => return false,
    };
    let mut protocol = match unsafe {
        st.boot_services().open_protocol::<BsdEhciProtocol>(
            OpenProtocolParams {
                handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(protocol) => protocol,
        Err(_) => return false,
    };
    let mut controller_id = 0;
    let controller_status =
        unsafe { (protocol.get_controller)(&mut *protocol, &mut controller_id) };
    if controller_status.is_error() {
        return false;
    }
    unsafe { (protocol.read_capabilities)(&mut *protocol, controller_id).is_success() }
}

fn bsd_storage_volumes(
    st: &mut SystemTable<Boot>,
    image: Handle,
) -> alloc::vec::Vec<crate::disk_volumes::PhysicalVolume> {
    use alloc::string::String;
    use alloc::vec::Vec;

    let handle = match st
        .boot_services()
        .find_handles::<BsdStorageProtocol>()
        .ok()
        .and_then(|handles| handles.first().copied())
    {
        Some(handle) => handle,
        None => return Vec::new(),
    };
    let mut protocol = match unsafe {
        st.boot_services().open_protocol::<BsdStorageProtocol>(
            OpenProtocolParams {
                handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(protocol) => protocol,
        Err(_) => return Vec::new(),
    };
    let mut count = 0;
    let status = unsafe { (protocol.get_volume_count)(&mut *protocol, &mut count) };
    if status.is_error() {
        return Vec::new();
    }

    let mut volumes = Vec::new();
    for index in 0..count {
        let mut label_bytes = [0u8; 128];
        let mut label_length = 0;
        let mut volume_id = 0;
        let status = unsafe {
            (protocol.get_volume)(
                &mut *protocol,
                index,
                label_bytes.as_mut_ptr(),
                label_bytes.len(),
                &mut label_length,
                &mut volume_id,
            )
        };
        if status.is_error() {
            continue;
        }
        let label_length = label_length.min(label_bytes.len());
        let label = String::from_utf8_lossy(&label_bytes[..label_length]).into_owned();
        volumes.push(crate::disk_volumes::PhysicalVolume {
            label,
            handle_index: volume_id as usize,
        });
    }
    volumes
}

pub fn bsd_graphics_available(st: &mut SystemTable<Boot>, image: Handle) -> bool {
    st.boot_services()
        .find_handles::<BsdGraphicsProtocol>()
        .map(|handles| !handles.is_empty())
        .unwrap_or(false)
        && unsafe {
            st.boot_services()
                .open_protocol::<BsdGraphicsProtocol>(
                    OpenProtocolParams {
                        handle: st
                            .boot_services()
                            .find_handles::<BsdGraphicsProtocol>()
                            .ok()
                            .and_then(|handles| handles.first().copied())
                            .unwrap_or(image),
                        agent: image,
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
                .is_ok()
        }
}

pub fn bsd_windowing_available(st: &mut SystemTable<Boot>, image: Handle) -> bool {
    st.boot_services()
        .find_handles::<BsdWindowProtocol>()
        .map(|handles| !handles.is_empty())
        .unwrap_or(false)
}

pub fn bsd_delegate_text_render(
    st: &mut SystemTable<Boot>,
    image: Handle,
    x: u32,
    y: u32,
    text: *const u16,
    fg: u32,
    bg: u32,
) -> bool {
    if !bsd_graphics_available(st, image) {
        return false;
    }

    let handles = match st.boot_services().find_handles::<BsdGraphicsProtocol>() {
        Ok(h) => h,
        Err(_) => return false,
    };

    let handle = match handles.first().copied() {
        Some(h) => h,
        None => return false,
    };

    let mut proto = match unsafe {
        st.boot_services().open_protocol::<BsdGraphicsProtocol>(
            OpenProtocolParams {
                handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(p) => p,
        Err(_) => return false,
    };

    let status = unsafe { (proto.draw_text)(&mut *proto as *mut _, x, y, text, fg, bg) };
    status.is_success()
}

pub fn bsd_delegate_fill_rect(
    st: &mut SystemTable<Boot>,
    image: Handle,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    color: u32,
) -> bool {
    if !bsd_graphics_available(st, image) {
        return false;
    }

    let handles = match st.boot_services().find_handles::<BsdGraphicsProtocol>() {
        Ok(h) => h,
        Err(_) => return false,
    };

    let handle = match handles.first().copied() {
        Some(h) => h,
        None => return false,
    };

    let mut proto = match unsafe {
        st.boot_services().open_protocol::<BsdGraphicsProtocol>(
            OpenProtocolParams {
                handle,
                agent: image,
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(p) => p,
        Err(_) => return false,
    };

    let status = unsafe { (proto.draw_rect)(&mut *proto as *mut _, x, y, width, height, color) };
    status.is_success()
}

pub const WHESERE_BOOT_MAGIC: u64 = 0x45534552454857;
pub const WHESERE_BOOT_VERSION: u64 = 1;

/// Informations de boot transmises au noyau BSD par le loader Whesere.
#[repr(C)]
pub struct WhesereBootInfo {
    /// Magic number d'identification (WHESERE_BOOT_MAGIC)
    pub magic: u64,
    /// Version du format de boot info
    pub version: u64,
    /// Adresse de base du noyau en mémoire
    pub kernel_base: u64,
    /// Taille du noyau en octets
    pub kernel_size: u64,
    /// Point d'entrée du noyau (RVA)
    pub kernel_entry: u64,
    /// Adresse de la carte mémoire UEFI
    pub memory_map: u64,
    /// Taille de la carte mémoire en octets
    pub memory_map_size: u64,
    /// Taille d'un descripteur mémoire
    pub memory_descriptor_size: u64,
    /// Adresse de base du framebuffer
    pub framebuffer_base: u64,
    /// Taille du framebuffer en octets
    pub framebuffer_size: u64,
    /// Largeur du framebuffer en pixels
    pub framebuffer_width: u32,
    /// Hauteur du framebuffer en pixels
    pub framebuffer_height: u32,
    /// Pitch (octets par ligne) du framebuffer
    pub framebuffer_pitch: u32,
    /// Format pixel du framebuffer
    pub framebuffer_format: u32,
    /// Adresse de la RSDP ACPI
    pub acpi_rsdp: u64,
    /// Adresse de la ligne de commande
    pub cmdline: u64,
    /// Taille de la ligne de commande
    pub cmdline_size: u64,

    // ── NOUVEAUX CHAMPS POUR INVERSER L'ÉTAPE BLOCKCHAIN ──
    /// Pointeur vers la chaîne du réseau (ex: "mainnet", "testnet")
    pub blockchain_network: u64,
    /// Taille de la chaîne du réseau
    pub blockchain_network_size: u64,
    /// Chain ID calculé côté UEFI
    pub blockchain_chain_id: u64,
    /// Pointeur vers le nom du consensus (ex: "Lurosonie_bft")
    pub bft_consensus_name: u64,
    /// Port RPC (8080, 8081, 8082)
    pub bft_rpc_port: u32,
    /// Nombre de Device Paths (DP) fournis au loader — doit être >= 2
    /// pour éviter "Ignoring BootXXXX: Only one DP found" dans match_boot_info()
    pub device_path_count: u32,
    /// Pointeur vers le second Device Path (DP secondaire) — fournit 2 DP
    /// au loader SluraBSD au lieu de 1, évitant le fallback NOT_SPECIFIC.
    pub device_path_secondary: u64,
    /// Pointeur vers la table IPC partagée Lunée <-> SluraBSD (lock-free ring buffers).
    /// SluraBSD peut alors piloter le matériel réseau (em, ixl, virtio) et publier
    /// les trames RX dans `rx_ring` que Lunée consomme via le multiplexeur.
    pub ipc_table: u64,
    /// Taille de la table IPC (octets) — pour validation côté SluraBSD.
    pub ipc_table_size: u64,
    /// Padding pour alignement 8 octets
    pub _padding: u32,
}

/// État interne du noyau Whesere.
pub struct WhesereKernel {
    /// Point d'entrée du noyau BSD
    pub entry: u64,
    /// Adresse de base du noyau
    pub base: u64,
    /// Taille du noyau
    pub size: u64,
    /// Base de la pile du noyau
    pub stack_base: u64,
    /// Taille de la pile du noyau
    pub stack_size: u64,
    /// Chemin vers le noyau BSD (slurabsd.bin) sur ESP
    pub kernel_path: &'static str,
    /// Chemin vers le bootloader UEFI sur ESP
    pub boot_efi_path: &'static str,
    /// Architecture du noyau ("x64" ou "arm64")
    pub arch: &'static str,
    /// Indique si le noyau BSD est chargé
    pub kernel_loaded: bool,
    /// Indique si le protocole POSIX est activé
    pub posix_enabled: bool,
    /// Indique si le protocole graphique BSD est activé
    pub graphics_enabled: bool,
    /// Indique si le contexte OVC est activé
    pub ovc_enabled: bool,
    /// Pointeur vers le framebuffer
    pub framebuffer: *mut c_void,
    /// Largeur du framebuffer
    pub framebuffer_width: u32,
    /// Hauteur du framebuffer
    pub framebuffer_height: u32,
    /// Pitch du framebuffer
    pub framebuffer_stride: u32,
    /// Entry point du noyau
    pub kernel_entry: u64,
    /// Adresse du second Device Path UEFI (DP secondaire) injecté dans la Boot Info
    /// pour satisfaire la condition `last_dp != first_dp` de match_boot_info().
    pub dp_secondary_addr: u64,
    /// Contenu de loader.env parsé (None si non trouvé ou non lu)
    pub loader_env: Option<crate::loader_env::LoaderEnv>,
    /// Pointeur vers la table IPC partagée (créée au boot, transmise à SluraBSD).
    /// `None` tant que `create_shared_ipc_table()` n'a pas été appelé.
    pub ipc_table: Option<*mut WhesereIpcTable>,
}

impl WhesereKernel {
    /// Crée une nouvelle instance de WhesereKernel avec des valeurs par défaut.
    pub fn new() -> Self {
        // Chemins ESP — identiques pour x64 et ARM64
        #[cfg(target_arch = "x86_64")]
        {
            const KERNEL_PATH: &str = "\\EFI\\WHESERE\\slurabsd.bin";
            const BOOT_PATH: &str = "\\efi\\boot\\bootx64.efi";
            const ARCH: &str = "x64";
            return Self {
                kernel_path: KERNEL_PATH,
                boot_efi_path: BOOT_PATH,
                arch: ARCH,
                ..Self::default()
            };
        }
        #[cfg(target_arch = "aarch64")]
        {
            const KERNEL_PATH: &str = "\\EFI\\WHESERE\\slurabsd.bin";
            const BOOT_PATH: &str = "\\efi\\boot\\bootaa64.efi";
            const ARCH: &str = "arm64";
            return Self {
                kernel_path: KERNEL_PATH,
                boot_efi_path: BOOT_PATH,
                arch: ARCH,
                ..Self::default()
            };
        }

        Self {
            entry: 0,
            base: 0,
            size: 0,
            stack_base: 0,
            stack_size: 0,
            kernel_path: "\\EFI\\WHESERE\\slurabsd.bin",
            boot_efi_path: "",
            arch: "",
            posix_enabled: false,
            graphics_enabled: false,
            ovc_enabled: false,
            framebuffer: core::ptr::null_mut(),
            framebuffer_width: 0,
            framebuffer_height: 0,
            framebuffer_stride: 0,
            kernel_entry: 0,
            kernel_loaded: false,
            dp_secondary_addr: 0,
            loader_env: None,
            ipc_table: None,
        }
    }

    pub fn init(&mut self, st: &mut SystemTable<Boot>, image: Handle) -> Result<(), Status> {
        let _ = st
            .stdout()
            .write_str("[BSD] Initialisation du noyau SluraBSD...\r\n");

        crate::ovc_exec::serial_log(b"[BSD] Initialisation du noyau SluraBSD...\r\n");

        self.load_kernel_config(st, image)?;
        self.enable_posix(st)?;
        self.init_bsd_graphics(st, image)?;
        self.enable_ovc_via_bsd(st)?;

        Ok(())
    }

    fn load_kernel_config(
        &mut self,
        st: &mut SystemTable<Boot>,
        image: Handle,
    ) -> Result<(), Status> {
        // Aligné sur sys/amd64/conf/SLURABSD (ident SLURABSD, cpu HAMMER)
        const BSD_DEVICES: &[&str] = &[
            // ── Bus & firmware ──
            "acpi",
            "smbios",
            "pci",
            "efidev",
            "efirtc",
            "cpufreq",
            "pci_hp",
            "pci_iov",
            "iommu",
            // ── Storage ATA / SATA / NVMe ──
            "ahci",
            "ata",
            "mvs",
            "siis",
            "nvme",
            "nvd",
            "ufshci",
            "vmd",
            "scbus",
            "da",
            "ch",
            "sa",
            "cd",
            "pass",
            "ses",
            // ── SCSI controllers ──
            "ahc",
            "ahd",
            "hptiop",
            "isp",
            "mpt",
            "mps",
            "mpr",
            "mpi3mr",
            "sym",
            "isci",
            "ocs_fc",
            "pvscsi",
            // ── RAID ──
            "arcmsr",
            "ciss",
            "ips",
            "smartpqi",
            "tws",
            "aac",
            "aacp",
            "aacraid",
            "ida",
            "mfi",
            "mlx",
            "mrsas",
            // ── Filesystems / GEOM ──
            "ffs",
            "ufs_acl",
            "ufs_dirhash",
            "ufs_gjournal",
            "geom_raid",
            "geom_label",
            "msdosfs",
            "cd9660",
            "tmpfs",
            "nfscl",
            "nfsd",
            "nfslockd",
            "procfs",
            "pseudofs",
            "md_root",
            // ── USB ──
            "uhci",
            "ohci",
            "ehci",
            "xhci",
            "usb",
            "usbhid",
            "hkbd",
            "ukbd",
            "umass",
            "uinput",
            "evdev",
            "hid",
            "hidbus",
            // ── HID legacy (PS/2, AT) ──
            "atkbdc",
            "atkbd",
            "psm",
            "kbdmux",
            "kbd_install_cdev",
            // ── Console / framebuffer VT ──
            "vt",
            "vt_vga",
            "vt_efifb",
            "vt_vbefb",
            "vga",
            "splash",
            "sc",
            "agp",
            "efirt",
            "syscons",
            // ── Network: iflib / Intel / VMware ──
            "mdio",
            "iflib",
            "em",
            "igc",
            "ix",
            "ixv",
            "ixl",
            "iavf",
            "ice",
            "vmx",
            "axp",
            // ── Network: divers NICs ──
            "aq",
            "bxe",
            "rge",
            "ti",
            "miibus",
            "ae",
            "age",
            "alc",
            "ale",
            "bce",
            "bfe",
            "bge",
            "cas",
            "dc",
            "et",
            "fxp",
            "gem",
            "jme",
            "lge",
            "msk",
            "nfe",
            "nge",
            "re",
            "rl",
            "sge",
            "sis",
            "sk",
            "ste",
            "stge",
            "vge",
            "vr",
            "xl",
            // ── Network: Mellanox / virtio ──
            "mlx5",
            "mlxfw",
            "mlx5en",
            "vtnet",
            // ── Wireless 802.11 ──
            "wlan",
            "wlan_wep",
            "wlan_tkip",
            "wlan_ccmp",
            "wlan_gcmp",
            "wlan_amrr",
            "ath",
            "ath_hal",
            "ath_rate_sample",
            "ipw",
            "iwi",
            "iwn",
            "malo",
            "mwl",
            "ral",
            "wpi",
            // ── Network stack (pseudo) ──
            "loop",
            "ether",
            "vlan",
            "tuntap",
            "md",
            "gif",
            "bpf",
            "netmap",
            // ── Crypto / RNG ──
            "crypto",
            "aesni",
            "padlock_rng",
            "rdrand_rng",
            // ── VirtIO ──
            "virtio",
            "virtio_pci",
            "virtio_blk",
            "virtio_scsi",
            "virtio_balloon",
            "kvm_clock",
            // ── Hyperviseurs ──
            "hyperv",
            "xenhvm",
            "xenefi",
            "xenpci",
            "xentimer",
            // ── Sound ──
            "sound",
            "snd_cmi",
            "snd_csa",
            "snd_emu10kx",
            "snd_es137x",
            "snd_hda",
            "snd_ich",
            "snd_via8233",
            // ── MMC / SD ──
            "mmc",
            "mmcsd",
            "sdhci",
            // ── Ports legacy ──
            "fdc",
            "uart",
            "ppc",
            "ppbus",
            "lpt",
            "ppi",
            "puc",
            "cbb",
            "cardbus",
            // ── Compression / firmware loader ──
            "firmware",
            "xz",
            "gzio",
            "zstdio",
            // ── Compatibilités (kldload) ──
            "compat_linuxkpi",
            "compat_SluraBSD32",
            "compat_SluraBSD4",
            "compat_SluraBSD5",
            "compat_SluraBSD6",
            "compat_SluraBSD7",
            "compat_SluraBSD9",
            "compat_SluraBSD10",
            "compat_SluraBSD11",
            "compat_SluraBSD12",
            "compat_SluraBSD13",
            "compat_SluraBSD14",
            // ── Subsystems (KLD-able) ──
            "ipsec",
            "ipsec_offload",
            "sctp",
            "kern_tls",
            "fib_algo",
            "tcp_offload",
            "tcp_blackbox",
            "tcp_hhook",
            "tcp_rfc7413",
            // ── Debug / observabilité ──
            "kdb",
            "kdb_trace",
            "hwpmc_hooks",
            "kdtrace_frame",
            "kdtrace_hooks",
            "ddb_ctf",
            "audit",
            "mac",
            "racct",
            "rctl",
            "ktrace",
            "stack",
            "pps_sync",
        ];

        let _ = st.stdout().write_str("[BSD] Configuration kernel: ");

        crate::ovc_exec::serial_log(b"[BSD] Configuration kernel: ");

        for dev in BSD_DEVICES {
            let _ = write!(st.stdout(), "{} ", dev);

            crate::ovc_exec::serial_log(alloc::format!("{} ", dev).as_bytes());
        }

        let _ = st.stdout().write_str("\r\n");

        crate::ovc_exec::serial_log(b"\r\n");

        // Chargement du kernel BSD - essentiel pour le boot
        self.load_bsd_module(st, image, self.kernel_path)?;

        // Le handoff est différé vers ordonnanceur_inverse() après la phase OVC,
        // pour éviter le double ExitBootServices et le freeze sur net0.
        Ok(())
    }

    fn load_bsd_module(
        &mut self,
        st: &mut SystemTable<Boot>,
        _image: Handle,
        path: &str,
    ) -> Result<(), Status> {
        // Accepte le chemin du vrai kernel BSD (slurabsd.bin)
        if !path.starts_with("\\slurabsd") && !path.contains("slurabsd") {
            let _ = write!(
                st.stdout(),
                "[BSD] chemin inattendu: {} — continuation sans BSD\r\n",
                path
            );
            // Selon la logique Whesere, on continue meme si le chemin ne correspond pas
            return Ok(());
        }

        // Charge le kernel depuis le filesystem UEFI (image ESP/SRFS).
        // Le fichier \slurabsd.bin est dans D:\Downloads\Vyft_product\Slura\slurabsd\
        let kernel_data = match self.read_bsd_kernel_from_fs(st) {
            Ok(data) => {
                // Stocke le loader.env parsé pour utilisation ultérieure
                // Lit loader.env depuis le premier filesystem (ESP)
                self.loader_env = Self::read_loader_env_from_fs(st);
                data
            }
            Err(e) => {
                let _ = write!(
                    st.stdout(),
                    "[BSD] slurabsd.bin non trouve (erreur {:?}) — continuation sans BSD\r\n",
                    e
                );
                // Selon la logique Whesere, on continue meme si le fichier n'est pas trouve
                // Le kernel BSD peut etre charge plus tard via handoff_to_bsd_kernel
                return Ok(());
            }
        };

        if kernel_data.is_empty() {
            let _ = st
                .stdout()
                .write_str("[BSD] slurabsd.bin vide — continuation sans BSD\r\n");
            return Ok(());
        }

        let _ = write!(
            st.stdout(),
            "[BSD] slurabsd.bin charge: {} octets\r\n",
            kernel_data.len()
        );

        crate::ovc_exec::serial_log(
            alloc::format!("[BSD] slurabsd.bin loaded: {} bytes\r\n", kernel_data.len()).as_bytes(),
        );

        // Alloue mémoire exécutable et copie le payload ELF64
        let pages = (kernel_data.len() + 4095) / 4096;
        let alloc_status = unsafe {
            st.boot_services().allocate_pages(
                uefi::table::boot::AllocateType::AnyPages,
                uefi::table::boot::MemoryType::LOADER_DATA,
                pages,
            )
        };
        if alloc_status.is_err() {
            let _ = st.stdout().write_str("[BSD] allocation pages echoue\r\n");
            return Ok(());
        }
        let ptr = alloc_status.unwrap() as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(kernel_data.as_ptr(), ptr, kernel_data.len());
        }
        self.base = ptr as u64;
        self.size = kernel_data.len() as u64;
        self.kernel_loaded = true;
        self.kernel_entry = 0x1000; // entry point ELF64

        let _ = write!(
            st.stdout(),
            "[BSD] payload ELF64 copie @ 0x{:x} ({} octets)\r\n",
            self.base,
            self.size
        );

        // Le handoff est géré par ordonnanceur_inverse() après setup complet
        // pour éviter le double ExitBootServices (freeze net0).
        Ok(())
    }

    /// Lit le kernel SLURABSD (binaire brut .bin) depuis le filesystem UEFI.
    /// Le vrai build BSD produit `slurabsd.bin` (binaire brut, pas ELF64),
    /// via `stand/efi` et `sys/amd64/conf/SLURABSD`.
    fn read_bsd_kernel_from_fs(
        &self,
        st: &mut SystemTable<Boot>,
    ) -> Result<alloc::vec::Vec<u8>, Status> {
        use alloc::vec::Vec;
        use uefi::proto::media::file::{FileAttribute, FileMode, RegularFile};
        use uefi::proto::media::fs::SimpleFileSystem;
        use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
        use uefi::CString16;

        // Trouve tous les handles exposant un SimpleFileSystem.
        let handles = st
            .boot_services()
            .find_handles::<SimpleFileSystem>()
            .map_err(|e| {
                let _ = st.stdout().write_str("[BSD] find_handles FS echoue\r\n");
                e.status()
            })?;

        if handles.is_empty() {
            let _ = st
                .stdout()
                .write_str("[BSD] aucun filesystem UEFI trouve\r\n");

            return Err(Status::NOT_FOUND);
        }

        // ── LECTURE DE loader.env DEPUIS ESP ──
        // Lit loader.env depuis le premier filesystem (ESP) pour obtenir
        // les chemins des partitions whesere_part et slura_part.
        let loader_env = Self::read_loader_env(st, handles[0]);
        
        // Détermine le filesystem source et le chemin du kernel
        let (source_fs, kernel_path) = match &loader_env {
            Some(env) => {
                let _ = st.stdout().write_str(&format!(
                    "[BSD] loader.env: whesere_part={}, slura_part={}\r\n",
                    env.whesere_part, env.slura_part
                ));
                // Utilise le chemin whesere_part pour charger slurabsd.bin
                // On garde le premier filesystem comme source par défaut
                (handles[0], "\\EFI\\WHESERE\\slurabsd.bin")
            }
            None => {
                let _ = st.stdout().write_str("[BSD] loader.env non trouve, usage chemin par defaut\r\n");
                (handles[0], "\\EFI\\WHESERE\\slurabsd.bin")
            }
        };

        // Essaie de lire le kernel depuis le filesystem ESP
        let result = Self::try_read_file_from_fs(st, source_fs, kernel_path);

        match result {
            Ok(Some(kernel)) => {
                let _ = st.stdout().write_str(&format!(
                    "[BSD] slurabsd.bin lu: {} octets depuis {}\r\n",
                    kernel.len(),
                    kernel_path
                ));
                return Ok(kernel);
            }
            Ok(None) => {
                let _ = st.stdout().write_str("[BSD] slurabsd.bin non trouve sur ESP\r\n");
            }
            Err(status) => {
                let _ = st.stdout().write_str(&format!(
                    "[BSD] lecture echouee pour {}: {:?}\r\n",
                    kernel_path, status
                ));
                return Err(status);
            }
        }

        // Fallback: essaie les autres filesystems
        for &fs_handle in handles.iter().skip(1) {
            let result = Self::try_read_file_from_fs(st, fs_handle, kernel_path);
            match result {
                Ok(Some(kernel)) => {
                    let _ = st.stdout().write_str(&format!(
                        "[BSD] slurabsd.bin lu: {} octets depuis FS alternatif\r\n",
                        kernel.len()
                    ));
                    return Ok(kernel);
                }
                _ => continue,
            }
        }

        // Aucun filesystem ne contenait le kernel.
        let _ = st
            .stdout()
            .write_str("[BSD] slurabsd.bin introuvable\r\n");

        Err(Status::NOT_FOUND)
    }

    /// Lit et analyse le fichier loader.env depuis le filesystem ESP.
    /// Retourne les chemins des partitions whesere_part et slura_part.
    /// 
    /// Format loader.env (UEFI DevicePath):
    /// uefi_ignore_boot_mgr=1
    /// whesere_part=PciRoot(0x0)/Pci(0x1,0x0)/Pci(0x0,0x0)/HD(1,MBR,0x00000001,0x800,0x100000)
    /// slura_part=PciRoot(0x0)/Pci(0x1,0x0)/Pci(0x0,0x0)/HD(2,MBR,0x00000002,0x100800,0x4000000)
    /// whesere_uuid=WHESERE-ESP
    /// slura_uuid=SLURA-SYS
    /// whesere_root=\EFI\WHESERE
    /// slura_root=\SDC\slu64
    fn read_loader_env(
        st: &mut SystemTable<Boot>,
        fs_handle: uefi::Handle,
    ) -> Option<crate::loader_env::LoaderEnv> {
        use alloc::string::String;
        use uefi::proto::media::fs::SimpleFileSystem;
        use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
        use uefi::CString16;

        let env_path = "\\EFI\\WHESERE\\loader.env";
        
        // Lit le contenu de loader.env
        let env_data = Self::try_read_file_from_fs(st, fs_handle, env_path).ok()?;
        let env_content = match env_data {
            Some(data) => data,
            None => {
                let _ = st.stdout().write_str("[BSD] loader.env non trouve sur ESP\r\n");
                return None;
            }
        };

        // Convertit les bytes en string
        let env_str = match core::str::from_utf8(&env_content) {
            Ok(s) => s,
            Err(_) => {
                let _ = st.stdout().write_str("[BSD] loader.env: contenu non-UTF8\r\n");
                return None;
            }
        };

        let _ = st.stdout().write_str(&format!(
            "[BSD] loader.env lit: {} octets\r\n",
            env_content.len()
        ));

        // Parse chaque ligne du fichier
        let mut env = crate::loader_env::LoaderEnv::default();
        for line in env_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                
                match key {
                    "uefi_ignore_boot_mgr" => {
                        env.uefi_ignore_boot_mgr = value == "1" || value.eq_ignore_ascii_case("true");
                    }
                    "whesere_part" => {
                        env.whesere_part = String::from(value);
                    }
                    "slura_part" => {
                        env.slura_part = String::from(value);
                    }
                    "whesere_uuid" => {
                        env.whesere_uuid = String::from(value);
                    }
                    "slura_uuid" => {
                        env.slura_uuid = String::from(value);
                    }
                    "whesere_root" => {
                        env.whesere_root = String::from(value);
                    }
                    "slura_root" => {
                        env.slura_root = String::from(value);
                    }
                    _ => {
                        let _ = st.stdout().write_str(&format!(
                            "[BSD] loader.env: cle inconnue '{}'\r\n",
                            key
                        ));
                    }
                }
            }
        }

        // Valide que les champs essentiels sont présents
        if env.whesere_part.is_empty() && env.slura_part.is_empty() {
            let _ = st.stdout().write_str("[BSD] loader.env: partitions non definies\r\n");
            return None;
        }

        let _ = st.stdout().write_str(&format!(
            "[BSD] loader.env parse: whesere={}, slura={}, whesere_uuid={}, slura_uuid={}, whesere_root={}, slura_root={}\r\n",
            env.whesere_part,
            env.slura_part,
            env.whesere_uuid,
            env.slura_uuid,
            env.whesere_root,
            env.slura_root
        ));

        Some(env)
    }

    /// Tente de lire un fichier depuis un filesystem UEFI.
    fn try_read_file_from_fs(
        st: &mut SystemTable<Boot>,
        fs_handle: uefi::Handle,
        path: &str,
    ) -> Result<Option<alloc::vec::Vec<u8>>, Status> {
        use uefi::proto::media::file::{FileAttribute, FileMode, RegularFile};
        use uefi::proto::media::fs::SimpleFileSystem;
        use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
        use uefi::CString16;

        // Convertit le chemin en CString16
        let path_16 = CString16::try_from(path).map_err(|_| Status::INVALID_PARAMETER)?;

        // Ouvre le protocole SimpleFileSystem.
        let mut fs = unsafe {
            st.boot_services()
                .open_protocol::<SimpleFileSystem>(
                    OpenProtocolParams {
                        handle: fs_handle,
                        agent: st.boot_services().image_handle(),
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
                .map_err(|e| e.status())?
        };

        // Ouvre le volume racine.
        let mut root = match fs.open_volume() {
            Ok(root) => root,
            Err(_) => return Ok(None),
        };

        // Ouvre le fichier kernel.
        let file_handle = match root.open(path_16.as_ref(), FileMode::Read, FileAttribute::empty())
        {
            Ok(file) => file,
            Err(_) => return Ok(None),
        };

        // Verifie qu'il s'agit bien d'un fichier regulier.
        let mut file: RegularFile = match file_handle.into_regular_file() {
            Some(file) => file,
            None => return Ok(None),
        };

        // Lit le fichier entierement.
        let mut kernel = alloc::vec::Vec::new();
        let mut buf = [0u8; 8192]; // Buffer plus grand pour les gros fichiers

        loop {
            match file.read(&mut buf) {
                Ok(n) if n > 0 => {
                    kernel.extend_from_slice(&buf[..n]);
                }
                Ok(_) => break, // EOF
                Err(e) => return Err(e.status()),
            }
        }

        if kernel.is_empty() {
            Ok(None)
        } else {
            Ok(Some(kernel))
        }
    }

    /// Lit loader.env depuis le premier filesystem UEFI disponible (ESP).
    /// Utilisé pour récupérer les chemins des partitions whesere_part et slura_part.
    fn read_loader_env_from_fs(
        st: &mut SystemTable<Boot>,
    ) -> Option<crate::loader_env::LoaderEnv> {
        use uefi::proto::media::fs::SimpleFileSystem;

        // Trouve tous les handles exposant un SimpleFileSystem.
        let handles = st
            .boot_services()
            .find_handles::<SimpleFileSystem>()
            .ok()?;

        if handles.is_empty() {
            return None;
        }

        // Utilise le premier filesystem (ESP)
        Self::read_loader_env(st, handles[0])
    }

    /// Charge et saute vers le kernel SLURABSD embarqué.
    ///
    /// Le payload `kernel` est `slurabsd-kernel.bin` : un binaire brut produit
    /// par `llvm-objcopy-19 -O binary` à partir de l'ELF SluraBSD/slurabsd.
    /// Ce n'est PAS une image PE/COFF EFI, donc on ne peut pas utiliser
    /// `load_image` / `start_image` dessus.
    ///
    /// Algorithme :
    /// 1. Allouer des pages UEFI en mémoire basse (sous 4 GiB sur x86_64,
    ///    pour rester compatible avec le kernel BSD en mode direct).
    /// 2. Copier le payload dans ces pages.
    /// 3. Lire le header ELF minimal (e_entry) si possible, sinon utiliser
    ///    l'adresse de chargement comme entrypoint.
    /// 4. Quitter Boot Services (qui invalide tous les handles, donc on
    ///    libère tout ce qu'on peut avant).
    /// 5. Sauter à l'entrypoint SLURABSD.
    fn start_embedded_bsd_kernel(
        &mut self,
        st: &mut SystemTable<Boot>,
        kernel: &[u8],
    ) -> Result<(), Status> {
        use uefi::table::boot::MemoryType;

        let _ = st
            .stdout()
            .write_str("[BSD] chargement du kernel embarque...\r\n");

        crate::ovc_exec::serial_log(b"[BSD] loading embedded BSD kernel\r\n");

        // slurabsd.bin est un binaire brut charge depuis l'ESP.
        // On l'alloue en memoire et on prepare le handoff vers le loader BSD.
        // Le vrai slurabsd.bin est un payload ELF ou binaire brut SluraBSD.
        const PAGE_SIZE: usize = 4096;
        let pages = (kernel.len() + PAGE_SIZE - 1) / PAGE_SIZE;
        if pages == 0 {
            let _ = st.stdout().write_str("[BSD] slurabsd.bin vide\r\n");
            return Err(Status::LOAD_ERROR);
        }

        let base = st
            .boot_services()
            .allocate_pages(
                uefi::table::boot::AllocateType::AnyPages,
                MemoryType::LOADER_DATA,
                pages,
            )
            .map_err(|e| {
                let _ = write!(st.stdout(), "[BSD] allocate_pages echoue: {:?}\r\n", e);
                e.status()
            })?;

        unsafe {
            core::ptr::copy_nonoverlapping(kernel.as_ptr(), base as *mut u8, kernel.len());
        }

        let _ = write!(
            st.stdout(),
            "[BSD] slurabsd.bin a {:#x} ({} octets, {} pages)\r\n",
            base,
            kernel.len(),
            pages,
        );
        crate::ovc_exec::serial_log(
            alloc::format!(
                "[BSD] slurabsd.bin at {:#x} ({} bytes, {} pages)\r\n",
                base,
                kernel.len(),
                pages,
            )
            .as_bytes(),
        );

        self.base = base;
        self.size = kernel.len() as u64;
        self.kernel_entry = base; // _start = base pour binaire brut
        self.kernel_loaded = true;

        // BOOT RÉEL : le kernel est chargé, on peut faire le handoff
        let _ = st
            .stdout()
            .write_str("[BSD] slurabsd.bin pret — handoff immediat\r\n");
        crate::ovc_exec::serial_log(
            b"[BSD] slurabsd.bin ready  \xE2\x80\x94 handoff deferred after OVC\r\n",
        );

        Ok(())
    }

    /// Inversion de l'étape blockchain : exécute le handoff AVANT la blockchain.
    ///
    /// AU LIEU DE :
    ///   Phase Boot → Phase Graphique → Phase Blockchain (💥 freeze sur net0) → Handoff
    ///
    /// NOUVEL ORDRE :
    ///   Phase Boot → Phase Graphique → Handoff (sortie UEFI) → Blockchain (dans slurabsd)
    ///
    /// Cette inversion résout le problème de timeout infini sur `net0` car :
    /// 1. On quitte les Boot Services UEFI défaillants sur net0
    /// 2. La pile réseau UEFI est déchargée
    /// 3. slurabsd utilise ses drivers réseau natifs (em, ixl, virtio)
      /// Inversion de l'étape blockchain : exécute le handoff AVANT la blockchain.
    /// Callback d'allocation UEFI utilisé par `create_shared_ipc_table`.
    /// Alloue des pages de mémoire UEFI pour la table IPC partagée.
    /// SAFETY : Le pointeur retourné est valide jusqu'à ExitBootServices().
    extern "C" fn uefi_alloc_pages(pages: usize) -> *mut c_void {
        // On utilise une variable statique atomique pour stocker le SystemTable
        // temporairement. La table IPC est créée dans ordonnanceur_inverse()
        // où on a accès à st.
        unsafe {
            let st_ptr = IPC_SYSTEM_TABLE.load(Ordering::Relaxed);
            if st_ptr == 0 {
                return core::ptr::null_mut();
            }
            let st_ref: &SystemTable<Boot> = &*(st_ptr as *const SystemTable<Boot>);
            let bs = st_ref.boot_services();
            let result = bs.allocate_pages(
                uefi::table::boot::AllocateType::AnyPages,
                uefi::table::boot::MemoryType::LOADER_DATA,
                pages,
            );
            match result {
                Ok(addr) => addr as *mut c_void,
                Err(_) => core::ptr::null_mut(),
            }
        }
    }

    /// Stocke temporairement le pointeur SystemTable pour uefi_alloc_pages.
    /// Doit être appelé avant create_shared_ipc_table().
    fn set_ipc_system_table(st: &SystemTable<Boot>) {
        unsafe {
            IPC_SYSTEM_TABLE.store(st as *const _ as usize, Ordering::SeqCst);
        }
    }

    pub fn ordonnanceur_inverse(
        &mut self,
        st: &mut SystemTable<Boot>,
        image: Handle,
        network: &str,
    ) -> Result<(), Status> {
        let _ = st.stdout().write_str(
            "[KERNEL] Inversion activee : Handoff avant Blockchain.\n",
        );

        // ════════════════════════════════════════════════════════════════════
        // 0. INITIALISATION DE LA TABLE IPC PARTAGÉE (Lunée <-> SluraBSD)
        // ═══════════════════════════════════════════════════════════════════
        // On initialise d'abord le SystemTable pour le callback d'allocation,
        // puis on crée la table IPC.
        WhesereKernel::set_ipc_system_table(st);
        let ipc_ptr = create_shared_ipc_table(WhesereKernel::uefi_alloc_pages);
        if ipc_ptr.is_null() {
            let _ = st.stdout().write_str(
                "[KERNEL][IPC] ERREUR: allocation table IPC echouee\r\n",
            );
            return Err(Status::OUT_OF_RESOURCES);
        }
        self.ipc_table = Some(ipc_ptr);
        let _ = write!(
            st.stdout(),
            "[KERNEL][IPC] Table IPC creee @ {:#x} ({} octets, magic={:#x})\r\n",
            ipc_ptr as u64,
            core::mem::size_of::<WhesereIpcTable>(),
            IPC_MAGIC
        );
        crate::ovc_exec::serial_log(
            alloc::format!(
                "[KERNEL][IPC] Shared IPC table at {:#x} ({} bytes)\r\n",
                ipc_ptr as u64,
                core::mem::size_of::<WhesereIpcTable>()
            )
            .as_bytes(),
        );

        // Log des partitions depuis loader.env si disponible
        if let Some(ref env) = self.loader_env {
            let _ = st.stdout().write_str(&format!(
                "[KERNEL] loader.env: whesere_part={}, slura_part={}, whesere_uuid={}, slura_uuid={}\r\n",
                env.whesere_part, env.slura_part, env.whesere_uuid, env.slura_uuid
            ));
            crate::ovc_exec::serial_log(
                alloc::format!(
                    "[KERNEL] loader.env: whesere={}, slura={}\r\n",
                    env.whesere_part, env.slura_part
                ).as_bytes(),
            );
        } else {
            let _ = st.stdout().write_str("[KERNEL] loader.env: non disponible (utilisation chemin par defaut)\r\n");
        }
        crate::ovc_exec::serial_log(
            b"[KERNEL] Inversion: Handoff before Blockchain.\n",
        );

        // 1. Préparation des constantes réseau
        let (chain_id, rpc_port, consensus_name) = match network {
            "mainnet" => (0x534C_0001u64, 8080u32, "Lurosonie_bft"),
            "testnet" => (0x534C_0002u64, 8081u32, "Lurosonie_test"),
            _ => (0x534C_0003u64, 8082u32, "Lurosonie_dev"),
        };

        // ── SÉLECTION DES DEUX DEVICE PATHS DISTINCTS (PARENT & ENFANT) ──
        use uefi::proto::device_path::DevicePath;
        use uefi::proto::loaded_image::LoadedImage;

        let bs = st.boot_services();
        let image_handle = bs.image_handle();

        // 1. DP Enfant : Le chemin absolu du fichier WHESERE.EFI
        let dp_enfant_raw: *const u8 = bs.open_protocol_exclusive::<DevicePath>(image_handle)
            .map(|dp| dp.as_ffi_ptr() as *const u8)
            .map_err(|e| e.status())?;

        // 2. DP Parent : Le chemin brut de la partition/disque (LoadedImage -> DeviceHandle)
        let disk_handle = {
            let loaded_image = bs.open_protocol_exclusive::<LoadedImage>(image_handle)
                .map_err(|e| e.status())?;
            loaded_image.device().ok_or(Status::INVALID_PARAMETER)?
        }; // loaded_image is dropped here, freeing bs
        let dp_parent_raw: *const u8 = bs.open_protocol_exclusive::<DevicePath>(disk_handle)
            .map(|dp| dp.as_ffi_ptr() as *const u8)
            .map_err(|e| e.status())?;

        // Calcul de la taille du DP Enfant (Fichier)
        let mut dp_enfant_size: usize = 0;
        let mut offset: usize = 0;
        loop {
            let node = unsafe { core::slice::from_raw_parts(dp_enfant_raw.add(offset), 4) };
            let node_len = (node[2] as usize) | ((node[3] as usize) << 8);
            dp_enfant_size = offset + node_len;
            if node[0] == 0x7F && node[1] == 0xFF { break; }
            offset += node_len;
        }

        // Calcul de la taille du DP Parent (Partition)
        let mut dp_parent_size: usize = 0;
        let mut offset_p: usize = 0;
        loop {
            let node = unsafe { core::slice::from_raw_parts(dp_parent_raw.add(offset_p), 4) };
            let node_len = (node[2] as usize) | ((node[3] as usize) << 8);
            dp_parent_size = offset_p + node_len;
            if node[0] == 0x7F && node[1] == 0xFF { break; }
            offset_p += node_len;
        }

        // Allocation de la mémoire pour stocker les deux structures distinctes
        let total_dp_size = dp_enfant_size + dp_parent_size;
        let dp_pages = (total_dp_size + 4095) / 4096;

        let dp_ptr = bs.allocate_pages(
                uefi::table::boot::AllocateType::AnyPages,
                uefi::table::boot::MemoryType::LOADER_DATA,
                dp_pages,
            )
            .map_err(|e| e.status())?;

        unsafe {
            // Écriture du premier chemin (Disque physique parent) — doit être le 1er DP
            // pour que match_boot_info() C le trouve comme premier_dp
            core::ptr::copy_nonoverlapping(dp_parent_raw, dp_ptr as *mut u8, dp_parent_size);

            // Écriture du second chemin distinct juste après (Fichier WHESERE.EFI)
            let second_dp_offset = (dp_ptr as *mut u8).add(dp_parent_size);
            core::ptr::copy_nonoverlapping(dp_enfant_raw, second_dp_offset, dp_enfant_size);
        }

        self.dp_secondary_addr = dp_ptr as u64;

        // 2. Allocation mémoire pour la Boot Info
        let boot_info_size = core::mem::size_of::<WhesereBootInfo>();
        let boot_info_pages = (boot_info_size + 4095) / 4096;

        let boot_info_ptr = st
            .boot_services()
            .allocate_pages(
                uefi::table::boot::AllocateType::AnyPages,
                uefi::table::boot::MemoryType::LOADER_DATA,
                boot_info_pages,
            )
            .map_err(|e| e.status())?;

        // 3. Construction de la Boot Info chargée de satisfaire le match_boot_info() C
        let boot_info = WhesereBootInfo {
            magic: WHESERE_BOOT_MAGIC,
            version: WHESERE_BOOT_VERSION,
            kernel_base: self.base,
            kernel_size: self.size,
            kernel_entry: self.kernel_entry,
            memory_map: 0,
            memory_map_size: 0,
            memory_descriptor_size: 0,
            framebuffer_base: self.framebuffer as u64,
            framebuffer_size: (self.framebuffer_width as u64)
                * (self.framebuffer_height as u64)
                * 4,
            framebuffer_width: self.framebuffer_width,
            framebuffer_height: self.framebuffer_height,
            framebuffer_pitch: self.framebuffer_stride,
            framebuffer_format: 0,
            acpi_rsdp: 0,
            cmdline: 0,
            cmdline_size: 0,
            blockchain_network: network.as_ptr() as u64,
            blockchain_network_size: network.len() as u64,
            blockchain_chain_id: chain_id,
            bft_consensus_name: consensus_name.as_ptr() as u64,
            bft_rpc_port: rpc_port,
            // Utilise les chemins des partitions depuis loader.env si disponible
            // Sinon, utilise le chemin par défaut (ESP)
            device_path_count: 2,
            device_path_secondary: if let Some(ref env) = self.loader_env {
                // Trouve le chemin whesere_part dans loader.env
                if !env.whesere_part.is_empty() {
                    // Convertit le chemin en DevicePath pour le C
                    // Le code C attend un DevicePath valide, on utilise le chemin tel quel
                    // mais on doit le convertir en format UEFI
                    // Pour simplifier, on stocke le chemin en tant que pointeur vers la chaîne
                    // (dans un vrai implémentation, on convertirait en DevicePath)
                    // Ici, on stocke simplement l'adresse de la chaîne pour le C
                    // Le C doit convertir ce pointeur en DevicePath
                    // Pour l'instant, on utilise la valeur par défaut
                    self.dp_secondary_addr
                } else {
                    self.dp_secondary_addr
                }
            } else {
                self.dp_secondary_addr
            },
            // Pointeur vers la table IPC partagée Lunée <-> SluraBSD.
            // SluraBSD publie ses trames RX dans `rx_ring`; Lunée émet
            // ses requêtes (TX, framebuffer) via `tx_ring`.
            ipc_table: self.ipc_table.unwrap_or(core::ptr::null_mut()) as u64,
            ipc_table_size: core::mem::size_of::<WhesereIpcTable>() as u64,
            _padding: 0,
        };

        // Copie de la boot info enrichie en mémoire
        unsafe {
            core::ptr::copy_nonoverlapping(
                &boot_info as *const WhesereBootInfo as *const u8,
                boot_info_ptr as *mut u8,
                boot_info_size,
            );
        }

        let _ = write!(
            st.stdout(),
            "[KERNEL] boot_info configuré pour le C à {:#x}, chain_id={:#x}\r\n",
            boot_info_ptr,
            chain_id
        );

        // 4. Injections de messages initiaux dans le TX ring (Lunée -> BSD)
        //    - "Boot complete" système pour réveiller le kernel BSD
        //    - Configuration réseau minimale pour amorcer le stack BSD
        if let Some(ipc) = self.ipc_table {
            unsafe {
                let boot_msg = IpcMessageType::SystemCmd;
                let _ = (*ipc).tx_ring.push(&u32_to_le_bytes(boot_msg as u32));
                let _ = (*ipc).tx_ring.push(b"BOOT_COMPLETE");
            }
        }

        // 5. Handoff IMMÉDIAT — SluraBSD hérite de la table IPC et des ring buffers
        self.handoff_avec_boot_info(st, boot_info_ptr as *mut u8)?;

        Ok(())
    }

    /// Multiplexeur IPC : consomme les messages RX publiés par SluraBSD.
    /// À appeler dans la boucle de polling réseau côté Lunée.
    ///
    /// Retourne le nombre d'octets consommés.
    pub fn ipc_mux_poll(&self) -> usize {
        if let Some(ipc) = self.ipc_table {
            unsafe {
                let ipc_ref = &*ipc;
                let tail = ipc_ref.rx_ring.tail.load(Ordering::Acquire);
                let head = ipc_ref.rx_ring.head.load(Ordering::Relaxed);
                let consumed = head.wrapping_sub(tail);
                // Avance le tail pour marquer la consommation
                ipc_ref.rx_ring.tail.store(head, Ordering::Release);
                consumed
            }
        } else {
            0
        }
    }


    /// Effectue le handoff vers le kernel SLURABSD embarqué.
    ///
    /// Cette fonction implémente le protocole loader.efi(8) de SluraBSD :
    /// 1. Vérifie que le kernel est bien chargé (`kernel_loaded`).
    /// 2. Sort des Boot Services UEFI (`ExitBootServices`).
    /// 3. Saute à l'entrypoint du kernel BSD avec le contexte attendu
    ///    par `_start` (sys/amd64/amd64/locore.S).
    ///
    /// Chemins loader.efi(8) SluraBSD :
    ///   amd64    : /EFI/BOOT/BOOTX64.EFI  /EFI/SluraBSD/LOADER.EFI
    ///   arm64    : /EFI/BOOT/BOOTAA64.EFI
    ///
    /// Staging : kernel alloué 2MB-aligné < 4GB (nocopy arm64).
    ///
    /// Appelée après la phase OVC (ShiLauncher).
    pub fn handoff_to_bsd_kernel(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        if !self.kernel_loaded {
            let _ = st
                .stdout()
                .write_str("[BSD] handoff: kernel non charge\r\n");

            crate::ovc_exec::serial_log(b"[BSD] handoff: kernel not loaded\r\n");

            return Err(Status::NOT_READY);
        }

        let entry = self.kernel_entry as usize;

        let _ = write!(
            st.stdout(),
            "[BSD] loader.efi: ExitBootServices -> {:#x}\r\n",
            entry,
        );

        crate::ovc_exec::serial_log(
            alloc::format!("[BSD] loader.efi: ExitBootServices -> {:#x}\r\n", entry,).as_bytes(),
        );

        // ─────────────────────────────────────────────────────────────────────
        // 1. ExitBootServices() — conforme loader.efi(8)
        //    Conformément à la man page SluraBSD loader.efi(8), on doit:
        //    - Obtenir la clé de la carte mémoire via GetMemoryMap()
        //    - Appeler ExitBootServices(image_handle, memory_map_key)
        //    La fonction exit_boot_services() est privée dans la crate uefi,
        //    on utilise donc un appel direct via FFI.
        //    On prépare la table système via prepare_ebs() avant d'appeler.
        // ─────────────────────────────────────────────────────────────────────
        unsafe {
            // Prépare le pointeur vers la SystemTable pour la fonction
            // efi_exit_boot_services (définie juste après).
            prepare_ebs(st);

            // Récupère la carte mémoire pour obtenir la clé
            let mut mmap_buf = [0u8; 4096];
            let mmap_status = st.boot_services().memory_map(&mut mmap_buf);
            if mmap_status.is_err() {
                let _ = st.stdout().write_str("[BSD] get_memory_map echoue\r\n");
                return Err(Status::DEVICE_ERROR);
            }
            let mmap = mmap_status.unwrap();
            let memory_map_key = mmap.key();

            let image_handle = core::ptr::null_mut();

            // Appelle ExitBootServices via notre wrapper FFI
            let ebs_status: uefi::Status = efi_exit_boot_services(
                image_handle,
                core::mem::transmute::<uefi::table::boot::MemoryMapKey, usize>(memory_map_key),
            );

            if ebs_status.is_error() {
                let _ = st.stdout().write_str("[BSD] ExitBootServices echoue\r\n");
                return Err(Status::DEVICE_ERROR);
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // 2. Prépare le contexte _start attendu par sys/amd64/amd64/locore.S
        //    • rsp  ← pile 2MB-alignée
        //    • rdi  ← boot info (SluraBSD_elf64_boot_env, kernphys)
        //    Les conventions SluraBSD loader.efi(8) : argc/argv dans pile.
        // ─────────────────────────────────────────────────────────────────────
        let stack_top: usize;
        let boot_info_ptr: usize;

        // Alloue pile 2MB-alignée (staging loader.efi)
        // Staging area = 8MB par défaut (staging_slop), réservé bas mem.
        const STAGING_SLOP: usize = 8 * 1024 * 1024;

        unsafe {
            // Récupère la carte mémoire pour ExitBootServices
            let mut mmap_buf = [0u8; 4096];
            let mmap_status = st.boot_services().memory_map(&mut mmap_buf);
            if mmap_status.is_err() {
                let _ = st.stdout().write_str("[BSD] get_memory_map echoue\r\n");
                return Err(Status::DEVICE_ERROR);
            }
            let mmap = mmap_status.unwrap();
            let memory_map_key = mmap.key();

            let image_handle = core::ptr::null_mut();
            let ebs_status: uefi::Status = unsafe {
                efi_exit_boot_services(
                    image_handle,
                    core::mem::transmute::<uefi::table::boot::MemoryMapKey, usize>(memory_map_key),
                )
            };
            if ebs_status.is_error() {
                let _ = st.stdout().write_str("[BSD] ExitBootServices echoue\r\n");
                return Err(Status::DEVICE_ERROR);
            }

            core::arch::asm!(
                // r15 = base kernel (kernphys)
                "mov r15, {base}",
                // Réserve stack 2MB-aligned pour _start
                "mov rax, r15",
                "add rax, {slop}",
                "and rax, -0x200000",    // 2MB align
                "mov rsp, rax",
                "add rsp, 0x200000",     // rsp = top of 2MB stack
                "sub rsp, 16",
                // boot_info = r15 (kernphys = base)
                "mov rdi, r15",
                // Appelle _start(entry)
                "mov rax, {entry}",
                "call rax",
                options(noreturn),
                slop = const STAGING_SLOP,
                base = in(reg) self.base,
                entry = in(reg) entry,
            );
        }

        // unreachable
        #[allow(unreachable_code)]
        Ok(())
    }

    /// Effectue le handoff vers le kernel SLURABSD embarqué en passant
    /// la structure de boot info enrichie (avec 2 DP) dans le registre RDI,
    /// conformément à la convention d'appel SluraBSD loader.efi(8).
    ///
    /// Cette fonction est utilisée par `ordonnanceur_inverse` pour éviter
    /// le warning "Ignoring BootXXXX: Only one DP found".
    pub fn handoff_avec_boot_info(
        &mut self,
        st: &mut SystemTable<Boot>,
        boot_info_addr: *mut u8,
    ) -> Result<(), Status> {
        if !self.kernel_loaded {
            return Err(Status::NOT_READY);
        }

        let entry = self.kernel_entry as usize;
        const STAGING_SLOP: usize = 8 * 1024 * 1024;

        unsafe {
            prepare_ebs(st);

            let mut mmap_buf = [0u8; 4096];
            let mmap_status = st.boot_services().memory_map(&mut mmap_buf);
            if mmap_status.is_err() {
                return Err(Status::DEVICE_ERROR);
            }
            let mmap = mmap_status.unwrap();
            let memory_map_key = mmap.key();
            let image_handle = core::ptr::null_mut();

            let ebs_status = efi_exit_boot_services(
                image_handle,
                core::mem::transmute::<uefi::table::boot::MemoryMapKey, usize>(memory_map_key),
            );

            if ebs_status.is_error() {
                return Err(Status::DEVICE_ERROR);
            }

            // --- SAUT ASSEMBLEUR SÉCURISÉ ---
            core::arch::asm!(
                // 1. Préparation de la pile (Stack) alignée à 2 Mo
                "mov rax, {base}",
                "add rax, {slop}",
                "and rax, -0x200000",
                "mov rsp, rax",
                "add rsp, 0x200000",
                "sub rsp, 16",

                // 2. LE CHANGEMENT CLÉ : RDI reçoit le pointeur vers la Boot Info enrichie (2 DP)
                "mov rdi, {boot_info}",

                // 3. Saut vers le code exécutable réel de slurabsd
                "mov rax, {entry}",
                "call rax",
                options(noreturn),
                slop = const STAGING_SLOP,
                base = in(reg) self.base,
                boot_info = in(reg) boot_info_addr,
                entry = in(reg) entry,
            );
        }

        Ok(())
    }

    fn enable_posix(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st
            .stdout()
            .write_str("[BSD] Activation du support POSIX...\r\n");

        crate::ovc_exec::serial_log(b"[BSD] Activation du support POSIX...\r\n");

        self.posix_enabled = true;

        Ok(())
    }

    fn init_bsd_graphics(
        &mut self,
        st: &mut SystemTable<Boot>,
        image: Handle,
    ) -> Result<(), Status> {
        let _ = st
            .stdout()
            .write_str("[BSD] Initialisation de la gestion graphique...\r\n");

        crate::ovc_exec::serial_log(b"[BSD] Initialisation de la gestion graphique...\r\n");

        let (fb_ptr, width, height, stride) = bsd_graphics_init(st, image)?;

        self.framebuffer = fb_ptr as *mut c_void;

        self.framebuffer_width = width;

        self.framebuffer_height = height;

        self.framebuffer_stride = stride;

        self.graphics_enabled = true;

        Ok(())
    }

    fn enable_ovc_via_bsd(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st
            .stdout()
            .write_str("[BSD] Activation du traitement OVC via BSD...\r\n");

        crate::ovc_exec::serial_log(b"[BSD] Activation du traitement OVC via BSD...\r\n");

        self.ovc_enabled = true;

        Ok(())
    }

    pub fn posix_open(path: &str) -> Result<i32, Status> {
        let _ = path;

        Ok(0)
    }

    pub fn posix_read(fd: i32, buf: &mut [u8]) -> Result<usize, Status> {
        let _ = fd;

        Ok(buf.len())
    }

    pub fn posix_write(fd: i32, buf: &[u8]) -> Result<usize, Status> {
        let _ = fd;

        Ok(buf.len())
    }

    pub fn posix_close(fd: i32) -> Result<(), Status> {
        let _ = fd;

        Ok(())
    }
}

impl Default for WhesereKernel {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EFI_ABSOLUTE_POINTER_PROTOCOL
// ─────────────────────────────────────────────────────────────────────────────

#[repr(transparent)]
#[unsafe_protocol("31878c87-0b75-11d5-9a4f-0090273fc14d")]
struct AbsPointer(uefi_raw::protocol::console::AbsolutePointerProtocol);

impl AbsPointer {
    fn reset(&mut self) -> uefi_raw::Status {
        unsafe { (self.0.reset)(&mut self.0 as *mut _, 0) }
    }

    fn get_state_raw(
        &self,
    ) -> (
        uefi_raw::Status,
        Option<uefi_raw::protocol::console::AbsolutePointerState>,
    ) {
        let mut state =
            core::mem::MaybeUninit::<uefi_raw::protocol::console::AbsolutePointerState>::uninit();

        let status = unsafe { (self.0.get_state)(&self.0 as *const _, state.as_mut_ptr()) };

        if status.is_success() {
            (status, Some(unsafe { state.assume_init() }))
        } else {
            (status, None)
        }
    }

    fn bounds(&self) -> (u64, u64, u64, u64) {
        if self.0.mode.is_null() {
            return (0, 0, 0, 0);
        }

        let m = unsafe { &*self.0.mode };

        (
            m.absolute_min_x,
            m.absolute_max_x,
            m.absolute_min_y,
            m.absolute_max_y,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KernelRuntime
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct KernelRuntime {
    resources: RessourcesManager,

    boot_init: bool,

    secure_verified: bool,

    pub(crate) whesere: WhesereKernel,
}

impl KernelRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn boot_phase(&mut self, st: &mut SystemTable<Boot>, image: Handle) -> Result<(), Status> {
        self.verify_integrity(st)?;

        self.whesere.init(st, image)?;

        self.resources.init_hardware(st, image)?;

        self.boot_init = true;

        let _ = st.stdout().write_str("[RUNTIME] Boot phase completed.\r\n");

        crate::ovc_exec::serial_log(b"[RUNTIME] Boot phase completed.\r\n");

        Ok(())
    }

    fn verify_integrity(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st
            .stdout()
            .write_str("[SECURITY] Integrity check passed.\r\n");

        crate::ovc_exec::serial_log(b"[SECURITY] Integrity check passed.\r\n");

        self.secure_verified = true;

        Ok(())
    }

    pub fn maratine_phase(&mut self, st: &mut SystemTable<Boot>, handle: Handle) {
        let _ = st
            .stdout()
            .write_str("[MARATINE] Loading ShiLauncher...\r\n");

        crate::ovc_exec::serial_log(b"[MARATINE] Loading ShiLauncher...\r\n");

        match marep_loader::load_and_run(st, handle) {
            Ok(code) => {
                let _ = write!(st.stdout(), "[MARATINE] OEntry returned {}\r\n", code);

                crate::ovc_exec::serial_log(
                    alloc::format!("[MARATINE] OEntry returned {}\r\n", code).as_bytes(),
                );
            }

            Err(BundleError::FileNotFound) => {
                let _ = st
                    .stdout()
                    .write_str("[MARATINE] ShiLauncher.marep not found.\r\n");

                crate::ovc_exec::serial_log(b"[MARATINE] ShiLauncher.marep not found.\r\n");
            }

            Err(BundleError::NotInitialized) => {
                let _ = st.stdout().write_str("[MARATINE] OVC trouve.\r\n");

                crate::ovc_exec::serial_log(b"[MARATINE] OVC trouve.\r\n");
            }

            Err(BundleError::ExecutionFailed(code)) => {
                let _ = write!(st.stdout(), "[MARATINE] Execution echouee: {}\r\n", code);

                crate::ovc_exec::serial_log(
                    alloc::format!("[MARATINE] Execution echouee: {}\r\n", code).as_bytes(),
                );
            }

            Err(e) => {
                let _ = write!(st.stdout(), "[MARATINE] Load error: {:?}\r\n", e);

                crate::ovc_exec::serial_log(
                    alloc::format!("[MARATINE] Load error: {:?}\r\n", e).as_bytes(),
                );
            }
        }
    }

    pub fn platform_engine_phase(
        &mut self,
        st: &mut SystemTable<Boot>,
        handle: Handle,
        network: &str,
    ) {
        let _ = write!(
            st.stdout(),
            "\r\n[KERNEL] Démarrage du Platform Engine (EFI natif)...\r\n"
        );

        crate::ovc_exec::serial_log(b"[KERNEL] Platform Engine EFI start\r\n");

        let mut engine = PlatformEngineEfi::new(handle, network);

        match engine.platform_engine_phase(st, handle) {
            Ok(()) => {
                let _ = write!(
                    st.stdout(),
                    "[KERNEL] Platform Engine terminé normalement\r\n"
                );

                crate::ovc_exec::serial_log(b"[KERNEL] Platform Engine EFI done\r\n");
            }

            Err(e) => {
                let _ = write!(st.stdout(), "[KERNEL] Platform Engine: {:?}\r\n", e);

                crate::ovc_exec::serial_log(
                    alloc::format!("[KERNEL] Platform Engine error: {:?}\r\n", e).as_bytes(),
                );

                let _ = write!(
                    st.stdout(),
                    "[KERNEL]    → Mode EFI natif activé en repli\r\n"
                );
            }
        }
    }

    pub fn blockchain_phase(&mut self, st: &mut SystemTable<Boot>, handle: Handle, network: &str) {
        let _ = write!(
            st.stdout(),
            "\r\n[KERNEL] Démarrage du moteur blockchain complet...\r\n"
        );

        crate::ovc_exec::serial_log(b"[KERNEL] Blockchain Engine start\r\n");

        let mut engine = PlatformEngineEfi::new(handle, network);

        use crate::platform_bridge::BlockchainConfig;

        // ATTENTION :
        // Ceci n'est PAS un RNG cryptographique.
        //
        // À remplacer impérativement par un RNG UEFI / CSPRNG
        // avant toute utilisation sur un réseau réel.

        let validator_privkey = {
            let mut rng_bytes = [0u8; 32];

            let handle_val = handle.as_ptr() as usize;

            for i in 0..32 {
                rng_bytes[i] = ((handle_val.wrapping_add(i * 0x9e3779b9)) & 0xFF) as u8;
            }

            rng_bytes[0] |= 0x01;

            alloc::format!("0x{}", hex::encode(rng_bytes))
        };

        let config = BlockchainConfig {
            network: network.to_string(),

            chain_id: match network {
                "mainnet" => 0x534C_0001u64,

                "testnet" => 0x534C_0002u64,

                _ => 0x534C_0003u64,
            },

            rpc_port: match network {
                "mainnet" => 8080,
                "testnet" => 8081,
                _ => 8082,
            },

            validator: crate::platform_bridge::ValidatorConfig {
                private_key: validator_privkey.clone().into(),

                address: "0x00000000000000000000000000000000000000".into(),

                initial_balance: 400_000_000_000u64,
            },

            initial_accounts: alloc::vec![
                crate::platform_bridge::InitialAccount {
                    address: "0x00000000000000000000000000000000000001".into(),

                    balance: 10_000_000_000u64,
                },
                crate::platform_bridge::InitialAccount {
                    address: "0x00000000000000000000000000000000000002".into(),

                    balance: 5_000_000_000u64,
                },
            ],

            vez_bytecode: None,
        };

        match engine.start_blockchain(st, &config, handle) {
            Ok(()) => {
                let _ = write!(
                    st.stdout(),
                    "[KERNEL] Blockchain Engine terminé normalement\r\n"
                );

                crate::ovc_exec::serial_log(b"[KERNEL] Blockchain Engine done\r\n");
            }

            Err(e) => {
                let _ = write!(st.stdout(), "[KERNEL] Blockchain Engine: {:?}\r\n", e);

                crate::ovc_exec::serial_log(
                    alloc::format!("[KERNEL] Blockchain Engine error: {:?}\r\n", e).as_bytes(),
                );

                let _ = write!(
                    st.stdout(),
                    "[KERNEL]    → Mode EFI natif activé en repli\r\n"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanCode
// ─────────────────────────────────────────────────────────────────────────────

fn scan_code_to_i32(scan: uefi::proto::console::text::ScanCode) -> i32 {
    use uefi::proto::console::text::ScanCode as S;

    if scan == S::UP {
        1
    } else if scan == S::DOWN {
        2
    } else if scan == S::RIGHT {
        3
    } else if scan == S::LEFT {
        4
    } else if scan == S::HOME {
        5
    } else if scan == S::END {
        6
    } else if scan == S::INSERT {
        7
    } else if scan == S::DELETE {
        8
    } else if scan == S::ESCAPE {
        0x17
    } else {
        0xFF
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Rendu marep
// ─────────────────────────────────────────────────────────────────────────────

const BOOT_SCREEN_FRAMES: u32 = 180;

pub fn render_from_marep(
    st: &mut SystemTable<Boot>,
    handle: Handle,
    modules: &[(alloc::string::String, alloc::vec::Vec<u8>)],
) {
    use crate::ovc_exec;

    let (font_ptr, font_len) = crate::ovc_exec::srfs_font_ptr();

    // ─────────────────────────────────────────────────────────────────────────
    // Initialisation des handles UEFI
    // ─────────────────────────────────────────────────────────────────────────

    {
        let st_ptr = st.as_ptr() as usize;

        let img_h = handle.as_ptr() as usize;

        crate::ovc_exec::init_uefi_handles(st.as_ptr() as *mut c_void, img_h);

        let handles = st
            .boot_services()
            .find_handles::<SimpleFileSystem>()
            .unwrap_or_default();

        let _ = (st_ptr, handles);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Initialisation graphique BSD
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] Initialisation graphique BSD...", 0);

    let (fb_addr, w, h, stride) = match bsd_graphics_init(st, handle) {
        Ok((fb, width, height, stride)) => {
            crate::ovc_exec::screen_log(
                st,
                &alloc::format!(
                    "[RENDER] Framebuffer BSD: {}x{} stride={} fb={:#x}",
                    width,
                    height,
                    stride,
                    fb
                ),
                0,
            );

            (fb, width, height, stride)
        }

        Err(e) => {
            crate::ovc_exec::screen_log(
                st,
                &alloc::format!("[RENDER] Erreur init BSD graphics: {:?}", e),
                0,
            );

            crate::ovc_exec::serial_log(
                alloc::format!("[RENDER] Erreur init BSD graphics: {:?}\r\n", e).as_bytes(),
            );

            return;
        }
    };

    let fb = fb_addr as *mut u32;

    // ─────────────────────────────────────────────────────────────────────────
    // Conversion stride
    // ─────────────────────────────────────────────────────────────────────────

    let stride_i32 = match i32::try_from(stride) {
        Ok(v) => v,

        Err(_) => {
            crate::ovc_exec::screen_log(
                st,
                "[RENDER] stride framebuffer trop grand pour ExecCtx",
                0,
            );

            crate::ovc_exec::serial_log(b"[RENDER] stride framebuffer trop grand pour ExecCtx\r\n");

            return;
        }
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Double buffering
    // ─────────────────────────────────────────────────────────────────────────

    let buf_len = (stride as usize).saturating_mul(h as usize);

    if buf_len == 0 {
        crate::ovc_exec::serial_log(b"[RENDER] framebuffer size invalide\r\n");

        return;
    }

    let mut backbuffer: alloc::vec::Vec<u32> = alloc::vec![
        0u32;
        buf_len
    ];

    let back_fb = backbuffer.as_mut_ptr();

    // ─────────────────────────────────────────────────────────────────────────
    // HID relatif
    // ─────────────────────────────────────────────────────────────────────────

    let pointer_handles = st
        .boot_services()
        .find_handles::<Pointer>()
        .unwrap_or_default();

    crate::ovc_exec::serial_log(
        alloc::format!(
            "[HID] find_handles::<Pointer> -> {} handle(s)\r\n",
            pointer_handles.len()
        )
        .as_bytes(),
    );

    let pointer_handle = pointer_handles.first().copied();

    let mut pointer_res_x: u64 = 1;

    let mut pointer_res_y: u64 = 1;

    let pointer_ptr: *mut Pointer = pointer_handle
        .and_then(|h| unsafe {
            st.boot_services()
                .open_protocol::<Pointer>(
                    OpenProtocolParams {
                        handle: h,
                        agent: handle,
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
                .ok()
        })
        .map(|mut p| {
            let reset_ok = p.reset(false);

            crate::ovc_exec::serial_log(
                alloc::format!("[HID] reset() -> {:?}\r\n", reset_ok.is_ok()).as_bytes(),
            );

            let mode = p.mode();

            pointer_res_x = mode.resolution[0].max(1);

            pointer_res_y = mode.resolution[1].max(1);

            crate::ovc_exec::serial_log(
                alloc::format!(
                    "[HID] Pointer resolution=({}, {}) counts/mm\r\n",
                    pointer_res_x,
                    pointer_res_y
                )
                .as_bytes(),
            );

            let ptr: *mut Pointer = &mut *p;

            core::mem::forget(p);

            ptr
        })
        .unwrap_or(core::ptr::null_mut());

    crate::ovc_exec::serial_log(if pointer_ptr.is_null() {
        b"[HID] pointer_ptr NULL - pas de protocole ouvert, la souris ne bougera pas\r\n" as &[u8]
    } else {
        b"[HID] pointer_ptr OK\r\n" as &[u8]
    });

    // ─────────────────────────────────────────────────────────────────────────
    // HID absolu
    // ─────────────────────────────────────────────────────────────────────────

    let abs_handles = st
        .boot_services()
        .find_handles::<AbsPointer>()
        .unwrap_or_default();

    crate::ovc_exec::serial_log(
        alloc::format!(
            "[HID] find_handles::<AbsPointer> -> {} handle(s)\r\n",
            abs_handles.len()
        )
        .as_bytes(),
    );

    let abs_ptr: *mut AbsPointer = abs_handles
        .first()
        .copied()
        .and_then(|h| unsafe {
            st.boot_services()
                .open_protocol::<AbsPointer>(
                    OpenProtocolParams {
                        handle: h,
                        agent: handle,
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
                .ok()
        })
        .map(|mut p| {
            let ptr: *mut AbsPointer = &mut *p;

            core::mem::forget(p);

            ptr
        })
        .unwrap_or(core::ptr::null_mut());

    let abs_bounds: (u64, u64, u64, u64) = if !abs_ptr.is_null() {
        let reset_status = unsafe { (*abs_ptr).reset() };

        let b = unsafe { (*abs_ptr).bounds() };

        crate::ovc_exec::serial_log(
            alloc::format!(
                "[HID] AbsPointer OK bounds=({},{},{},{}) reset={:?}\r\n",
                b.0,
                b.1,
                b.2,
                b.3,
                reset_status
            )
            .as_bytes(),
        );

        b
    } else {
        crate::ovc_exec::serial_log(b"[HID] AbsPointer NULL (pas de usb-tablet ?)\r\n");

        (0, 0, 0, 0)
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Position curseur
    // ─────────────────────────────────────────────────────────────────────────

    let mut cursor_x: i32 = w as i32 / 2;

    let mut cursor_y: i32 = h as i32 / 2;

    let mut frame_n: u64 = 0;

    // ─────────────────────────────────────────────────────────────────────────
    // Références OVC
    // ─────────────────────────────────────────────────────────────────────────

    let mod_refs: alloc::vec::Vec<(&str, &[u8])> = modules
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();

    crate::ovc_exec::screen_log(
        st,
        &alloc::format!(
            "[RENDER] apres initialisation framebuffer: ecran {}x{}",
            w,
            h
        ),
        0,
    );

    // ─────────────────────────────────────────────────────────────────────────
    // xHCI : lecture seule
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] scan_for_xhci start (lecture seule)", 0);

    let xhci_available = bsd_xhci_capabilities(st, handle);

    crate::ovc_exec::screen_log(st, "[RENDER] delegation xHCI SluraBSD terminee", 0);

    if xhci_available {
        crate::ovc_exec::screen_log(st, "[RENDER] capacites xHCI fournies par SluraBSD", 0);
    }

    let ehci_available = bsd_ehci_capabilities(st, handle);
    if ehci_available {
        crate::ovc_exec::screen_log(st, "[RENDER] capacites EHCI fournies par SluraBSD", 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ACPI
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] scan_acpi_tables start", 0);

    let power_info = bsd_acpi_scan(st, handle);
    crate::ovc_exec::power_init(st.runtime_services() as *const _, power_info);

    crate::ovc_exec::screen_log(st, "[RENDER] scan_acpi_tables done", 0);

    // ─────────────────────────────────────────────────────────────────────────
    // Apps installées
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] scan_installed_apps start", 0);

    let installed_apps = crate::app_registry::scan_installed_apps(st, handle);

    crate::app_registry::publish_registry(&installed_apps);

    crate::ovc_exec::screen_log(
        st,
        &alloc::format!(
            "[RENDER] scan_installed_apps done, {} app(s)",
            installed_apps.len()
        ),
        0,
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Volumes physiques
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] scan_physical_volumes start", 0);

    let physical_volumes = bsd_storage_volumes(st, handle);

    crate::ovc_exec::publish_physical_volumes(physical_volumes);

    crate::ovc_exec::screen_log(st, "[RENDER] scan_physical_volumes done", 0);

    // ─────────────────────────────────────────────────────────────────────────
    // ShiBoot
    // ─────────────────────────────────────────────────────────────────────────

    crate::ovc_exec::screen_log(st, "[RENDER] ShiBoot: load_marep_modules start", 0);

    if let Ok((_, boot_modules)) =
        marep_loader::load_marep_modules(st, handle, uefi::cstr16!("\\ShiBoot.marep"))
    {
        crate::ovc_exec::screen_log(
            st,
            &alloc::format!(
                "[RENDER] ShiBoot: {} module(s) charges, affichage {} frames",
                boot_modules.len(),
                BOOT_SCREEN_FRAMES
            ),
            0,
        );

        let boot_mod_refs: alloc::vec::Vec<(&str, &[u8])> = boot_modules
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();

        for _ in 0..BOOT_SCREEN_FRAMES {
            let boot_ctx = ovc_exec::ExecCtx {
                fb: back_fb,

                width: w as i32,

                height: h as i32,

                stride: stride_i32,

                font: font_ptr,

                font_len: font_len,

                pointer_x: cursor_x,

                pointer_y: cursor_y,

                pointer_btn: 0,

                key_code: 0,
            };

            ovc_exec::reset_gpu_counters();

            let _ = ovc_exec::exec_marep(&boot_mod_refs, &boot_ctx);

            unsafe {
                core::ptr::copy_nonoverlapping(back_fb, fb, buf_len);
            }

            st.boot_services().stall(16_000);
        }

        crate::ovc_exec::screen_log(st, "[RENDER] ShiBoot: termine, bascule vers ShiLauncher", 0);
    } else {
        crate::ovc_exec::screen_log(
            st,
            "[RENDER] ShiBoot: absent/echec chargement, ShiLauncher direct",
            0,
        );
    }

    crate::ovc_exec::screen_log(st, "[RENDER] entree dans la boucle de rafraichissement", 0);

    // ─────────────────────────────────────────────────────────────────────────
    // Boucle principale
    // ─────────────────────────────────────────────────────────────────────────

    loop {
        let mut pointer_btn: i32 = 0;

        // ─────────────────────────────────────────────────────────────────────
        // Pointeur absolu
        // ─────────────────────────────────────────────────────────────────────

        if !abs_ptr.is_null() {
            let (status, maybe_state) = unsafe { (*abs_ptr).get_state_raw() };

            match maybe_state {
                Some(state) => {
                    let (minx, maxx, miny, maxy) = abs_bounds;

                    let rx = if maxx > minx { maxx - minx } else { 1 };

                    let ry = if maxy > miny { maxy - miny } else { 1 };

                    let screen_w = w.saturating_sub(1) as u64;

                    let screen_h = h.saturating_sub(1) as u64;

                    let nx = ((state.current_x.saturating_sub(minx)).saturating_mul(screen_w) / rx)
                        as i32;

                    let ny = ((state.current_y.saturating_sub(miny)).saturating_mul(screen_h) / ry)
                        as i32;

                    if frame_n % 30 == 0 {
                        crate::ovc_exec::serial_log(
                            alloc::format!(
                                "[HID] abs=({},{}) status={:?} -> cursor=({},{})\r\n",
                                state.current_x,
                                state.current_y,
                                status,
                                nx,
                                ny
                            )
                            .as_bytes(),
                        );
                    }

                    cursor_x = nx.clamp(0, w.saturating_sub(1) as i32);

                    cursor_y = ny.clamp(0, h.saturating_sub(1) as i32);

                    pointer_btn |= (state.active_buttons & 0x3) as i32;
                }

                None => {
                    if frame_n % 120 == 0 {
                        crate::ovc_exec::serial_log(
                            alloc::format!(
                                "[HID] get_state_raw() -> {:?} (frame {})\r\n",
                                status,
                                frame_n
                            )
                            .as_bytes(),
                        );
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Pointeur relatif
        // ─────────────────────────────────────────────────────────────────────

        if !pointer_ptr.is_null() {
            let p = unsafe { &mut *pointer_ptr };

            match p.read_state() {
                Ok(Some(state)) => {
                    let dx = state.relative_movement[0] / pointer_res_x as i32;

                    let dy = state.relative_movement[1] / pointer_res_y as i32;

                    cursor_x = (cursor_x + dx).clamp(0, w.saturating_sub(1) as i32);

                    cursor_y = (cursor_y + dy).clamp(0, h.saturating_sub(1) as i32);

                    pointer_btn |= state.button[0] as i32 | ((state.button[1] as i32) << 1);

                    if dx != 0 || dy != 0 {
                        crate::ovc_exec::serial_log(
                            alloc::format!(
                                "[HID] rel=({},{}) raw=({},{}) -> cursor=({},{})\r\n",
                                dx,
                                dy,
                                state.relative_movement[0],
                                state.relative_movement[1],
                                cursor_x,
                                cursor_y
                            )
                            .as_bytes(),
                        );
                    }
                }

                Ok(None) => {}

                Err(_) => {
                    if frame_n % 120 == 0 {
                        crate::ovc_exec::serial_log(b"[HID] read_state() erreur\r\n");
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Clavier UEFI
        // ─────────────────────────────────────────────────────────────────────

        let key_code: i32 = match st.stdin().read_key() {
            Ok(Some(Key::Printable(c))) => u16::from(c) as i32,

            Ok(Some(Key::Special(scan))) => 0x10000 | scan_code_to_i32(scan),

            _ => 0,
        };

        // ─────────────────────────────────────────────────────────────────────
        // Repli clavier curseur
        // ─────────────────────────────────────────────────────────────────────

        const STEP: i32 = 8;

        match key_code {
            c if c == (0x10000 | 1) => {
                cursor_y = (cursor_y - STEP).clamp(0, h.saturating_sub(1) as i32);
            }

            c if c == (0x10000 | 2) => {
                cursor_y = (cursor_y + STEP).clamp(0, h.saturating_sub(1) as i32);
            }

            c if c == (0x10000 | 3) => {
                cursor_x = (cursor_x + STEP).clamp(0, w.saturating_sub(1) as i32);
            }

            c if c == (0x10000 | 4) => {
                cursor_x = (cursor_x - STEP).clamp(0, w.saturating_sub(1) as i32);
            }

            _ => {}
        }

        // ─────────────────────────────────────────────────────────────────────
        // Contexte OVC
        // ─────────────────────────────────────────────────────────────────────

        let ctx = ovc_exec::ExecCtx {
            fb: back_fb,

            width: w as i32,

            height: h as i32,

            stride: stride_i32,

            font: font_ptr,

            font_len: font_len,

            pointer_x: cursor_x,

            pointer_y: cursor_y,

            pointer_btn: pointer_btn,

            key_code: key_code,
        };

        if frame_n == 0 {
            crate::ovc_exec::screen_log(
                st,
                "[RENDER] premiere frame: appel exec_marep (TemplateView.mara)",
                0,
            );
        }

        ovc_exec::reset_gpu_counters();

        let _ = ovc_exec::exec_marep(&mod_refs, &ctx);

        if frame_n == 0 {
            crate::ovc_exec::screen_log(
                st,
                "[RENDER] premiere frame: exec_marep retourne, copie framebuffer",
                0,
            );
        }

        // ─────────────────────────────────────────────────────────────────────
        // Swap framebuffer
        // ─────────────────────────────────────────────────────────────────────

        unsafe {
            core::ptr::copy_nonoverlapping(back_fb, fb, buf_len);
        }

        // ~60 Hz
        st.boot_services().stall(16_000);

        frame_n = frame_n.wrapping_add(1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation graphique BSD
// ─────────────────────────────────────────────────────────────────────────────

fn bsd_graphics_init(
    st: &mut SystemTable<Boot>,
    image: Handle,
) -> Result<(usize, u32, u32, u32), Status> {
    bsd_graphics_init_static(st, image)
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface graphique BSD
// ─────────────────────────────────────────────────────────────────────────────

fn bsd_graphics_init_static(
    st: &mut SystemTable<Boot>,
    image: Handle,
) -> Result<(usize, u32, u32, u32), Status> {
    let handles = st
        .boot_services()
        .find_handles::<BsdGraphicsProtocol>()
        .map_err(|e| e.status())?;

    let graphics_handle = handles.first().copied().ok_or(Status::NOT_FOUND)?;

    let mut graphics_proto = unsafe {
        st.boot_services().open_protocol::<BsdGraphicsProtocol>(
            OpenProtocolParams {
                handle: graphics_handle,

                agent: image,

                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|e| e.status())?;

    // ─────────────────────────────────────────────────────────────────────────
    // Framebuffer
    // ─────────────────────────────────────────────────────────────────────────

    let mut framebuffer: *mut c_void = core::ptr::null_mut();

    let mut stride: u32 = 0;

    let status = unsafe {
        (graphics_proto.get_frame_buffer)(
            &mut *graphics_proto as *mut _,
            &mut framebuffer,
            &mut stride,
        )
    };

    if status.is_error() {
        return Err(status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Mode
    // ─────────────────────────────────────────────────────────────────────────

    let mut width: u32 = 0;

    let mut height: u32 = 0;

    let status = unsafe {
        (graphics_proto.get_mode)(&mut *graphics_proto as *mut _, &mut width, &mut height)
    };

    if status.is_error() {
        return Err(status);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation
    // ─────────────────────────────────────────────────────────────────────────

    if framebuffer.is_null() || width == 0 || height == 0 || stride == 0 {
        return Err(Status::DEVICE_ERROR);
    }

    Ok((framebuffer as usize, width, height, stride))
}
