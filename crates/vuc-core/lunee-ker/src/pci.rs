//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — PCI enumeration (étape 1/N vers un pilote USB/HID natif) ___

//! Étape 1 d'un pilote USB/HID natif Slura (remplace à terme la dépendance aux
//! drivers USB/HID fournis par le firmware — UsbBusDxe/UsbMouseDxe d'OVMF).
//!
//! Ce module ne fait QUE de l'énumération PCI en lecture seule via
//! EFI_PCI_IO_PROTOCOL (`Pci.Read`, `GetLocation`) : aucune écriture, aucun
//! accès MMIO, aucune prise de possession de matériel. Objectif unique de
//! cette étape : localiser le contrôleur USB (classe PCI 0x0C, sous-classe
//! 0x03) et identifier s'il s'agit d'un contrôleur xHCI (prog-if 0x30), et
//! logguer son adresse BAR0 (MMIO) — sans encore la mapper/l'utiliser.
//!
//! EFI_PCI_IO_PROTOCOL n'a pas de wrapper sûr dans les crates `uefi`/`uefi-raw`
//! utilisées ici (seul `uefi_raw::protocol::pci` manque à l'appel) — le type
//! FFI brut est donc défini ici à la main, layout tiré de la spec UEFI (stable
//! et inchangée depuis 2006). Vérifié une seule fois via ce module avant toute
//! étape suivante (accès MMIO xHCI) qui, elle, serait dangereuse si le layout
//! était faux — d'où l'insistance sur du lecture-seule ici.

use crate::ovc_exec::serial_log;
use uefi::proto::unsafe_protocol;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::table::{Boot, SystemTable};
use uefi::Handle;
use uefi_raw::{guid, Guid, Status};

const PCI_IO_PROTOCOL_GUID: Guid = guid!("4cf5b200-68b8-4ca5-9eec-b23e3f50029a");

// u32 explicite plutôt que #[repr(C)] seul : la taille d'un enum C "nu" sous
// repr(C) dépend de l'ABI cible — u32 est sans ambiguïté et correspond à la
// taille réelle de EFI_PCI_IO_PROTOCOL_WIDTH sur toutes les toolchains UEFI.
#[repr(u32)]
#[allow(dead_code)]
enum PciIoWidth {
    Uint8 = 0,
    Uint16 = 1,
    Uint32 = 2,
    Uint64 = 3,
}

// Signatures minimales : seules `Pci.Read`/`Pci.Write` et `GetLocation` sont
// appelées à cette étape. Les autres champs du protocole doivent néanmoins
// être présents avec la BONNE TAILLE (des pointeurs de fonction opaques
// suffisent) pour que les offsets de `Pci`/`GetLocation` plus loin dans la
// struct soient corrects — un layout C ne tolère aucun champ manquant.
type OpaqueFn = unsafe extern "efiapi" fn();

type PciIoConfigFn = unsafe extern "efiapi" fn(
    this: *mut PciIoProtocolRaw,
    width: PciIoWidth,
    offset: u32,
    count: usize,
    buffer: *mut core::ffi::c_void,
) -> Status;

#[repr(C)]
struct PciIoConfigAccess {
    read:  PciIoConfigFn,
    write: PciIoConfigFn,
}

/// Signature de `Mem.Read`/`Mem.Write` — accès MMIO relatif à un BAR (index +
/// offset), PAS une adresse physique brute : c'est le mécanisme standard/
/// portable pour lire les registres d'un contrôleur PCI depuis EFI_PCI_IO_PROTOCOL
/// (spec UEFI §14.4.4), utilisé ici pour lire les registres de capacité xHCI.
type PciIoMemFn = unsafe extern "efiapi" fn(
    this: *mut PciIoProtocolRaw,
    width: PciIoWidth,
    bar_index: u8,
    offset: u64,
    count: usize,
    buffer: *mut core::ffi::c_void,
) -> Status;

type PciIoGetLocationFn = unsafe extern "efiapi" fn(
    this: *mut PciIoProtocolRaw,
    segment_number: *mut usize,
    bus_number: *mut usize,
    device_number: *mut usize,
    function_number: *mut usize,
) -> Status;

/// EFI_PCI_IO_PROTOCOL — layout complet (spec UEFI §14.4), même si seuls
/// `pci` et `get_location` sont utilisés pour l'instant.
#[repr(C)]
struct PciIoProtocolRaw {
    poll_mem:          OpaqueFn,
    poll_io:           OpaqueFn,
    mem_read:          PciIoMemFn,
    mem_write:         OpaqueFn,
    io_read:           OpaqueFn,
    io_write:          OpaqueFn,
    pci:               PciIoConfigAccess,
    copy_mem:          OpaqueFn,
    map:               OpaqueFn,
    unmap:             OpaqueFn,
    allocate_buffer:   OpaqueFn,
    free_buffer:       OpaqueFn,
    flush:             OpaqueFn,
    get_location:      PciIoGetLocationFn,
    attributes:        OpaqueFn,
    get_bar_attributes: OpaqueFn,
    set_bar_attributes: OpaqueFn,
    rom_size:          u64,
    rom_image:         *mut core::ffi::c_void,
}

#[repr(transparent)]
#[unsafe_protocol(PCI_IO_PROTOCOL_GUID)]
struct PciIo(PciIoProtocolRaw);

impl PciIo {
    fn location(&mut self) -> Option<(usize, usize, usize, usize)> {
        let (mut seg, mut bus, mut dev, mut func) = (0usize, 0usize, 0usize, 0usize);
        let status = unsafe {
            (self.0.get_location)(&mut self.0, &mut seg, &mut bus, &mut dev, &mut func)
        };
        if status.is_success() { Some((seg, bus, dev, func)) } else { None }
    }

    /// Lit `count` DWORD (u32) depuis l'espace de configuration PCI à `offset`.
    fn read_config32(&mut self, offset: u32, out: &mut [u32]) -> bool {
        let status = unsafe {
            (self.0.pci.read)(
                &mut self.0, PciIoWidth::Uint32, offset, out.len(),
                out.as_mut_ptr() as *mut core::ffi::c_void,
            )
        };
        status.is_success()
    }

    /// Lit `count` DWORD (u32) en MMIO, relatif au BAR `bar_index` (0 pour BAR0).
    fn read_mem32(&mut self, bar_index: u8, offset: u64, out: &mut [u32]) -> bool {
        let status = unsafe {
            (self.0.mem_read)(
                &mut self.0, PciIoWidth::Uint32, bar_index, offset, out.len(),
                out.as_mut_ptr() as *mut core::ffi::c_void,
            )
        };
        status.is_success()
    }

    /// Écrit `count` DWORD (u32) dans l'espace de configuration PCI à `offset`.
    /// Utilisé UNIQUEMENT pour activer Memory Space/Bus Master (registre
    /// Command, offset 0x04) avant l'accès MMIO au contrôleur xHCI — pas
    /// d'autre écriture de configuration PCI dans ce projet.
    fn write_config32(&mut self, offset: u32, data: &[u32]) -> bool {
        let status = unsafe {
            (self.0.pci.write)(
                &mut self.0, PciIoWidth::Uint32, offset, data.len(),
                data.as_ptr() as *mut core::ffi::c_void,
            )
        };
        status.is_success()
    }
}

/// S'assure que Memory Space Enable (bit 1) et Bus Master Enable (bit 2) sont
/// actifs dans le registre Command (offset 0x04) du contrôleur xHCI, AVANT
/// tout accès MMIO — sans Memory Space, les lectures/écritures sur BAR0
/// peuvent être silencieusement ignorées ; sans Bus Master, le contrôleur ne
/// peut pas faire de DMA vers les anneaux qu'on va lui donner (commande,
/// événements). `PciIo` reste privé à ce module — xhci.rs passe uniquement
/// par cette fonction, pas par le type lui-même.
pub fn enable_memory_and_bus_master(st: &mut SystemTable<Boot>, image_handle: Handle, xhci: &XhciInfo) -> bool {
    let mut pci_io = match unsafe {
        st.boot_services().open_protocol::<PciIo>(
            OpenProtocolParams { handle: xhci.handle, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(p) => p,
        Err(_) => {
            serial_log(b"[XHCI-INIT] impossible de rouvrir PciIo pour Command register\r\n");
            return false;
        }
    };
    let mut dw = [0u32; 1];
    if !pci_io.read_config32(0x04, &mut dw) {
        serial_log(b"[XHCI-INIT] lecture registre Command echouee\r\n");
        return false;
    }
    let before = dw[0];
    dw[0] |= 0x1 << 1; // Memory Space Enable
    dw[0] |= 0x1 << 2; // Bus Master Enable
    if dw[0] != before {
        if !pci_io.write_config32(0x04, &dw) {
            serial_log(b"[XHCI-INIT] ecriture registre Command echouee\r\n");
            return false;
        }
    }
    serial_log(alloc::format!("[XHCI-INIT] Command register = {:#x} (Memory+BusMaster actifs)\r\n", dw[0]).as_bytes());
    true
}

/// Résultat de la localisation du contrôleur USB.
pub struct XhciInfo {
    pub handle: Handle,
    pub bus: usize,
    pub device: usize,
    pub function: usize,
    pub bar0: u64,
}

/// Registres de capacité xHCI (xHCI Spec §5.3, offset 0 depuis BAR0) — tous en
/// lecture seule côté matériel, aucune écriture possible sur ce bloc.
pub struct XhciCapabilities {
    pub cap_length: u8,
    pub hci_version: u16,
    pub max_slots: u8,
    pub max_intrs: u16,
    pub max_ports: u8,
    pub ac64: bool,
    pub context_size_64: bool,
    pub ext_cap_ptr_dwords: u32,
    pub doorbell_offset: u32,
    pub runtime_offset: u32,
    /// Max Scratchpad Buffers (HCSPARAMS2 bits Hi[25:21]:Lo[31:27]) — nombre de
    /// pages de travail que le contrôleur EXIGE que l'OS lui fournisse via
    /// DCBAA[0]. QEMU met 0, mais beaucoup de contrôleurs réels demandent >0 et
    /// n'exécutent AUCUNE commande tant qu'elles ne sont pas allouées (product-grade).
    pub max_scratchpad_bufs: u32,
    /// Page Size supporté (PAGESIZE op reg §5.4.3) — taille de page attendue
    /// par le contrôleur pour les scratchpad buffers (généralement 4 Ko).
    pub page_size_bytes: u32,
}

/// Force le firmware à connecter (binder) tous les drivers de bus standards
/// disponibles sur tous les handles présents, de façon récursive — PCI Root
/// Bridge → PCI Bus → PciIo, mais aussi GOP (GraphicsOutput) et HID
/// (Pointer/AbsPointer/ConIn) selon la topologie ACPI/PCI de la machine.
/// QEMU/VMware préconnectent tout par défaut au boot, donc `find_handles::<T>()`
/// y voit déjà tous les devices (écran, souris, clavier, xHCI...) — mais un
/// firmware OEM réel ne "bind" souvent que ce qui est nécessaire au chemin de
/// boot minimal, et peut laisser d'autres devices/protocoles non connectés
/// tant que rien ne le demande explicitement (symptôme observé en bare-metal :
/// écran noir, clavier/souris inertes, xHCI introuvable — tous résolus par le
/// même appel). `ConnectController` est l'appel standard EFI_BOOT_SERVICES
/// pour déclencher ce binding (spec UEFI §7.3) — ce n'est ni une écriture
/// MMIO ni une prise de possession matérielle, juste une invocation des
/// drivers déjà fournis par le firmware. Erreurs ignorées par design :
/// beaucoup de handles n'ont simplement aucun driver à connecter (NOT_FOUND).
///
/// Appelée une seule fois, le plus tôt possible après l'entrée dans Boot
/// Services et avant tout `find_handles`/`open_protocol` (GOP, HID, PciIo).
///
/// Une seule passe : `connect_controller(recursive=true)` sur chaque handle
/// racine se propage déjà à ses enfants côté firmware (c'est le sens de
/// `recursive`) — répéter le scan complet sur du matériel réel avec beaucoup
/// de devices (SATA/NVMe/réseau/USB...) coûtait plusieurs secondes par passe,
/// fait pour un gain marginal (couvrir un xHCI derrière un bridge découvert
/// tardivement, cas rare). Un xHCI non détecté n'empêche de toute façon aucun
/// affichage (voir kernel_runtime.rs : le bloc d'init xHCI est simplement
/// sauté si absent) — mieux vaut une détection légèrement moins exhaustive
/// mais un boot rapide, cohérent avec QEMU/VMware.
pub fn connect_all_controllers(st: &mut SystemTable<Boot>) {
    let handles = match st.boot_services().locate_handle_buffer(SearchType::AllHandles) {
        Ok(h) => h,
        Err(_) => {
            serial_log(b"[PCI] locate_handle_buffer(AllHandles) echoue\r\n");
            return;
        }
    };
    for &h in handles.iter() {
        let _ = st.boot_services().connect_controller(h, None, None, true);
    }
    serial_log(alloc::format!(
        "[PCI] ConnectController tente sur {} handle(s)\r\n", handles.len()
    ).as_bytes());
}

/// Parcourt tous les devices PCI (lecture seule) et logue vendor/device/classe
/// pour chacun ; retourne les infos du premier contrôleur xHCI trouvé
/// (classe 0x0C, sous-classe 0x03, prog-if 0x30), s'il y en a un.
pub fn scan_for_xhci(st: &mut SystemTable<Boot>, image_handle: Handle) -> Option<XhciInfo> {
    connect_all_controllers(st);
    let handles = match st.boot_services().find_handles::<PciIo>() {
        Ok(h) => h,
        Err(_) => {
            serial_log(b"[PCI] find_handles::<PciIo> echoue (protocole absent ?)\r\n");
            return None;
        }
    };
    serial_log(alloc::format!("[PCI] {} device(s) PCI trouve(s)\r\n", handles.len()).as_bytes());

    let mut result: Option<XhciInfo> = None;

    for h in handles {
        let mut pci_io = match unsafe {
            st.boot_services().open_protocol::<PciIo>(
                OpenProtocolParams { handle: h, agent: image_handle, controller: None },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(p) => p,
            Err(_) => continue,
        };

        let loc = pci_io.location();

        // Offset 0x00 : Vendor ID (u16) | Device ID (u16) → lu comme 1 DWORD.
        // Offset 0x08 : Revision ID (u8) | Class Code sur 3 octets (prog-if,
        // sous-classe, classe, du octet le plus bas au plus haut) → 1 DWORD.
        let mut id_dw = [0u32; 1];
        let mut class_dw = [0u32; 1];
        let ok_id    = pci_io.read_config32(0x00, &mut id_dw);
        let ok_class = pci_io.read_config32(0x08, &mut class_dw);
        if !ok_id || !ok_class { continue; }

        let vendor_id = (id_dw[0] & 0xFFFF) as u16;
        let device_id = (id_dw[0] >> 16) as u16;
        let prog_if  = ((class_dw[0] >> 8)  & 0xFF) as u8;
        let subclass = ((class_dw[0] >> 16) & 0xFF) as u8;
        let class    = ((class_dw[0] >> 24) & 0xFF) as u8;

        let (seg, bus, dev, func) = loc.unwrap_or((0, 0, 0, 0));
        serial_log(alloc::format!(
            "[PCI] {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}:{:02x}:{:02x}\r\n",
            bus, dev, func, vendor_id, device_id, class, subclass, prog_if
        ).as_bytes());
        let _ = seg;

        // Classe 0x0C (Serial Bus Controller), sous-classe 0x03 (USB),
        // prog-if 0x30 (XHCI, USB3). 0x20 = EHCI/USB2, 0x00 = UHCI, 0x10 = OHCI.
        // Un contrôleur USB non-xHCI (EHCI/OHCI/UHCI, matériel plus ancien ou
        // config firmware différente) est logué explicitement même si ce module
        // ne sait piloter que du xHCI — sans ce log, son absence de la liste
        // finale se confondait avec "aucun contrôleur USB du tout" alors qu'il
        // peut très bien être présent sous une autre forme.
        if class == 0x0C && subclass == 0x03 && prog_if != 0x30 {
            serial_log(alloc::format!(
                "[PCI] controleur USB non-xHCI trouve en {:02x}:{:02x}.{} prog-if={:#04x} (EHCI=0x20/OHCI=0x10/UHCI=0x00) - non pilotable par ce module\r\n",
                bus, dev, func, prog_if
            ).as_bytes());
        }
        if class == 0x0C && subclass == 0x03 && prog_if == 0x30 && result.is_none() {
            // BAR0 : offset 0x10 dans l'espace de config. Un contrôleur xHCI
            // déclare toujours un BAR mémoire (bit 0 = 0) ; bits [2:1] indiquent
            // 32-bit (00) ou 64-bit (10). On lit BAR0 (+ BAR1 si 64-bit) et on
            // masque les bits de type/flags bas (4 bits pour un BAR mémoire).
            let mut bar = [0u32; 2];
            if pci_io.read_config32(0x10, &mut bar) {
                let is_64bit = (bar[0] & 0b110) == 0b100;
                let bar0: u64 = if is_64bit {
                    ((bar[0] & !0xF) as u64) | ((bar[1] as u64) << 32)
                } else {
                    (bar[0] & !0xF) as u64
                };
                serial_log(alloc::format!(
                    "[PCI] -> contrôleur xHCI trouvé en {:02x}:{:02x}.{} BAR0={:#x} (64-bit={})\r\n",
                    bus, dev, func, bar0, is_64bit
                ).as_bytes());
                result = Some(XhciInfo { handle: h, bus, device: dev, function: func, bar0 });
            }
        }
    }

    if result.is_none() {
        serial_log(b"[PCI] Aucun controleur xHCI (classe 0C:03:30) trouve\r\n");
    }
    result
}

/// Résultat de la localisation d'un modem WWAN/cellulaire PCI (M.2 ou carte
/// intégrée — les dongles USB ne sont PAS couverts ici, voir commentaire de
/// `scan_for_wwan_modem`).
pub struct WwanModemInfo {
    pub handle: Handle,
    pub bus: usize,
    pub device: usize,
    pub function: usize,
    pub vendor_id: u16,
    pub device_id: u16,
}

/// Parcourt tous les devices PCI (lecture seule, même mécanisme que
/// `scan_for_xhci`) à la recherche d'un modem WWAN/cellulaire réel — classe
/// 0x02 (Network Controller), sous-classe 0x80 ("Other network controller",
/// la convention PCI standard pour les cartes WWAN/cellulaires M.2, utilisée
/// par ex. par les modules Intel XMM7360/Fibocom/Quectel/Sierra Wireless).
/// Retourne le PREMIER trouvé, ou None si aucun (cas normal sur une VM QEMU/
/// VMware sans carte WWAN passthrough — état honnête, pas de simulation).
///
/// ⚠️ Couverture PARTIELLE assumée : un modem WWAN USB (dongle) ne serait PAS
/// détecté ici — `usb.rs` n'expose aucune énumération générique indépendante
/// du flux HID clavier/souris (voir investigation de cette session). Étendre
/// cette détection au bus USB est un travail distinct, non fait ici.
pub fn scan_for_wwan_modem(st: &mut SystemTable<Boot>, image_handle: Handle) -> Option<WwanModemInfo> {
    let handles = match st.boot_services().find_handles::<PciIo>() {
        Ok(h) => h,
        Err(_) => {
            serial_log(b"[WWAN-PCI] find_handles::<PciIo> echoue (protocole absent ?)\r\n");
            return None;
        }
    };

    let mut result: Option<WwanModemInfo> = None;

    for h in handles {
        let mut pci_io = match unsafe {
            st.boot_services().open_protocol::<PciIo>(
                OpenProtocolParams { handle: h, agent: image_handle, controller: None },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut id_dw = [0u32; 1];
        let mut class_dw = [0u32; 1];
        if !pci_io.read_config32(0x00, &mut id_dw) { continue; }
        if !pci_io.read_config32(0x08, &mut class_dw) { continue; }

        let vendor_id = (id_dw[0] & 0xFFFF) as u16;
        let device_id = (id_dw[0] >> 16) as u16;
        let subclass = ((class_dw[0] >> 16) & 0xFF) as u8;
        let class    = ((class_dw[0] >> 24) & 0xFF) as u8;

        if class == 0x02 {
            let (seg, bus, dev, func) = pci_io.location().unwrap_or((0, 0, 0, 0));
            let _ = seg;
            serial_log(alloc::format!(
                "[WWAN-PCI] controleur reseau {:02x}:{:02x}.{} vendor={:04x} device={:04x} classe=02:{:02x}\r\n",
                bus, dev, func, vendor_id, device_id, subclass
            ).as_bytes());
            if subclass == 0x80 && result.is_none() {
                result = Some(WwanModemInfo { handle: h, bus, device: dev, function: func, vendor_id, device_id });
            }
        }
    }

    if result.is_none() {
        serial_log(b"[WWAN-PCI] Aucun modem WWAN PCI (classe 02:80) trouve - etat honnetement non connecte\r\n");
    }
    result
}

/// Étape 2 : lit les registres de capacité xHCI (xHCI Spec §5.3, offset 0
/// depuis BAR0) via `PciIo.Mem.Read` (accès MMIO relatif au BAR, PAS un
/// pointeur physique brut — portable, ne suppose aucune correspondance
/// mémoire particulière). Lecture seule : ne réinitialise pas le contrôleur,
/// ne touche à aucun registre opérationnel — juste de quoi valider le layout
/// avant l'étape 3 (initialisation réelle, qui elle écrit dans le matériel).
pub fn read_xhci_capabilities(
    st: &mut SystemTable<Boot>,
    image_handle: Handle,
    xhci: &XhciInfo,
) -> Option<XhciCapabilities> {
    let mut pci_io = match unsafe {
        st.boot_services().open_protocol::<PciIo>(
            OpenProtocolParams { handle: xhci.handle, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(p) => p,
        Err(_) => {
            serial_log(b"[XHCI] impossible de rouvrir PciIo sur le handle xHCI\r\n");
            return None;
        }
    };

    // DWORD 0 : CAPLENGTH[7:0] | Reserved[15:8] | HCIVERSION[31:16] (BCD).
    let mut dw0 = [0u32; 1];
    if !pci_io.read_mem32(0, 0x00, &mut dw0) {
        serial_log(b"[XHCI] lecture registre de capacite (offset 0) echouee\r\n");
        return None;
    }
    let cap_length  = (dw0[0] & 0xFF) as u8;
    let hci_version = (dw0[0] >> 16) as u16;

    // HCSPARAMS1 (0x04) : MaxSlots[7:0] | MaxIntrs[18:8] | MaxPorts[31:24].
    let mut hcsparams1 = [0u32; 1];
    // HCSPARAMS2 (0x08) : ... | Max Scratchpad Bufs Hi[25:21] | Max Scratchpad Bufs Lo[31:27].
    let mut hcsparams2 = [0u32; 1];
    // HCCPARAMS1 (0x10) : AC64[0] | ... | CSZ[2] | ... | xECP[31:16] (DWORDS).
    let mut hccparams1 = [0u32; 1];
    // DBOFF (0x14) / RTSOFF (0x18) : offsets en octets depuis BAR0.
    let mut dboff  = [0u32; 1];
    let mut rtsoff = [0u32; 1];
    let ok = pci_io.read_mem32(0, 0x04, &mut hcsparams1)
        && pci_io.read_mem32(0, 0x08, &mut hcsparams2)
        && pci_io.read_mem32(0, 0x10, &mut hccparams1)
        && pci_io.read_mem32(0, 0x14, &mut dboff)
        && pci_io.read_mem32(0, 0x18, &mut rtsoff);
    if !ok {
        serial_log(b"[XHCI] lecture des registres de capacite (HCSPARAMS1/2/HCCPARAMS1/DBOFF/RTSOFF) echouee\r\n");
        return None;
    }

    let max_slots = (hcsparams1[0] & 0xFF) as u8;
    let max_intrs = ((hcsparams1[0] >> 8) & 0x7FF) as u16;
    let max_ports = ((hcsparams1[0] >> 24) & 0xFF) as u8;

    // Max Scratchpad Buffers = Hi[25:21] << 5 | Lo[31:27] (xHCI Spec §5.3.4).
    let sp_hi = (hcsparams2[0] >> 21) & 0x1F;
    let sp_lo = (hcsparams2[0] >> 27) & 0x1F;
    let max_scratchpad_bufs = (sp_hi << 5) | sp_lo;

    let ac64             = (hccparams1[0] & 0x1) != 0;
    let context_size_64  = (hccparams1[0] & 0x4) != 0;
    let ext_cap_ptr_dwords = hccparams1[0] >> 16;

    // PAGESIZE (op reg §5.4.3, à op_base+0x08 = cap_length+0x08 depuis BAR0) : bit n
    // positionné = page de 2^(n+12) octets supportée. On prend la plus petite (bit le
    // plus bas). Défaut sûr = 4 Ko si lecture impossible.
    let mut pagesize = [0u32; 1];
    let page_size_bytes = if pci_io.read_mem32(0, (cap_length as u64) + 0x08, &mut pagesize) {
        let bit = (pagesize[0] & 0xFFFF).trailing_zeros();
        1u32 << (bit + 12)
    } else { 4096 };

    // Bits bas réservés à masquer avant usage (xHCI Spec §5.3.7/§5.3.8).
    let doorbell_offset = dboff[0] & !0x3;
    let runtime_offset  = rtsoff[0] & !0x1F;

    serial_log(alloc::format!(
        "[XHCI] CAPLENGTH={:#x} HCIVERSION={:#x} MaxSlots={} MaxIntrs={} MaxPorts={}\r\n",
        cap_length, hci_version, max_slots, max_intrs, max_ports
    ).as_bytes());
    serial_log(alloc::format!(
        "[XHCI] AC64={} ContextSize64={} xECP={:#x} DBOFF={:#x} RTSOFF={:#x}\r\n",
        ac64, context_size_64, ext_cap_ptr_dwords, doorbell_offset, runtime_offset
    ).as_bytes());
    serial_log(alloc::format!(
        "[XHCI] MaxScratchpadBufs={} PageSize={} octets\r\n",
        max_scratchpad_bufs, page_size_bytes
    ).as_bytes());

    Some(XhciCapabilities {
        cap_length, hci_version, max_slots, max_intrs, max_ports,
        ac64, context_size_64, ext_cap_ptr_dwords, doorbell_offset, runtime_offset,
        max_scratchpad_bufs, page_size_bytes,
    })
}
