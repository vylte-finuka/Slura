//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — énumération USB + pilote HID boot protocol (étapes 4-5/N) ___

//! Étapes 4 (énumération USB) et 5 (pilote de classe HID boot protocol),
//! au-dessus du contrôleur xHCI initialisé par xhci.rs (étape 3).
//!
//! Portée volontairement réduite (cf. décision utilisateur — étape 7 séparée
//! pour le support HID générique) :
//!   - Contextes de device 32 octets uniquement (context_size_64 non géré —
//!     si le contrôleur l'exige, on logue et on abandonne proprement).
//!   - MaxPacketSize de EP0 fixé à 8 (correct pour Low/Full Speed — la
//!     majorité des souris/claviers émulés QEMU ; High/SuperSpeed avec des
//!     tailles réelles de 64/512 ne sont pas gérées ici).
//!   - Uniquement le "boot protocol" HID (clavier 8 octets, souris 3-4
//!     octets) — pas de parsing de report descriptor générique.
//!   - Un seul segment de transfert par endpoint, taille modeste.
//!
//! C'est la partie la plus complexe et la moins vérifiable à l'aveugle de
//! tout ce chantier (contrairement aux étapes 1-3, plus mécaniques) — à
//! tester et affiner avec de vrais retours matériel/QEMU.

use crate::ovc_exec::serial_log;
use crate::xhci::{alloc_pages_zeroed, mmio_read32, mmio_write32, mmio_write64, wait_bit, PAGE_SIZE, XhciController};
use uefi::table::{Boot, SystemTable};

// ── PORTSC (xHCI Spec §5.4.8) ────────────────────────────────────────────────
const PORTSC_CCS:   u32 = 1 << 0;  // Current Connect Status (RO)
const PORTSC_PED:   u32 = 1 << 1;  // Port Enabled/Disabled (RW1CS)
const PORTSC_PR:    u32 = 1 << 4;  // Port Reset (RW1S)
const PORTSC_PP:    u32 = 1 << 9;  // Port Power (RW)
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK:  u32 = 0xF << PORTSC_SPEED_SHIFT;
const PORTSC_RW1C_MASK: u32 = 0x00FE_0000; // bits 17-23 : *C (change) bits

/// Masque à appliquer à une valeur PORTSC lue avant d'y ajouter les bits
/// qu'on veut réellement modifier — sinon toute écriture PORTSC risquerait
/// de désactiver le port (PED) ou d'acquitter des *Change bits par accident.
fn portsc_preserve(current: u32) -> u32 {
    current & !PORTSC_RW1C_MASK & !PORTSC_PED
}

// ── TRB Types utilisés (xHCI Spec Table 6-91) ───────────────────────────────
const TRB_SETUP_STAGE:      u32 = 2;
const TRB_DATA_STAGE:       u32 = 3;
const TRB_STATUS_STAGE:     u32 = 4;
const TRB_NORMAL:           u32 = 1;
const TRB_ENABLE_SLOT_CMD:  u32 = 9;
const TRB_ADDRESS_DEV_CMD:  u32 = 11;
const TRB_CONFIG_EP_CMD:    u32 = 12;
const TRB_EVAL_CONTEXT_CMD: u32 = 13;
const TRB_TRANSFER_EVENT:   u32 = 32;
const TRB_CMD_COMPLETION:   u32 = 33;
const TRB_PORT_STATUS_CHG:  u32 = 34;

const EP_TYPE_CONTROL:      u32 = 4;
const EP_TYPE_INTERRUPT_IN: u32 = 7;

const CTRL_RING_TRBS: usize = 16;
const INTR_RING_TRBS: usize = 16;

/// Un device HID identifié et configuré (boot protocol) — l'appelant
/// (kernel_runtime.rs) poll `poll_report` chaque frame.
pub struct HidDevice {
    pub slot_id: u8,
    pub is_keyboard: bool,
    pub is_mouse: bool,
    pub intr_ep_dci: u8,
    pub intr_ring: *mut u8,
    pub intr_ring_trbs: usize,
    pub intr_enqueue_index: usize,
    pub intr_pcs: bool,
    pub report_buf: *mut u8,
    pub report_len: usize,
}

unsafe fn zero(ptr: *mut u8, len: usize) {
    core::ptr::write_bytes(ptr, 0, len);
}

/// Écrit un Link TRB de bouclage au dernier slot d'un anneau fraîchement
/// alloué (même convention que le Command Ring, xHCI Spec §4.9.2).
unsafe fn install_link_trb(ring: *mut u8, trbs: usize) {
    let link_off = ((trbs - 1) * 16) as u64;
    mmio_write64(ring, link_off, ring as u64);
    mmio_write32(ring, link_off + 8, 0);
    let control: u32 = (6u32 << 10) | (1 << 1) | 1; // Type=Link, TC=1, Cycle=1
    mmio_write32(ring, link_off + 12, control);
}

/// Place un TRB "Normal" ou de contrôle dans un anneau de transfert generique
/// (même logique de retournement de cycle que submit_command, mais sans
/// sonner de doorbell ici — l'appelant décide quand sonner).
unsafe fn enqueue_transfer_trb(
    ring: *mut u8, trbs: usize, enqueue_index: &mut usize, pcs: &mut bool,
    parameter: u64, status: u32, control_no_cycle: u32,
) -> u64 {
    if *enqueue_index == trbs - 1 {
        let off = (*enqueue_index * 16) as u64;
        let mut ctrl = mmio_read32(ring, off + 12);
        ctrl = (ctrl & !1) | (*pcs as u32);
        mmio_write32(ring, off + 12, ctrl);
        *pcs = !*pcs;
        *enqueue_index = 0;
    }
    let idx = *enqueue_index;
    let off = (idx * 16) as u64;
    let control = (control_no_cycle & !1) | (*pcs as u32);
    mmio_write64(ring, off, parameter);
    mmio_write32(ring, off + 8, status);
    mmio_write32(ring, off + 12, control);
    *enqueue_index += 1;
    ring as u64 + off
}

/// Complétion d'une commande : poll l'anneau d'événements jusqu'à une
/// Command Completion Event (xHCI Spec §6.4.2.1) — retourne (completion_code, slot_id_or_0).
fn wait_command_completion(st: &mut SystemTable<Boot>, xhci: &mut XhciController, max_tries: u32) -> Option<(u8, u8)> {
    let trb = xhci.poll_event(st, max_tries)?;
    if trb.trb_type() != TRB_CMD_COMPLETION { return None; }
    let completion_code = (trb.status >> 24) as u8;
    let slot_id = (trb.control >> 24) as u8;
    Some((completion_code, slot_id))
}

/// Transfert de contrôle bloquant sur EP0 (DCI=1) : Setup [+ Data] + Status.
/// `data` : buffer pour la phase Data (lecture si `data_in`, écriture sinon) ;
/// vide = pas de phase Data. Retourne le nombre d'octets transférés (best
/// effort) ou None en cas d'échec/timeout.
#[allow(clippy::too_many_arguments)]
fn control_transfer(
    st: &mut SystemTable<Boot>, xhci: &mut XhciController,
    slot_id: u8, ep0_ring: *mut u8, ep0_idx: &mut usize, ep0_pcs: &mut bool,
    bm_request_type: u8, b_request: u8, w_value: u16, w_index: u16,
    data: Option<&mut [u8]>, data_in: bool,
) -> Option<usize> {
    let w_length: u16 = data.as_ref().map(|d| d.len() as u16).unwrap_or(0);
    let setup_param: u64 = (bm_request_type as u64)
        | ((b_request as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((w_length as u64) << 48);
    let transfer_type: u32 = if w_length == 0 { 0 } else if data_in { 3 } else { 2 };
    let setup_control = (TRB_SETUP_STAGE << 10) | (1 << 6) /* IDT */ | (transfer_type << 16);
    unsafe { enqueue_transfer_trb(ep0_ring, CTRL_RING_TRBS, ep0_idx, ep0_pcs, setup_param, 8, setup_control); }

    if let Some(buf) = &data {
        let dir_bit: u32 = if data_in { 1 << 16 } else { 0 };
        let data_control = (TRB_DATA_STAGE << 10) | dir_bit;
        unsafe {
            enqueue_transfer_trb(
                ep0_ring, CTRL_RING_TRBS, ep0_idx, ep0_pcs,
                buf.as_ptr() as u64, buf.len() as u32, data_control,
            );
        }
    }

    // Direction de la Status Stage = opposée à la Data Stage (ou IN si pas de
    // Data, xHCI Spec §4.11.2.2).
    let status_dir_bit: u32 = if w_length == 0 || !data_in { 1 << 16 } else { 0 };
    let status_control = (TRB_STATUS_STAGE << 10) | status_dir_bit | (1 << 5) /* IOC */;
    unsafe { enqueue_transfer_trb(ep0_ring, CTRL_RING_TRBS, ep0_idx, ep0_pcs, 0, 0, status_control); }

    xhci.ring_doorbell(slot_id, 1); // DCI 1 = EP0 control

    // Attend la Transfer Event de la Status Stage (marquée IOC).
    for _ in 0..500 {
        if let Some(trb) = xhci.poll_event(st, 1) {
            if trb.trb_type() == TRB_TRANSFER_EVENT {
                let completion_code = (trb.status >> 24) as u8;
                if completion_code == 1 || completion_code == 13 {
                    // 1=Success, 13=Short Packet (normal si le device renvoie
                    // moins que demandé, ex. descripteur plus court).
                    let remaining = trb.status & 0xFFFFFF;
                    let transferred = (w_length as u32).saturating_sub(remaining) as usize;
                    return Some(if w_length == 0 { 0 } else { transferred });
                }
                serial_log(alloc::format!("[USB] control_transfer: completion_code={} (echec)\r\n", completion_code).as_bytes());
                return None;
            }
        }
    }
    serial_log(b"[USB] control_transfer: timeout attente Transfer Event\r\n");
    None
}

/// Étapes 4+5 : parcourt tous les ports, énumère + configure en boot protocol
/// HID le premier clavier et la première souris trouvés. Chaque échec de
/// port est loggé et on passe au suivant (pas d'abandon global).
pub fn enumerate_and_setup_hid(
    st: &mut SystemTable<Boot>,
    xhci: &mut XhciController,
    max_ports: u8,
) -> alloc::vec::Vec<HidDevice> {
    let mut devices = alloc::vec::Vec::new();

    // Après HCRST, alimenter TOUS les ports (PP=1) AVANT de tester la connexion :
    // le bit CCS n'est VALIDE qu'une fois le port sous tension (xHCI Spec §4.19.1.1),
    // et la détection de connexion prend quelques ms. Sans ça, CCS lu à 0 partout juste
    // après le reset → "0 device(s)" (bug observé au boot : la souris existe côté
    // firmware mais aucun port ne remonte CCS car les ports sortent du HCRST non alimentés).
    for port in 1..=max_ports {
        let portsc = xhci.read_portsc(port);
        if (portsc & PORTSC_PP) == 0 {
            xhci.write_portsc(port, portsc_preserve(portsc) | PORTSC_PP);
        }
    }
    st.boot_services().stall(50_000); // 50ms : stabilisation alimentation + détection de connexion

    for port in 1..=max_ports {
        let mut portsc = xhci.read_portsc(port);
        // Attend l'apparition de la connexion (CCS=1) jusqu'à ~100ms : après un HCRST le
        // device peut mettre quelques dizaines de ms à se ré-annoncer sur le port.
        if (portsc & PORTSC_CCS) == 0 {
            let mut connected = false;
            for _ in 0..100 {
                st.boot_services().stall(1000);
                portsc = xhci.read_portsc(port);
                if (portsc & PORTSC_CCS) != 0 { connected = true; break; }
            }
            if !connected {
                serial_log(alloc::format!("[USB] port {} : rien connecte (PORTSC={:#x})\r\n", port, portsc).as_bytes());
                continue;
            }
        }
        serial_log(alloc::format!("[USB] port {} : device connecte (PORTSC={:#x})\r\n", port, portsc).as_bytes());

        let cur = xhci.read_portsc(port);
        xhci.write_portsc(port, portsc_preserve(cur) | PORTSC_PR);
        if !wait_bit(st, xhci.op_base, crate::xhci::PORTSC_BASE + (port as u64 - 1) * crate::xhci::PORTSC_STRIDE, 1 << 21, 1 << 21, 500) {
            serial_log(alloc::format!("[USB] port {} : timeout Port Reset Change, abandon ce port\r\n", port).as_bytes());
            continue;
        }
        let post_reset = xhci.read_portsc(port);
        xhci.write_portsc(port, portsc_preserve(post_reset) | (1 << 21)); // acquitte PRC
        if (post_reset & PORTSC_PED) == 0 {
            serial_log(alloc::format!("[USB] port {} : PED=0 apres reset, abandon ce port\r\n", port).as_bytes());
            continue;
        }
        let speed = (post_reset & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT;
        serial_log(alloc::format!("[USB] port {} : reset OK, speed={}\r\n", port, speed).as_bytes());

        // Enable Slot.
        xhci.submit_command(0, 0, TRB_ENABLE_SLOT_CMD << 10);
        let Some((cc, slot_id)) = wait_command_completion(st, xhci, 1000) else {
            serial_log(alloc::format!("[USB] port {} : timeout Enable Slot, abandon\r\n", port).as_bytes());
            continue;
        };
        if cc != 1 || slot_id == 0 {
            serial_log(alloc::format!("[USB] port {} : Enable Slot echec (code={})\r\n", port, cc).as_bytes());
            continue;
        }
        serial_log(alloc::format!("[USB] port {} : slot {} attribue\r\n", port, slot_id).as_bytes());

        match setup_device(st, xhci, port, slot_id, speed) {
            Some(dev) => {
                serial_log(alloc::format!(
                    "[USB] port {} slot {} : HID configure (clavier={} souris={})\r\n",
                    port, slot_id, dev.is_keyboard, dev.is_mouse
                ).as_bytes());
                devices.push(dev);
            }
            None => {
                serial_log(alloc::format!("[USB] port {} slot {} : configuration HID echouee\r\n", port, slot_id).as_bytes());
            }
        }
    }

    serial_log(alloc::format!("[USB] enumeration terminee : {} device(s) HID configure(s)\r\n", devices.len()).as_bytes());
    devices
}

fn setup_device(
    st: &mut SystemTable<Boot>, xhci: &mut XhciController,
    port: u8, slot_id: u8, speed: u32,
) -> Option<HidDevice> {
    // MaxPacketSize EP0 — simplifié (cf. doc module) : 8 pour Low/Full Speed,
    // qui couvre les devices émulés QEMU (usb-mouse/usb-kbd/usb-tablet).
    let ep0_max_packet: u16 = match speed { 3 => 64, 4..=15 => 512, _ => 8 };
    if speed == 3 || speed >= 4 {
        serial_log(b"[USB] vitesse High/SuperSpeed detectee - EP0 MaxPacketSize approxime, a verifier\r\n");
    }

    // Anneau de transfert EP0 (control).
    let ep0_ring = alloc_pages_zeroed(st, 1)?;
    unsafe { install_link_trb(ep0_ring, CTRL_RING_TRBS); }
    let mut ep0_idx = 0usize;
    let mut ep0_pcs = true;

    // Input Context : Input Control Context (32) + Slot Context (32) + EP0..EP15 (32 chacun).
    // 1 page suffit largement (33*32=1056 octets max).
    // Taille d'entrée de contexte = 32 OU 64 selon CSZ (product-grade) : tous les
    // offsets de contexte en dépendent. Input Control @0, Slot @ces, EP0 @2*ces.
    let ces = xhci.ctx_entry_size;
    let input_ctx = alloc_pages_zeroed(st, 1)?;
    unsafe {
        // Input Control Context : Add Context flags (DWORD1) = slot(bit0) | EP0(bit1).
        mmio_write32(input_ctx, 4, 0b11);
        // Slot Context : DWORD0 = Context Entries=1 (bits[31:27]), Speed (bits[23:20]).
        let slot_off = ces;
        mmio_write32(input_ctx, slot_off, (1u32 << 27) | (speed << 20));
        mmio_write32(input_ctx, slot_off + 4, (port as u32) << 16); // Root Hub Port Number
        // EP0 Context : DWORD1 = EP Type=4 (Control) | MaxPacketSize.
        let ep0_off = 2 * ces;
        mmio_write32(input_ctx, ep0_off + 4, (EP_TYPE_CONTROL << 3) | ((ep0_max_packet as u32) << 16));
        // DWORD2 = TR Dequeue Pointer (low, avec DCS=1) — l'anneau est aligné
        // page donc les 4 bits bas sont déjà à 0, on peut juste OR le DCS.
        mmio_write64(input_ctx, ep0_off + 8, (ep0_ring as u64) | 1);
        // DWORD4 = Average TRB Length — valeur conservatrice (8).
        mmio_write32(input_ctx, ep0_off + 16, 8);
    }

    // Device Context (Slot + jusqu'à 31 EP, 32 octets chacun) — référencé par DCBAA[slot_id].
    let device_ctx = alloc_pages_zeroed(st, 1)?;
    unsafe { mmio_write64(xhci.dcbaa, (slot_id as u64) * 8, device_ctx as u64); }

    // Address Device.
    xhci.submit_command(input_ctx as u64, 0, (TRB_ADDRESS_DEV_CMD << 10) | ((slot_id as u32) << 24));
    let Some((cc, _)) = wait_command_completion(st, xhci, 1000) else {
        serial_log(b"[USB] timeout Address Device\r\n");
        return None;
    };
    if cc != 1 {
        serial_log(alloc::format!("[USB] Address Device echec (code={})\r\n", cc).as_bytes());
        return None;
    }

    // GET_DESCRIPTOR(Device) — d'abord 8 octets pour lire bMaxPacketSize0 (offset 7)
    // et corriger le contexte EP0 si notre supposition de taille était fausse
    // (product-grade : Full Speed peut valoir 8/16/32/64). Sinon les transferts EP0
    // suivants peuvent échouer (babble/packet mismatch) sur un vrai device.
    let mut dev_head = [0u8; 8];
    if control_transfer(
        st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs,
        0x80, 6, 0x0100, 0, Some(&mut dev_head), true,
    ).is_none() {
        serial_log(b"[USB] GET_DESCRIPTOR(Device, 8o) echoue\r\n");
        return None;
    }
    let raw_mps0 = dev_head[7];
    // Full/Low Speed : valeur directe (8/16/32/64). SuperSpeed : 2^bMaxPacketSize0
    // (=512 si 9). High Speed : toujours 64. 0 = on garde notre supposition.
    let real_mps0: u16 = if raw_mps0 == 0 { ep0_max_packet }
        else if speed >= 4 { 1u16 << (raw_mps0 as u16) }
        else if speed == 3 { 64 }
        else { raw_mps0 as u16 };
    if real_mps0 != ep0_max_packet {
        serial_log(alloc::format!("[USB] EP0 MaxPacket corrige {} -> {} (Evaluate Context)\r\n", ep0_max_packet, real_mps0).as_bytes());
        // Evaluate Context : seule la MaxPacketSize d'EP0 est évaluée (xHCI §4.6.7) —
        // NE PAS toucher au TR Dequeue Pointer (ignoré par cette commande, et l'anneau
        // EP0 est déjà en cours d'utilisation, index != 0).
        unsafe {
            zero(input_ctx, PAGE_SIZE);
            mmio_write32(input_ctx, 4, 0b10); // Add Context : EP0 uniquement
            let ep0_off = 2 * ces;
            mmio_write32(input_ctx, ep0_off + 4, (EP_TYPE_CONTROL << 3) | ((real_mps0 as u32) << 16));
        }
        xhci.submit_command(input_ctx as u64, 0, (TRB_EVAL_CONTEXT_CMD << 10) | ((slot_id as u32) << 24));
        let _ = wait_command_completion(st, xhci, 1000);
    }

    // Descripteur complet (18 octets) pour logguer VID/PID.
    let mut dev_desc = [0u8; 18];
    if control_transfer(
        st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs,
        0x80, 6, 0x0100, 0, Some(&mut dev_desc), true,
    ).is_none() {
        serial_log(b"[USB] GET_DESCRIPTOR(Device) echoue\r\n");
        return None;
    }
    let vendor_id = u16::from_le_bytes([dev_desc[8], dev_desc[9]]);
    let product_id = u16::from_le_bytes([dev_desc[10], dev_desc[11]]);
    serial_log(alloc::format!("[USB] device VID={:#06x} PID={:#06x}\r\n", vendor_id, product_id).as_bytes());

    // GET_DESCRIPTOR(Configuration) — d'abord l'en-tête (9 octets) pour
    // connaitre wTotalLength, puis la lecture complète.
    let mut cfg_header = [0u8; 9];
    control_transfer(
        st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs,
        0x80, 6, 0x0200, 0, Some(&mut cfg_header), true,
    )?;
    let total_len = u16::from_le_bytes([cfg_header[2], cfg_header[3]]) as usize;
    let total_len = total_len.clamp(9, PAGE_SIZE);
    let cfg_buf_page = alloc_pages_zeroed(st, 1)?;
    let cfg_buf = unsafe { core::slice::from_raw_parts_mut(cfg_buf_page, total_len) };
    if control_transfer(
        st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs,
        0x80, 6, 0x0200, 0, Some(cfg_buf), true,
    ).is_none() {
        serial_log(b"[USB] GET_DESCRIPTOR(Configuration) complet echoue\r\n");
        return None;
    }

    // Parcourt les sous-descripteurs chaînés à la recherche d'une interface
    // HID Boot Protocol (bInterfaceClass=3, bInterfaceSubClass=1) et de son
    // endpoint Interrupt IN.
    let config_value = cfg_buf[5];
    let mut i = 0usize;
    let mut interface_number: Option<u8> = None;
    let mut interface_protocol: u8 = 0;
    let mut intr_ep_addr: Option<u8> = None;
    let mut intr_max_packet: u16 = 8;
    let mut intr_interval: u8 = 8;
    while i + 2 <= cfg_buf.len() {
        let desc_len = cfg_buf[i] as usize;
        if desc_len == 0 { break; }
        let desc_type = cfg_buf[i + 1];
        if desc_type == 0x04 && desc_len >= 9 { // Interface descriptor
            let class = cfg_buf[i + 5];
            let subclass = cfg_buf[i + 6];
            let protocol = cfg_buf[i + 7];
            if class == 3 && subclass == 1 && (protocol == 1 || protocol == 2) && interface_number.is_none() {
                interface_number = Some(cfg_buf[i + 2]);
                interface_protocol = protocol;
            }
        } else if desc_type == 0x05 && desc_len >= 7 && interface_number.is_some() && intr_ep_addr.is_none() {
            // Endpoint descriptor suivant l'interface HID retenue.
            let ep_addr = cfg_buf[i + 2];
            let attributes = cfg_buf[i + 3];
            if (ep_addr & 0x80) != 0 && (attributes & 0x03) == 3 { // IN + Interrupt
                intr_ep_addr = Some(ep_addr);
                intr_max_packet = u16::from_le_bytes([cfg_buf[i + 4], cfg_buf[i + 5]]);
                intr_interval = cfg_buf[i + 6];
            }
        }
        i += desc_len;
    }

    let (Some(iface), Some(ep_addr)) = (interface_number, intr_ep_addr) else {
        serial_log(b"[USB] pas d'interface HID boot protocol (clavier/souris) trouvee sur ce device\r\n");
        return None;
    };

    // SET_CONFIGURATION.
    if control_transfer(st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs, 0x00, 9, config_value as u16, 0, None, false).is_none() {
        serial_log(b"[USB] SET_CONFIGURATION echoue\r\n");
        return None;
    }
    // SET_PROTOCOL(Boot=0), classe HID, requete d'interface (bmRequestType=0x21, bRequest=0x0B).
    if control_transfer(st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs, 0x21, 0x0B, 0, iface as u16, None, false).is_none() {
        serial_log(b"[USB] SET_PROTOCOL(Boot) echoue (poursuite quand meme)\r\n");
    }
    // SET_IDLE(0) — pas de répétition automatique de rapport, on poll nous-mêmes.
    let _ = control_transfer(st, xhci, slot_id, ep0_ring, &mut ep0_idx, &mut ep0_pcs, 0x21, 0x0A, 0, iface as u16, None, false);

    // Configure Endpoint : ajoute l'endpoint Interrupt IN au Device Context.
    let ep_num = ep_addr & 0x0F;
    let dci = (ep_num as u32) * 2 + 1; // DCI = 2*EPnum + Direction(1=IN)
    let intr_ring = alloc_pages_zeroed(st, 1)?;
    unsafe { install_link_trb(intr_ring, INTR_RING_TRBS); }

    unsafe {
        zero(input_ctx, PAGE_SIZE); // toute la page (contextes 64o = 33*64=2112 o)
        mmio_write32(input_ctx, 4, 0b1 | (1 << dci)); // Add Context : slot + cette EP
        let slot_off = ces;
        mmio_write32(input_ctx, slot_off, (dci << 27) | (speed << 20)); // Context Entries = dci
        mmio_write32(input_ctx, slot_off + 4, (port as u32) << 16);
        let ep_off = ces + (dci as u64) * ces; // EP DCI n @ (1+n)*ctx_entry_size
        // Interval xHCI = exposant en base 2 d'unités de 125us. bInterval est
        // en ms pour Low/Full Speed (~8 unités de 125us par ms) — approximation
        // volontaire (cf. doc module), suffisant pour un clavier/souris boot.
        let interval_exp = (32 - (((intr_interval as u32).max(1) * 8).leading_zeros())).min(15);
        mmio_write32(input_ctx, ep_off, interval_exp << 16);
        mmio_write32(input_ctx, ep_off + 4, (EP_TYPE_INTERRUPT_IN << 3) | ((intr_max_packet as u32) << 16));
        mmio_write64(input_ctx, ep_off + 8, (intr_ring as u64) | 1); // DCS=1
        mmio_write32(input_ctx, ep_off + 16, intr_max_packet as u32);
    }

    xhci.submit_command(input_ctx as u64, 0, (TRB_CONFIG_EP_CMD << 10) | ((slot_id as u32) << 24));
    let Some((cc, _)) = wait_command_completion(st, xhci, 1000) else {
        serial_log(b"[USB] timeout Configure Endpoint\r\n");
        return None;
    };
    if cc != 1 {
        serial_log(alloc::format!("[USB] Configure Endpoint echec (code={})\r\n", cc).as_bytes());
        return None;
    }

    // Pré-charge le premier TRB Normal du transfert d'interruption + sonne la
    // doorbell : c'est ce qui fait démarrer le polling matériel du endpoint.
    let report_len = intr_max_packet.max(8) as usize; // 8 = taille boot clavier ; souris tient dedans
    let report_buf = alloc_pages_zeroed(st, 1)?;
    let mut intr_idx = 0usize;
    let mut intr_pcs = true;
    unsafe {
        enqueue_transfer_trb(
            intr_ring, INTR_RING_TRBS, &mut intr_idx, &mut intr_pcs,
            report_buf as u64, report_len as u32, (TRB_NORMAL << 10) | (1 << 5) /* IOC */,
        );
    }
    xhci.ring_doorbell(slot_id, dci as u8);

    Some(HidDevice {
        slot_id,
        is_keyboard: interface_protocol == 1,
        is_mouse: interface_protocol == 2,
        intr_ep_dci: dci as u8,
        intr_ring, intr_ring_trbs: INTR_RING_TRBS, intr_enqueue_index: intr_idx, intr_pcs,
        report_buf, report_len,
    })
}

/// Traduit un Usage ID clavier HID (USB HID Usage Tables, page 0x07) en
/// `key_code` compatible avec le format déjà utilisé par kernel_runtime.rs
/// pour ConIn : caractère imprimable brut, ou `0x10000 | N` pour les touches
/// spéciales (mêmes N que `scan_code_to_i32` — 1=UP 2=DOWN 3=RIGHT 4=LEFT
/// 5=HOME 6=END 7=INSERT 8=DELETE 0x17=ESCAPE). Ne couvre que
/// lettres/chiffres/touches de navigation/Entrée/Espace/Retour arrière —
/// symboles ponctuation et disposition clavier (AZERTY/QWERTY) hors scope.
fn hid_usage_to_key_code(usage: u8, shift: bool) -> i32 {
    match usage {
        0x04..=0x1D => {
            let c = b'a' + (usage - 0x04);
            (if shift { c.to_ascii_uppercase() } else { c }) as i32
        }
        0x1E..=0x26 => (b'1' + (usage - 0x1E)) as i32, // 1-9
        0x27 => b'0' as i32,
        0x28 => 0x0D,             // Enter
        0x29 => 0x10000 | 0x17,   // Escape
        0x2A => 0x08,             // Backspace
        0x2B => 0x09,             // Tab
        0x2C => b' ' as i32,      // Space
        0x4A => 0x10000 | 5,      // Home
        0x4D => 0x10000 | 6,      // End
        0x4C => 0x10000 | 8,      // Delete
        0x49 => 0x10000 | 7,      // Insert
        0x4F => 0x10000 | 3,      // Right Arrow
        0x50 => 0x10000 | 4,      // Left Arrow
        0x51 => 0x10000 | 2,      // Down Arrow
        0x52 => 0x10000 | 1,      // Up Arrow
        _ => 0,
    }
}

/// À appeler chaque frame : vérifie si une Transfer Event est arrivée pour
/// l'endpoint interrupt d'un device HID, décode le rapport boot protocol
/// (clavier 8 octets ou souris 3-4 octets) si oui, et ré-arme le transfert.
/// Ne bloque jamais (poll non bloquant, `poll_event(.., 1)` = une seule
/// tentative immédiate par appel, jamais d'attente).
///
/// Retourne (dx, dy, buttons, key_code) — mêmes conventions que les chemins
/// EFI_SIMPLE_POINTER_PROTOCOL / ConIn déjà utilisés par kernel_runtime.rs
/// (étape 6 : vient s'additionner à ces sources existantes, pas les
/// remplacer, pour ne rien casser si un device firmware répond aussi).
pub fn poll_hid_reports(
    st: &mut SystemTable<Boot>, xhci: &mut XhciController, devices: &mut [HidDevice],
) -> (i32, i32, i32, i32) {
    let mut dx = 0i32;
    let mut dy = 0i32;
    let mut buttons = 0i32;
    let mut key_code = 0i32;

    // Poll non-bloquant de l'anneau d'événements : plusieurs Transfer Events
    // ont pu s'accumuler depuis la frame précédente.
    for _ in 0..8 {
        let Some(trb) = xhci.poll_event(st, 1) else { break; };
        if trb.trb_type() != TRB_TRANSFER_EVENT { continue; }
        let completion_code = (trb.status >> 24) as u8;
        if completion_code != 1 && completion_code != 13 { continue; }

        // TRB Pointer (Parameter) permet de savoir quel buffer a été rempli —
        // on retrouve le device en comparant à report_buf de chacun.
        for dev in devices.iter_mut() {
            if trb.parameter < dev.report_buf as u64 || trb.parameter >= dev.report_buf as u64 + PAGE_SIZE as u64 {
                continue;
            }
            let buf = unsafe { core::slice::from_raw_parts(dev.report_buf, dev.report_len) };
            if dev.is_mouse && buf.len() >= 3 {
                buttons |= (buf[0] & 0x7) as i32;
                dx += (buf[1] as i8) as i32;
                dy += (buf[2] as i8) as i32;
            } else if dev.is_keyboard && buf.len() >= 8 {
                // buf[2..8] = jusqu'à 6 touches actives simultanément (boot
                // protocol) ; on ne traite que la première — pas de gestion
                // multi-touche ici. Rapport tout-zéro = relâchement (key_code
                // reste à 0, comme "pas de touche" pour ConIn).
                if buf[2] != 0 {
                    let shift = (buf[0] & 0x22) != 0; // Left/Right Shift (bits 1 et 5)
                    key_code = hid_usage_to_key_code(buf[2], shift);
                }
            }
            // Ré-arme un nouveau transfert Normal sur le même buffer.
            unsafe {
                enqueue_transfer_trb(
                    dev.intr_ring, dev.intr_ring_trbs, &mut dev.intr_enqueue_index, &mut dev.intr_pcs,
                    dev.report_buf as u64, dev.report_len as u32, (TRB_NORMAL << 10) | (1 << 5),
                );
            }
            xhci.ring_doorbell(dev.slot_id, dev.intr_ep_dci);
            break;
        }
    }

    let _ = TRB_PORT_STATUS_CHG; // reservé pour une future gestion du hotplug (hors etape 5)
    (dx, dy, buttons, key_code)
}
