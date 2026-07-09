//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — initialisation xHCI (étape 3/N vers un pilote USB/HID natif) ___

//! Étape 3 : reset + initialisation réelle du contrôleur xHCI (xHCI Spec §4.2,
//! "Host Controller Initialization"). PREMIÈRE étape qui ÉCRIT dans le
//! matériel — les étapes 1-2 (pci.rs) étaient strictement lecture seule.
//!
//! Conséquence assumée (décision utilisateur explicite) : réinitialiser le
//! contrôleur le retire de force au pilote USB du firmware (OVMF UsbBusDxe/
//! UsbMouseDxe/UsbMouseAbsolutePointerDxe). EFI_SIMPLE_POINTER_PROTOCOL et
//! EFI_ABSOLUTE_POINTER_PROTOCOL (utilisés par kernel_runtime.rs pour le
//! curseur aujourd'hui) risquent de ne plus répondre après cette étape, tant
//! que le pilote HID natif (étapes 4-6) n'a pas pris le relai. Le clavier
//! ConIn (EFI_SIMPLE_TEXT_INPUT_PROTOCOL, hors xHCI) n'est pas affecté.
//!
//! Sécurité : toute attente sur un bit matériel est BORNÉE (jamais de boucle
//! infinie) — en cas de non-réponse du matériel, on abandonne proprement
//! (log + None) plutôt que de figer tout le boot. Aucune structure n'est
//! utilisée par le contrôleur (USBCMD.RS) tant que toutes les étapes
//! précédentes n'ont pas réussi.

use crate::ovc_exec::serial_log;
use crate::pci::{enable_memory_and_bus_master, XhciCapabilities, XhciInfo};
use uefi::table::boot::{AllocateType, MemoryType};
use uefi::table::{Boot, SystemTable};

// ── Registres opérationnels — base = BAR0 + CAPLENGTH (xHCI Spec §5.4) ─────
const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const CRCR:   u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;

const USBCMD_RS:    u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBSTS_HCH:   u32 = 1 << 0;
const USBSTS_CNR:   u32 = 1 << 11;

// ── Registres d'exécution — base = BAR0 + RTSOFF (xHCI Spec §5.5) ──────────
// Interrupteur 0 à l'offset fixe 0x20 depuis la base runtime.
const IR0_ERSTSZ: u64 = 0x20 + 0x08;
const IR0_ERDP:   u64 = 0x20 + 0x18;
const IR0_ERSTBA: u64 = 0x20 + 0x10;

pub(crate) const PAGE_SIZE: usize = 4096;
// 16 TRB × 16 octets = 256 octets — largement sous 1 page, marge confortable.
const CMD_RING_TRBS: usize = 16;
const EVT_RING_TRBS: usize = 16;
// Registre PORTSC du port N (1-based) — xHCI Spec §5.4.8, tableau des
// registres de port démarrant à op_base+0x400, 0x10 octets par port.
pub(crate) const PORTSC_BASE: u64 = 0x400;
pub(crate) const PORTSC_STRIDE: u64 = 0x10;

/// État du contrôleur après initialisation réussie — utilisé par les étapes
/// suivantes (4: énumération USB, 5: pilote HID) pour piloter les anneaux.
pub struct XhciController {
    pub op_base: *mut u8,
    pub rt_base: *mut u8,
    pub db_base: *mut u8,
    /// Device Context Base Address Array — un pointeur 64-bit par slot
    /// (+1 pour le tableau de scratchpad, non utilisé ici) ; usb.rs y écrit
    /// l'adresse du Device Context après Enable Slot.
    pub dcbaa: *mut u8,
    pub max_slots_enabled: u8,
    pub event_ring: *mut u8,
    pub event_ring_trbs: usize,
    pub event_dequeue_index: usize,
    /// Consumer Cycle State attendu — un TRB est "nouveau" si son bit Cycle
    /// correspond à cette valeur (xHCI Spec §4.9.4).
    pub event_ccs: bool,
    pub command_ring: *mut u8,
    pub command_ring_trbs: usize,
    pub command_enqueue_index: usize,
    /// Producer Cycle State courant de l'anneau de commande.
    pub command_pcs: bool,
    /// CSZ (HCCPARAMS1 bit 2) : si vrai, les contextes device/input font 64
    /// octets au lieu de 32 → usb.rs double tous les offsets de contexte. QEMU
    /// met 0, mais beaucoup de contrôleurs réels exigent 64 (product-grade).
    pub context_size_64: bool,
    /// Taille des entrées de contexte (32 ou 64) — dérivée de context_size_64,
    /// pré-calculée pour usb.rs.
    pub ctx_entry_size: u64,
}

// pub(crate) : réutilisés tels quels par usb.rs pour manipuler les anneaux de
// transfert/contextes (mémoire DMA partagée avec le contrôleur — accès
// volatile nécessaire, mêmes garanties que pour les registres MMIO).
pub(crate) unsafe fn mmio_read32(base: *mut u8, offset: u64) -> u32 {
    core::ptr::read_volatile(base.add(offset as usize) as *const u32)
}
pub(crate) unsafe fn mmio_write32(base: *mut u8, offset: u64, val: u32) {
    core::ptr::write_volatile(base.add(offset as usize) as *mut u32, val);
}
pub(crate) unsafe fn mmio_read64(base: *mut u8, offset: u64) -> u64 {
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}
/// Écrit un registre/champ 64-bit en deux DWORD séparés (low puis high) —
/// pattern recommandé xHCI Spec §5.4 pour les contrôleurs sans écriture
/// 64-bit atomique.
pub(crate) unsafe fn mmio_write64(base: *mut u8, offset: u64, val: u64) {
    mmio_write32(base, offset, (val & 0xFFFF_FFFF) as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

pub(crate) fn alloc_pages_zeroed(st: &mut SystemTable<Boot>, pages: usize) -> Option<*mut u8> {
    let addr = st.boot_services().allocate_pages(
        AllocateType::MaxAddress(0xFFFF_FFFF), // sous 4 Go : valide que le device supporte AC64 ou non
        MemoryType::BOOT_SERVICES_DATA,
        pages,
    ).ok()?;
    let ptr = addr as *mut u8;
    unsafe { core::ptr::write_bytes(ptr, 0, pages * PAGE_SIZE); }
    Some(ptr)
}

/// Attend que `(registre & mask) == expected`, borné à `max_tries` essais
/// espacés de 1ms (jamais d'attente infinie). Retourne false sur timeout.
pub(crate) fn wait_bit(st: &mut SystemTable<Boot>, base: *mut u8, offset: u64, mask: u32, expected: u32, max_tries: u32) -> bool {
    for _ in 0..max_tries {
        let val = unsafe { mmio_read32(base, offset) };
        if (val & mask) == expected { return true; }
        st.boot_services().stall(1000); // 1 ms
    }
    false
}

// ── Capacités étendues (xHCI Spec §7) ───────────────────────────────────────
const XECP_ID_LEGACY: u32 = 1;     // USB Legacy Support Capability
const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
const USBLEGSUP_OS_OWNED:   u32 = 1 << 24;

/// Prise de possession BIOS→OS (xHCI Spec §7.1.1) : parcourt la liste chaînée
/// des capacités étendues depuis xECP, trouve l'USB Legacy Support Capability,
/// pose OS_OWNED et attend que BIOS_OWNED se libère. Indispensable sur vrai
/// matériel (le firmware SMM tient sinon le contrôleur et interfère avec nos
/// écritures) ; no-op propre si la capacité est absente (cas QEMU fréquent).
fn usb_legacy_handoff(st: &mut SystemTable<Boot>, base: *mut u8, ext_cap_ptr_dwords: u32) {
    if ext_cap_ptr_dwords == 0 {
        serial_log(b"[XHCI-INIT] pas de capacites etendues (xECP=0), handoff ignore\r\n");
        return;
    }
    // xECP est un offset en DWORDs depuis la base des registres de capacité (BAR0).
    let mut off = (ext_cap_ptr_dwords as u64) * 4;
    for _ in 0..64 { // borne dure : jamais de liste chaînée infinie
        let cap = unsafe { mmio_read32(base, off) };
        if cap == 0 || cap == 0xFFFF_FFFF { break; }
        let cap_id = cap & 0xFF;
        let next = (cap >> 8) & 0xFF;
        if cap_id == XECP_ID_LEGACY {
            let legsup = unsafe { mmio_read32(base, off) };
            if (legsup & USBLEGSUP_BIOS_OWNED) == 0 {
                serial_log(b"[XHCI-INIT] Legacy Support present, deja OS-owned\r\n");
                return;
            }
            unsafe { mmio_write32(base, off, legsup | USBLEGSUP_OS_OWNED); }
            // Attend que le BIOS relâche (borné à 1s).
            for _ in 0..1000 {
                let v = unsafe { mmio_read32(base, off) };
                if (v & USBLEGSUP_BIOS_OWNED) == 0 {
                    serial_log(b"[XHCI-INIT] USB Legacy handoff BIOS->OS reussi\r\n");
                    // Désactive les SMI legacy (USBLEGCTLSTS à off+4) pour éviter
                    // que le firmware ne reprenne la main via une interruption SMM.
                    unsafe { mmio_write32(base, off + 4, 0xE000_00FF); } // clear/ack SMI sources
                    return;
                }
                st.boot_services().stall(1000);
            }
            serial_log(b"[XHCI-INIT] timeout handoff (BIOS ne relache pas) - on continue quand meme\r\n");
            return;
        }
        if next == 0 { break; }
        off += (next as u64) * 4;
    }
}

/// Alloue les Scratchpad Buffers exigés par le contrôleur (xHCI Spec §4.20) :
/// un tableau de N pointeurs 64-bit (aligné page), chacun pointant sur une page
/// de travail zéro. L'adresse du tableau est écrite dans DCBAA[0]. Sans ça, un
/// contrôleur avec Max Scratchpad Bufs > 0 n'exécute AUCUNE commande. Retourne
/// false si une allocation échoue.
fn setup_scratchpad(st: &mut SystemTable<Boot>, dcbaa: *mut u8, count: u32, page_size: u32) -> bool {
    if count == 0 { return true; } // rien à faire (cas QEMU)
    let page_size = page_size.max(4096) as usize;
    let pages_for_array = ((count as usize * 8) + page_size - 1) / page_size;
    let Some(array) = alloc_pages_zeroed(st, pages_for_array.max(1)) else { return false; };
    for i in 0..count as usize {
        // Une page de travail par buffer (page_size arrondi au multiple de PAGE_SIZE).
        let bpages = (page_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let Some(buf) = alloc_pages_zeroed(st, bpages) else { return false; };
        unsafe { mmio_write64(array, (i * 8) as u64, buf as u64); }
    }
    unsafe { mmio_write64(dcbaa, 0, array as u64); } // DCBAA[0] = Scratchpad Buffer Array
    serial_log(alloc::format!("[XHCI-INIT] {} scratchpad buffer(s) alloue(s)\r\n", count).as_bytes());
    true
}

/// Exécute la séquence d'initialisation xHCI Spec §4.2. Retourne `None` (sans
/// avoir démarré le contrôleur) si une étape échoue ou dépasse son délai.
pub fn init_xhci(
    st: &mut SystemTable<Boot>,
    image_handle: uefi::Handle,
    xhci: &XhciInfo,
    caps: &XhciCapabilities,
) -> Option<XhciController> {
    serial_log(b"[XHCI-INIT] debut (premiere ecriture materielle de ce pilote)\r\n");

    if !enable_memory_and_bus_master(st, image_handle, xhci) {
        serial_log(b"[XHCI-INIT] echec activation Memory Space/Bus Master, abandon\r\n");
        return None;
    }

    let base    = xhci.bar0 as *mut u8;
    let op_base = unsafe { base.add(caps.cap_length as usize) };
    let rt_base = unsafe { base.add(caps.runtime_offset as usize) };
    let db_base = unsafe { base.add(caps.doorbell_offset as usize) };
    serial_log(alloc::format!(
        "[XHCI-DBG] bar0={:#x} op_base={:#x} rt_base={:#x} db_base={:#x}\r\n",
        base as u64, op_base as u64, rt_base as u64, db_base as u64
    ).as_bytes());

    // 0. Prise de possession BIOS→OS AVANT toute écriture matérielle (sinon le
    // firmware SMM peut interférer). No-op propre si la capacité est absente.
    usb_legacy_handoff(st, base, caps.ext_cap_ptr_dwords);

    // 1. Attendre que le contrôleur soit prêt (CNR = Controller Not Ready → 0).
    if !wait_bit(st, op_base, USBSTS, USBSTS_CNR, 0, 2000) {
        serial_log(b"[XHCI-INIT] timeout CNR==0 (pre-reset), abandon\r\n");
        return None;
    }

    // 2. Arrêter le contrôleur s'il tournait déjà (ex. piloté par OVMF).
    let cmd = unsafe { mmio_read32(op_base, USBCMD) };
    if (cmd & USBCMD_RS) != 0 {
        unsafe { mmio_write32(op_base, USBCMD, cmd & !USBCMD_RS); }
        if !wait_bit(st, op_base, USBSTS, USBSTS_HCH, USBSTS_HCH, 2000) {
            serial_log(b"[XHCI-INIT] timeout HCH==1 apres Stop, abandon\r\n");
            return None;
        }
    }

    // 3. Reset matériel complet (HCRST) — remet TOUS les registres à zéro.
    unsafe { mmio_write32(op_base, USBCMD, USBCMD_HCRST); }
    if !wait_bit(st, op_base, USBCMD, USBCMD_HCRST, 0, 2000) {
        serial_log(b"[XHCI-INIT] timeout HCRST==0, abandon\r\n");
        return None;
    }
    if !wait_bit(st, op_base, USBSTS, USBSTS_CNR, 0, 2000) {
        serial_log(b"[XHCI-INIT] timeout CNR==0 (post-reset), abandon\r\n");
        return None;
    }
    serial_log(b"[XHCI-INIT] reset materiel effectue\r\n");

    // 4. Device Context Base Address Array — (MaxSlots+1) pointeurs 64-bit,
    // largement couvert par 1 page (512 entrees possibles).
    let Some(dcbaa) = alloc_pages_zeroed(st, 1) else {
        serial_log(b"[XHCI-INIT] allocation DCBAA echouee\r\n");
        return None;
    };

    // 4b. Scratchpad Buffers (product-grade) : DCBAA[0] doit pointer sur le
    // tableau de scratchpad AVANT DCBAAP/démarrage si le contrôleur en exige.
    if !setup_scratchpad(st, dcbaa, caps.max_scratchpad_bufs, caps.page_size_bytes) {
        serial_log(b"[XHCI-INIT] allocation scratchpad echouee, abandon\r\n");
        return None;
    }

    unsafe { mmio_write64(op_base, DCBAAP, dcbaa as u64); }

    // 5. Nombre de slots activés — borné à 8, largement suffisant pour
    // clavier+souris (et quelques devices de plus), évite de gaspiller.
    let max_slots_enabled = caps.max_slots.min(8).max(1);
    unsafe { mmio_write32(op_base, CONFIG, max_slots_enabled as u32); }

    // 6. Anneau de commande : CMD_RING_TRBS TRB + un Link TRB final qui
    // reboucle sur le début (xHCI Spec §4.9.2). Cycle bit du Link = 1, pour
    // correspondre au RCS=1 qu'on va programmer dans CRCR juste après.
    let Some(command_ring) = alloc_pages_zeroed(st, 1) else {
        serial_log(b"[XHCI-INIT] allocation anneau de commande echouee\r\n");
        return None;
    };
    {
        let link_off = ((CMD_RING_TRBS - 1) * 16) as u64;
        unsafe {
            mmio_write64(command_ring, link_off, command_ring as u64); // Parameter = debut anneau
            mmio_write32(command_ring, link_off + 8, 0); // Status
            // Control : TRB Type=6 (Link) [15:10], Toggle Cycle=bit1, Cycle=bit0.
            let control: u32 = (6u32 << 10) | (1 << 1) | 1;
            mmio_write32(command_ring, link_off + 12, control);
        }
    }
    unsafe { mmio_write64(op_base, CRCR, (command_ring as u64) | 1); } // RCS=1

    // 7. Anneau d'événements (1 segment) + table de segments (ERST, 1 entrée).
    let (Some(event_ring), Some(erst)) = (alloc_pages_zeroed(st, 1), alloc_pages_zeroed(st, 1)) else {
        serial_log(b"[XHCI-INIT] allocation anneau d'evenements/ERST echouee\r\n");
        return None;
    };
    unsafe {
        // Entrée ERST : {Ring Segment Base Address (u64), Ring Segment Size (u32), Reserved (u32)}.
        mmio_write64(erst, 0, event_ring as u64);
        mmio_write32(erst, 8, EVT_RING_TRBS as u32);
        mmio_write32(erst, 12, 0);
    }
    // Ordre imposé par la spec (§5.5.2.3.3) : ERSTSZ, puis ERDP, puis ERSTBA
    // en dernier — c'est l'écriture d'ERSTBA qui "arme" l'anneau d'événements.
    unsafe {
        mmio_write32(rt_base, IR0_ERSTSZ, 1);
        mmio_write64(rt_base, IR0_ERDP, event_ring as u64);
        mmio_write64(rt_base, IR0_ERSTBA, erst as u64);
    }

    serial_log(alloc::format!(
        "[XHCI-INIT] DCBAAP={:#x} CRCR={:#x} ERSTBA={:#x} MaxSlotsEn={}\r\n",
        dcbaa as u64, command_ring as u64, erst as u64, max_slots_enabled
    ).as_bytes());

    // 8. Démarrer le contrôleur — pas d'interruptions programmées (INTE=0) :
    // on poll l'anneau d'événements nous-mêmes (contexte UEFI boot, un seul
    // fil d'exécution, pas de gestionnaire d'IRQ en place).
    let cmd = unsafe { mmio_read32(op_base, USBCMD) };
    unsafe { mmio_write32(op_base, USBCMD, cmd | USBCMD_RS); }
    if !wait_bit(st, op_base, USBSTS, USBSTS_HCH, 0, 2000) {
        serial_log(b"[XHCI-INIT] timeout HCH==0 (demarrage), abandon\r\n");
        return None;
    }

    serial_log(b"[XHCI-INIT] controleur demarre avec succes (RS=1, HCH=0)\r\n");

    Some(XhciController {
        op_base, rt_base, db_base, dcbaa,
        max_slots_enabled,
        event_ring, event_ring_trbs: EVT_RING_TRBS, event_dequeue_index: 0, event_ccs: true,
        command_ring, command_ring_trbs: CMD_RING_TRBS, command_enqueue_index: 0, command_pcs: true,
        context_size_64: caps.context_size_64,
        ctx_entry_size: if caps.context_size_64 { 64 } else { 32 },
    })
}

/// Un TRB générique (16 octets) — Parameter/Status/Control (xHCI Spec §4.11).
#[derive(Clone, Copy, Debug)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub fn trb_type(&self) -> u32 { (self.control >> 10) & 0x3F }
    pub fn cycle(&self) -> bool { (self.control & 1) != 0 }
}

unsafe fn read_trb(ring: *mut u8, index: usize) -> Trb {
    let off = (index * 16) as u64;
    Trb {
        parameter: mmio_read64(ring, off),
        status: mmio_read32(ring, off + 8),
        control: mmio_read32(ring, off + 12),
    }
}
unsafe fn write_trb(ring: *mut u8, index: usize, trb: Trb) {
    let off = (index * 16) as u64;
    mmio_write64(ring, off, trb.parameter);
    mmio_write32(ring, off + 8, trb.status);
    mmio_write32(ring, off + 12, trb.control);
}

impl XhciController {
    /// Sonne la doorbell d'un slot (0 = anneau de commande, N = slot N) —
    /// `target` = index d'endpoint (DCI) pour un slot de device, ignoré (0)
    /// pour l'anneau de commande (xHCI Spec §5.6).
    pub fn ring_doorbell(&self, slot: u8, target: u8) {
        // Log fin (debug diagnostic) : db_base + offset écrits explicitement —
        // seule zone MMIO jamais exercée avant l'étape 4 (contrairement à
        // op_base/rt_base, déjà validés en écriture par l'étape 3).
        serial_log(alloc::format!(
            "[XHCI-DBG] ring_doorbell: db_base={:#x} offset={:#x} target={}...\r\n",
            self.db_base as u64, (slot as u64) * 4, target
        ).as_bytes());
        unsafe { mmio_write32(self.db_base, (slot as u64) * 4, target as u32); }
        serial_log(b"[XHCI-DBG] ring_doorbell: ecriture terminee\r\n");
    }

    /// Place un TRB dans l'anneau de commande (en gérant le Link TRB de
    /// bouclage et le retournement du Producer Cycle State), sonne la
    /// doorbell 0. Retourne l'adresse physique du TRB inséré (sert à
    /// identifier la Command Completion Event correspondante).
    pub fn submit_command(&mut self, parameter: u64, status: u32, control_no_cycle: u32) -> u64 {
        // Le dernier slot de l'anneau est le Link TRB (posé à l'init) — si on
        // est dessus, on le retourne (toggle cycle) et on repart à l'index 0.
        if self.command_enqueue_index == self.command_ring_trbs - 1 {
            unsafe {
                let off = (self.command_enqueue_index * 16) as u64;
                let mut ctrl = mmio_read32(self.command_ring, off + 12);
                ctrl = (ctrl & !1) | (self.command_pcs as u32);
                mmio_write32(self.command_ring, off + 12, ctrl);
            }
            self.command_pcs = !self.command_pcs;
            self.command_enqueue_index = 0;
        }
        let idx = self.command_enqueue_index;
        let control = (control_no_cycle & !1) | (self.command_pcs as u32);
        serial_log(alloc::format!(
            "[XHCI-DBG] submit_command: ecriture TRB idx={} @ ring={:#x} param={:#x} status={:#x} control={:#x}...\r\n",
            idx, self.command_ring as u64, parameter, status, control
        ).as_bytes());
        unsafe { write_trb(self.command_ring, idx, Trb { parameter, status, control }); }
        serial_log(b"[XHCI-DBG] submit_command: TRB ecrit, doorbell suivante\r\n");
        let trb_addr = self.command_ring as u64 + (idx * 16) as u64;
        self.command_enqueue_index += 1;
        self.ring_doorbell(0, 0);
        serial_log(b"[XHCI-DBG] submit_command: termine\r\n");
        trb_addr
    }

    /// Poll l'anneau d'événements jusqu'à trouver un TRB dont le bit Cycle
    /// correspond au Consumer Cycle State attendu (= un événement neuf),
    /// borné à `max_tries` essais de 1ms (jamais d'attente infinie). Avance
    /// le pointeur de lecture et le publie via ERDP (xHCI Spec §4.9.4).
    pub fn poll_event(&mut self, st: &mut SystemTable<Boot>, max_tries: u32) -> Option<Trb> {
        for i in 0..max_tries {
            if i == 0 {
                serial_log(alloc::format!(
                    "[XHCI-DBG] poll_event: 1ere iteration, event_ring={:#x} idx={} ccs={}...\r\n",
                    self.event_ring as u64, self.event_dequeue_index, self.event_ccs
                ).as_bytes());
            }
            let trb = unsafe { read_trb(self.event_ring, self.event_dequeue_index) };
            if i == 0 {
                serial_log(b"[XHCI-DBG] poll_event: 1ere lecture TRB ok\r\n");
            }
            if trb.cycle() == self.event_ccs {
                serial_log(alloc::format!(
                    "[XHCI-DBG] poll_event: TRB trouve a l'essai {} (type={})\r\n", i, trb.trb_type()
                ).as_bytes());
                self.event_dequeue_index += 1;
                if self.event_dequeue_index >= self.event_ring_trbs {
                    self.event_dequeue_index = 0;
                    self.event_ccs = !self.event_ccs;
                }
                let erdp = self.event_ring as u64 + (self.event_dequeue_index * 16) as u64;
                unsafe { mmio_write64(self.rt_base, IR0_ERDP, erdp | (1 << 3)); } // EHB=1 (clear busy)
                serial_log(b"[XHCI-DBG] poll_event: ERDP mis a jour, retour\r\n");
                return Some(trb);
            }
            st.boot_services().stall(1000);
        }
        serial_log(b"[XHCI-DBG] poll_event: max_tries atteint, aucun evenement\r\n");
        None
    }

    /// Lit PORTSC du port `port` (1-based).
    pub fn read_portsc(&self, port: u8) -> u32 {
        unsafe { mmio_read32(self.op_base, PORTSC_BASE + (port as u64 - 1) * PORTSC_STRIDE) }
    }
    pub fn write_portsc(&self, port: u8, val: u32) {
        unsafe { mmio_write32(self.op_base, PORTSC_BASE + (port as u64 - 1) * PORTSC_STRIDE, val); }
    }
}
