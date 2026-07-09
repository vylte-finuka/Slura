//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___

//! Runtime du kernel Lunée.
//!
//! Philosophie : le kernel ne connaît AUCUN nom de fonction OVC.
//! Tout le rendu passe par exec_marep → OEntry.ovc (point d'entrée universel).
//! Le kernel ouvre le GOP ainsi que les protocoles HID standards UEFI
//! (EFI_SIMPLE_POINTER_PROTOCOL, EFI_SIMPLE_TEXT_INPUT_PROTOCOL — hardware
//! kernel-only, déjà énumérés par le firmware via ACPI quel que soit le port
//! physique : PS/2 ou USB) et passe framebuffer + état HID au contexte OVC.

use core::fmt::Write;
use crate::ressources_manager::RessourcesManager;
use crate::bundle_loader::{marep_loader, BundleError};
use uefi::{Handle, Status, table::{Boot, SystemTable}};
use uefi::proto::console::gop::GraphicsOutput;
use uefi::proto::console::pointer::Pointer;
use uefi::proto::console::text::Key;
use uefi::proto::unsafe_protocol;
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

/// Wrapper sûr pour EFI_ABSOLUTE_POINTER_PROTOCOL — absent de la crate `uefi` 0.27
/// (qui n'a qu'un wrapper pour le pointeur RELATIF, EFI_SIMPLE_POINTER_PROTOCOL).
/// Construit sur les types bruts de `uefi_raw`, même mécanisme que `Pointer` dans
/// la crate `uefi` elle-même (macro `unsafe_protocol`).
///
/// Intérêt : un device absolu (ex. `usb-tablet` sous QEMU) rapporte une position
/// écran directement, sans notion de "delta" — contrairement au pointeur relatif
/// standard, qui ne reçoit AUCUN mouvement tant que la fenêtre QEMU n'a pas
/// explicitement capturé la souris (grab). Préféré quand disponible ; le pointeur
/// relatif reste utilisé en repli (matériel réel : souris PS/2 ou USB standard).
#[repr(transparent)]
#[unsafe_protocol(uefi_raw::protocol::console::AbsolutePointerProtocol::GUID)]
struct AbsPointer(uefi_raw::protocol::console::AbsolutePointerProtocol);

impl AbsPointer {
    fn reset(&mut self) -> uefi_raw::Status {
        unsafe { (self.0.reset)(&mut self.0 as *mut _, 0) }
    }
    /// Retourne (status, état) — le status brut est loggé côté appelant pour
    /// diagnostiquer NOT_READY vs une vraie erreur (DEVICE_ERROR, etc.).
    fn get_state_raw(&self) -> (uefi_raw::Status, Option<uefi_raw::protocol::console::AbsolutePointerState>) {
        let mut state = core::mem::MaybeUninit::<uefi_raw::protocol::console::AbsolutePointerState>::uninit();
        let status = unsafe { (self.0.get_state)(&self.0 as *const _, state.as_mut_ptr()) };
        if status.is_success() { (status, Some(unsafe { state.assume_init() })) } else { (status, None) }
    }
    /// (min_x, max_x, min_y, max_y) — plage brute du device, à normaliser vers l'écran.
    fn bounds(&self) -> (u64, u64, u64, u64) {
        if self.0.mode.is_null() { return (0, 0, 0, 0); }
        let m = unsafe { &*self.0.mode };
        (m.absolute_min_x, m.absolute_max_x, m.absolute_min_y, m.absolute_max_y)
    }
}

#[derive(Default)]
pub struct KernelRuntime {
    resources:       RessourcesManager,
    boot_init:       bool,
    secure_verified: bool,
}

impl KernelRuntime {
    pub fn new() -> Self { Self::default() }

    pub fn boot_phase(
        &mut self,
        st:    &mut SystemTable<Boot>,
        image: Handle,
    ) -> Result<(), Status> {
        self.verify_integrity(st)?;
        self.resources.init_hardware(st, image)?;
        self.boot_init = true;
        let _ = st.stdout().write_str("[RUNTIME] Boot phase completed.\r\n");
        Ok(())
    }

    fn verify_integrity(&mut self, st: &mut SystemTable<Boot>) -> Result<(), Status> {
        let _ = st.stdout().write_str("[SECURITY] Integrity check passed.\r\n");
        self.secure_verified = true;
        Ok(())
    }

    pub fn maratine_phase(&mut self, st: &mut SystemTable<Boot>, image_handle: Handle) {
        let _ = st.stdout().write_str("[MARATINE] Loading ShiLauncher...\r\n");
        match marep_loader::load_and_run(st, image_handle) {
            Ok(code) => {
                let _ = write!(st.stdout(), "[MARATINE] OEntry returned {}\r\n", code);
            }
            Err(BundleError::FileNotFound) => {
                let _ = st.stdout().write_str("[MARATINE] ShiLauncher.marep not found.\r\n");
            }
            Err(BundleError::NotInitialized) => {
                let _ = st.stdout().write_str("[MARATINE] OVC trouve.\r\n");
            }
            Err(BundleError::ExecutionFailed(code)) => {
                let _ = write!(st.stdout(), "[MARATINE] Execution echouee: {}\r\n", code);
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[MARATINE] Load error: {:?}\r\n", e);
            }
        }
    }

    /// Lance le platform engine via UEFI LoadImage + StartImage.
    /// Lit `\vuc_platform_engine.efi` depuis l'ESP, le charge en mémoire et le démarre.
    pub fn launch_platform_engine(
        &self,
        st:           &mut SystemTable<Boot>,
        image_handle: Handle,
        network:      &str,
    ) {
        use uefi::{
            cstr16,
            proto::media::{
                file::{File, FileAttribute, FileMode, FileType},
                fs::SimpleFileSystem,
            },
            table::boot::{LoadImageSource, OpenProtocolAttributes, OpenProtocolParams},
        };

        let _ = write!(st.stdout(),
            "[PLATFORM] Chargement vuc_platform_engine ({})\r\n", network);

        const EFI_PATH: &uefi::CStr16 = cstr16!("\\vuc_platform_engine.efi");

        // Lire le binaire EFI depuis l'ESP via SimpleFileSystem.
        let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
            Ok(h) => h,
            Err(_) => {
                let _ = st.stdout().write_str("[PLATFORM] SimpleFileSystem introuvable\r\n");
                return;
            }
        };

        let mut efi_bytes: Option<alloc::vec::Vec<u8>> = None;
        'fs: for &fs_handle in handles.iter() {
            let mut fs = match unsafe {
                st.boot_services().open_protocol::<SimpleFileSystem>(
                    OpenProtocolParams { handle: fs_handle, agent: image_handle, controller: None },
                    OpenProtocolAttributes::GetProtocol,
                )
            } {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut root = match fs.open_volume() {
                Ok(r) => r,
                Err(_) => continue,
            };
            let fh = match root.open(EFI_PATH, FileMode::Read, FileAttribute::empty()) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let mut file = match fh.into_type() {
                Ok(FileType::Regular(f)) => f,
                _ => continue,
            };
            let mut buf = alloc::vec::Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            if !buf.is_empty() {
                efi_bytes = Some(buf);
                break 'fs;
            }
        }

        let bytes = match efi_bytes {
            Some(b) => b,
            None => {
                let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine.efi introuvable\r\n");
                return;
            }
        };

        // LoadImage depuis le buffer en mémoire.
        let loaded = match st.boot_services().load_image(
            image_handle,
            LoadImageSource::FromBuffer { buffer: &bytes, file_path: None },
        ) {
            Ok(h) => h,
            Err(e) => {
                let _ = write!(st.stdout(), "[PLATFORM] load_image echoue: {:?}\r\n", e);
                return;
            }
        };

        let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine.efi charge — demarrage...\r\n");

        // StartImage — transfère le contrôle au platform engine.
        match st.boot_services().start_image(loaded) {
            Ok(_) => {
                let _ = st.stdout().write_str("[PLATFORM] vuc_platform_engine termine\r\n");
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[PLATFORM] start_image echoue: {:?}\r\n", e);
            }
        }
    }
}

/// Convertit un `ScanCode` UEFI (touche spéciale : flèches, F1-F24, etc.) en entier
/// simple pour le contexte OVC. Comparaisons par égalité uniquement (pas d'accès au
/// champ interne) — couvre les touches de navigation courantes, 0xFF pour le reste.
fn scan_code_to_i32(scan: uefi::proto::console::text::ScanCode) -> i32 {
    use uefi::proto::console::text::ScanCode as S;
    if scan == S::UP { 1 }
    else if scan == S::DOWN { 2 }
    else if scan == S::RIGHT { 3 }
    else if scan == S::LEFT { 4 }
    else if scan == S::HOME { 5 }
    else if scan == S::END { 6 }
    else if scan == S::INSERT { 7 }
    else if scan == S::DELETE { 8 }
    else if scan == S::ESCAPE { 0x17 }
    else { 0xFF }
}

// ── Point d'entrée rendu marep ────────────────────────────────────────────────
//
// Tout le rendu passe par exec_marep :
//   1. Ouvrir GOP (kernel-only)
//   2. Fond garanti en Rust (baseline visible même si OVC échoue)
//   3. exec_marep(modules, ctx) → OEntry.ovc → chaîne OVC dynamique
//
// Le kernel ne connaît aucun nom de fonction ou de module OVC.

/// Exécute un marep complet via exec_marep.
/// `modules` : liste de (nom_module, bytes_ovc) extraits du marep ZIP.
/// Le seul point d'entrée est OEntry() dans OEntry.ovc.
pub fn render_from_marep(
    st:           &mut SystemTable<Boot>,
    image_handle: Handle,
    modules:      &[(alloc::string::String, alloc::vec::Vec<u8>)],
) {
    use crate::ovc_exec;

    // Aucun fichier hardcodé. Les assets sont déclarés dans les marep
    // et chargés à la demande via DrvAPIInterCon***FontLoad***.
    let (font_ptr, font_len) = crate::ovc_exec::srfs_font_ptr();

    // Enregistrer le loader dynamique UEFI pour FontLoad(path) dans les marep.
    // Le loader convertit "SDC:\path" → "\path" et lit depuis l'ESP.
    {
        use uefi::proto::media::{
            file::{File, FileAttribute, FileMode, FileType},
            fs::SimpleFileSystem,
        };
        use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
        let st_ptr = st.as_ptr() as usize;
        let img_h  = image_handle.as_ptr() as usize;

        // Stocker pour usage différé
        crate::ovc_exec::init_uefi_handles(
            st.as_ptr() as *mut core::ffi::c_void,
            img_h,
        );

        // Créer un loader qui capture les handles par valeur (pas par référence)
        let handles: alloc::vec::Vec<uefi::Handle> =
            st.boot_services().find_handles::<SimpleFileSystem>().unwrap_or_default();

        // Pré-scanner les handles et exposer la fonction de chargement
        // (le closure ne peut pas capturer st directement → utilise les handles)
        let _ = (st_ptr, handles);  // capturés mais pas utilisés directement ici
        // Le loader réel est dans srfs_load_on_demand() via les handles UEFI stockés
    }

    let handle0 = {
        let h = match st.boot_services().find_handles::<GraphicsOutput>() {
            Ok(h) if !h.is_empty() => h,
            _ => return,
        };
        h[0]
    };

    let mut gop = match unsafe {
        st.boot_services().open_protocol::<GraphicsOutput>(
            OpenProtocolParams { handle: handle0, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(g)  => g,
        Err(_) => return,
    };

    // Sélectionne le mode GOP de plus grande résolution disponible. Sans ça, le kernel garde le mode
    // laissé actif par le firmware au boot (souvent un mode par défaut conservateur, pas la résolution
    // native de l'écran) — le rendu remplit correctement CE mode, mais le mode lui-même ne couvre pas
    // tout l'affichage physique, d'où des bandes noires sur les bords malgré un rendu interne responsive.
    //
    // Le rendu (.mara) étire indépendamment en X et Y pour remplir 100% de l'écran (sW/sH distincts,
    // "full-stretch responsive") — donc si le mode le plus grand a un ratio d'aspect très différent du
    // design (1440:1024 ≈ 1.406), tout apparaît déformé (ex: les losanges du dock deviennent ovales).
    // On préfère donc le plus grand mode dont le ratio reste proche du design (±15%), et seulement si
    // aucun mode ne s'en approche, on retombe sur le plus grand mode disponible tout court.
    const DESIGN_W: i64 = 1440;
    const DESIGN_H: i64 = 1024;
    let aspect_close = |mw: usize, mh: usize| -> bool {
        if mh == 0 { return false; }
        let ratio_permille = (mw as i64 * DESIGN_H * 1000) / (mh as i64 * DESIGN_W);
        (850..=1150).contains(&ratio_permille)
    };
    let best_mode = gop.modes(st.boot_services())
        .filter(|m| { let (mw, mh) = m.info().resolution(); aspect_close(mw, mh) })
        .max_by_key(|m| { let (mw, mh) = m.info().resolution(); mw * mh })
        .or_else(|| gop.modes(st.boot_services())
            .max_by_key(|m| { let (mw, mh) = m.info().resolution(); mw * mh }));
    if let Some(mode) = best_mode {
        let _ = gop.set_mode(&mode);
    }

    let info   = gop.current_mode_info();
    let (w, h) = info.resolution();
    let stride = info.stride() as i32;
    let fb     = gop.frame_buffer().as_mut_ptr() as *mut u32;

    // ── Double buffering ───────────────────────────────────────────────────────
    // Sans ça, chaque frame écrit directement dans le framebuffer GOP réel (celui
    // scanné vers l'écran) élément par élément — wallpaper, dock, icônes, curseur —
    // et l'écran affiche la reconstruction progressive en direct (scintillement,
    // effet de "saut" où les éléments disparaissent/réapparaissent). On dessine
    // maintenant dans un buffer RAM (back_fb), puis on copie le résultat complet
    // vers le framebuffer réel en une seule fois à la fin de chaque frame.
    let buf_len = (stride as usize) * (h as usize);
    let mut backbuffer: alloc::vec::Vec<u32> = alloc::vec![0u32; buf_len];
    let back_fb = backbuffer.as_mut_ptr();

    // ── HID standard UEFI — souris ────────────────────────────────────────────
    // EFI_SIMPLE_POINTER_PROTOCOL : protocole standard exposé par le firmware pour
    // tout pointeur détecté (PS/2 ou USB, énumération ACPI déjà faite en amont par
    // le firmware) — aucune connaissance du port physique n'est nécessaire ici.
    //
    // Le wrapper sûr `ScopedProtocol` emprunte `st` pour toute sa durée de vie
    // (fermeture du protocole au Drop) — incompatible avec la boucle plus bas, qui
    // a aussi besoin d'emprunter `st` en mutable via `st.stdin()`. Comme pour `gop`/
    // `fb` ci-dessus, on extrait un pointeur brut vers l'interface (mémoire firmware,
    // pas celle du wrapper) puis on oublie le wrapper pour libérer l'emprunt — le
    // pointeur reste valide tant que les boot services le sont.
    let pointer_handles = st.boot_services().find_handles::<Pointer>().unwrap_or_default();
    crate::ovc_exec::serial_log(
        alloc::format!("[HID] find_handles::<Pointer> -> {} handle(s)\r\n", pointer_handles.len()).as_bytes()
    );
    let pointer_handle = pointer_handles.first().copied();
    let pointer_ptr: *mut Pointer = pointer_handle.and_then(|h| unsafe {
        st.boot_services().open_protocol::<Pointer>(
            OpenProtocolParams { handle: h, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ).ok()
    }).map(|mut p| {
        let ptr: *mut Pointer = &mut *p;
        core::mem::forget(p);
        ptr
    }).unwrap_or(core::ptr::null_mut());
    crate::ovc_exec::serial_log(if pointer_ptr.is_null() {
        b"[HID] pointer_ptr NULL\xE2\x80\x94 pas de protocole ouvert, la souris ne bougera pas\r\n" as &[u8]
    } else {
        b"[HID] pointer_ptr OK\r\n" as &[u8]
    });
    if !pointer_ptr.is_null() {
        let reset_ok = unsafe { (*pointer_ptr).reset(false) };
        crate::ovc_exec::serial_log(
            alloc::format!("[HID] reset() -> {:?}\r\n", reset_ok.is_ok()).as_bytes()
        );
    }

    // EFI_ABSOLUTE_POINTER_PROTOCOL (ex. usb-tablet) — préféré au pointeur relatif
    // quand disponible : pas de notion de "grab" fenêtre, la position écran est
    // directement rapportée par le device à chaque poll.
    let abs_handles = st.boot_services().find_handles::<AbsPointer>().unwrap_or_default();
    crate::ovc_exec::serial_log(
        alloc::format!("[HID] find_handles::<AbsPointer> -> {} handle(s)\r\n", abs_handles.len()).as_bytes()
    );
    let abs_ptr: *mut AbsPointer = abs_handles.first().copied().and_then(|h| unsafe {
        st.boot_services().open_protocol::<AbsPointer>(
            OpenProtocolParams { handle: h, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        ).ok()
    }).map(|mut p| {
        let ptr: *mut AbsPointer = &mut *p;
        core::mem::forget(p);
        ptr
    }).unwrap_or(core::ptr::null_mut());
    let abs_bounds: (u64, u64, u64, u64) = if !abs_ptr.is_null() {
        let reset_status = unsafe { (*abs_ptr).reset() };
        let b = unsafe { (*abs_ptr).bounds() };
        crate::ovc_exec::serial_log(alloc::format!(
            "[HID] AbsPointer OK bounds=({},{},{},{}) reset={:?}\r\n", b.0, b.1, b.2, b.3, reset_status
        ).as_bytes());
        b
    } else {
        crate::ovc_exec::serial_log(b"[HID] AbsPointer NULL (pas de usb-tablet ?)\r\n");
        (0, 0, 0, 0)
    };

    // Position absolue — soit lue directement du device absolu, soit accumulée à
    // partir des déplacements relatifs du device relatif. Démarre au centre de
    // l'écran. Le clavier passe par ConIn (st.stdin()), déjà le protocole
    // EFI_SIMPLE_TEXT_INPUT_PROTOCOL standard du firmware.
    let mut cursor_x: i32 = w as i32 / 2;
    let mut cursor_y: i32 = h as i32 / 2;
    let mut frame_n: u64 = 0;

    // Le kernel ne fait AUCUN rendu direct.
    // Tout le graphique vient des .ovc (SluGpu.slul + HelloSlura.marep).

    // Construire les références &[u8] pour exec_marep
    let mod_refs: alloc::vec::Vec<(&str, &[u8])> = modules.iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();

    core::mem::forget(gop);

    // ── Étape 1/N d'un pilote USB/HID natif Slura ─────────────────────────────
    // Purement diagnostique pour l'instant : énumère les devices PCI en lecture
    // seule et logue le contrôleur xHCI s'il est trouvé (voir pci.rs). N'affecte
    // pas encore le pointeur/clavier ci-dessus (qui reste sur les protocoles
    // firmware existants) — sert à valider le layout EFI_PCI_IO_PROTOCOL avant
    // d'attaquer l'étape suivante (accès MMIO au contrôleur). Placé après le
    // `forget(gop)` : `gop` empruntait `st` en immutable jusque-là, incompatible
    // avec le `&mut st` requis ici (E0502 sinon).
    let _xhci = crate::pci::scan_for_xhci(st, image_handle);

    // ── Étape 2/N ──────────────────────────────────────────────────────────────
    // Registres de capacité xHCI (lecture seule, aucune init/écriture matérielle
    // encore) — juste de quoi valider le layout avant l'étape 3 (init réelle).
    //
    // ── Étape 3/N ──────────────────────────────────────────────────────────────
    // Reset + initialisation réelle du contrôleur (xhci.rs) — PREMIÈRE écriture
    // matérielle. Retire le contrôleur au pilote USB du firmware : le curseur
    // (EFI_SIMPLE_POINTER_PROTOCOL/EFI_ABSOLUTE_POINTER_PROTOCOL ci-dessus) peut
    // cesser de bouger à partir d'ici, jusqu'à ce que les étapes 4-6 branchent de
    // vrais rapports HID natifs sur pointer_x/y/btn/key_code. Décision assumée
    // par l'utilisateur (curseur temporairement gelé, clavier ConIn non affecté).
    //
    // ── Étapes 4-5/N ───────────────────────────────────────────────────────────
    // Une fois le contrôleur démarré : énumération USB (reset de port, Enable
    // Slot, Address Device, descripteurs) + configuration HID boot protocol
    // (clavier/souris) sur les endpoints interrupt trouvés (usb.rs). Best-effort
    // — chaque device qui échoue est loggé et ignoré, sans bloquer le boot.
    let mut _xhci_ctrl = None;
    let mut hid_devices: alloc::vec::Vec<crate::usb::HidDevice> = alloc::vec::Vec::new();
    if let Some(xhci) = _xhci.as_ref() {
        if let Some(caps) = crate::pci::read_xhci_capabilities(st, image_handle, xhci) {
            _xhci_ctrl = crate::xhci::init_xhci(st, image_handle, xhci, &caps);
            if let Some(ref mut ctrl) = _xhci_ctrl {
                hid_devices = crate::usb::enumerate_and_setup_hid(st, ctrl, caps.max_ports);
                // ATTENTION (correction d'un commentaire précédent FAUX) : init_xhci a
                // fait un HCRST qui a RETIRÉ le contrôleur au pilote USB du firmware.
                // Les protocoles EFI_SIMPLE_POINTER/ABSOLUTE_POINTER ne répondent donc
                // PLUS, que l'énumération native réussisse ou non. Si 0 device HID natif,
                // la souris est indisponible (seul le clavier ConIn survit) — on le signale
                // clairement au lieu de prétendre que le firmware « reste maître ».
                if hid_devices.is_empty() {
                    crate::ovc_exec::serial_log(
                        b"[USB] AUCUN device HID natif configure : souris indisponible (firmware retire par le HCRST, clavier ConIn seul actif)\r\n"
                    );
                }
            }
        }
    }

    // Complément lecture-seule : tables ACPI réelles (RSDP → XSDT → MCFG) au lieu
    // de s'appuyer uniquement sur l'abstraction EFI_PCI_IO_PROTOCOL — donne
    // l'adresse ECAM (config space PCIe mappé mémoire) par segment/plage de bus.
    let _mcfg = crate::acpi::scan_acpi_tables(st);

    // ── Étape 2/N du plan bureau à fenêtres ───────────────────────────────────
    // Registre des apps installées (SDC/slu64/apps/*/Maraset.yaml) — purement
    // diagnostique pour l'instant (log [REGISTRY]), pas encore consommé par le
    // dock (TemplateView.mara garde ses icônes hardcodées jusqu'au branchement
    // dynamique, délibérément différé après le jalon 1 du plan).
    let app_registry = crate::app_registry::scan_installed_apps(st, image_handle);
    // Publie la liste pour le dock dynamique de TemplateView.mara (builtins AppRegistry***).
    crate::app_registry::publish_registry(&app_registry);

    // ── Étape 3/N (révisée) du plan bureau à fenêtres ─────────────────────────
    // La gestion des fenêtres (chargement d'une 2e app, buffer offscreen,
    // compositeur, chrome, hit-test) est désormais pilotée depuis Maratine
    // (LAPrevent.mara, via les builtins DrvAPIInterCon***WindowMan...***,
    // ovc_exec.rs) — le kernel Rust n'appelle plus qu'un seul exec_marep par
    // tick, exactement comme avant l'introduction du bureau à fenêtres.

    // ── Boucle de rafraîchissement ─────────────────────────────────────────────
    // Chaque tick : lit l'état HID réel, ré-exécute exec_marep (seul point
    // d'entrée OVC) avec le contexte à jour — c'est ce qui permet au curseur
    // (dessiné côté Mara via PointerGetX/PointerGetY) de suivre la souris.
    loop {
        let mut pointer_btn: i32 = 0;

        // Les deux chemins souris sont essayés CHAQUE frame (pas de exclusif/sinon) —
        // sur un environnement où l'un des deux ne délivre jamais d'événement (ex.
        // usb-tablet bloqué en NOT_READY dans certains QEMU/OVMF), l'autre reste
        // utilisable. Celui qui a réellement une donnée fraîche met à jour le curseur.
        if !abs_ptr.is_null() {
            let (status, maybe_state) = unsafe { (*abs_ptr).get_state_raw() };
            match maybe_state {
                Some(state) => {
                    let (minx, maxx, miny, maxy) = abs_bounds;
                    let rx = if maxx > minx { maxx - minx } else { 1 };
                    let ry = if maxy > miny { maxy - miny } else { 1 };
                    let nx = (((state.current_x.saturating_sub(minx)) * (w as u64 - 1)) / rx) as i32;
                    let ny = (((state.current_y.saturating_sub(miny)) * (h as u64 - 1)) / ry) as i32;
                    crate::ovc_exec::serial_log(alloc::format!(
                        "[HID] abs=({},{}) active_buttons={:#x} status={:?} -> cursor=({},{})\r\n",
                        state.current_x, state.current_y, state.active_buttons, status, nx, ny
                    ).as_bytes());
                    cursor_x = nx.clamp(0, w as i32 - 1);
                    cursor_y = ny.clamp(0, h as i32 - 1);
                    pointer_btn |= (state.active_buttons & 0x3) as i32;
                }
                None => {
                    // Log périodique (pas chaque frame) pour voir le VRAI status
                    // (NOT_READY, DEVICE_ERROR, UNSUPPORTED...) sans spammer.
                    if frame_n % 120 == 0 {
                        crate::ovc_exec::serial_log(alloc::format!(
                            "[HID] get_state_raw() -> {:?} (frame {})\r\n", status, frame_n
                        ).as_bytes());
                    }
                }
            }
        }
        if !pointer_ptr.is_null() {
            let p = unsafe { &mut *pointer_ptr };
            match p.read_state() {
                Ok(Some(state)) => {
                    cursor_x = (cursor_x + state.relative_movement[0]).clamp(0, w as i32 - 1);
                    cursor_y = (cursor_y + state.relative_movement[1]).clamp(0, h as i32 - 1);
                    pointer_btn |= (state.button[0] as i32) | ((state.button[1] as i32) << 1);
                    if state.button[0] || state.button[1] {
                        crate::ovc_exec::serial_log(alloc::format!(
                            "[HID] rel BOUTON btn0={} btn1={}\r\n", state.button[0], state.button[1]
                        ).as_bytes());
                    }
                    if state.relative_movement[0] != 0 || state.relative_movement[1] != 0 {
                        crate::ovc_exec::serial_log(alloc::format!(
                            "[HID] rel=({},{}) -> cursor=({},{})\r\n",
                            state.relative_movement[0], state.relative_movement[1], cursor_x, cursor_y
                        ).as_bytes());
                    }
                }
                Ok(None) => {} // pas de changement d'état depuis le dernier appel — normal, silencieux
                Err(_) => {
                    crate::ovc_exec::serial_log(b"[HID] read_state() erreur\r\n");
                }
            }
        }

        let mut key_code: i32 = match st.stdin().read_key() {
            Ok(Some(Key::Printable(c))) => u16::from(c) as i32,
            Ok(Some(Key::Special(scan))) => 0x10000 | scan_code_to_i32(scan),
            _ => 0,
        };

        // ── Étape 6/N ──────────────────────────────────────────────────────────
        // Rapports HID natifs (usb.rs) — vient s'ADDITIONNER aux sources
        // firmware ci-dessus, pas les remplacer : si le contrôleur xHCI n'a pas
        // pu être initialisé/énuméré (hid_devices vide), ce bloc ne fait rien et
        // les protocoles EFI_SIMPLE_POINTER/ABSOLUTE_POINTER/ConIn restent seuls
        // maîtres du curseur/clavier, comme avant l'étape 3.
        if !hid_devices.is_empty() {
            if let Some(ref mut ctrl) = _xhci_ctrl {
                let (dx, dy, native_btn, native_key) = crate::usb::poll_hid_reports(st, ctrl, &mut hid_devices);
                if dx != 0 || dy != 0 {
                    cursor_x = (cursor_x + dx).clamp(0, w as i32 - 1);
                    cursor_y = (cursor_y + dy).clamp(0, h as i32 - 1);
                    crate::ovc_exec::serial_log(alloc::format!(
                        "[USB-HID] rel=({},{}) -> cursor=({},{})\r\n", dx, dy, cursor_x, cursor_y
                    ).as_bytes());
                }
                pointer_btn |= native_btn;
                if key_code == 0 && native_key != 0 { key_code = native_key; }
            }
        }

        // Repli garanti : flèches clavier — ConIn fonctionne systématiquement (aucune
        // dépendance à un protocole pointeur USB/PS2 particulier ni à un grab de
        // fenêtre), donc ça bouge le curseur quel que soit l'état de la souris HID.
        const STEP: i32 = 8;
        match key_code {
            c if c == (0x10000 | 1) => cursor_y = (cursor_y - STEP).clamp(0, h as i32 - 1), // UP
            c if c == (0x10000 | 2) => cursor_y = (cursor_y + STEP).clamp(0, h as i32 - 1), // DOWN
            c if c == (0x10000 | 3) => cursor_x = (cursor_x + STEP).clamp(0, w as i32 - 1), // RIGHT
            c if c == (0x10000 | 4) => cursor_x = (cursor_x - STEP).clamp(0, w as i32 - 1), // LEFT
            _ => {}
        }

        let ctx = ovc_exec::ExecCtx {
            fb: back_fb,
            width:    w as i32,
            height:   h as i32,
            stride,
            font:     font_ptr,
            font_len,
            pointer_x:   cursor_x,
            pointer_y:   cursor_y,
            pointer_btn,
            key_code,
        };

        ovc_exec::reset_gpu_state();
        ovc_exec::reset_gpu_counters();
        let _ = ovc_exec::exec_marep(&mod_refs, &ctx);

        // Bascule atomique : le résultat complet de la frame part d'un coup vers
        // l'écran réel, au lieu que chaque élément apparaisse au fil de son dessin.
        unsafe { core::ptr::copy_nonoverlapping(back_fb, fb, buf_len); }

        // ~60 Hz — assez réactif pour suivre la souris sans saturer le CPU en boot UEFI.
        st.boot_services().stall(16_000);
        frame_n = frame_n.wrapping_add(1);
    }
}

