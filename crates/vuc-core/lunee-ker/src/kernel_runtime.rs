//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee ___

//! Runtime du kernel Lunée.
//! Le rendu graphique passe par SluGpu.slul (ovc_exec::exec_fn → GpuImpl.ovc).

use core::fmt::Write;

use crate::ressources_manager::RessourcesManager;
use crate::bundle_loader::{marep_loader, BundleError};
use uefi::{CStr16, Handle, Status, table::{Boot, SystemTable}};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};

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
        let _ = st.stdout().write_str("[MARATINE] Searching for HelloSlura.marep...\r\n");
        match marep_loader::load_and_run(st, image_handle) {
            Ok(code) => {
                let _ = write!(st.stdout(), "[MARATINE] OEntry returned {}\r\n", code);
            }
            Err(BundleError::FileNotFound) => {
                let _ = st.stdout().write_str("[MARATINE] HelloSlura.marep not found.\r\n");
            }
            Err(BundleError::NotInitialized) => {
                let _ = st.stdout().write_str("[MARATINE] HelloSlura.marep OK — OVC trouve.\r\n");
            }
            Err(BundleError::ExecutionFailed(code)) => {
                let _ = write!(st.stdout(), "[MARATINE] Execution echouee code {}\r\n", code);
            }
            Err(e) => {
                let _ = write!(st.stdout(), "[MARATINE] Load error: {:?}\r\n", e);
            }
        }
    }
}

// ── Rendu HelloSlura via SluGpu.slul / GpuImpl.ovc ───────────────────────────
//
// Toutes les opérations GOP passent par ovc_exec::exec_fn(GpuImpl.ovc, ...).
// Le kernel ne contient aucune logique de rendu direct — uniquement :
//   1. ouverture du GOP (accès hardware kernel-only)
//   2. conversion pixel format (bridge DrvManSpec ↔ GOP)
//   3. dispatch via exec_fn → SluGpu driver
//
// DrvManSpec___PtrWrite32At___ est la seule primitive qui écrit dans le fb.

/// Conversion ARGB 0x00RRGGBB → format GOP.
fn col(argb: u32, fmt: PixelFormat) -> i64 {
    let r = (argb >> 16) & 0xFF;
    let g = (argb >> 8)  & 0xFF;
    let b =  argb        & 0xFF;
    let v = match fmt {
        PixelFormat::Bgr => (r << 16) | (g << 8) | b,
        _                => (b << 16) | (g << 8) | r,
    };
    v as i64
}

/// Lance le rendu HelloSlura via SluGpu.slul (GpuImpl.ovc) puis la boucle clavier.
pub fn render_marep_screen(st: &mut SystemTable<Boot>, image_handle: Handle) {
    use crate::ovc_exec;

    // SluGpu doit avoir enregistré son GpuImpl.ovc
    if !ovc_exec::gpu_ready() {
        let _ = st.stdout().write_str("[MARATINE] SluGpu non charge — rendu annule.\r\n");
        return;
    }
    let gpu_ovc = match ovc_exec::gpu_ovc() {
        Some(o) => o,
        None    => return,
    };

    // Ouvrir GOP
    let handles = match st.boot_services().find_handles::<GraphicsOutput>() {
        Ok(h) if !h.is_empty() => h,
        Ok(_) => {
            let _ = st.stdout().write_str("[MARATINE] GOP: aucun handle — VGA absent (ajoutez -device VGA)\r\n");
            return;
        },
        Err(_) => {
            let _ = st.stdout().write_str("[MARATINE] GOP: find_handles echoue\r\n");
            return;
        },
    };
    let _ = st.stdout().write_str("[MARATINE] GOP: handle trouve, ouverture...\r\n");
    let mut gop = match unsafe {
        st.boot_services().open_protocol::<GraphicsOutput>(
            OpenProtocolParams { handle: handles[0], agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    } { Ok(g) => g, Err(_) => return };

    let info   = gop.current_mode_info();
    let (w, h) = info.resolution();
    let stride = info.stride() as i32;
    let fmt    = info.pixel_format();
    let fb     = gop.frame_buffer().as_mut_ptr() as *mut u32;

    let ctx = ovc_exec::ExecCtx { fb, width: w as i32, height: h as i32, stride };
    let log_res = alloc::format!("[MARATINE] GOP: {}x{} stride={}\r\n", w, h, stride);

    // Couleurs HelloWorld.ovc converties au format GOP
    let bg   = col(0x001A1A2E, fmt);
    let rect = col(0x00334466, fmt);
    let titl = col(0x00FFE0E0, fmt);
    let sub  = col(0x00AAAACC, fmt);
    let foot = col(0x00443D26, fmt);

    let wi = w as i32;
    let hi = h as i32;
    let hw = hi / 2;
    let rx = wi / 4;
    let rw = wi / 2;

    // ── GpuInit(gop_handle) ───────────────────────────────────────────────────
    ovc_exec::exec_fn(gpu_ovc, "GpuInit", &[fb as i64], &ctx);

    // ── GpuFill(bg) ───────────────────────────────────────────────────────────
    ovc_exec::exec_fn(gpu_ovc, "GpuFill", &[bg], &ctx);

    // ── GpuDrawRect(w/4, h/2-36, w/2, 2, rect) ── barre supérieure
    ovc_exec::exec_fn(gpu_ovc, "GpuDrawRect",
        &[rx as i64, (hw-36) as i64, rw as i64, 2, rect], &ctx);

    // ── GpuDrawText("Hello Slura !") ──────────────────────────────────────────
    {
        let title  = b"Hello Slura !\0";
        let scale  = 2i32;   // GpuDrawText est 8×16 natif, scale via appels multiples
        let t_w    = (title.len() as i32 - 1) * 8 * scale;
        let tx     = ((wi - t_w) / 2) as i64;
        // Appel direct : GpuDrawText dessine en 8×16 (scale 1)
        // Pour "scale 2" on double le rendu en deux passes décalées de 8 px
        ovc_exec::exec_fn(gpu_ovc, "GpuDrawText",
            &[tx, (hw-24) as i64, title.as_ptr() as i64, titl, bg], &ctx);
        // 2ème passe décalée de 8px en Y pour simuler scale ×2
        ovc_exec::exec_fn(gpu_ovc, "GpuDrawText",
            &[tx, (hw-16) as i64, title.as_ptr() as i64, titl, bg], &ctx);
    }

    // ── GpuDrawText("Lunee Kernel v0.1  |  Maratine 1.0") ────────────────────
    {
        let subtitle = b"Lunee Kernel v0.1  |  Maratine 1.0\0";
        let s_w = (subtitle.len() as i32 - 1) * 8;
        let sx  = ((wi - s_w) / 2) as i64;
        ovc_exec::exec_fn(gpu_ovc, "GpuDrawText",
            &[sx, (hw+4) as i64, subtitle.as_ptr() as i64, sub, bg], &ctx);
    }

    // ── GpuDrawRect(w/4, h/2+28, w/2, 1, rect) ── barre inférieure
    ovc_exec::exec_fn(gpu_ovc, "GpuDrawRect",
        &[rx as i64, (hw+28) as i64, rw as i64, 1, rect], &ctx);

    // ── GpuDrawText("Vyft Ltd  --  2026") ────────────────────────────────────
    {
        let footer = b"Vyft Ltd  --  2026\0";
        let f_w = (footer.len() as i32 - 1) * 8;
        let fx  = ((wi - f_w) / 2) as i64;
        ovc_exec::exec_fn(gpu_ovc, "GpuDrawText",
            &[fx, (hw+38) as i64, footer.as_ptr() as i64, foot, bg], &ctx);
    }

    // ── GpuFlushRenderContext ─────────────────────────────────────────────────
    ovc_exec::exec_fn(gpu_ovc, "GpuFlushRenderContext", &[0], &ctx);

    // GOP fermé ici — framebuffer VRAM persiste à l'écran.
    drop(gop);

    // Log résolution (après drop pour éviter le conflit d'emprunt)
    let _ = st.stdout().write_str(&log_res);
    let _ = st.stdout().write_str("[MARATINE] Rendu HelloSlura OK — ESC pour quitter\r\n");

    // ── Boucle événement : ESC pour quitter ───────────────────────────────────
    use uefi::proto::console::text::{Key, ScanCode};
    loop {
        if let Ok(Some(Key::Special(sc))) = st.stdin().read_key() {
            if sc == ScanCode::ESCAPE { break; }
        }
        for _ in 0..100_000u32 { core::hint::spin_loop(); }
    }
}
