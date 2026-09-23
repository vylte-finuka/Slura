#![no_std]
#![no_main]

extern crate alloc;

pub mod app_registry;
pub mod bundle_loader;
pub mod chain_ca;
pub mod hal_manager;
pub(crate) mod kernel_runtime;
pub mod ovc_exec;
pub mod platform_bridge;
pub mod platform_engine_efi;
mod ressources_manager;

pub mod window_manager {
    use alloc::string::String;
    use alloc::vec::Vec;

    #[derive(Clone, Debug, Default)]
    pub struct RunningApp {
        pub name: String,
        pub modules: Vec<(String, Vec<u8>)>,
        pub x: i32,
        pub y: i32,
        pub w: i32,
        pub h: i32,
        pub content_w: i32,
        pub content_h: i32,
        pub opened_tick: u64,
        pub launch_arg_c: Vec<u8>,
        pub launch_arg_gen: i32,
        pub buffer: Vec<u32>,
        pub dirty: bool,
        pub last_rendered_tick: u64,
    }

    impl RunningApp {
        pub fn new(
            name: String,
            modules: Vec<(String, Vec<u8>)>,
            x: i32,
            y: i32,
            w: i32,
            h: i32,
        ) -> Self {
            let content_w = w.max(1);
            let content_h = h.max(1);
            Self {
                name,
                modules,
                x,
                y,
                w,
                h,
                content_w,
                content_h,
                opened_tick: 0,
                launch_arg_c: Vec::new(),
                launch_arg_gen: 0,
                buffer: alloc::vec![0; (content_w as usize) * (content_h as usize)],
                dirty: true,
                last_rendered_tick: 0,
            }
        }

        pub fn resize(&mut self, w: i32, h: i32) {
            self.w = w.max(1);
            self.h = h.max(1);
            self.content_w = self.w;
            self.content_h = self.h;
            self.buffer
                .resize((self.content_w as usize) * (self.content_h as usize), 0);
            self.dirty = true;
        }

        pub fn mod_refs(&mut self) -> alloc::vec::Vec<(&str, &[u8])> {
            let _ = &mut self.modules;
            alloc::vec::Vec::new()
        }

        pub fn blit_into(
            &mut self,
            _dst: &mut [u32],
            _stride: i32,
            _width: i32,
            _height: i32,
            _corner_r: i32,
        ) {
            let _ = (&mut self.buffer, _stride, _width, _height, _corner_r);
        }
    }
}

pub mod format_detect {
    pub const FMT_UNKNOWN: i32 = 0;
    pub fn format_name(_fmt: i32) -> alloc::string::String {
        "bsd-delegated".into()
    }
    pub fn detect_format(_data: &[u8]) -> i32 {
        FMT_UNKNOWN
    }
    pub fn decode_support(_fmt: i32) -> i32 {
        0
    }
}

pub mod media_encode {
    pub fn avi_frame_geometry(w: u32, h: u32) -> (usize, usize) {
        let row = ((w as usize).max(1) * 3 + 3) & !3;
        (row, row * h as usize)
    }
    pub fn png_encode(_w: u32, _h: u32, _rgba: &[u8]) -> alloc::vec::Vec<u8> {
        let _ = (_w, _h, _rgba);
        alloc::vec![]
    }
    pub fn avi_encode(
        _w: u32,
        _h: u32,
        _bpp: u32,
        _frames: &[alloc::vec::Vec<u8>],
    ) -> alloc::vec::Vec<u8> {
        let _ = (_w, _h, _bpp, _frames);
        alloc::vec![]
    }
}

pub mod image_decode {
    pub fn bmp_decode_rgba(_data: &[u8]) -> Option<(u32, u32, alloc::vec::Vec<u8>)> {
        None
    }
    pub fn gif_decode_rgba(_data: &[u8]) -> Option<(u32, u32, alloc::vec::Vec<u8>)> {
        None
    }
}

pub mod mmio_io {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct AcpiReg(pub u64);

    impl AcpiReg {
        pub fn is_present(&self) -> bool {
            self.0 != 0
        }
    }

    impl From<AcpiReg> for u64 {
        fn from(v: AcpiReg) -> u64 {
            v.0
        }
    }
    impl From<u64> for AcpiReg {
        fn from(v: u64) -> Self {
            Self(v)
        }
    }

    pub fn hw_io_call(
        _eax_in: u32,
        _ebx_in: u32,
        _ecx_in: u32,
        _edx_in: u32,
    ) -> (u32, u32, u32, u32) {
        (0, 0, 0, 0)
    }
    pub fn read_reg16<T: Into<u64> + Copy>(_addr: T) -> u16 {
        let _ = _addr;
        0
    }
    pub fn write_reg16<T: Into<u64> + Copy>(_addr: T, _value: u16) {
        let _ = (_addr, _value);
    }
    pub fn write_reg8<T: Into<u64> + Copy>(_addr: T, _value: u8) {
        let _ = (_addr, _value);
    }
    pub fn write_com1_byte(_b: u8) {
        let _ = _b;
    }
}

pub mod acpi {
    use crate::mmio_io::AcpiReg;

    #[derive(Clone, Debug, Default)]
    pub struct PowerMgmt {
        pub smi_cmd: AcpiReg,
        pub pm1a_cnt: AcpiReg,
        pub pm1b_cnt: AcpiReg,
        pub slp_typ_a: u16,
        pub slp_typ_b: u16,
        pub acpi_enable_val: u8,
        pub acpi_disable_val: u8,
        pub sleep_state: u8,
    }

    pub fn scan_acpi_tables(_st: &mut uefi::table::SystemTable<uefi::table::Boot>) -> Option<()> {
        let _ = _st;
        Some(())
    }

    pub fn scan_power_management(
        _st: &mut uefi::table::SystemTable<uefi::table::Boot>,
    ) -> Option<PowerMgmt> {
        let _ = _st;
        None
    }
}

pub mod disk_volumes {
    #[derive(Clone, Debug, Default)]
    pub struct PhysicalVolume {
        pub label: alloc::string::String,
        pub handle_index: usize,
    }

    pub fn scan_physical_volumes(
        _st: &mut uefi::table::SystemTable<uefi::table::Boot>,
        _handle: uefi::Handle,
    ) -> alloc::vec::Vec<PhysicalVolume> {
        let _ = (_st, _handle);
        alloc::vec::Vec::new()
    }

    pub fn list_dir_on_volume(
        _st: &mut uefi::table::SystemTable<uefi::table::Boot>,
        _img: uefi::Handle,
        _handle_index: usize,
        _rel: &str,
    ) -> Option<alloc::vec::Vec<alloc::string::String>> {
        let _ = (_st, _img, _handle_index, _rel);
        None
    }
}

pub mod pci {
    pub type XhciController = ();

    pub fn connect_all_controllers(_st: &mut uefi::table::SystemTable<uefi::table::Boot>) {
        let _ = _st;
    }

    pub fn scan_for_xhci(
        _st: &mut uefi::table::SystemTable<uefi::table::Boot>,
        _handle: uefi::Handle,
    ) -> Option<XhciController> {
        let _ = (_st, _handle);
        None
    }

    pub fn read_xhci_capabilities(
        _st: &mut uefi::table::SystemTable<uefi::table::Boot>,
        _handle: uefi::Handle,
        _xhci: &XhciController,
    ) -> Option<()> {
        let _ = (_st, _handle, _xhci);
        None
    }
}

use crate::kernel_runtime::KernelRuntime;
use core::fmt::Write;
use uefi::{
    entry,
    table::{Boot, SystemTable},
    CStr16, Handle, Status,
};

#[entry]
fn efi_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialise l'allocateur global et les services UEFI.
    uefi_services::init(&mut system_table).unwrap();

    let mut runtime = KernelRuntime::new();

    // ── Phase 0 : lecture loader.env (UEFI DevicePath) ───────────────────────
    // Lit le fichier loader.env depuis l'ESP pour obtenir whesere_root/slura_root
    // et valider que sys/esp correspondent au format UEFI DevicePath.
    if let Some(env) = runtime.read_loader_env(&mut system_table, image_handle) {
        let stdout = system_table.stdout();
        let _ = write!(
            stdout,
            "[BOOT] loader.env: whesere_root={}, slura_root={}\r\n",
            env.whesere_root, env.slura_root
        );
        // Stocke dans le runtime pour le handoff BSD
        runtime.whesere_env = Some(env);
    } else {
        let stdout = system_table.stdout();
        let _ = write!(
            stdout,
            "[BOOT] loader.env non lu (utilise valeurs par defaut)\r\n"
        );
    }

    // ── Phase 1 : boot hardware + chargement drivers .slul ───────────────────
    // boot_phase (kernel_runtime.rs) gère bsd.init, verify_integrity et resources.
    // Selon la logique Whesere, le kernel BSD est chargé mais le saut est différé.
    if let Err(e) = runtime.boot_phase(&mut system_table, image_handle) {
        let stdout = system_table.stdout();
        stdout.clear().unwrap();
        stdout.output_string(
            CStr16::from_u16_with_nul(&[
                // "[ERROR] Boot failed.\r\n\0"
                0x005B, 0x0045, 0x0052, 0x0052, 0x004F, 0x0052, 0x005D, 0x0020, 0x0042, 0x006F,
                0x006F, 0x0074, 0x0020, 0x0066, 0x0061, 0x0069, 0x006C, 0x0065, 0x0064, 0x002E,
                0x000D, 0x000A, 0x0000,
            ])
            .unwrap(),
        );
        // Affiche le code d'erreur pour le débogage
        let _ = write!(stdout, "Status: {:?}\r\n", e);
        loop {}
    }

    // ── Bannière kernel ───────────────────────────────────────────────────────
    system_table
        .stdout()
        .output_string(
            CStr16::from_u16_with_nul(&[
                // "=== Slura Lunée Kernel v0.1 ===\r\n\0"
                0x003D, 0x003D, 0x003D, 0x0020, 0x0053, 0x006C, 0x0075, 0x0072, 0x0061, 0x0020,
                0x004C, 0x0075, 0x006E, 0x00E9, 0x0065, 0x0020, 0x004B, 0x0065, 0x0072, 0x006E,
                0x0065, 0x006C, 0x0020, 0x0076, 0x0030, 0x002E, 0x0031, 0x0020, 0x003D, 0x003D,
                0x003D, 0x000D, 0x000A, 0x0000,
            ])
            .unwrap(),
        )
        .unwrap();

    // ── MARATINE : Lancement direct de ShiLauncher (OVC/GUI) ─────────────────
    // Whesere/BSD = Darwin : OS sous-jacent sans écran de login.
    // ShiLauncher affiche directement. Le handoff BSD est différé après login/config.
    runtime.maratine_phase(&mut system_table, image_handle);

    // NOTE: le handoff BSD (ordonnanceur_inverse) est différé après la phase OVC.
    // ShiLauncher gère la configuration/login, puis déclenche le handoff vers BSD.
    // runtime.whesere.ordonnanceur_inverse(&mut system_table, image_handle, "devnet");

    // Atteint uniquement si OEntry retourne (ne devrait pas arriver).
    loop {
        system_table.boot_services().stall(1_000_000);
    }
}

// ── Wrapper C-ABI attendu par le bootloader C++ ───────────────────────────────
use core::ffi::c_void;

#[no_mangle]
#[inline(never)]
#[allow(dead_code)]
pub extern "C" fn RustEfiEntry(
    image_handle: *mut c_void,
    system_table: *mut c_void,
    _load_options: *mut c_void,
) -> bool {
    // SAFETY: le bootloader fournit des pointeurs valides.
    let image_handle =
        unsafe { Handle::from_ptr(image_handle) }.expect("Invalid ImageHandle pointer");
    let system_table = unsafe { &mut *(system_table as *mut SystemTable<Boot>) };
    let system_table_owned = unsafe { core::ptr::read(system_table) };
    let status = efi_main(image_handle, system_table_owned, _load_options);
    status.is_success()
}

#[used]
static KEEP_RUST_EFI_ENTRY: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool =
    RustEfiEntry;
