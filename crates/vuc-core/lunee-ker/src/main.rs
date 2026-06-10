#![no_std]
#![no_main]

extern crate alloc;

pub(crate) mod kernel_runtime;
pub mod hal_manager;
mod ressources_manager;

// Import uniquement les types du module `boot`
use uefi::{entry, CStr16, Status, Handle, table::{Boot, SystemTable}};
use crate::kernel_runtime::KernelRuntime;

// Le panic handler fourni par `uefi_services` est déjà présent, donc aucune
// définition supplémentaire n’est nécessaire.

#[entry]
fn efi_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    // Initialise les services UEFI (enregistre l'allocateur global).
    uefi_services::init(&mut system_table).unwrap();

    let mut runtime = KernelRuntime::new();
    if let Err(_) = runtime.boot_phase(&mut system_table, image_handle) {
        let stdout = system_table.stdout();
        stdout.clear().unwrap();
        stdout.output_string(CStr16::from_u16_with_nul(&[
            0x005B,0x0045,0x0052,0x0052,0x004F,0x0052,0x005D,0x0020,
            0x0042,0x006F,0x006F,0x0074,0x0020,0x0066,0x0061,0x0069,
            0x006C,0x0065,0x0064,0x002E,0x000D,0x000A,0x0000,
        ]).unwrap());
        loop {}
    }

    let stdout = system_table.stdout();

    // ---------------------------------------------------------------------
    //  Affichage du message de démarrage du kernel.
    // ---------------------------------------------------------------------
    stdout.output_string(CStr16::from_u16_with_nul(&[
        0x003D,0x003D,0x003D,0x0020,0x0053,0x006C,0x0075,0x0072,0x0061,0x0020,
        0x004C,0x0075,0x006E,0x00E9,0x0065,0x0020,0x004B,0x0065,0x0072,0x006E,
        0x0065,0x006C,0x0020,0x0076,0x0030,0x002E,0x0031,0x0020,0x003D,0x003D,
        0x003D,0x000D,0x000A,0x0000,
    ]).unwrap()).unwrap();

    loop {
        system_table.boot_services().stall(1_000_000);
    }
}

// ---------------------------------------------------------------------
//  Wrapper C‑ABI function expected by le bootloader C++.
// ---------------------------------------------------------------------
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
    // SAFETY: the pointer comes from the UEFI bootloader and is guaranteed to be valid.
    let image_handle = unsafe { Handle::from_ptr(image_handle) };
    // Cast the raw pointer to the concrete UEFI boot SystemTable type.
    let system_table = unsafe { &mut *(system_table as *mut SystemTable<Boot>) };
    // `Handle::from_ptr` returns `Option<Handle>`; unwrap safely.
    let image_handle = image_handle.expect("Invalid ImageHandle pointer");
    // Move the SystemTable out of the raw pointer without requiring Copy.
    let system_table_owned = unsafe { core::ptr::read(system_table) };
    let status = efi_main(image_handle, system_table_owned);
    status.is_success()
}

// Force the linker to keep the `RustEfiEntry` symbol even if it appears unused in Rust code.
#[used]
static KEEP_RUST_EFI_ENTRY: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool = RustEfiEntry;