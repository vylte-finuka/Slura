//! Point d'entrée du module kernel Lunee (bibliothèque statique).

#![no_std]
#![no_main]

extern crate alloc;

pub mod kernel_runtime;
pub mod ressources_manager;
pub mod hal_manager;
pub mod bundle_loader;
pub mod platform_bridge;
pub mod ovc_exec;
pub mod pci;
pub mod acpi;
pub mod xhci;
pub mod usb;
pub mod app_registry;
pub mod disk_volumes;
pub mod window_manager;
pub mod chain_ca;
pub mod media_encode;
pub mod image_decode;
pub mod format_detect;

use uefi::{entry, CStr16, Status, Handle, table::{Boot, SystemTable}};
use crate::kernel_runtime::KernelRuntime;

#[entry]
fn efi_main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
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

	system_table.stdout().output_string(CStr16::from_u16_with_nul(&[
		0x003D,0x003D,0x003D,0x0020,0x0053,0x006C,0x0075,0x0072,0x0061,0x0020,
		0x004C,0x0075,0x006E,0x00E9,0x0065,0x0020,0x004B,0x0065,0x0072,0x006E,
		0x0065,0x006C,0x0020,0x0076,0x0030,0x002E,0x0031,0x0020,0x003D,0x003D,
		0x003D,0x000D,0x000A,0x0000,
	]).unwrap()).unwrap();

	// Démarre le moteur SluraChain SUR l'OS : LoadImage + StartImage du vrai
	// vuc_platform_engine.efi (application UEFI x86_64-unknown-uefi). Doit être ici,
	// boot services ACTIFS et AVANT maratine_phase (bureau ShiLauncher, boucle infinie).
	runtime.launch_platform_engine(&mut system_table, image_handle, "devnet");

	runtime.maratine_phase(&mut system_table, image_handle);

	loop { system_table.boot_services().stall(1_000_000); }
}

// ── C-ABI wrapper attendu par le bootloader C++ ───────────────────────────────
use core::ffi::c_void;

#[no_mangle]
#[inline(never)]
#[allow(dead_code)]
pub extern "C" fn RustEfiEntry(
	image_handle: *mut c_void,
	system_table: *mut c_void,
	_load_options: *mut c_void,
) -> bool {
	let image_handle = unsafe { Handle::from_ptr(image_handle) }.expect("Invalid ImageHandle");
	let system_table = unsafe { &mut *(system_table as *mut SystemTable<Boot>) };
	let system_table_owned = unsafe { core::ptr::read(system_table) };
	let status = efi_main(image_handle, system_table_owned);
	status.is_success()
}

#[used]
static KEEP_RUST_EFI_ENTRY: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool = RustEfiEntry;
