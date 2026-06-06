// Minimal FFI bridge for EFI boot

#[no_mangle]
pub static mut load_options: *const u8 = std::ptr::null();

#[no_mangle]
pub unsafe extern "C" fn RustEfiEntry(
    _image_handle: *mut core::ffi::c_void,
    _system_table: *mut core::ffi::c_void,
    _load_options: *mut core::ffi::c_void,
) -> bool {
    // mémoriser le pointeur LoadOptions pour le kernel
    load_options = _load_options as *const u8;
    true            // indique que le démarrage s’est bien passé
}