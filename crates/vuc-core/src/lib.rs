#![cfg_attr(feature = "kernel", no_std)]
#![cfg_attr(feature = "kernel", no_main)]
#![cfg_attr(feature = "kernel", feature(alloc_error_handler))]

#[cfg(all(feature = "std", feature = "kernel"))]
compile_error!("features 'std' et 'kernel' sont mutuellement exclusives");

extern crate alloc;

pub use vuc_common::async_once_cell::AsyncOnceCell;

#[cfg(feature = "std")]
pub mod service;

#[cfg(feature = "kernel")]
pub mod lunee;
