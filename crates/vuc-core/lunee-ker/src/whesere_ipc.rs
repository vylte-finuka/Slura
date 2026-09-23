//! Zone d'échange IPC unifiée pour le noyau hybride Whesere (Lunée + SluraBSD).
//! Conçu pour être conforme C-ABI et thread-safe sans dépendances externes.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::ffi::c_void;

pub const IPC_MAGIC: u64 = 0x574853525F495043; // "WHSR_IPC"
pub const BUFFER_SIZE: usize = 65536; // 64 Ko pour les paquets réseau

/// Types de messages transitant dans l'IPC unifié
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcMessageType {
    SystemCmd = 1,
    NetworkTx = 2,
    NetworkRx = 3,
    GraphicsUpdate = 4,
}

/// Structure d'un message individuel au format C-ABI
#[repr(C)]
pub struct IpcMessage {
    pub msg_type: IpcMessageType,
    pub length: u32,
    pub payload: [u8; 1024],
}

/// Tampon circulaire partagé (Ring Buffer) Lock-Free
#[repr(C)]
pub struct SharedRingBuffer {
    pub head: AtomicUsize,
    pub tail: AtomicUsize,
    pub buffer: [u8; BUFFER_SIZE],
}

/// Table d'interface unifiée partagée en Kernelspace (Similaire au modèle Mach / XNU)
#[repr(C)]
pub struct WhesereIpcTable {
    /// Identifiant de contrôle de validité de la structure
    pub magic: u64,
    /// Ring buffer pour les requêtes de Lunée vers SluraBSD (ex: Envoi Réseau TX)
    pub tx_ring: SharedRingBuffer,
    /// Ring buffer pour les requêtes de SluraBSD vers Lunée (ex: Réception Réseau RX, Framebuffer)
    pub rx_ring: SharedRingBuffer,
    /// Pointeur de fonction vers l'allocateur de pages de Lunée accessible par BSD
    pub alloc_pages_cb: extern "C" fn(pages: usize) -> *mut c_void,
}

// Primitives de communication Ring-Buffer de base
impl SharedRingBuffer {
    pub const fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [0u8; BUFFER_SIZE],
        }
    }

    pub fn push(&self, data: &[u8]) -> Result<(), ()> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let available = BUFFER_SIZE - (head.wrapping_sub(tail));

        if available < data.len() + 2 { return Err(()); }

        let base = self.buffer.as_ptr() as usize;

        // Écrit d'abord la taille (u16)
        let len = data.len() as u16;
        let len_bytes = len.to_le_bytes();
        for i in 0..2 {
            let idx = (head + i) % BUFFER_SIZE;
            unsafe { (base as *mut u8).add(idx).write(len_bytes[i]); }
        }

        // Écrit le payload
        for i in 0..data.len() {
            let idx = (head + 2 + i) % BUFFER_SIZE;
            unsafe { (base as *mut u8).add(idx).write(data[i]); }
        }

        self.head.store(head.wrapping_add(2 + data.len()), Ordering::Release);
        Ok(())
    }
}

/// Fonction d'initialisation de l'IPC appelée par Lunée au boot
pub fn create_shared_ipc_table(alloc_cb: extern "C" fn(usize) -> *mut c_void) -> *mut WhesereIpcTable {
    // Allocation globale en mémoire brute kernel
    let ptr = alloc_cb((core::mem::size_of::<WhesereIpcTable>() + 4095) / 4096) as *mut WhesereIpcTable;
    if ptr.is_null() { return core::ptr::null_mut(); }
    
    unsafe {
        (*ptr).magic = IPC_MAGIC;
        core::ptr::write(&mut (*ptr).tx_ring, SharedRingBuffer::new());
        core::ptr::write(&mut (*ptr).rx_ring, SharedRingBuffer::new());
        (*ptr).alloc_pages_cb = alloc_cb;
    }
    ptr
}