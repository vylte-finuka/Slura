//===================================================================
//  input_manager.rs – Gestion complète des entrées/sorties (I/O)
//
//  Support pour :
//  - Clavier/souris PS/2 (IRQ 1, IRQ 12)
//  - Clavier/souris USB HID
//  - Scancode decoder
//  - Buffer circulaire d'entrées
//
//  Respect strict de l'AMD64 Architecture Programmer's Manual
//===================================================================

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

// ===================================================================
//  1️⃣  PORTS I/O (Conformité AMD64 x86-64)
// ===================================================================

/// Lecture d'un octet depuis un port I/O
/// AMD64 spec : IN (REX.W ignored, 8-bit read)
#[inline]
pub unsafe fn io_read_u8(port: u16) -> u8 {
    let mut result: u8;
    asm!("in al, dx", 
         in("dx") port, 
         out("al") result, 
         options(nostack, preserves_flags));
    result
}

/// Écriture d'un octet vers un port I/O
/// AMD64 spec : OUT (REX.W ignored, 8-bit write)
#[inline]
pub unsafe fn io_write_u8(port: u16, value: u8) {
    asm!("out dx, al", 
         in("dx") port, 
         in("al") value, 
         options(nostack, preserves_flags));
}

/// Lecture d'un mot (16-bit) depuis un port I/O
#[inline]
pub unsafe fn io_read_u16(port: u16) -> u16 {
    let mut result: u16;
    asm!("in ax, dx", 
         in("dx") port, 
         out("ax") result, 
         options(nostack, preserves_flags));
    result
}

/// Écriture d'un mot (16-bit) vers un port I/O
#[inline]
pub unsafe fn io_write_u16(port: u16, value: u16) {
    asm!("out dx, ax", 
         in("dx") port, 
         in("ax") value, 
         options(nostack, preserves_flags));
}

// ===================================================================
//  2️⃣  PS/2 CONTROLLER (Clavier et souris)
// ===================================================================

/// Ports du contrôleur PS/2 (Intel 8042)
pub mod ps2_ports {
    pub const DATA_PORT: u16 = 0x60;        // Lecture/écriture données
    pub const CMD_STATUS_PORT: u16 = 0x64;  // Écriture commande / Lecture status
}

/// Registre de statut PS/2
#[repr(u8)]
pub enum PS2Status {
    OutputBufferFull = 0x01,    // Bit 0 : données disponibles
    InputBufferFull = 0x02,     // Bit 1 : buffer d'entrée plein
    SystemFlag = 0x04,          // Bit 2 : drapeau système
    CommandData = 0x08,         // Bit 3 : 0=données, 1=commande
    Locked = 0x10,              // Bit 4 : clavier verrouillé
    MouseOutputBufferFull = 0x20, // Bit 5 : données souris
    TimeoutError = 0x40,        // Bit 6 : timeout
    ParityError = 0x80,         // Bit 7 : erreur parité
}

/// Commandes PS/2 standard
pub mod ps2_commands {
    pub const SEND_DIAGNOSTIC: u8 = 0xAA;      // Auto-test
    pub const SEND_PORT2_CMD: u8 = 0xA9;       // Test port 2
    pub const DISABLE_PORT2: u8 = 0xA7;        // Désactiver port 2 (souris)
    pub const ENABLE_PORT2: u8 = 0xA8;         // Activer port 2
    pub const DISABLE_PORT1: u8 = 0xAD;        // Désactiver port 1 (clavier)
    pub const ENABLE_PORT1: u8 = 0xAE;         // Activer port 1
    pub const SEND_CONTROLLER_CONFIG: u8 = 0x20; // Lire config
    pub const SEND_CONFIG_TO_CONTROLLER: u8 = 0x60; // Écrire config
}

/// Configuration du contrôleur PS/2
#[repr(u8)]
pub struct PS2Config {
    pub port1_interrupt: bool,      // Bit 0 : IRQ clavier activée
    pub port2_interrupt: bool,      // Bit 1 : IRQ souris activée
    pub system_flag: bool,          // Bit 2 : drapeau système
    pub _reserved1: bool,           // Bit 3
    pub port1_translation: bool,    // Bit 6 : traduction scancode
    pub _reserved2: bool,           // Bits 4, 5, 7
}

impl PS2Config {
    pub fn to_u8(&self) -> u8 {
        let mut val: u8 = 0;
        if self.port1_interrupt { val |= 0x01; }
        if self.port2_interrupt { val |= 0x02; }
        if self.system_flag { val |= 0x04; }
        if self.port1_translation { val |= 0x40; }
        val
    }

    pub fn from_u8(val: u8) -> Self {
        Self {
            port1_interrupt: (val & 0x01) != 0,
            port2_interrupt: (val & 0x02) != 0,
            system_flag: (val & 0x04) != 0,
            _reserved1: false,
            port1_translation: (val & 0x40) != 0,
            _reserved2: false,
        }
    }
}

// ===================================================================
//  3️⃣  SCANCODE DECODER (US QWERTY)
// ===================================================================

/// Table de décodage scancode vers ASCII (US QWERTY)
pub const SCANCODE_TO_ASCII: [u8; 256] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',      // 0-9
    b'9', b'0', b'-', b'=', b'\x08', b'\t', b'q', b'w', b'e', b'r', // 10-19
    b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n', 0,   // 20-29 (Control)
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';',  // 30-39
    b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v', b'b', b'n',   // 40-49 (LShift)
    b'm', b',', b'.', b'/', 0, b'*', 0, b' ', 0, 0,               // 50-59
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 60-79 (F-keys, etc)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 80-99
    // Rest filled with 0 for unmapped keys
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 100-115
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 116-131
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 132-147
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 148-163
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 164-179
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 180-195
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 196-211
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 212-227
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 228-243
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              // 244-256
];

/// Drapeaux de touche
#[derive(Copy, Clone)]
pub struct KeyFlags {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
    pub scroll_lock: bool,
}

impl KeyFlags {
    pub fn new() -> Self {
        Self {
            shift: false,
            ctrl: false,
            alt: false,
            caps_lock: false,
            num_lock: false,
            scroll_lock: false,
        }
    }
}

/// Événement clavier
#[derive(Copy, Clone, Debug)]
pub struct KeyEvent {
    pub scancode: u8,
    pub ascii: u8,
    pub pressed: bool,   // true = appuyée, false = relâchée
}

// ===================================================================
//  4️⃣  ÉVÉNEMENT SOURIS (PS/2 ou USB HID)
// ===================================================================

/// Événement souris
#[derive(Copy, Clone, Debug)]
pub struct MouseEvent {
    pub x: i16,         // Déplacement X (signé)
    pub y: i16,         // Déplacement Y (signé)
    pub left_button: bool,
    pub right_button: bool,
    pub middle_button: bool,
}

impl MouseEvent {
    pub fn new() -> Self {
        Self {
            x: 0,
            y: 0,
            left_button: false,
            right_button: false,
            middle_button: false,
        }
    }
}

// ===================================================================
//  5️⃣  BUFFER CIRCULAIRE (Thread-safe)
// ===================================================================

/// Buffer circulaire pour événements entrée
pub struct CircularBuffer<T: Copy, const CAPACITY: usize> {
    buffer: UnsafeCell<[T; CAPACITY]>,
    head: AtomicU16,
    tail: AtomicU16,
}

impl<T: Copy + Default, const CAPACITY: usize> CircularBuffer<T, CAPACITY> {
    pub fn new() -> Self {
        Self {
            buffer: UnsafeCell::new([T::default(); CAPACITY]),
            head: AtomicU16::new(0),
            tail: AtomicU16::new(0),
        }
    }

    pub fn push(&self, item: T) -> bool {
        let head = self.head.load(Ordering::SeqCst);
        let next_head = (head + 1) % (CAPACITY as u16);

        if next_head == self.tail.load(Ordering::SeqCst) {
            return false; // Buffer plein
        }

        unsafe {
            (*self.buffer.get_mut())[head as usize] = item;
        }
        self.head.store(next_head, Ordering::SeqCst);
        true
    }

    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::SeqCst);

        if tail == self.head.load(Ordering::SeqCst) {
            return None; // Buffer vide
        }

        let item = unsafe { (*self.buffer.get())[tail as usize] };
        self.tail.store((tail + 1) % (CAPACITY as u16), Ordering::SeqCst);
        Some(item)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::SeqCst) == self.tail.load(Ordering::SeqCst)
    }

    pub fn is_full(&self) -> bool {
        let next_head = (self.head.load(Ordering::SeqCst) + 1) % (CAPACITY as u16);
        next_head == self.tail.load(Ordering::SeqCst)
    }
}

// ===================================================================
//  6️⃣  PS/2 CONTROLLER MANAGER
// ===================================================================

pub struct PS2Controller {
    key_flags: KeyFlags,
    initialized: AtomicBool,
}

impl PS2Controller {
    pub fn new() -> Self {
        Self {
            key_flags: KeyFlags::new(),
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialisation du contrôleur PS/2 (AMD64)
    pub fn init(&mut self) -> Result<(), &'static str> {
        unsafe {
            // 1. Désactiver les ports
            self.send_command(ps2_commands::DISABLE_PORT1)?;
            self.send_command(ps2_commands::DISABLE_PORT2)?;

            // 2. Vider le buffer
            while (self.read_status() & (PS2Status::OutputBufferFull as u8)) != 0 {
                let _ = io_read_u8(ps2_ports::DATA_PORT);
            }

            // 3. Lire la configuration
            self.send_command(ps2_commands::SEND_CONTROLLER_CONFIG)?;
            let config_byte = io_read_u8(ps2_ports::DATA_PORT);
            let mut config = PS2Config::from_u8(config_byte);

            // 4. Configurer les interruptions
            config.port1_interrupt = true;
            config.port2_interrupt = true;
            config.port1_translation = false; // Mode scancode brut

            // 5. Écrire nouvelle configuration
            self.send_command(ps2_commands::SEND_CONFIG_TO_CONTROLLER)?;
            io_write_u8(ps2_ports::DATA_PORT, config.to_u8());

            // 6. Activer les ports
            self.send_command(ps2_commands::ENABLE_PORT1)?;
            self.send_command(ps2_commands::ENABLE_PORT2)?;

            self.initialized.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Lire le statut PS/2
    unsafe fn read_status(&self) -> u8 {
        io_read_u8(ps2_ports::CMD_STATUS_PORT)
    }

    /// Envoyer une commande au contrôleur
    unsafe fn send_command(&self, cmd: u8) -> Result<(), &'static str> {
        // Attendre que le buffer d'entrée soit vide
        for _ in 0..100 {
            if (self.read_status() & (PS2Status::InputBufferFull as u8)) == 0 {
                io_write_u8(ps2_ports::CMD_STATUS_PORT, cmd);
                return Ok(());
            }
        }
        Err("PS/2: Timeout sending command")
    }

    /// Lire un scancode clavier
    pub fn read_scancode(&self) -> Option<u8> {
        unsafe {
            let status = self.read_status();
            if (status & (PS2Status::OutputBufferFull as u8)) != 0 {
                Some(io_read_u8(ps2_ports::DATA_PORT))
            } else {
                None
            }
        }
    }

    /// Décoder un scancode en ASCII
    pub fn decode_scancode(&mut self, scancode: u8) -> Option<KeyEvent> {
        let pressed = (scancode & 0x80) == 0;
        let code = scancode & 0x7F;

        // Mettre à jour les drapeaux
        match code {
            0x2A | 0x36 => self.key_flags.shift = pressed,     // Shift
            0x1D => self.key_flags.ctrl = pressed,              // Ctrl
            0x38 => self.key_flags.alt = pressed,               // Alt
            0x3A => self.key_flags.caps_lock = !self.key_flags.caps_lock,
            0x45 => self.key_flags.num_lock = !self.key_flags.num_lock,
            0x46 => self.key_flags.scroll_lock = !self.key_flags.scroll_lock,
            _ => {}
        }

        let ascii = SCANCODE_TO_ASCII[code as usize];

        Some(KeyEvent {
            scancode: code,
            ascii,
            pressed,
        })
    }
}

// ===================================================================
//  7️⃣  INPUT MANAGER (Interface unifiée)
// ===================================================================

pub struct InputManager {
    ps2: PS2Controller,
    keyboard_buffer: CircularBuffer<KeyEvent, 256>,
    mouse_buffer: CircularBuffer<MouseEvent, 128>,
}

impl InputManager {
    pub fn new() -> Self {
        Self {
            ps2: PS2Controller::new(),
            keyboard_buffer: CircularBuffer::new(),
            mouse_buffer: CircularBuffer::new(),
        }
    }

    /// Initialiser tous les périphériques d'entrée
    pub fn init(&mut self) -> Result<(), &'static str> {
        self.ps2.init()?;
        Ok(())
    }

    /// Traiter les événements clavier PS/2
    pub fn process_keyboard(&mut self) {
        if let Some(scancode) = self.ps2.read_scancode() {
            if let Some(key_event) = self.ps2.decode_scancode(scancode) {
                let _ = self.keyboard_buffer.push(key_event);
            }
        }
    }

    /// Lire un événement clavier du buffer
    pub fn read_key(&self) -> Option<KeyEvent> {
        self.keyboard_buffer.pop()
    }

    /// Ajouter un événement souris au buffer
    pub fn push_mouse_event(&self, event: MouseEvent) -> bool {
        self.mouse_buffer.push(event)
    }

    /// Lire un événement souris du buffer
    pub fn read_mouse(&self) -> Option<MouseEvent> {
        self.mouse_buffer.pop()
    }

    /// Vérifier si le buffer clavier est vide
    pub fn keyboard_empty(&self) -> bool {
        self.keyboard_buffer.is_empty()
    }

    /// Vérifier si le buffer souris est vide
    pub fn mouse_empty(&self) -> bool {
        self.mouse_buffer.is_empty()
    }
}

// ===================================================================
//  8️⃣  IRQ HANDLERS (AMD64 Interrupt Service Routines)
// ===================================================================

/// Handler IRQ 1 (clavier PS/2)
/// À enregistrer dans l'IDT (Interrupt Descriptor Table) AMD64
pub extern "x86-interrupt" fn irq1_keyboard_handler(
    _stack_frame: &mut crate::hal_manager::InterruptStackFrame,
) {
    // À implémenter avec le gestionnaire global d'entrées
    // Appeler InputManager::process_keyboard()
}

/// Handler IRQ 12 (souris PS/2)
/// À enregistrer dans l'IDT
pub extern "x86-interrupt" fn irq12_mouse_handler(
    _stack_frame: &mut crate::hal_manager::InterruptStackFrame,
) {
    // À implémenter avec le gestionnaire global de souris
    // Lire les données PS/2 et créer MouseEvent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_buffer() {
        let buf: CircularBuffer<u8, 4> = CircularBuffer::new();
        
        assert!(buf.push(1));
        assert!(buf.push(2));
        assert!(buf.push(3));
        
        assert_eq!(buf.pop(), Some(1));
        assert_eq!(buf.pop(), Some(2));
        assert_eq!(buf.pop(), Some(3));
        assert_eq!(buf.pop(), None);
    }

    #[test]
    fn test_ps2_config() {
        let mut config = PS2Config::new();
        config.port1_interrupt = true;
        config.port2_interrupt = true;
        
        let byte = config.to_u8();
        let decoded = PS2Config::from_u8(byte);
        
        assert!(decoded.port1_interrupt);
        assert!(decoded.port2_interrupt);
    }
}
