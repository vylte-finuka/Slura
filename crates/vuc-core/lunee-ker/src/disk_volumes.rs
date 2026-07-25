//___  Vyft Ltd __  (c) 2026  ___
// ___ Kernel core named Lunee — détection de vrais volumes UEFI physiques ___

//! Scanne tous les handles `SimpleFileSystem` réellement présents au boot (même
//! mécanisme que `app_registry::scan_installed_apps` — lecture seule, aucune
//! écriture) et retient ceux qui ne sont PAS le volume système (celui qui porte
//! `\SDC\slu64`, déjà géré par `disk_id` 0/1 dans `ovc_exec.rs`). Chaque volume
//! supplémentaire trouvé devient un "disque physique" additionnel, exposé en
//! lecture seule (listing de dossier réel, pas de création/format — voir
//! `PhysicalVolume` ci-dessous), avec un `disk_id` à partir de 2. Approche
//! ADDITIVE : ne touche jamais SRFS_DISK_IMAGE/NTFS_DISK_IMAGE ni les 66 sites
//! d'ovc_exec.rs qui supposent `disk_id ∈ {0,1}` pour SDC/A — ces deux restent
//! inchangés, ce module ajoute seulement des entrées AU-DELÀ.

use crate::ovc_exec::serial_log;
use uefi::proto::media::{
    file::{File, FileAttribute, FileMode, FileType},
    fs::SimpleFileSystem,
};
use uefi::table::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::table::{Boot, SystemTable};
use uefi::Handle;

/// Un volume UEFI réel détecté au boot, autre que le volume système (SDC).
/// `handle_index` est l'index dans le tableau retourné par `find_handles` au
/// moment du scan — stable pour toute la session (le noyau ne rescane jamais
/// les volumes en cours de route), utilisé pour rouvrir ce volume précis à la
/// demande (listing de dossier) sans avoir à re-identifier lequel est lequel.
pub struct PhysicalVolume {
    pub handle_index: usize,
    pub label: alloc::string::String, // ex: "Physical Disk 1"
}

/// Scanne tous les volumes `SimpleFileSystem` et retient ceux qui NE contiennent
/// PAS `\SDC\slu64` (marqueur du volume système déjà géré par disk_id 0/1).
/// Lecture seule : ouvre chaque volume juste pour tester l'existence de ce
/// chemin, ne modifie rien. Sur QEMU/VMware standard (un seul volume ESP), ceci
/// retournera très probablement une liste vide — honnête, pas de volume
/// fantôme inventé si aucun second volume UEFI n'est réellement présent.
pub fn scan_physical_volumes(st: &mut SystemTable<Boot>, image_handle: Handle) -> alloc::vec::Vec<PhysicalVolume> {
    let mut result: alloc::vec::Vec<PhysicalVolume> = alloc::vec::Vec::new();

    let handles = match st.boot_services().find_handles::<SimpleFileSystem>() {
        Ok(h) => h,
        Err(_) => {
            serial_log(b"[DISKVOL] SimpleFileSystem introuvable\r\n");
            return result;
        }
    };

    let mut next_label_idx = 1;
    for (idx, &fs_handle) in handles.iter().enumerate() {
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

        // Marqueur du volume système : `\SDC\slu64` existe UNIQUEMENT sur l'ESP
        // que ce noyau a lui-même préparé — tout autre volume qui s'ouvre sans
        // ce dossier est un vrai disque physique distinct.
        let is_system_volume = root
            .open(uefi::cstr16!("\\SDC\\slu64"), FileMode::Read, FileAttribute::empty())
            .map(|h| matches!(h.into_type(), Ok(FileType::Dir(_))))
            .unwrap_or(false);
        if is_system_volume { continue; }

        let label = alloc::format!("Physical Disk {}", next_label_idx);
        next_label_idx += 1;
        serial_log(alloc::format!("[DISKVOL] volume physique trouve : {} (handle #{})\r\n", label, idx).as_bytes());
        result.push(PhysicalVolume { handle_index: idx, label });
    }

    if result.is_empty() {
        serial_log(b"[DISKVOL] aucun volume physique supplementaire (normal sur QEMU/VMware standard)\r\n");
    }
    result
}

/// Énumère RÉELLEMENT le contenu d'un dossier à la racine d'un volume physique
/// (`rel_path` relatif à la racine du volume, ex: "" ou "Documents/") — même
/// idiome que `srfs_uefi_list_dir` (ovc_exec.rs) mais sans le préfixe
/// `SDC/slu64` (ce n'est pas le volume système), et ciblé sur UN volume précis
/// via son `handle_index` plutôt que le premier qui matche.
pub fn list_dir_on_volume(
    st: &mut SystemTable<Boot>,
    image_handle: Handle,
    handle_index: usize,
    rel_path: &str,
) -> Option<alloc::vec::Vec<alloc::string::String>> {
    let handles = st.boot_services().find_handles::<SimpleFileSystem>().ok()?;
    let &fs_handle = handles.get(handle_index)?;
    let mut fs = unsafe {
        st.boot_services().open_protocol::<SimpleFileSystem>(
            OpenProtocolParams { handle: fs_handle, agent: image_handle, controller: None },
            OpenProtocolAttributes::GetProtocol,
        )
    }.ok()?;
    let mut root = fs.open_volume().ok()?;

    let trimmed = rel_path.trim_matches(|c: char| c == '/' || c == '\\');
    let mut ucs2: alloc::vec::Vec<u16> = alloc::vec::Vec::with_capacity(trimmed.len() + 2);
    ucs2.push(b'\\' as u16);
    let mut last_sep = true;
    for b in trimmed.bytes() {
        if b == b'\\' || b == b'/' {
            if !last_sep { ucs2.push(b'\\' as u16); }
            last_sep = true;
        } else {
            ucs2.push(b as u16);
            last_sep = false;
        }
    }
    ucs2.push(0u16);
    let uefi_path = uefi::CStr16::from_u16_with_nul(&ucs2).ok()?;

    let fh = root.open(uefi_path, FileMode::Read, FileAttribute::empty()).ok()?;
    let mut dir = match fh.into_type() { Ok(FileType::Dir(d)) => d, _ => return None };

    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    loop {
        match dir.read_entry_boxed() {
            Ok(Some(info)) => {
                let name = alloc::string::String::from_utf16_lossy(info.file_name().to_u16_slice());
                if name == "." || name == ".." { continue; }
                if info.is_directory() {
                    names.push(alloc::format!("{}/", name));
                } else {
                    names.push(name);
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    Some(names)
}
