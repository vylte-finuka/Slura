/// Structure pour stocker les variables lues depuis loader.env
#[derive(Debug, Default, Clone)]
pub struct LoaderEnv {
    /// Chemin de la partition WHESERE (ESP), ex: "/dev/sda1"
    pub whesere_part: alloc::string::String,
    /// Chemin de la partition SLURA (système), ex: "/dev/sda2"
    pub slura_part: alloc::string::String,
    /// UUID de la partition WHESERE
    pub whesere_uuid: alloc::string::String,
    /// UUID de la partition SLURA
    pub slura_uuid: alloc::string::String,
    /// Drapeau uefi_ignore_boot_mgr
    pub uefi_ignore_boot_mgr: bool,
    /// Racine WHESERE (ex: \EFI\WHESERE)
    pub whesere_root: alloc::string::String,
    /// Racine SLURA (ex: \SDC\slu64)
    pub slura_root: alloc::string::String,
}
