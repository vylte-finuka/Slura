#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------
# Chemins du projet
# -----------------------------------------------------------------
PROJ_ROOT="/mnt/d/Downloads/Vyft_product/Slura/slr_clk_bt/x64/amd64"
ESP_DIR="${PROJ_ROOT}/esp"
ISO_FILE="/mnt/d/Downloads/Vyft_product/Slura/booter.iso"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="${PROJ_ROOT}/OVMF_VARS_4M.fd"

# -----------------------------------------------------------------
# Mode de démarrage :
#   --esp  (défaut) : répertoire ESP via fat:rw  — dev / rechargement à chaud
#   --iso           : fichier booter.iso          — test de distribution
# -----------------------------------------------------------------
MODE="${1:---esp}"

# -----------------------------------------------------------------
# 0️⃣  Nettoyage des logs
# -----------------------------------------------------------------
rm -f "${PROJ_ROOT}/qemu.log" "${PROJ_ROOT}/ovmf.log" 2>/dev/null || true

# -----------------------------------------------------------------
# Structure ESP (générée par le pipeline de build) :
#
#   esp/
#   ├── slr_clk_bt.efi            ← kernel Lunée (Rust UEFI)
#   │     └─ chargé par BOOTX64.EFI via LoadImage(\slr_clk_bt.efi)
#   │
#   ├── HelloSlura.marep           ← application Maratine (racine)
#   │
#   ├── boot/
#   │   ├── assets/font/
#   │   │   └── brsonomasemibold.ttf  ← police TrueType (accessible au boot)
#   │   └── font/
#   │       └── SluFontConf.slul      ← driver polices (boot-time)
#   │
#   ├── sources/
#   │   ├── SluGpu.slul           ← driver GOP framebuffer
#   │   ├── SluKeyMouse.slul      ← driver clavier + pointeur
#   │   ├── SluFontConf.slul      ← driver polices TrueType/OTF/WOFF
#   │   ├── SRFSMan.slul          ← driver Slura File System (SRFS v2)
#   │   └── install.slin          ← image SRFS (SDC:\) contenant :
#   │         ├── slu64/assets/fonts/brsonomasemibold.ttf
#   │         └── slu64/DrivRequirment/{SluGpu,SluKeyMouse,SluFontConf,SRFSMan}.slul
#   │
#   ├── EFI/
#   │   └── BOOT/
#   │       └── BOOTX64.EFI       ← sélecteur UEFI (boot_selector.cpp)
#   │
#   └── NvVars                    ← variables UEFI NVRAM (OVMF)
#
# Séquence de démarrage :
#   UEFI firmware
#     → EFI/BOOT/BOOTX64.EFI
#       → LoadImage(\slr_clk_bt.efi)
#         → Lunee kernel
#           → slul_loader  : sources\SluGpu.slul        [AuthARoot SRID_slugpu_001]
#           → slul_loader  : sources\SluKeyMouse.slul   [AuthARoot SRID_slulkm_001]
#           → slul_loader  : sources\SluFontConf.slul   [AuthARoot SRID_slufontconf_001]
#           → slul_loader  : sources\SRFSMan.slul        [AuthARoot SRID_srfsman_001]
#           → marep_loader : HelloSlura.marep            [AuthARoot SRID_helloslura_001]
#             → SluGpu exécute GpuImpl.ovc → rendu GOP
#             → ESC pour quitter
# -----------------------------------------------------------------

# -----------------------------------------------------------------
# 1️⃣  Vérifications
# -----------------------------------------------------------------
if [ ! -d "${ESP_DIR}" ]; then
    echo "❌  ESP introuvable : ${ESP_DIR}"
    echo "    Lance '🔨 build all drivers' dans VS Code."
    exit 1
fi

if [ ! -f "${ESP_DIR}/EFI/BOOT/BOOTX64.EFI" ]; then
    echo "❌  BOOTX64.EFI manquant dans esp/EFI/BOOT/"
    exit 1
fi

if [ ! -f "${ESP_DIR}/slr_clk_bt.efi" ]; then
    echo "⚠️   slr_clk_bt.efi absent (boot échouera)"
fi

# Vérifications drivers
for drv in SluGpu SluKeyMouse SRFSMan; do
    if [ ! -f "${ESP_DIR}/sources/${drv}.slul" ]; then
        echo "⚠️   sources/${drv}.slul manquant"
    fi
done

# Vérification police
if [ ! -f "${ESP_DIR}/boot/assets/font/brsonomasemibold.ttf" ]; then
    echo "⚠️   boot/assets/font/brsonomasemibold.ttf manquant"
fi

# Vérification install.slin
if [ ! -f "${ESP_DIR}/sources/install.slin" ]; then
    echo "⚠️   sources/install.slin manquant"
fi

if [ ! -f "${OVMF_VARS}" ]; then
    echo "ℹ️   OVMF_VARS absent — copie depuis le firmware système"
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "${OVMF_VARS}" 2>/dev/null || \
    cp /usr/share/OVMF/OVMF_VARS.fd    "${OVMF_VARS}" 2>/dev/null || true
fi

# -----------------------------------------------------------------
# 2️⃣  Sélection de la source de boot
# -----------------------------------------------------------------
if [ "${MODE}" = "--iso" ]; then
    if [ ! -f "${ISO_FILE}" ]; then
        echo "❌  booter.iso introuvable : ${ISO_FILE}"
        echo "    Lance 'make: booter.iso' dans VS Code."
        exit 1
    fi
    echo "🚀  QEMU ← ISO : ${ISO_FILE}"
    BOOT_ARGS="-cdrom ${ISO_FILE} -boot d"
else
    echo "🚀  QEMU ← ESP dir : ${ESP_DIR}"
    BOOT_ARGS="-drive if=ide,format=raw,file=fat:rw:${ESP_DIR}"
fi

# -----------------------------------------------------------------
# 3️⃣  Lancement QEMU avec OVMF (UEFI)
# -----------------------------------------------------------------
qemu-system-x86_64 \
    -nodefaults \
    -machine   q35,accel=kvm:tcg \
    -m         1024M \
    -device    bochs-display \
    -display   sdl,gl=off \
    -drive     if=pflash,format=raw,readonly=on,file="${OVMF_CODE}",id=ovmf_code \
    -drive     if=pflash,format=raw,file="${OVMF_VARS}",id=ovmf_vars \
    -global    driver=efi-pflash.0,property=secure-boot,value=0 \
    ${BOOT_ARGS} \
    -serial    stdio \
    -monitor   none \
    -d         int \
    -D         "${PROJ_ROOT}/qemu.log" \
    -debugcon  file:"${PROJ_ROOT}/ovmf.log" \
    -global    isa-debugcon.iobase=0x402 \
    -no-reboot \
    -no-shutdown
