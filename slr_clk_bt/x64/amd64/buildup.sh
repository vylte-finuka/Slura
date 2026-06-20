#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------
# Chemins du projet (réels)
# -----------------------------------------------------------------
PROJ_ROOT="/mnt/d/Downloads/Vyft_product/Slura/slr_clk_bt/x64/amd64"
ESP_DIR="${PROJ_ROOT}/esp"                      # répertoire EFI/BOOT/BOOTX64.EFI + EFI/SLURA/…
ISO_FILE="/mnt/d/Downloads/Vyft_product/Slura/booter.iso"  # image ISO bootable (même structure)
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"   # code OVMF (read-only)
OVMF_VARS="${PROJ_ROOT}/OVMF_VARS_4M.fd"       # variables OVMF (writable)

# -----------------------------------------------------------------
# Mode de démarrage :
#   --esp   (défaut) : répertoire ESP via fat:rw — rechargement à chaud
#   --iso           : fichier booter.iso         — test de distribution
# -----------------------------------------------------------------
MODE="${1:---esp}"

# -----------------------------------------------------------------
# 0️⃣ Nettoyage
# -----------------------------------------------------------------
rm -f "${PROJ_ROOT}/qemu.log" "${PROJ_ROOT}/ovmf.log" 2>/dev/null || true

# -----------------------------------------------------------------
# Structure ESP commune (identique dans l'ISO et dans le SLIN) :
#
#   EFI/
#   ├── BOOT/
#   │   └── BOOTX64.EFI          ← kernel Lunee (Rust)
#   └── SLURA/
#       ├── DRIVERS/
#       │   ├── SluGpu.slul      ← driver GPU (GOP framebuffer)
#       │   └── SluKeyMouse.slul ← driver clavier + pointeur
#       └── HOME/
#           └── home.marep       ← application Maratine de démarrage
# -----------------------------------------------------------------

# -----------------------------------------------------------------
# 1️⃣ Sélection de la source de boot
# -----------------------------------------------------------------
if [ "${MODE}" = "--iso" ]; then
    if [ ! -f "${ISO_FILE}" ]; then
        echo "❌  booter.iso introuvable : ${ISO_FILE}"
        echo "    Génère-le d'abord via la tâche VS Code 'make: booter.iso'"
        exit 1
    fi
    echo "🚀  Démarrage QEMU depuis ISO : ${ISO_FILE}"
    BOOT_DRIVE="-cdrom ${ISO_FILE} -boot d"
else
    echo "🚀  Démarrage QEMU depuis ESP dir : ${ESP_DIR}"
    BOOT_DRIVE="-drive if=ide,format=raw,file=fat:rw:${ESP_DIR} -boot c"
fi

# -----------------------------------------------------------------
# 2️⃣ Lancement de QEMU
# -----------------------------------------------------------------
qemu-system-x86_64 \
    -nodefaults \
    -machine q35,accel=kvm:tcg \
    -m 1024M \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}",id=ovmf_code \
    -drive if=pflash,format=raw,file="${OVMF_VARS}",id=ovmf_vars \
    -global driver=efi-pflash.0,property=secure-boot,value=0 \
    ${BOOT_DRIVE} \
    -serial stdio \
    -monitor none \
    -d int \
    -D "${PROJ_ROOT}/qemu.log" \
    -debugcon file:ovmf.log -global isa-debugcon.iobase=0x402 \
    -no-reboot -no-shutdown
