#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------
# Chemins du projet (réels)
# -----------------------------------------------------------------
PROJ_ROOT="/mnt/d/Downloads/Vyft_product/Slura/slr_clk_bt/x64/amd64"
ESP_DIR="${PROJ_ROOT}/esp"                     # ← répertoire contenant EFI/BOOT/BOOTX64.EFI
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"   # code OVMF (read‑only)
OVMF_VARS="${PROJ_ROOT}/OVMF_VARS_4M.fd"      # variables OVMF (writable)

# -----------------------------------------------------------------
# 0️⃣ Nettoyage (facultatif – supprime les anciens logs)
# -----------------------------------------------------------------
rm -f "${PROJ_ROOT}/qemu.log" "${PROJ_ROOT}/ovmf.log" 2>/dev/null || true

# -----------------------------------------------------------------
# 1️⃣ Lancement de QEMU – l’ESP est le **seul** disque présenté
# -----------------------------------------------------------------
echo "🚀  Démarrage QEMU – utilisation du répertoire ${ESP_DIR} comme disque EFI"
qemu-system-x86_64 \
    -nodefaults \
    -machine q35,accel=kvm:tcg \
    -m 1024M \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}",id=ovmf_code \
    -drive if=pflash,format=raw,file="${OVMF_VARS}",id=ovmf_vars \
    -global driver=efi-pflash.0,property=secure-boot,value=0 \
    -drive if=ide,format=raw,file=fat:rw:"${ESP_DIR}" \
    -serial stdio \
    -monitor none \
    -boot c \
    -d int \
    -D "${PROJ_ROOT}/qemu.log" \
    -debugcon file:ovmf.log -global isa-debugcon.iobase=0x402 \
    -no-reboot -no-shutdown