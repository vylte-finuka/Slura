$stamp = Get-Date -Format 'ddMMyyHH'
$isoName = "Slura1_NAVERTA_dev_build${stamp}.iso"
Write-Host "[ISO] $isoName"

Set-Location "D:\Downloads\Vyt_product\Slura"

# Path WSL pour l'ESP
$espWsl = "/mnt/d/Downloads/Vyft_product/Slura/slr_clk_bt/x64/amd64/esp"

# Build efiboot.img via WSL
Write-Host '[ISO] building efiboot.img (FAT ESP image, via WSL mkfs.vfat) ...'
wsl -u root -e bash -lc "set -e; dd if=/dev/zero of=/tmp/efiboot.img bs=1M count=512 status=none; mkfs.vfat -F 32 -n SLURA_ESP /tmp/efiboot.img >/dev/null 2>&1; mkdir -p /tmp/efimnt; mount -o loop /tmp/efiboot.img /tmp/efimnt; cp -r ${espWsl}/. /tmp/efimnt/; sync; umount /tmp/efimnt; cp /tmp/efiboot.img ${espWsl}/efiboot.img"

if ($LASTEXITCODE -ne 0) {
    Write-Error 'efiboot.img (WSL) a echoue'
    exit 1
}

# Build ISO with xorriso
& 'D:\msys64\usr\bin\xorriso.exe' -as mkisofs -V SLURA_PARTDISK -R -J -joliet-long -iso-level 3 -eltorito-alt-boot -e 'efiboot.img' -no-emul-boot -isohybrid-gpt-basdat -o $isoName 'slr_clk_bt/x64/amd64/esp'

if ($LASTEXITCODE -ne 0) {
    Write-Error 'xorriso a echoue'
    exit 1
}
Write-Host "[ISO] OK -> $isoName"