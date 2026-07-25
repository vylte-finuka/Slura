$stamp = Get-Date -Format 'ddMMyyHH'
$isoName = "Slura1_NAVERTA_dev_build${stamp}.iso"
Write-Host "[ISO] $isoName"

Set-Location "D:\Downloads\Vyft_product\Slura"

& 'D:\msys64\usr\bin\xorriso.exe' -as mkisofs `
  -V SLURA_PARTDISK `
  -R -J -joliet-long -iso-level 3 `
  -eltorito-alt-boot -e 'efiboot.img' -no-emul-boot -isohybrid-gpt-basdat `
  -o $isoName `
  'slr_clk_bt/x64/amd64/esp'

if ($LASTEXITCODE -ne 0) {
    Write-Error "xorriso a echoue (exit code $LASTEXITCODE)"
    exit 1
}
Write-Host "[ISO] OK -> $isoName"