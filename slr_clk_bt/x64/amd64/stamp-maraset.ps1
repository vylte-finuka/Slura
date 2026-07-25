# stamp-maraset.ps1 — Horodate DYNAMIQUEMENT tous les Maraset.yaml sources
# (build:, Marav:, et les versions dependencies.basecon) sur le meme stamp
# DDMMYYHH que l'ISO du meme run (voir README.md §11 — Versionning & Build,
# et "make: booter.iso" dans tasks.json qui suit exactement la meme logique).
#
# Ne touche QUE les Maraset.yaml sources sous slr_clk_bt/<Nom>.slul|.marep/ —
# jamais les copies de build sous esp/ ou installed/, qui sont regenerees a
# chaque build par les taches "copy:"/"install:".

param(
    [string]$Channel = "dev"
)

$Stamp = Get-Date -Format 'ddMMyyHH'
$root  = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")

$maraFiles = @(
    "slr_clk_bt\SluGpu.slul\Maraset.yaml",
    "slr_clk_bt\SluHIIDMan.slul\Maraset.yaml",
    "slr_clk_bt\SluFontConf.slul\Maraset.yaml",
    "slr_clk_bt\SRFSMan.slul\Maraset.yaml",
    "slr_clk_bt\NTFSMan.slul\Maraset.yaml",
    "slr_clk_bt\SluEnvSys.slul\Maraset.yaml",
    "slr_clk_bt\CryptoAssetSupport.slul\Maraset.yaml",
    "slr_clk_bt\ShiLauncher.marep\Maraset.yaml",
    "slr_clk_bt\ShiLooker.marep\Maraset.yaml",
    "slr_clk_bt\TestApp.marep\Maraset.yaml"
)

Write-Host "[STAMP] build=$Stamp canal=$Channel"

foreach ($rel in $maraFiles) {
    $path = Join-Path $root $rel
    if (-not (Test-Path $path)) {
        Write-Warning "[STAMP] introuvable, ignore : $rel"
        continue
    }

    # Marav garde le suffixe "-dev" pour les drivers .slul (convention deja en
    # place) ; les apps .marep n'ont jamais eu ce suffixe.
    $maravSuffix = ""
    if ($rel -notlike "*.marep*") { $maravSuffix = "-dev" }

    # Get-Content/Set-Content par defaut (Windows PowerShell 5.1) ne font PAS
    # un aller-retour UTF-8 sans BOM fiable — ca corrompt tous les accents
    # francais (mojibake). Lecture/ecriture via .NET directement, en UTF-8
    # SANS BOM (les fichiers sources n'en ont pas), pour rester bit-identique
    # partout sauf les champs vises.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $text = [System.IO.File]::ReadAllText($path, $utf8NoBom)

    # package.build: <ancien> -> <stamp>
    $text = $text -replace '(?m)^(\s*build:\s*).+$', "`${1}$Stamp"

    # metadata.attributes.Marav: 0.1 build <ancien>[-dev] -> 0.1 build <stamp>[-dev]
    $text = $text -replace '(?m)^(\s*Marav:\s*0\.1 build )\S+', "`${1}$Stamp$maravSuffix"

    # dependencies.basecon : base***SluraOS***<Dep>: <ancien> -> <stamp>
    $text = $text -replace '(base\*\*\*SluraOS\*\*\*\w+:\s*)\S+', "`${1}$Stamp"

    [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
    Write-Host "[STAMP] $rel -> build=$Stamp Marav=$Stamp$maravSuffix basecon=$Stamp"
}
