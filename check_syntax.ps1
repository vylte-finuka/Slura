$f = 'D:\Downloads\Vyft_product\Slura\build_iso.ps1'
$errors = @()
$null = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errors)
if ($errors.Count -eq 0) {
    Write-Host 'SYNTAX OK - Aucune erreur' -ForegroundColor Green
} else {
    foreach ($e in $errors) {
        Write-Host ('Ligne ' + $e.Extent.StartLine + ': ' + $e.Message) -ForegroundColor Red
    }
}