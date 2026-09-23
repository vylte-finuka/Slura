$root = (Get-Location).Path
$abiPath = Join-Path $root 'build\slr_clk_bt_contracts_FfseNetworkOracle_sol_FfseNetworkOracle.abi'
$binPath = Join-Path $root 'build\slr_clk_bt_contracts_FfseNetworkOracle_sol_FfseNetworkOracle.bin'
if (-not (Test-Path $abiPath)) { Write-Error "ABI not found: $abiPath"; exit 1 }
$abi = Get-Content $abiPath -Raw | ConvertFrom-Json
$bin = if (Test-Path $binPath) { Get-Content $binPath -Raw } else { '' }
$ca = @{ 
    schema_version='1.0';
    type='CRYPTO_ASSET_BUNDLE';
    license='UNLICENSED';
    issuer='Vyft, SAS';
    network='charene';
    chain_id=45057;
    source_path='SDC:\\slu64\\contracts\\FfseNetworkOracle.sol';
    srfs_path='SDC:\\slu64\\assets\\crypto\\FfseNetworkOracle.ca';
    contracts=@{ FfseNetworkOracle=@{ contract=$bin; contract_pending=$false; asset_class='EVM_CONTRACT'; token_standard='UNKNOWN'; abi=$abi; events=@() } }
}
$ca | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $root 'build\FfseNetworkOracle.ca') -Encoding utf8
Write-Host "FfseNetworkOracle.ca généré -> " (Join-Path $root 'build\FfseNetworkOracle.ca')
