# Patch : initialisation VEZproxy + Oracle + mint (vezcurproxy.sol)

Fichier modifié : `crates/vuc-platform/src/engine_platform.rs`

## Changements

### 1. Exception de frais (`send_transaction`)
- Gratuit pour `initialize(address,address,address,uint256)` → selector **`0xcf756fdf`**
- Gratuit pour `mint(address,uint256)` → selector **`0x40c10f19`**
- Adresse cible : `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`

### 2. Spawn de déploiement VEZ (flux conforme au contrat)
Ordre d’exécution au boot :

1. **EACAggregatorProxy** (oracle PoR)  
   - Adresse CREATE2 : `0xcccccccccccccccccccccccccccccccccccccccc`  
   - Bytecode : env `EAC_AGGREGATOR_BYTECODE` (ou `EAC_PROXY_AGGREGATOR`)

2. **VEZproxy** (impl / proxy)  
   - Adresse CREATE2 : `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`  
   - Bytecode : env `VEZCUR`

3. **`initialize(owner, priceFeed, firstCustodian, initialSupply)`**  
   - Calldata ABI : selector `0xcf756fdf` + 4 args paddés  
   - Déclenche le **mint initial** vers `owner` (comme dans le contrat Solidity)  
   - Fallback : si la VM n’exécute pas encore le bytecode, crédit manuel du balance owner

4. **Métadonnées** écrites dans `resources` du compte proxy :
   - `initialized = true`
   - `total_supply`
   - `price_feed`
   - `first_custodian`
   - `owner`
   - `currency = "EUR"`
   - `isCustodian:<addr> = true`
   - `is_uups_proxy = true`

### 3. Spawn PoR
- Oracle utilise maintenant `EAC_AGGREGATOR_BYTECODE` (plus `VEZCUR`).

### 4. `validate_system_integrity`
- Vérifie `initialized`, `price_feed`, `first_custodian`, `total_supply`
- Avertit si l’oracle est absent

## Variables d’environnement à ajouter

```bash
# Obligatoire pour le token
VEZCUR=<creation_bytecode_hex_VEZproxy>

# Oracle PoR (recommandé)
EAC_AGGREGATOR_BYTECODE=<creation_bytecode_hex_EACAggregatorProxy>

# Optionnel
VEZ_INITIAL_SUPPLY=1000000000000000000000000   # 1_000_000 * 1e18 (défaut)
```

## Adresses fixes (déjà définies dans main)

| Rôle | Adresse |
|------|---------|
| VEZ proxy | `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee` |
| Oracle PoR | `0xcccccccccccccccccccccccccccccccccccccccc` |
| **Owner + premier custodian** (mint initial) | **`0x53ae54b11251d5003e9aa51422405bc35a2ef32d`** |

`initialize(...)` est appelé avec `owner = firstCustodian = 0x53ae54b1…` → le mint initial va sur ce compte.

## Application du patch

Remplacer le fichier distant par :

```
crates/vuc-platform/src/engine_platform.rs
```

depuis ce dossier `slura_work/`, ou copier le diff dans ton working tree local.

## Notes

- Le nœud conserve l’adresse fixe `0xeeee…eeee` pour compatibilité MetaMask / RPC.
- Un vrai déploiement UUPS (impl séparée + ERC-1967 Proxy) nécessiterait le bytecode du proxy OpenZeppelin ; ici on déploie le bytecode `VEZCUR` directement à l’adresse native et on appelle `initialize`, ce qui reproduit le comportement fonctionnel du contrat (mint + custodian + oracle).
- Pour un déploiement UUPS strict (impl + proxy ERC-1967), fournis aussi `VEZPROXY_IMPL_BYTECODE` et on pourra l’étendre.
