# Séquenceur Sidechain — Intégration Bitcoin (connect_doc.md)

## Objectif
Transformer le bridge Bitcoin (`vuc-bridge`) en **séquenceur de blocs** pour la sidechain Slura (Lurosonie). Le doc `Bitcoin connect_doc.md` fournit les endpoints nécessaires.

## Méthodes utilisées du doc

| Méthode (connect_doc.md) | Rôle séquenceur | Usage dans `lurosonie_manager.rs` |
|---|---|---|
| `getblockcount` | Hauteur BTC actuelle | Déclencheur de production bloc Slura |
| `getblockhash` | Hash du bloc BTC | Lien de séquence (prev_hash) |
| `getblock` | Transactions du bloc BTC | Séquenceur : tx à inclure dans bloc Slura |
| `getrawtransaction` | Détail tx BTC | Vérification dépôt / mint |
| `sendrawtransaction` | Soumission tx BTC | Optionnel : ancrage sidechain sur BTC |
| `getblocktemplate` | Template minage | Non utilisé directement (consensus BFT) |

## Architecture séquenceur

```
Bitcoin Mainnet/Testnet
    │ getblockcount / getblockhash / getblock
    ▼
BitcoinBridge (vuc-bridge/src/lib.rs)
    │ watch_blocks() → process_new_block()
    ▼
LurosonieManager (lurosonie_manager.rs)
    │ start_lurosonie_consensus() → loop 10s
    │   ├─ get_block_height() (BTC)
    │   ├─ select_block_producer() (BFT)
    │   ├─ produce_lurosonie_block_with_consensus()
    │   └─ lurosonie_bft_consensus()
    ▼
Slurachain (DB + mémoire)
```

## Modifications requises dans `lurosonie_manager.rs`

1. **Séquenceur actif** : remplacer le `loop { sleep(10) }` par un appel au bridge pour récupérer le bloc BTC et produire le bloc Slura synchronisé.
2. **Lien de séquence** : utiliser `getblockhash` pour lier `prev_hash` du bloc Slura au bloc BTC.
3. **Inclusion tx** : utiliser `getblock` (tx array) pour copier les transactions BTC pertinentes dans le bloc Slura.
4. **Validation** : `validate_bitcoin_block()` (déjà présent dans `BitcoinBridge`) pour vérifier l'inclusion du txid.

## Fichier cible
- `crates/vuc-platform/src/consensus/lurosonie_manager.rs` (sélection active, lignes 1-1411)
- `crates/vuc-bridge/src/lib.rs` (bridge, lignes 45-200+)

## Status
- Bridge existant : ✅ (`BitcoinBridge::watch_blocks`)
- Séquenceur : ❌ (besoin d'intégrer `getblockhash` + `getblock` dans le loop de consensus)
- Doc API : ✅ (`Bitcoin connect_doc.md` — index complet)

## Corrections appliquées (2025-07-11)

### 1. Compilation `mint_vez_for_deposit` (vuc-bridge/src/lib.rs:242)
- **Avant** : `async fn mint_vez_for_deposit(&self, txid: &str, recipient: &str, amount: u64)` → retournait `()` implicitement.
- **Après** : `async fn mint_vez_for_deposit(&self, txid: &str, recipient: &str, amount: u64) -> String` → retourne `"minted".to_string()` en succès et `"error: no contract".to_string()` si contrat absent.
- **Résultat** : `cargo check -p vuc-bridge` ✅ clean (1 warning dead_code sur `persistent_path`, non bloquant).

### 2. Compilation `vuc-platform`
- `cargo check -p vuc-platform` ✅ clean (53 warnings dead_code existants, non bloquants).

### 3. Intégration séquenceur (à compléter)
- `start_lurosonie_consensus()` boucle actuellement sur `last_btc_height` (RwLock) alimenté par `watch_blocks()` en arrière-plan.
- **Prochaine étape** : dans le loop, appeler `bridge.get_block_data(btc_height, &client)` pour récupérer `(block_hash, txids)` et :
  1. Insérer `block_hash` comme `prev_hash` du bloc Slura.
  2. Filtrer les txids pertinents (dépôts bridge) et les inclure dans `BlockData.transactions`.
  3. Appeler `bridge.validate_bitcoin_block(btc_height, txid)` pour chaque tx de dépôt.
