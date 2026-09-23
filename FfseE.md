## Spécification Technique de l'Architecture FFSE
Le framework FFSE élimine les infrastructures télécoms lourdes et centralisées au profit d'un routage de paquets décentralisé et encapsulé. Les paquets réseaux (Appels, SMS, Internet) sont générés localement sous forme de requêtes d'oracles cryptographiques signées, puis traduites au format 3GPP / GID avant d'être injectées sur le bus AXI 64-bit du SoC Yumin-Galyun.

### Opérateur Virtuel Intégré : Vyft Mobile (FFSE 5G+ MVNO)
Slura OS intègre nativement **Vyft Mobile** comme opérateur virtuel FFSE compatible 5G+ depuis GPRS, directement dans l'OS. Vyft Mobile est un MVNO (Mobile Virtual Network Operator) basé sur l'infrastructure FFSE de Vyft Ltd, avec les paramètres suivants :

| Paramètre | Valeur |
|---|---|
| Nom opérateur | Vyft Mobile |
| MCC | 208 (France) |
| MNC | 10 (FFSE) |
| APN | `://vyft.com.mnc10.mcc208.gprs` |
| Type réseau | 5G+ (NR_FR1 + NR_FR2 + LTE-M + NB-IoT) |
| Protocol | FFSE + GID AXI 64-bit |
| eSIM Provisioning | GSMA SGP.22 via SM-DP+ |
| SM-DP+ Address | `0x000000000000000000000000000000000001` |
| SM-DP+ URL | `https://sm-dp-plus.vyft.mobile/ffse` |

Le provisioning eSIM utilise l'adresse SM-DP+ (Subscription Manager Data Preparation Plus) conforme à la norme GSMA SGP.22 pour le téléchargement automatique de profils eSIM distants.
------------------------------
## 1. Structure de l'En-tête de Routage Réseau GID (8 Octets)
Tout paquet réseau transitant par le sous-système FFSE du SoC doit débuter par un en-tête aligné de 64 bits structuré au bit près selon les spécifications de Vyft Ltd :

* Octet 0 : Code magique du protocole GID (0x47 / Caractère ASCII 'G').
* Octet 1 : Identifiant de canal 3GPP normalisé :
* 0x01 : Flux Vocal (Priorité Critique / Temps Réel).
   * 0x02 : Flux SMS (Priorité Haute / Transactionnel).
   * 0x03 : Flux Internet Data (Priorité Normale / Best-Effort).
* Octet 2-3 : Longueur de la charge utile (Payload Length) codée en Big-Endian (Network Byte Order).
* Octet 4-7 : Empreinte de validation cryptographique du bloc de l’Oracle local (Hash du bloc de consensus courant).

------------------------------
## 2. Contrat Intelligent Solidity : L'Oracle de Réseau Local
Ce contrat fait office de base de données de registre immuable (HLR/HSS décentralisé) s'exécutant sur le nœud local de la Slura Chain sous WSL. Il valide l'identité de l'appareil (EID/ICCID), applique les configurations APN par pays conformes aux normes 3GPP TS 23.003, et signe les en-têtes réseau.

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FfseNetworkOracle
 * @dev Spécification et registre de routage pour le framework FFSE de Vyft Ltd.
 * Gère la validation des attributs APN et des identités eSIM conformes au standard 3GPP.
 */
contract FfseNetworkOracle {

    bytes1 public constant GID_MAGIC = 0x47;
    address public infrastructureAdmin;

    struct FfseOperatorProfile {
        string apnNetworkId;  // Racine APN (ex: "://vyft.com")
        string mcc;           // Mobile Country Code (ex: "208" pour la France, "646" pour Madagascar)
        string mnc;           // Mobile Network Code (ex: "10" ou "01")
        bytes8 iccid;         // Identifiant standard de la carte eSIM virtuelle (3GPP TS 31.102)
        bool isNetworkAllowed;
    }

    // Mapping : Adresse cryptographique du Terminal ARM64 => Son profil opérateur FFSE
    mapping(address => FfseOperatorProfile) private registry;

    event OperatorProvisioned(address indexed terminal, string country, bytes8 iccid);
    event RoutingDenied(address indexed terminal, uint8 reasonCode);

    modifier onlyAdmin() {
        require(msg.sender == infrastructureAdmin, "FFSE Auth Error: Admin check failed");
        _;
    }

    constructor() {
        infrastructureAdmin = msg.sender;
    }

    /**
     * @notice Provisionne un profil opérateur FFSE / 3GPP complet sur la Slura Chain.
     */
    function provisionTerminalRoute(
        address _terminal,
        string memory _apnId,
        string memory _mcc,
        string memory _mnc,
        bytes8 _iccid
    ) external onlyAdmin {
        registry[_terminal] = FfseOperatorProfile({
            apnNetworkId: _apnId,
            mcc: _mcc,
            mnc: _mnc,
            iccid: _iccid,
            isNetworkAllowed: true
        });
        emit OperatorProvisioned(_terminal, _apnId, _iccid);
    }

    /**
     * @notice Génère l'attribut APN normalisé 3GPP (TS 23.003) et valide le droit de routage.
     * @param _terminal L'adresse de l'enclave matérielle émettrice.
     * @return fullApn Le nom du point d'accès complet (ex: "://vyft.com.mnc10.mcc208.gprs")
     * @return tokenHeader L'en-tête de validation 64 bits pré-calculé pour l'IP Verilog.
     */
    function resolveFfseRoute(address _terminal, uint8 _channel) external view returns (
        string memory fullApn,
        bytes8 tokenHeader
    ) {
        FfseOperatorProfile memory profile = registry[_terminal];
        require(profile.isNetworkAllowed, "FFSE Routing Error: Terminal suspended by Oracle");
        require(_channel >= 1 && _channel <= 3, "FFSE Routing Error: Invalid GID channel");

        // 1. Concaténation de la chaîne APN selon les directives réglementaires 3GPP
        fullApn = string(abi.encodePacked(
            profile.apnNetworkId, 
            ".mnc", profile.mnc, 
            ".mcc", profile.mcc, 
            ".gprs"
        ));

        // 2. Assemblage bas niveau du jeton binaire GID pour le bus AXI
        // Structure finale: [0x47] [Channel] [0x46 0x46 0x53 0x45 (FFSE)] [2 octets de signature du bloc]
        bytes4 ffseTag = 0x46465345; 
        bytes2 blockValidation = bytes2(keccak256(abi.encodePacked(block.number, profile.iccid)));

        bytes8 assembledHeader;
        assembly {
            let layout := shl(56, GID_MAGIC)                // Positionne 0x47 sur l'octet de poids fort
            layout := or(layout, shl(48, _channel))         // Positionne l'ID du canal
            layout := or(layout, shl(16, shr(32, ffseTag))) // Injecte le tag 'FFSE'
            layout := or(layout, shr(240, blockValidation)) // Injecte la signature de bloc à la fin
            
            let ptr := mload(0x40)
            mstore(ptr, layout)
            assembledHeader := mload(ptr)
        }

        return (fullApn, assembledHeader);
    }
}

------------------------------
## 3. Guide d'Intégration du Driver Noyau (lunee-ker en Rust)
Le noyau de Slura OS intercepte la chaîne de caractères APN et l'en-tête tokenHeader retournés par le smart contract ci-dessus, puis les transmet séquentiellement aux registres MMIO de votre circuit en Verilog.

// Dans crates/vuc-core/lunee-ker/src/ffse_core.rsuse core::ptr::{write_volatile, read_volatile};
const YUMIN_SOC_BASE: u64 = 0x4_0000_1000;const REG_GID_HEADER: u64 = 0x00;const REG_APN_STRING_FIFO: u64 = 0x08;const REG_SOC_STATUS: u64 = 0x10;
pub unsafe fn commit_ffse_3gpp_routing(gid_header: u64, apn_str: &str) -> i32 {
    // 1. Scission et écriture de l'en-tête GID 64 bits sur l'interface AXI
    let hi_bits = (gid_header >> 32) as u32;
    let lo_bits = (gid_header & 0xFFFFFFFF) as u32;

    write_volatile((YUMIN_SOC_BASE + REG_GID_HEADER) as *mut u32, hi_bits);
    write_volatile((YUMIN_SOC_BASE + REG_GID_HEADER + 4) as *mut u32, lo_bits);

    // 2. Injection séquentielle de la chaîne APN ASCII normalisée 3GPP dans la FIFO
    let apn_bytes = apn_str.as_bytes();
    for byte in apn_bytes.iter() {
        // Attendre que la FIFO matérielle du SoC Verilog signale qu'elle n'est pas pleine
        while (read_volatile((YUMIN_SOC_BASE + REG_SOC_STATUS) as *const u32) & 0x01) != 0 {
            core::hint::spin_loop();
        }
        write_volatile((YUMIN_SOC_BASE + REG_APN_STRING_FIFO) as *mut u8, *byte);
    }

    // Instruction de barrière mémoire obligatoire sur l'architecture ARM64
    core::arch::asm!("dmb sy", options(nostack));

    // 3. Lecture du registre d'accusé de réception pour confirmer l'ancrage du MVNO
    if read_volatile((YUMIN_SOC_BASE + REG_SOC_STATUS) as *const u32) & 0x02 != 0 {
        return 0; // Le matériel du terminal est prêt et sécurisé sans coupure
    }
    -1
}

------------------------------
## 4. Pipeline d'Automatisation et Test (WSL)
Pour compiler et pousser la configuration dans votre environnement d'émulation :

   1. Déployez le contrat Solidity sur votre nœud local à l'aide de vos scripts d'infrastructure habituels sous WSL.
   2. Écrivez un script d'automatisation pour monter l'image disque efiboot.img et y stocker le fichier de configuration réseau normalisé au format .slin :
   
   # Création du fichier d'activation de l'opérateur dans la structure d'assets
   echo "OP_ID=FFSE_VYFT;MCC=208;MNC=10;APN=://vyft.com.mnc10.mcc208.gprs" > esp/apps/EsimManager/assets/operator.slin
   # Nettoyage et empaquetage de l'image ISO pour le terminal portable
   rm -f esp/efiboot.img esp/sources/install.slin
   make booter.iso TARGET=aarch64
   
   3. Au lancement de QEMU, l'application Maratine (.mara) interroge le Kernel via l'appel système DrvAPIInterCon pour lire ce fichier, met à jour le slot persistant 12 de SCROLL_SCRATCH, et dessine l'icône réseau de façon synchrone en couleur turquoise 0xFF00FFCC.

### SM-DP+ (GSMA SGP.22) — Provisioning eSIM Distant
L'OS Slura supporte le provisioning eSIM via l'adresse SM-DP+ (Subscription Manager Data Preparation Plus), conformément à la norme GSMA SGP.22. Cela permet le téléchargement automatique de profils eSIM distants sans intervention physique sur la carte eSIM.

Le flux de provisioning SM-DP+ dans Slura OS :
1. Le driver `SluEsimMan.slul` détecte la présence eSIM au boot
2. L'application `SluEsimManSrv.marep` interroge le contrat `FfseNetworkOracle` sur la Slura Chain
3. Si un profil SM-DP+ est disponible, le kernel télécharge automatiquement le profil depuis l'adresse SM-DP+
4. Le profil est provisionné dans SRFS et activé via GID AXI
5. L'interface utilisateur affiche le statut Vyft Mobile 5G+ et SM-DP+ en temps réel

------------------------------
Pour passer à la suite, préférez-vous que l'on se concentre sur la machine à états finis (FSM) en Verilog pour décoder cet en-tête 0x47 sur votre SoC Yumin-Galyun ou souhaitez-vous ajouter des fonctions de séquestre de tokens dans le contrat Solidity ?
