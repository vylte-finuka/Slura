// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, Ltd. 2026. Tous droits réservés.

pragma solidity ^0.8.26;

import "D:/Downloads/Vyft_product/Slura/node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "D:/Downloads/Vyft_product/Slura/node_modules/@openzeppelin/contracts/access/Ownable.sol";
import "D:/Downloads/Vyft_product/Slura/node_modules/@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "D:/Downloads/Vyft_product/Slura/node_modules/@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

///====≈====≈===
/// Interface minimale ERC20 utilisée par reservVEZ
///====≈====≈===
interface IERC20Minimal {
    function totalSupply() external view returns (uint256);
    function complet_quant() external view returns (uint256);
}

///====≈====≈===
/// Interface PoR utilisée par VEZproxy
///====≈====≈===
interface reservVEZInterface {
    function reserveValueEUR() external view returns (uint256);
    function reserveUnits() external view returns (uint256);
    function nav() external view returns (uint256);
    function reserveTimestamp() external view returns (uint256);
    function reportHash() external view returns (bytes32);
    function isSolvent() external view returns (bool);
    function availableMint() external view returns (uint256);
}

///====≈====≈===
/// VEZproxy – Token principal (déflationniste + stablecoin hybride)
/// Mint déclenché via custodian et limité par le Proof of Reserves
///====≈====≈===
contract VEZproxy is ERC20, Ownable, UUPSUpgradeable {

    ///====≈====≈=== CONSTANTES
    uint256 private constant TRANSFER_BURN_PCT   = 10;
    uint256 private constant DISBURSE_BURN_PCT   = 10;
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;
    uint256 public constant MAX_MINT_PER_TX      = 1_000_000 * 10**18;

    ///====≈====≈=== VARIABLES
    reservVEZInterface public reserveProof;

    mapping(address => bool) public custodians;  // Liste extensible de custodians (SLURC-2)
    address[] public custodianList;               // Tableau ordonné des custodians

    string public currency = "EUR";
    address public me;
    uint256 private complet_quantData;

    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    mapping(address => uint256) public validatorRelayPower;
    uint256 public totalRelayPower;

    ///====≈====≈=== EVENTS
    event TransferWithBurn(
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 burned
    );

    event DisbursedWithBurn(
        uint256 amount,
        uint256 burned
    );

    event Blacklisted(
        address indexed account
    );

    event UnBlacklisted(
        address indexed account
    );

    event BlacklisterChanged(
        address indexed newBlacklister
    );

    event Paused(
        address account
    );

    event Unpaused(
        address account
    );

    event RelayPowerUpdated(
        address indexed validator,
        uint256 delegatedAmount,
        uint256 totalPower
    );

    event LurosonieRewardDistributed(
        address indexed holder,
        uint256 amount,
        uint256 timestamp
    );

    event MintLimited(
        address indexed to,
        uint256 amount
    );

    event FiatBackingConfirmed(
        uint256 amount,
        string proofHash
    );

    event CustodianAdded(
        address indexed newCustodian
    );

    event CustodianRemoved(
        address indexed removedCustodian
    );

    event ObtainRequested(
        address indexed user,
        uint256 amount,
        string proof
    );

    event ReserveProofUpdated(
        address indexed reserveProof
    );

    ///====≈====≈=== CONSTRUCTOR – aucune émission initiale hors PoR
    constructor(
        address _reserveProof
    )
        ERC20("Vyft Enhancing ZER", "VEZ")
        Ownable(0x53Ae54b11251D5003e9aA51422405bC35A2eF32D)
    {
        require(
            _reserveProof != address(0),
            "Invalid reserve proof"
        );

        reserveProof = reservVEZInterface(_reserveProof);

        _addCustodian(
            0x53Ae54b11251D5003e9aA51422405bC35A2eF32D
        );

        me =
            0x53Ae54b11251D5003e9aA51422405bC35A2eF32D;

        complet_quantData = 0;

        blacklister = owner();
        _paused = false;
    }

    ///====≈====≈=== CONFIGURATION PoR
    /// Permet de remplacer le contrat PoR.
    /// En production, cette fonction devrait idéalement être
    /// protégée par une gouvernance / timelock / multisig.
    function updateReserveProof(
        address _reserveProof
    )
        external
        onlyOwner
    {
        require(
            _reserveProof != address(0),
            "Invalid reserve proof"
        );

        reserveProof =
            reservVEZInterface(_reserveProof);

        emit ReserveProofUpdated(
            _reserveProof
        );
    }

    ///====≈====≈=== MINT – Automatisé par un custodian
    /// Le montant minté doit être couvert par les réserves
    /// EUR publiées par reservVEZ.
    ///====≈====≈===
    function mint(
        address to,
        uint256 amount
    )
        public
    {
        // Autorisé par tout custodian enregistré (SLURC20)
        require(
            custodians[msg.sender],
            "Only custodian can mint"
        );

        require(
            to != address(0),
            "Invalid recipient"
        );

        require(
            amount > 0 &&
            amount <= MAX_MINT_PER_TX,
            "Invalid mint amount"
        );

        require(
            !_paused,
            "Token paused"
        );

        // Le PoR détermine la quantité encore disponible.
        uint256 available =
            reserveProof.availableMint();

        require(
            amount <= available,
            "Insufficient verified reserves"
        );

        _mint(
            to,
            amount
        );

        complet_quantData += amount;

        emit MintLimited(
            to,
            amount
        );

        emit FiatBackingConfirmed(
            amount,
            "verified-proof-of-reserves"
        );
    }

    ///====≈====≈=== OBTAIN – Demande remboursement euro
    /// Burn immédiat du VEZ + enregistrement de la demande
    /// auprès du custodian.
    ///====≈====≈===
    function obtain(
        uint256 amount,
        string calldata proof
    )
        external
    {
        require(
            amount > 0 &&
            balanceOf(msg.sender) >= amount,
            "Invalid obtain"
        );

        require(
            !_blacklisted[msg.sender],
            "Blacklisted"
        );

        _burn(
            msg.sender,
            amount
        );

        if (complet_quantData >= amount) {
            complet_quantData -= amount;
        }

        emit ObtainRequested(
            msg.sender,
            amount,
            proof
        );

        // Le custodian peut récupérer cette demande via
        // l'appel de registerObtain() prévu dans VEZcustodian.
    }

    ///====≈====≈=== TRANSFER & TRANSFER_FROM (avec burn)
    function transfer(
        address to,
        uint256 amount
    )
        public
        virtual
        override
        returns (bool)
    {
        require(
            !_blacklisted[msg.sender] &&
            !_blacklisted[to],
            "Blacklisted"
        );

        require(
            amount <= MAX_SAFE_AMOUNT &&
            !_paused,
            "Invalid transfer"
        );

        uint256 burnAmount =
            amount *
            TRANSFER_BURN_PCT /
            100;

        uint256 sendAmount =
            amount -
            burnAmount;

        _burn(
            _msgSender(),
            burnAmount
        );

        bool success =
            super.transfer(
                to,
                sendAmount
            );

        if (success) {
            emit TransferWithBurn(
                _msgSender(),
                to,
                sendAmount,
                burnAmount
            );
        }

        return success;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public
        virtual
        override
        returns (bool)
    {
        require(
            !_blacklisted[from] &&
            !_blacklisted[to],
            "Blacklisted"
        );

        require(
            amount <= MAX_SAFE_AMOUNT &&
            !_paused,
            "Invalid transferFrom"
        );

        uint256 burnAmount =
            amount *
            TRANSFER_BURN_PCT /
            100;

        uint256 sendAmount =
            amount -
            burnAmount;

        _burn(
            from,
            burnAmount
        );

        bool success =
            super.transferFrom(
                from,
                to,
                sendAmount
            );

        if (success) {
            emit TransferWithBurn(
                from,
                to,
                sendAmount,
                burnAmount
            );
        }

        return success;
    }

    ///====≈====≈=== DISBURSE
    function disburse(
        uint256 amount,
        address disburser
    )
        public
    {
        require(
            amount > 0 &&
            amount <= MAX_SAFE_AMOUNT &&
            balanceOf(disburser) >= amount &&
            !_paused,
            "Invalid disburse"
        );

        uint256 burnAmount =
            amount *
            DISBURSE_BURN_PCT /
            100;

        _burn(
            disburser,
            burnAmount +
            (amount - burnAmount)
        );

        if (complet_quantData >= amount) {
            complet_quantData -= amount;
        }

        emit DisbursedWithBurn(
            amount,
            burnAmount
        );
    }

    ///====≈====≈=== RELAYED PoS & REWARDS
    function relay_master(
        address validator,
        uint256 delegatedAmount
    )
        external
        onlyOwner
        returns (uint256)
    {
        totalRelayPower -=
            validatorRelayPower[validator];

        uint256 newPower =
            balanceOf(validator) +
            delegatedAmount;

        validatorRelayPower[validator] =
            newPower;

        totalRelayPower +=
            newPower;

        emit RelayPowerUpdated(
            validator,
            delegatedAmount,
            newPower
        );

        return newPower;
    }

    function reward_lurosonie_holder(
        address holder,
        uint256 rewardAmount
    )
        external
        onlyOwner
    {
        require(
            holder != address(0) &&
            rewardAmount > 0 &&
            rewardAmount <= MAX_SAFE_AMOUNT,
            "Invalid reward"
        );

        // Les récompenses doivent également rester couvertes
        // par les réserves PoR.
        uint256 available =
            reserveProof.availableMint();

        require(
            rewardAmount <= available,
            "Insufficient verified reserves"
        );

        _mint(
            holder,
            rewardAmount
        );

        complet_quantData +=
            rewardAmount;

        emit LurosonieRewardDistributed(
            holder,
            rewardAmount,
            block.timestamp
        );
    }

    ///====≈====≈=== BLACKLIST & PAUSE
    function blacklist(
        address account
    )
        external
        onlyOwner
    {
        _blacklisted[account] = true;

        emit Blacklisted(
            account
        );
    }

    function unBlacklist(
        address account
    )
        external
        onlyOwner
    {
        _blacklisted[account] = false;

        emit UnBlacklisted(
            account
        );
    }

    function updateBlacklister(
        address newBlacklister
    )
        external
        onlyOwner
    {
        require(
            newBlacklister != address(0),
            "Invalid blacklister"
        );

        blacklister =
            newBlacklister;

        emit BlacklisterChanged(
            newBlacklister
        );
    }

    function pause()
        external
        onlyOwner
    {
        require(
            !_paused,
            "Already paused"
        );

        _paused = true;

        emit Paused(
            msg.sender
        );
    }

    function unpause()
        external
        onlyOwner
    {
        require(
            _paused,
            "Not paused"
        );

        _paused = false;

        emit Unpaused(
            msg.sender
        );
    }

    ///====≈====≈=== GESTION CUSTODIAN (SLURC20 – liste extensible)
    function _addCustodian(
        address _custodian
    )
        internal
    {
        require(
            _custodian != address(0),
            "Invalid custodian address"
        );

        if (!custodians[_custodian]) {
            custodians[_custodian] = true;

            custodianList.push(
                _custodian
            );

            emit CustodianAdded(
                _custodian
            );
        }
    }

    function addCustodian(
        address _custodian
    )
        external
        onlyOwner
    {
        _addCustodian(
            _custodian
        );
    }

    function removeCustodian(
        address _custodian
    )
        external
        onlyOwner
    {
        require(
            custodians[_custodian],
            "Custodian not found"
        );

        custodians[_custodian] = false;

        // Swap avec le dernier élément et pop (O(1) removal)
        for (
            uint256 i = 0;
            i < custodianList.length;
            i++
        ) {
            if (
                custodianList[i] ==
                _custodian
            ) {
                custodianList[i] =
                    custodianList[
                        custodianList.length - 1
                    ];

                custodianList.pop();

                break;
            }
        }

        emit CustodianRemoved(
            _custodian
        );
    }

    function getCustodianCount()
        external
        view
        returns (uint256)
    {
        return custodianList.length;
    }

    function complet_quant() public view returns (uint256) {
        return complet_quantData;
    }

    ///====≈====≈=== INFORMATIONS PoR
    function getReserveStatus()
        external
        view
        returns (
            uint256 reserveEUR,
            uint256 supplyVEZ,
            uint256 availableMint,
            bool solvent,
            uint256 reserveTimestamp,
            bytes32 proofHash
        )
    {
        reserveEUR =
            reserveProof.reserveValueEUR();

        supplyVEZ =
            complet_quant();

        availableMint =
            reserveProof.availableMint();

        solvent =
            reserveProof.isSolvent();

        reserveTimestamp =
            reserveProof.reserveTimestamp();

        proofHash =
            reserveProof.reportHash();
    }

    function _authorizeUpgrade(
        address
    )
        internal
        override
        onlyOwner
    {}
}

///====≈====≈===
/// reservVEZ – Proof of Reserves (transparence collatéral)
///====≈====≈===
///
/// Ce contrat conserve la dernière attestation des réserves EUR.
///
/// Le montant reserveValueEUR ne doit pas être une simple déclaration
/// arbitraire du propriétaire : il est publié par l'oracle PoR autorisé.
///
/// Pour le pilote Slura, l'oracle peut être ton infrastructure PoR.
/// Pour une intégration Chainlink ultérieure, le writer pourra être
/// remplacé par l'infrastructure Chainlink compatible avec Slura.
///====≈====≈===
contract reservVEZ {

    address public immutable VEZIssuer;
    address public immutable VEZasset;

    address public oracle;

    uint256 public reserveValueEUR;
    uint256 public reserveUnits;
    uint256 public nav;

    string public lienIpfs;

    uint256 public reserveTimestamp;

    bytes32 public reportHash;

    ///====≈====≈=== EVENTS
    event OracleUpdated(
        address indexed oldOracle,
        address indexed newOracle
    );

    event ReservesUpdated(
        uint256 reserveValueEUR,
        uint256 reserveUnits,
        uint256 nav,
        uint256 date,
        bytes32 reportHash,
        string lienIpfs
    );

    ///====≈====≈=== CONSTRUCTOR
    constructor(
        address _VEZIssuer,
        address _VEZasset,
        address _oracle
    ) {
        require(
            _VEZIssuer != address(0),
            "Invalid issuer"
        );

        require(
            _VEZasset != address(0),
            "Invalid VEZ asset"
        );

        require(
            _oracle != address(0),
            "Invalid oracle"
        );

        VEZIssuer = _VEZIssuer;
        VEZasset = _VEZasset;
        oracle = _oracle;
    }

    ///====≈====≈=== UPDATE ORACLE
    function updateOracle(
        address _oracle
    )
        external
    {
        require(
            msg.sender == VEZIssuer,
            "Only VEZIssuer"
        );

        require(
            _oracle != address(0),
            "Invalid oracle"
        );

        address oldOracle =
            oracle;

        oracle =
            _oracle;

        emit OracleUpdated(
            oldOracle,
            _oracle
        );
    }

    ///====≈====≈=== UPDATE RESERVES
    /// Publication d'une nouvelle valeur PoR.
    ///
    /// _reserveValueEUR :
    /// valeur totale des réserves exprimée en EUR avec
    /// 18 décimales.
    ///
    /// _reserveUnits :
    /// quantité de parts / unités du produit de réserve.
    ///
    /// _nav :
    /// valeur liquidative utilisée pour déterminer la valeur
    /// des unités.
    ///
    /// _reportHash :
    /// hash cryptographique du rapport PoR externe.
    ///====≈====≈===
    function updateReserves(
        uint256 _reserveValueEUR,
        uint256 _reserveUnits,
        uint256 _nav,
        uint256 _timestamp,
        bytes32 _reportHash,
        string calldata _lienIpfs
    )
        external
    {
        require(
            msg.sender == oracle,
            "Only oracle"
        );

        require(
            _reserveValueEUR > 0,
            "Invalid reserve"
        );

        require(
            _timestamp <= block.timestamp,
            "Future timestamp"
        );

        require(
            _timestamp >= reserveTimestamp,
            "Old report"
        );

        require(
            _reportHash != bytes32(0),
            "Invalid report hash"
        );

        reserveValueEUR =
            _reserveValueEUR;

        reserveUnits =
            _reserveUnits;

        nav =
            _nav;

        reserveTimestamp =
            _timestamp;

        reportHash =
            _reportHash;

        lienIpfs =
            _lienIpfs;

        emit ReservesUpdated(
            _reserveValueEUR,
            _reserveUnits,
            _nav,
            _timestamp,
            _reportHash,
            _lienIpfs
        );
    }

    ///====≈====≈=== GET RESERVES
    function getReserves()
        external
        view
        returns (
            uint256 onChainSupply,
            uint256 _reserveValueEUR,
            uint256 _reserveUnits,
            uint256 _nav,
            string memory _lienIpfs,
            uint256 lastUpdated,
            bytes32 _reportHash
        )
    {
        onChainSupply =
            IERC20Minimal(VEZasset).complet_quant();

        return (
            onChainSupply,
            reserveValueEUR,
            reserveUnits,
            nav,
            lienIpfs,
            reserveTimestamp,
            reportHash
        );
    }

    ///====≈====≈=== SOLVENCY CHECK
    function isSolvent()
        public
        view
        returns (bool)
    {
        return
            reserveValueEUR >=
            IERC20Minimal(VEZasset).complet_quant();
    }

    ///====≈====≈=== AVAILABLE MINT
    function availableMint()
        public
        view
        returns (uint256)
    {
        uint256 activeSupply =
            IERC20Minimal(VEZasset).complet_quant();

        if (
            reserveValueEUR <=
            activeSupply
        ) {
            return 0;
        }

        return
            reserveValueEUR -
            activeSupply;
    }
}

///====≈====≈===
/// VEZcustodian – Gestion automatisée des euros (dépôt → mint)
///====≈====≈===
///
/// Le custodian ne décide pas seul de la quantité maximale
/// pouvant être créée.
///
/// VEZproxy vérifie le PoR avant chaque mint.
///====≈====≈===
contract VEZcustodian is Ownable, ReentrancyGuard {

    VEZproxy public immutable vezProxy;

    address public treasury;  // Compte multisig qui reçoit les euros

    mapping(address => uint256) public depositedEuro;
    mapping(address => uint256) public pendingObtains;

    uint256 public totalDeposited;
    uint256 public totalRequested;

    ///====≈====≈=== EVENTS
    event EuroDeposited(
        address indexed user,
        uint256 amountEuro,
        uint256 vezMinted
    );

    event ObtainRequested(
        address indexed user,
        uint256 amountEuro,
        string proof
    );

    event ObtainConfirmed(
        address indexed user,
        uint256 amountEuro
    );

    event TreasuryUpdated(
        address indexed oldTreasury,
        address indexed newTreasury
    );

    ///====≈====≈=== CONSTRUCTOR
    constructor(
        address _vezProxy,
        address _treasury,
        address _initialOwner
    )
        Ownable(_initialOwner)
    {
        require(
            _vezProxy != address(0),
            "Invalid VEZ proxy"
        );

        require(
            _treasury != address(0),
            "Invalid treasury"
        );

        vezProxy =
            VEZproxy(_vezProxy);

        treasury =
            _treasury;
    }

    ///====≈====≈=== Enregistrer VEZcustodian comme custodian
    /// sur VEZproxy (SLURC20)
    function registerAsCustodian()
        external
        onlyOwner
    {
        vezProxy.addCustodian(
            address(this)
        );
    }

    ///====≈====≈=== UPDATE TREASURY
    function updateTreasury(
        address _treasury
    )
        external
        onlyOwner
    {
        require(
            _treasury != address(0),
            "Invalid treasury"
        );

        address oldTreasury =
            treasury;

        treasury =
            _treasury;

        emit TreasuryUpdated(
            oldTreasury,
            _treasury
        );
    }

    ///====≈====≈=== DÉPÔT EURO CONFIRMÉ → MINT AUTOMATIQUE
    ///
    /// amountEuro est exprimé en euros entiers.
    ///
    /// Exemple :
    /// 10 000 EUR
    /// →
    /// 10 000 * 10**18 VEZ
    ///
    /// VEZproxy applique ensuite la limite PoR.
    ///====≈====≈===
    function confirmDeposit(
        address user,
        uint256 amountEuro,
        string calldata proof
    )
        external
        onlyOwner
        nonReentrant
    {
        require(
            user != address(0),
            "Invalid user"
        );

        require(
            amountEuro > 0,
            "Montant nul"
        );

        uint256 vezAmount =
            amountEuro *
            10**18;

        // Mint automatique 1:1.
        // Le VEZproxy vérifie obligatoirement le PoR.
        vezProxy.mint(
            user,
            vezAmount
        );

        depositedEuro[user] +=
            amountEuro;

        totalDeposited +=
            amountEuro;

        emit EuroDeposited(
            user,
            amountEuro,
            vezAmount
        );
    }

    ///====≈====≈=== DEMANDE DE RETRAIT
    /// Le burn VEZ est réalisé par VEZproxy.
    ///
    /// Cette fonction est appelée par l'owner du custodian
    /// après observation de la demande on-chain.
    ///====≈====≈===
    function registerObtain(
        address user,
        uint256 amountEuro,
        string calldata proof
    )
        external
        onlyOwner
    {
        require(
            user != address(0),
            "Invalid user"
        );

        require(
            amountEuro > 0,
            "Invalid amount"
        );

        pendingObtains[user] +=
            amountEuro;

        totalRequested +=
            amountEuro;

        emit ObtainRequested(
            user,
            amountEuro,
            proof
        );
    }

    ///====≈====≈=== CONFIRMATION RETRAIT
    /// Virement EUR effectué hors-chain par le treasury.
    ///====≈====≈===
    function confirmObtain(
        address user,
        uint256 amountEuro
    )
        external
        onlyOwner
        nonReentrant
    {
        require(
            user != address(0),
            "Invalid user"
        );

        require(
            amountEuro > 0,
            "Invalid amount"
        );

        require(
            pendingObtains[user] >=
            amountEuro,
            "Pas assez pending"
        );

        pendingObtains[user] -=
            amountEuro;

        emit ObtainConfirmed(
            user,
            amountEuro
        );

        // Le treasury envoie amountEuro EUR à user
        // hors-chain.
    }

    ///====≈====≈=== USER STATUS
    function getUserStatus(
        address user
    )
        external
        view
        returns (
            uint256 deposited,
            uint256 pending
        )
    {
        return (
            depositedEuro[user],
            pendingObtains[user]
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
//                          INTERFACES
// ───────────────────────────────────────────────────────────────────────

interface VEZproxyInterface {

    function mint(
        address to,
        uint256 amount
    )
        external;

    function balanceOf(
        address account
    )
        external
        view
        returns (uint256);

    function addCustodian(
        address _custodian
    )
        external;

    function removeCustodian(
        address _custodian
    )
        external;

    function getCustodianCount()
        external
        view
        returns (uint256);

    function custodians(
        address
    )
        external
        view
        returns (bool);
}
