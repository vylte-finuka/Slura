// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./EACAggregatorProxy.sol";

///====≈====≈===
/// VEZproxy – Token principal (déflationniste + stablecoin hybride)
/// Mint déclenché via custodian (même pour l'initial supply)
///====≈====≈===
contract VEZproxy is ERC20, Ownable, UUPSUpgradeable {

    ///====≈====≈=== CONSTANTES
    uint256 private constant TRANSFER_BURN_PCT   = 10;
    uint256 private constant DISBURSE_BURN_PCT   = 10;
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;
    uint256 public constant MAX_MINT_PER_TX      = 1_000_000 * 10**18;

    ///====≈====≈=== VARIABLES
    EACAggregatorProxy public priceFeed;
    address public custodian;                  // Doit mint l'initial supply et les ajouts
    string public currency = "EUR";
    address public me;
    uint256 public complet_quant;

    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    mapping(address => uint256) public validatorRelayPower;
    uint256 public totalRelayPower;

    ///====≈====≈=== EVENTS
    event TransferWithBurn(address indexed from, address indexed to, uint256 amount, uint256 burned);
    event DisbursedWithBurn(uint256 amount, uint256 burned);
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event BlacklisterChanged(address indexed newBlacklister);
    event Paused(address account);
    event Unpaused(address account);
    event RelayPowerUpdated(address indexed validator, uint256 delegatedAmount, uint256 totalPower);
    event LurosonieRewardDistributed(address indexed holder, uint256 amount, uint256 timestamp);
    event MintLimited(address indexed to, uint256 amount);
    event FiatBackingConfirmed(uint256 amount, string proofHash);
    event CustodianUpdated(address oldCustodian, address newCustodian);
    event ObtainRequested(address indexed user, uint256 amount, string proof);

    ///====≈====≈=== CONSTRUCTOR – mint initial via la logique mint()
    constructor(
        address _priceFeed,
        address _custodian,
        address _initialOwner,
        address _initialMe
    ) ERC20("Vyft Enhancing ZER", "VEZ") Ownable(_initialOwner) {
        priceFeed      = EACAggregatorProxy(_priceFeed);
        custodian      = _custodian;
        me             = _initialMe;
<<<<<<< HEAD
        complet_quant  = 888_000_000;
=======
        complet_quant  = 888_000_000 * 10**18;
>>>>>>> c33d5dca50728ea7f7856d339b04ad833a6fe66f

        // IMPORTANT : mint initial via la fonction mint() (coherent avec custodian)
        // On suppose que _custodian ou _initialOwner est autorisé
        mint(me, complet_quant);  // ← appel à mint au lieu de _mint direct

        blacklister = _initialOwner;
        _paused = false;
    }

    ///====≈====≈=== MINT – Automatisé par custodian (y compris initial)
    function mint(address to, uint256 amount) public {
        // Autorisé seulement par custodian (pour cohérence avec les dépôts)
        require(msg.sender == custodian, "Only custodian can mint");

        require(amount > 0 && amount <= MAX_MINT_PER_TX, "Invalid mint amount");

<<<<<<< HEAD
        int256 price = priceFeed.latestRoundData();
=======
        (, int256 price,,,) = priceFeed.latestRoundData();
>>>>>>> c33d5dca50728ea7f7856d339b04ad833a6fe66f
        require(price > 0, "Oracle price invalid");

        _mint(to, amount);

        emit MintLimited(to, amount);
        emit FiatBackingConfirmed(amount, "auto-deposit-custodian");
    }

    ///====≈====≈=== OBTAIN – Demande remboursement euro (burn + événement)
    function obtain(uint256 amount, string calldata proof) external {
        require(amount > 0 && balanceOf(msg.sender) >= amount, "Invalid obtain");

        _burn(msg.sender, amount);

        emit ObtainRequested(msg.sender, amount, proof);
        // Gnosis Safe / custodian traite le virement hors-chain
    }

    ///====≈====≈=== TRANSFER & TRANSFER_FROM (avec burn)
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[msg.sender] && !_blacklisted[to], "Blacklisted");
        require(amount <= MAX_SAFE_AMOUNT && !_paused, "Invalid transfer");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(_msgSender(), burnAmount);
        bool success = super.transfer(to, sendAmount);

        if (success) emit TransferWithBurn(_msgSender(), to, sendAmount, burnAmount);
        return success;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[from] && !_blacklisted[to], "Blacklisted");
        require(amount <= MAX_SAFE_AMOUNT && !_paused, "Invalid transferFrom");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(from, burnAmount);
        bool success = super.transferFrom(from, to, sendAmount);

        if (success) emit TransferWithBurn(from, to, sendAmount, burnAmount);
        return success;
    }

    ///====≈====≈=== DISBURSE
    function disburse(uint256 amount, address disburser) external {
        require(amount > 0 && amount <= MAX_SAFE_AMOUNT && balanceOf(disburser) >= amount && !_paused, "Invalid disburse");

        uint256 burnAmount = amount * DISBURSE_BURN_PCT / 100;
        _burn(disburser, burnAmount + (amount - burnAmount));

        emit DisbursedWithBurn(amount, burnAmount);
    }

    ///====≈====≈=== RELAYED PoS & REWARDS
    function relay_master(address validator, uint256 delegatedAmount) external onlyOwner returns (uint256) {
        totalRelayPower -= validatorRelayPower[validator];
        uint256 newPower = balanceOf(validator) + delegatedAmount;
        validatorRelayPower[validator] = newPower;
        totalRelayPower += newPower;

        emit RelayPowerUpdated(validator, delegatedAmount, newPower);
        return newPower;
    }

    function reward_lurosonie_holder(address holder, uint256 rewardAmount) external onlyOwner {
        require(holder != address(0) && rewardAmount > 0 && rewardAmount <= MAX_SAFE_AMOUNT);
        _mint(holder, rewardAmount);
        emit LurosonieRewardDistributed(holder, rewardAmount, block.timestamp);
    }

    ///====≈====≈=== BLACKLIST & PAUSE
    function blacklist(address account) external onlyOwner {
        _blacklisted[account] = true;
        emit Blacklisted(account);
    }

    function unBlacklist(address account) external onlyOwner {
        _blacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    function updateBlacklister(address newBlacklister) external onlyOwner {
        blacklister = newBlacklister;
        emit BlacklisterChanged(newBlacklister);
    }

    function pause() external onlyOwner {
        require(!_paused, "Already paused");
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(_paused, "Not paused");
        _paused = false;
        emit Unpaused(msg.sender);
    }

    ///====≈====≈=== GESTION CUSTODIAN
    function setVEZcustodian(address newCustodian) external onlyOwner {
        require(newCustodian != address(0), "Invalid custodian");
        emit CustodianUpdated(custodian, newCustodian);
        custodian = newCustodian;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

///====≈====≈===
/// reservVEZ – Proof of Reserves (transparence collatéral)
///====≈====≈===
contract reservVEZ {

    address public immutable VEZIssuer;
    address public immutable VEZasset;

    EACAggregatorProxy public priceFeed;

    uint256 public supplySolde;
    string  public lienIpfs;
    uint256 public lastUpdate;

    event ReservesUpdated(uint256 supplySolde, string lienIpfs, uint256 date);

    constructor(address _VEZIssuer, address _VEZasset, address _priceFeed) {
        VEZIssuer = _VEZIssuer;
        VEZasset  = _VEZasset;
        priceFeed = EACAggregatorProxy(_priceFeed);
    }

    function updateReserves(uint256 _supplySolde, string calldata _lienIpfs) external {
        require(msg.sender == VEZIssuer, "Only VEZIssuer");

<<<<<<< HEAD
        int256 price = priceFeed.latestRoundData();
=======
        (, int256 price,,,) = priceFeed.latestRoundData();
>>>>>>> c33d5dca50728ea7f7856d339b04ad833a6fe66f
        require(price > 0, "Oracle price invalid");

        supplySolde = _supplySolde;
        lienIpfs = _lienIpfs;
        lastUpdate = block.timestamp;

        emit ReservesUpdated(_supplySolde, _lienIpfs, block.timestamp);
    }

<<<<<<< HEAD
function getReserves() external view returns (
    uint256 onChainSupply,
    uint256 _supplySolde,  // Renamed parameter
    string memory lienIpfs,
    uint256 lastUpdated,
    int256 eurUsdPrice
) {
    onChainSupply = IERC20(VEZasset).totalSupply();
    int256 price = priceFeed.latestRoundData();
    return (onChainSupply, supplySolde, lienIpfs, lastUpdate, price);
}
=======
    function getReserves() external view returns (
        uint256 onChainSupply,
        uint256 supplySolde,
        string memory lienIpfs,
        uint256 lastUpdated,
        int256 eurUsdPrice
    ) {
        onChainSupply = IERC20(VEZasset).totalSupply();
        (, int256 price,,,) = priceFeed.latestRoundData();
        return (onChainSupply, supplySolde, lienIpfs, lastUpdate, price);
    }
>>>>>>> c33d5dca50728ea7f7856d339b04ad833a6fe66f
}

///====≈====≈===
/// VEZcustodian – Gestion automatisée des euros (dépôt → mint)
///====≈====≈===
contract VEZcustodian is Ownable, ReentrancyGuard {

    VEZproxy public immutable vezProxy;
    address public treasury;  // Compte multisig qui reçoit les euros

    mapping(address => uint256) public depositedEuro;
    mapping(address => uint256) public pendingObtains;

    uint256 public totalDeposited;
    uint256 public totalRequested;

    event EuroDeposited(address indexed user, uint256 amountEuro, uint256 vezMinted);
    event ObtainRequested(address indexed user, uint256 amountEuro, string proof);
    event ObtainConfirmed(address indexed user, uint256 amountEuro);

    constructor(address _vezProxy, address _treasury, address _initialOwner) Ownable(_initialOwner) {
        vezProxy   = VEZproxy(_vezProxy);
        treasury   = _treasury;
    }

    ///====≈====≈=== Dépôt euro confirmé → mint automatique
    function confirmDeposit(address user, uint256 amountEuro, string calldata proof)
        external
        onlyOwner
        nonReentrant
    {
        require(amountEuro > 0, "Montant nul");

        // Mint automatique 1:1
        vezProxy.mint(user, amountEuro * 10**18);

        depositedEuro[user] += amountEuro;
        totalDeposited += amountEuro;

        emit EuroDeposited(user, amountEuro, amountEuro * 10**18);
    }

    ///====≈====≈=== Demande de retrait (obtain depuis VEZproxy)
    function registerObtain(address user, uint256 amountEuro) external {
        require(msg.sender == address(vezProxy), "Only VEZproxy can register obtain");

        pendingObtains[user] += amountEuro;
        totalRequested += amountEuro;

        emit ObtainRequested(user, amountEuro, "proof-from-obtain");
    }

    ///====≈====≈=== Confirmation retrait (virement effectué hors-chain)
    function confirmObtain(address user, uint256 amountEuro) external onlyOwner nonReentrant {
        require(pendingObtains[user] >= amountEuro, "Pas assez pending");

        pendingObtains[user] -= amountEuro;

        emit ObtainConfirmed(user, amountEuro);
        // Le owner envoie amountEuro € à user hors-chain
    }

    function getUserStatus(address user) external view returns (uint256 deposited, uint256 pending) {
        return (depositedEuro[user], pendingObtains[user]);
    }
}

// ───────────────────────────────────────────────────────────────────────
//                          INTERFACES
// ───────────────────────────────────────────────────────────────────────

interface VEZproxyInterface {
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
<<<<<<< HEAD
}
=======
}
>>>>>>> c33d5dca50728ea7f7856d339b04ad833a6fe66f
