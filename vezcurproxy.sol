// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./EACAggregatorProxy.sol";

// ───────────────────────────────────────────────────────────────────────
//                          VEZproxy – Token principal
// ───────────────────────────────────────────────────────────────────────
// Dépend de VEZcustodian pour mint/redeem fiat et de reservVEZ pour PoR

contract VEZproxy is ERC20, Ownable, ReentrancyGuard, UUPSUpgradeable {

    // ────────────────────────────────────────────────────────────────
    //                         CONSTANTES
    // ────────────────────────────────────────────────────────────────
    uint256 private constant TRANSFER_BURN_PCT   = 10;
    uint256 private constant DISBURSE_BURN_PCT   = 10;
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;
    uint256 public constant MAX_MINT_PER_TX      = 1_000_000 * 10**18;

    // ────────────────────────────────────────────────────────────────
    //                         VARIABLES
    // ────────────────────────────────────────────────────────────────
    EACAggregatorProxy public priceFeed;       // Oracle EUR/USD
    VEZcustodian public custodian;             // Contrat qui gère dépôts/retraits fiat
    reservVEZ public reserves;                 // Contrat Proof of Reserves

    string public currency = "EUR";
    address public me;
    uint256 public complet_quant;

    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    mapping(address => uint256) public validatorRelayPower;
    uint256 public totalRelayPower;

    // ────────────────────────────────────────────────────────────────
    //                         EVENTS
    // ────────────────────────────────────────────────────────────────
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
    event FiatMinted(address indexed to, uint256 amount, string proof);
    event FiatRedeemRequested(address indexed from, uint256 amount, string proof);

    // ────────────────────────────────────────────────────────────────
    //                         CONSTRUCTOR
    // ────────────────────────────────────────────────────────────────
    constructor(
        address _priceFeed,
        address _custodian,
        address _reserves,
        address _initialOwner,
        address _initialMe
    ) ERC20("Vyft Enhancing ZER", "VEZ") Ownable(_initialOwner) {
        priceFeed   = EACAggregatorProxy(_priceFeed);
        custodian   = VEZcustodian(_custodian);
        reserves    = reservVEZ(_reserves);
        me          = _initialMe;
        complet_quant = 888_000_000 * 10**18;

        _mint(me, complet_quant);

        blacklister = _initialOwner;
        _paused = false;
    }

    // ────────────────────────────────────────────────────────────────
    //                         MINT (via custodian seulement)
    // ────────────────────────────────────────────────────────────────
    function mint(address to, uint256 amount, string calldata proof) external nonReentrant {
        require(msg.sender == address(custodian), "Only custodian can mint");
        require(amount > 0 && amount <= MAX_MINT_PER_TX, "Invalid mint amount");

        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        _mint(to, amount);

        emit FiatMinted(to, amount, proof);
        emit MintLimited(to, amount);
    }

    // ────────────────────────────────────────────────────────────────
    //                         REDEEM (burn + demande fiat)
    // ────────────────────────────────────────────────────────────────
    function redeem(uint256 amount, string calldata proof) external nonReentrant {
        require(amount > 0 && balanceOf(msg.sender) >= amount, "Invalid redeem");

        _burn(msg.sender, amount);

        // Demande de remboursement fiat via custodian
        emit FiatRedeemRequested(msg.sender, amount, proof);
    }

    // ────────────────────────────────────────────────────────────────
    //               TRANSFER & TRANSFER_FROM (avec burn – inchangé)
    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    //                        DISBURSE (inchangé)
    // ────────────────────────────────────────────────────────────────
    function disburse(uint256 amount, address disburser) external {
        require(amount > 0 && amount <= MAX_SAFE_AMOUNT && balanceOf(disburser) >= amount && !_paused, "Invalid disburse");

        uint256 burnAmount = amount * DISBURSE_BURN_PCT / 100;
        _burn(disburser, burnAmount + (amount - burnAmount));

        emit DisbursedWithBurn(amount, burnAmount);
    }

    // ────────────────────────────────────────────────────────────────
    //                 RELAYED PoS & REWARDS (inchangé)
    // ────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    //                     BLACKLIST & PAUSE (inchangé)
    // ────────────────────────────────────────────────────────────────
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
        require(!_paused);
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(_paused);
        _paused = false;
        emit Unpaused(msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// ───────────────────────────────────────────────────────────────────────
//                          reservVEZ – Proof of Reserves
// ───────────────────────────────────────────────────────────────────────

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
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        supplySolde = _supplySolde;
        lienIpfs = _lienIpfs;
        lastUpdate = block.timestamp;

        emit ReservesUpdated(_supplySolde, _lienIpfs, block.timestamp);
    }

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
}

// ───────────────────────────────────────────────────────────────────────
//                          VEZCUSTODIAN – Gestion dépôts/retraits €
// ───────────────────────────────────────────────────────────────────────

contract VEZcustodian is Ownable, ReentrancyGuard {

    VEZproxy public immutable vezProxy;
    address public treasury;

    mapping(address => uint256) public depositedEuro;
    mapping(address => uint256) public pendingWithdrawals;

    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    event EuroDeposited(address indexed user, uint256 amountEuro, uint256 vezMinted);
    event WithdrawalRequested(address indexed user, uint256 amountEuro, uint256 vezBurned);
    event EuroWithdrawn(address indexed user, uint256 amountEuro);

    constructor(address _vezProxy, address _treasury, address _initialOwner) Ownable(_initialOwner) {
        vezProxy  = VEZproxy(_vezProxy);
        treasury  = _treasury;
    }

    function depositEuro(uint256 amountEuro, string calldata proof) external onlyOwner nonReentrant {
        require(amountEuro > 0, "Montant nul");

        // Mint 1:1 VEZ à l’utilisateur
        vezProxy.mint(msg.sender, amountEuro * 10**18);

        depositedEuro[msg.sender] += amountEuro;
        totalDeposited += amountEuro;

        emit EuroDeposited(msg.sender, amountEuro, amountEuro * 10**18);
    }

    function requestWithdrawal(uint256 amountEuro) external nonReentrant {
        require(amountEuro > 0, "Montant nul");
        require(vezProxy.balanceOf(msg.sender) >= amountEuro * 10**18, "Solde insuffisant");

        // Burn VEZ
        vezProxy.transferFrom(msg.sender, address(this), amountEuro * 10**18);
        vezProxy.burn(address(this), amountEuro * 10**18);

        pendingWithdrawals[msg.sender] += amountEuro;
        totalWithdrawn += amountEuro;

        emit WithdrawalRequested(msg.sender, amountEuro, amountEuro * 10**18);
    }

    function confirmWithdrawal(address user, uint256 amountEuro) external onlyOwner nonReentrant {
        require(pendingWithdrawals[user] >= amountEuro, "Montant non pending");

        pendingWithdrawals[user] -= amountEuro;

        emit EuroWithdrawn(user, amountEuro);
        // Le owner envoie amountEuro € à user hors-chain
    }

    function getUserBalance(address user) external view returns (uint256 deposited, uint256 pending) {
        return (depositedEuro[user], pendingWithdrawals[user]);
    }

    function getGlobalStats() external view returns (uint256 totalDep, uint256 totalWithd, uint256 supply) {
        return (totalDeposited, totalWithdrawn, vezProxy.totalSupply());
    }
}

// ───────────────────────────────────────────────────────────────────────
//                          Interfaces nécessaires
// ───────────────────────────────────────────────────────────────────────

interface VEZproxy {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
}
