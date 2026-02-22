// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "./EACAggregatorProxy.sol";

/// @title VEZproxy – Vyft Enhancing ZER
/// @notice Token déflationniste avec burn et disburse – version non-upgradable pour simplifier
/// @dev Owner = Gnosis Safe (VEZIssuer)
contract VEZproxy is ERC20, Ownable, UUPSUpgradeable {

    // ────────────────────────────────────────────────────────────────
    //                         CONSTANTES
    // ────────────────────────────────────────────────────────────────
    uint256 private constant TRANSFER_BURN_PCT   = 10;
    uint256 private constant DISBURSE_BURN_PCT   = 10;
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;
    uint256 public constant MAX_MINT_PER_TX      = 1_000_000 * 10**18; // Limite max par mint

    // ────────────────────────────────────────────────────────────────
    //                         VARIABLES
    // ────────────────────────────────────────────────────────────────
    EACAggregatorProxy public priceFeed;       // Oracle EUR/USD
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

    // ────────────────────────────────────────────────────────────────
    //                         CONSTRUCTOR (initialisation)
    // ────────────────────────────────────────────────────────────────
    constructor(
        address _priceFeed,
        address _initialOwner,
        address _initialMe
    ) ERC20("Vyft Enhancing ZER", "VEZ") Ownable(_initialOwner) {
        priceFeed      = EACAggregatorProxy(_priceFeed);
        me             = _initialMe;
        complet_quant  = 888_000_000 * 10**18;

        _mint(me, complet_quant);

        blacklister = _initialOwner;
        _paused = false;
    }

    // ────────────────────────────────────────────────────────────────
    //                         MINT (limité + oracle)
    // ────────────────────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyOwner {
        require(amount > 0, "Amount must be > 0");
        require(amount <= MAX_MINT_PER_TX, "Mint exceeds per-tx limit");

        // Vérification oracle EUR/USD
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        _mint(to, amount);
        emit MintLimited(to, amount);
    }

    // ────────────────────────────────────────────────────────────────
    //               TRANSFER & TRANSFER_FROM (avec burn)
    // ────────────────────────────────────────────────────────────────
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[msg.sender], "Sender is blacklisted");
        require(!_blacklisted[to], "Recipient is blacklisted");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");
        require(!_paused, "Transfers paused");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(_msgSender(), burnAmount);
        bool success = super.transfer(to, sendAmount);

        if (success) emit TransferWithBurn(_msgSender(), to, sendAmount, burnAmount);
        return success;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[from], "From is blacklisted");
        require(!_blacklisted[to], "Recipient is blacklisted");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");
        require(!_paused, "Transfers paused");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(from, burnAmount);
        bool success = super.transferFrom(from, to, sendAmount);

        if (success) emit TransferWithBurn(from, to, sendAmount, burnAmount);
        return success;
    }

    // ────────────────────────────────────────────────────────────────
    //                        DISBURSE
    // ────────────────────────────────────────────────────────────────
    function disburse(uint256 amount, address disburser) external {
        require(amount > 0, "Amount must be > 0");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");
        require(balanceOf(disburser) >= amount, "Insufficient balance");
        require(!_paused, "Disburse paused");

        uint256 burnAmount = amount * DISBURSE_BURN_PCT / 100;
        _burn(disburser, burnAmount + (amount - burnAmount));

        emit DisbursedWithBurn(amount, burnAmount);
    }

    // ────────────────────────────────────────────────────────────────
    //                 RELAYED PoS & REWARDS
    // ────────────────────────────────────────────────────────────────
    function relay_master(address validator, uint256 delegatedAmount)
        external onlyOwner
        returns (uint256)
    {
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
    //                     BLACKLIST & PAUSE
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
        require(!_paused, "Already paused");
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(_paused, "Not paused");
        _paused = false;
        emit Unpaused(msg.sender);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// ===================================================================
// ====================== PROOF OF RESERVES ==========================
// ===================================================================

/// @title reservVEZ - Proof of Reserves officiel
/// @notice Transparence totale du collatéral euro pour VEZ
contract reservVEZ {

    address public immutable VEZIssuer;     // Gnosis Safe
    address public immutable VEZasset;      // Adresse de VEZproxy

    EACAggregatorProxy public priceFeed;    // Oracle EUR/USD

    uint256 public supplySolde;             // Supply déclarée collatéralisée
    string  public lienIpfs;                // Lien IPFS du relevé bancaire
    uint256 public lastUpdate;

    event ReservesUpdated(uint256 supplySolde, string lienIpfs, uint256 date);

    constructor(address _VEZIssuer, address _VEZasset, address _priceFeed) {
        VEZIssuer = _VEZIssuer;
        VEZasset  = _VEZasset;
        priceFeed = EACAggregatorProxy(_priceFeed);
    }

    /// @notice Mise à jour des réserves (uniquement par le Gnosis Safe)
    function updateReserves(uint256 _supplySolde, string calldata _lienIpfs) external {
        require(msg.sender == VEZIssuer, "Only VEZIssuer");

        // Vérification oracle EUR/USD
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        supplySolde = _supplySolde;
        lienIpfs = _lienIpfs;
        lastUpdate = block.timestamp;

        emit ReservesUpdated(_supplySolde, _lienIpfs, block.timestamp);
    }

    /// @notice Vue publique des réserves
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

// Interface simplifiée
interface IERC20 {
    function totalSupply() external view returns (uint256);
}
