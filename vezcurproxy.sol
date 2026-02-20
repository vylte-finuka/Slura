// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./EACAggregatorProxy.sol";

/// @title VEZ Token – Vyft Enhancing ZER
/// @notice Token upgradable déflationniste avec burn sur transferts et disburse
/// @dev Intègre Relayed PoS (pouvoir de relais) et distribution de récompenses staking
contract VEZproxy is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {

    // ────────────────────────────────────────────────────────────────
    //                         CONSTANTES
    // ────────────────────────────────────────────────────────────────

    uint256 private constant TRANSFER_BURN_PCT   = 10;   // 10% burn sur transfer
    uint256 private constant DISBURSE_BURN_PCT   = 10;   // 10% burn sur disburse
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;

    // ────────────────────────────────────────────────────────────────
    //                         VARIABLES
    // ────────────────────────────────────────────────────────────────

    EACAggregatorProxy public priceFeed;
    string public currency;
    address public me;
    uint256 public complet_quant;

    // Blacklist & Pausable
    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    // ─── Relayed PoS ────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────
    //                         MODIFICATEURS
    // ────────────────────────────────────────────────────────────────

    modifier onlyBlacklister() {
        require(msg.sender == blacklister, "Caller is not the blacklister");
        _;
    }

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(_paused, "Pausable: not paused");
        _;
    }

    modifier onlyGovernanceOrSystem() {
        require(msg.sender == owner() || msg.sender == me, "Only governance or system allowed");
        _;
    }

    // ────────────────────────────────────────────────────────────────
    //                         INITIALISATION
    // ────────────────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    function initialize() public initializer {
        __ERC20_init("Vyft Enhancing ZER", "VEZ");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        currency       = "EUR";
        me             = 0x53Ae54b11251D5003e9aA51422405bC35A2eF32D;
        complet_quant  = 888_000_000 * 10**18;

        _mint(me, complet_quant);

        // Initialisation blacklist & pausable
        blacklister = msg.sender;
        _paused = false;
    }

    // ────────────────────────────────────────────────────────────────
    //                         MINT (contrôlé)
    // ────────────────────────────────────────────────────────────────

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    // ────────────────────────────────────────────────────────────────
    //               TRANSFER & TRANSFER_FROM (avec burn)
    // ────────────────────────────────────────────────────────────────

    function transfer(address to, uint256 amount)
        public
        virtual
        override
        whenNotPaused
        returns (bool)
    {
        require(!_blacklisted[msg.sender], "Sender is blacklisted");
        require(!_blacklisted[to], "Recipient is blacklisted");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large (burn overflow risk)");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(_msgSender(), burnAmount);
        bool success = super.transfer(to, sendAmount);

        if (success) {
            emit TransferWithBurn(_msgSender(), to, sendAmount, burnAmount);
        }

        return success;
    }

    function transferFrom(address from, address to, uint256 amount)
        public
        virtual
        override
        whenNotPaused
        returns (bool)
    {
        require(!_blacklisted[from], "From is blacklisted");
        require(!_blacklisted[to], "Recipient is blacklisted");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large (burn overflow risk)");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(from, burnAmount);
        bool success = super.transferFrom(from, to, sendAmount);

        if (success) {
            emit TransferWithBurn(from, to, sendAmount, burnAmount);
        }

        return success;
    }

    // ────────────────────────────────────────────────────────────────
    //                        DISBURSE (avec burn)
    // ────────────────────────────────────────────────────────────────

    function disburse(uint256 amount, address disburser) external whenNotPaused {
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large (burn overflow risk)");
        require(balanceOf(disburser) >= amount, "Insufficient balance");

        uint256 burnAmount       = amount * DISBURSE_BURN_PCT / 100;
        uint256 distributeAmount = amount - burnAmount;

        _burn(disburser, burnAmount + distributeAmount);

        emit DisbursedWithBurn(amount, burnAmount);
    }

    // ────────────────────────────────────────────────────────────────
    //                 RELAYED PoS – RELAY MASTER
    // ────────────────────────────────────────────────────────────────

    function relay_master(
        address validator,
        uint256 delegatedAmount
    )
        external
        onlyGovernanceOrSystem
        whenNotPaused
        returns (uint256 newTotalPower)
    {
        require(validator != address(0), "Invalid validator address");

        // Retrait de l’ancien pouvoir du total global
        totalRelayPower -= validatorRelayPower[validator];

        // Nouveau pouvoir = balance actuelle + délégation déclarée
        uint256 selfBalance = balanceOf(validator);
        newTotalPower = selfBalance + delegatedAmount;

        // Mise à jour
        validatorRelayPower[validator] = newTotalPower;
        totalRelayPower += newTotalPower;

        emit RelayPowerUpdated(validator, delegatedAmount, newTotalPower);

        return newTotalPower;
    }

    // ────────────────────────────────────────────────────────────────
    //              REWARDS – STAKING REWARDS DISTRIBUTION
    // ────────────────────────────────────────────────────────────────

    function reward_lurosonie_holder(address holder, uint256 rewardAmount)
        external
        onlyGovernanceOrSystem
        whenNotPaused
    {
        require(holder != address(0), "Cannot reward zero address");
        require(rewardAmount > 0, "Reward amount must be positive");
        require(rewardAmount <= MAX_SAFE_AMOUNT, "Reward too large");

        _mint(holder, rewardAmount);

        emit LurosonieRewardDistributed(holder, rewardAmount, block.timestamp);
    }

    // ────────────────────────────────────────────────────────────────
    //                     VUES PUBLIQUES UTILES
    // ────────────────────────────────────────────────────────────────

    function getValidatorRelayPower(address validator)
        external
        view
        returns (uint256)
    {
        return validatorRelayPower[validator];
    }

    function getTotalRelayPower() external view returns (uint256) {
        return totalRelayPower;
    }

    function getCirculatingSupply() external view returns (uint256) {
        return totalSupply();
    }

    function isBlacklisted(address account) external view returns (bool) {
        return _blacklisted[account];
    }

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    // ────────────────────────────────────────────────────────────────
    //                         BLACKLIST & PAUSE
    // ────────────────────────────────────────────────────────────────

    function blacklist(address account) external onlyBlacklister {
        require(account != address(0), "Cannot blacklist zero address");
        _blacklisted[account] = true;
        emit Blacklisted(account);
    }

    function unBlacklist(address account) external onlyBlacklister {
        _blacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    function updateBlacklister(address newBlacklister) external onlyOwner {
        require(newBlacklister != address(0), "Invalid blacklister address");
        blacklister = newBlacklister;
        emit BlacklisterChanged(newBlacklister);
    }

    function pause() external onlyOwner whenNotPaused {
        _paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner whenPaused {
        _paused = false;
        emit Unpaused(msg.sender);
    }

    // ────────────────────────────────────────────────────────────────
    //                          UUPS UPGRADE
    // ────────────────────────────────────────────────────────────────

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Possibilité d’ajouter timelock ou autres vérifs ici
    }
}