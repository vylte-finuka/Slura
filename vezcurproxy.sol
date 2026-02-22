// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title VEZproxy – Vyft Enhancing ZER
/// @notice Token upgradable déflationniste avec burn et disburse
/// @dev Owner = Gnosis Safe (VEZIssuer)
contract VEZproxy is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {

    // ────────────────────────────────────────────────────────────────
    //                         CONSTANTES
    // ────────────────────────────────────────────────────────────────
    uint256 private constant TRANSFER_BURN_PCT   = 10;
    uint256 private constant DISBURSE_BURN_PCT   = 10;
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;

    // ────────────────────────────────────────────────────────────────
    //                         VARIABLES
    // ────────────────────────────────────────────────────────────────
    string public currency;
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
    constructor() initializer {}

    function initialize() public initializer {
        __ERC20_init("Vyft Enhancing ZER", "VEZ");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        currency       = "EUR";
        me             = 0x53Ae54b11251D5003e9aA51422405bC35A2eF32D;
        complet_quant  = 888_000_000 * 10**18;

        _mint(me, complet_quant);

        blacklister = msg.sender;
        _paused = false;
    }

    // ────────────────────────────────────────────────────────────────
    //                         MINT (contrôlé par le Safe)
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
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");

        uint256 burnAmount = amount * TRANSFER_BURN_PCT / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(_msgSender(), burnAmount);
        bool success = super.transfer(to, sendAmount);

        if (success) emit TransferWithBurn(_msgSender(), to, sendAmount, burnAmount);
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
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");

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
    function disburse(uint256 amount, address disburser) external whenNotPaused {
        require(amount > 0, "Amount must be > 0");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");
        require(balanceOf(disburser) >= amount, "Insufficient balance");

        uint256 burnAmount = amount * DISBURSE_BURN_PCT / 100;
        _burn(disburser, burnAmount + (amount - burnAmount));

        emit DisbursedWithBurn(amount, burnAmount);
    }

    // ────────────────────────────────────────────────────────────────
    //                 RELAYED PoS & REWARDS
    // ────────────────────────────────────────────────────────────────
    function relay_master(address validator, uint256 delegatedAmount)
        external onlyGovernanceOrSystem whenNotPaused returns (uint256)
    {
        totalRelayPower -= validatorRelayPower[validator];
        uint256 newPower = balanceOf(validator) + delegatedAmount;
        validatorRelayPower[validator] = newPower;
        totalRelayPower += newPower;

        emit RelayPowerUpdated(validator, delegatedAmount, newPower);
        return newPower;
    }

    function reward_lurosonie_holder(address holder, uint256 rewardAmount)
        external onlyGovernanceOrSystem whenNotPaused
    {
        require(holder != address(0) && rewardAmount > 0 && rewardAmount <= MAX_SAFE_AMOUNT);
        _mint(holder, rewardAmount);
        emit LurosonieRewardDistributed(holder, rewardAmount, block.timestamp);
    }

    // ────────────────────────────────────────────────────────────────
    //                     BLACKLIST & PAUSE
    // ────────────────────────────────────────────────────────────────
    function blacklist(address account) external onlyBlacklister {
        _blacklisted[account] = true;
        emit Blacklisted(account);
    }

    function unBlacklist(address account) external onlyBlacklister {
        _blacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    function updateBlacklister(address newBlacklister) external onlyOwner {
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

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// ===================================================================
// ====================== PROOF OF RESERVES ==========================
// ===================================================================

/// @title reservVEZ - Proof of Reserves officiel
/// @notice Transparence totale du collatéral euro pour VEZ
contract reservVEZ {

    address public immutable VEZIssuer;     // Gnosis Safe
    address public immutable vezToken;      // Adresse de VEZproxy

    uint256 public supplySolde;             // Supply déclarée collatéralisée
    string  public lienIpfs;                // Lien IPFS du relevé bancaire
    uint256 public lastUpdate;

    event ReservesUpdated(uint256 supplySolde, string lienIpfs, uint256 date);

    constructor(address _VEZIssuer, address _vezToken) {
        VEZIssuer = _VEZIssuer;
        vezToken = _vezToken;
    }

    function updateReserves(uint256 _supplySolde, string calldata _lienIpfs) external {
        require(msg.sender == VEZIssuer, "Only VEZIssuer");
        
        supplySolde = _supplySolde;
        lienIpfs = _lienIpfs;
        lastUpdate = block.timestamp;

        emit ReservesUpdated(_supplySolde, _lienIpfs, block.timestamp);
    }

    function getReserves() external view returns (
        uint256 onChainSupply,
        uint256 supplySolde,
        string memory lienIpfs,
        uint256 lastUpdated
    ) {
        onChainSupply = IERC20(vezToken).totalSupply();
        return (onChainSupply, supplySolde, lienIpfs, lastUpdate);
    }
}

// Interface simplifiée
interface IERC20 {
    function totalSupply() external view returns (uint256);
}
