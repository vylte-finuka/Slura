// SPDX-License-Identifier: MIT
// Copyright (C) Vyft Ltd. All rights reserved.

pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

///====≈====≈===
/// AggregatorV3Interface – Interface Oracle / Proof of Reserve
///====≈====≈===
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

///====≈====≈===
/// EACAggregatorProxy – Oracle PoR autonome pour VEZ
///====≈====≈===
contract EACAggregatorProxy is AggregatorV3Interface {
    uint80 public roundId;
    int256 public answer;
    uint256 public startedAt;
    uint256 public updatedAt;
    uint80 public answeredInRound;

    address public owner;

    event RoundUpdated(uint80 indexed roundId, int256 answer, uint256 updatedAt);

    constructor() {
        owner = msg.sender;
        roundId = 1;
        answer = 1_000_000_000_000_000_000_000_000; // 1 EUR avec 18 décimales
        startedAt = block.timestamp;
        updatedAt = block.timestamp;
        answeredInRound = 1;
    }

    function updateRoundData(int256 _answer, uint256 _timestamp) external {
        require(msg.sender == owner, "Only owner");
        require(_timestamp <= block.timestamp, "Future timestamp");
        require(_timestamp >= updatedAt, "Old timestamp");

        roundId += 1;
        answer = _answer;
        startedAt = _timestamp;
        updatedAt = _timestamp;
        answeredInRound = roundId;

        emit RoundUpdated(roundId, _answer, _timestamp);
    }

    function latestRoundData()
        external
        view
        override
        returns (
            uint80 _roundId,
            int256 _answer,
            uint256 _startedAt,
            uint256 _updatedAt,
            uint80 _answeredInRound
        )
    {
        return (roundId, answer, startedAt, updatedAt, answeredInRound);
    }

    function getFullRoundData()
        external
        view
        returns (
            uint80 _roundId,
            int256 _answer,
            uint256 _startedAt,
            uint256 _updatedAt,
            uint80 _answeredInRound
        )
    {
        return this.latestRoundData();
    }

    function isOracleValid() external view returns (bool) {
        return answer > 0 && updatedAt > 0;
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }

    function getAggregatorAddress() external view returns (address) {
        return address(this);
    }
}

///====≈====≈===
/// VEZproxy – Token principal (déflationniste + stablecoin hybride)
/// Mint déclenché via custodian (même pour l'initial supply)
///====≈====≈===
contract VEZproxy is
    Initializable,
    ERC20Upgradeable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    uint256 private constant TRANSFER_BURN_PCT = 10;
    uint256 private constant DISBURSE_BURN_PCT = 10;
    uint256 private constant MAX_SAFE_AMOUNT = type(uint256).max / 10;
    uint256 public constant MAX_MINT_PER_TX = 1_000_000 * 10**18;

    EACAggregatorProxy public priceFeed;
    string public currency;
    address public me;
    uint256 public complet_quant;

    mapping(address => bool) public isCustodian;

    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    mapping(address => uint256) public validatorRelayPower;
    uint256 public totalRelayPower;

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
    event CustodianAdded(address indexed custodian);
    event CustodianRemoved(address indexed custodian);
    event ObtainRequested(address indexed user, uint256 amount, string proof);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _priceFeed,
        address _firstCustodian,
        uint256 _initialSupply
    ) external initializer {
        __ERC20_init("Vyft Enhancing ZER", "VEZ");
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        priceFeed = EACAggregatorProxy(_priceFeed);
        currency = "EUR";
        me = _owner;
        complet_quant = _initialSupply;

        isCustodian[_firstCustodian] = true;
        emit CustodianAdded(_firstCustodian);

        blacklister = _owner;
        _paused = false;

        // Mint initial
        _mint(me, complet_quant);
    }

    // ==== MINT – Support de la liste illimitée de custodians ====
    function mint(address to, uint256 amount) external nonReentrant {
        require(isCustodian[msg.sender], "Only custodian can mint");
        require(amount > 0 && amount <= MAX_MINT_PER_TX, "Invalid mint amount");

        (, int256 price, , , ) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        _mint(to, amount);

        emit MintLimited(to, amount);
        emit FiatBackingConfirmed(amount, "auto-deposit-custodian");
    }

    // ==== GESTION ILLIMITÉE DES CUSTODIANS ====
    function addCustodian(address newCustodian) external onlyOwner {
        require(newCustodian != address(0), "Invalid address");
        require(!isCustodian[newCustodian], "Already a custodian");

        isCustodian[newCustodian] = true;
        emit CustodianAdded(newCustodian);
    }

    function removeCustodian(address oldCustodian) external onlyOwner {
        require(isCustodian[oldCustodian], "Not a custodian");

        isCustodian[oldCustodian] = false;
        emit CustodianRemoved(oldCustodian);
    }

    // ==== OBTAIN – Demande remboursement euro (burn + événement) ====
    function obtain(uint256 amount, string calldata proof) external nonReentrant {
        require(amount > 0 && balanceOf(msg.sender) >= amount, "Invalid obtain");

        _burn(msg.sender, amount);
        emit ObtainRequested(msg.sender, amount, proof);
    }

    // ==== TRANSFER & TRANSFER_FROM (avec burn) ====
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[msg.sender] && !_blacklisted[to], "Blacklisted");
        require(amount <= MAX_SAFE_AMOUNT && !_paused, "Invalid transfer");

        uint256 burnAmount = (amount * TRANSFER_BURN_PCT) / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(_msgSender(), burnAmount);
        bool success = super.transfer(to, sendAmount);

        if (success) {
            emit TransferWithBurn(_msgSender(), to, sendAmount, burnAmount);
        }
        return success;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[from] && !_blacklisted[to], "Blacklisted");
        require(amount <= MAX_SAFE_AMOUNT && !_paused, "Invalid transferFrom");

        uint256 burnAmount = (amount * TRANSFER_BURN_PCT) / 100;
        uint256 sendAmount = amount - burnAmount;

        _burn(from, burnAmount);
        bool success = super.transferFrom(from, to, sendAmount);

        if (success) {
            emit TransferWithBurn(from, to, sendAmount, burnAmount);
        }
        return success;
    }

    // ==== DISBURSE (accessible de l'extérieur) ====
    /// @notice Brûle 10 % du montant depuis le compte du disburser.
    /// Les 90 % restants restent sur le compte du disburser.
    /// Accessible par n'importe qui (external).
    function disburse(uint256 amount, address disburser) external nonReentrant {
        require(disburser != address(0), "Invalid disburser");
        require(amount > 0, "Amount must be > 0");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large");
        require(!_paused, "Contract is paused");
        require(balanceOf(disburser) >= amount, "Insufficient balance");

        uint256 burnAmount = (amount * DISBURSE_BURN_PCT) / 100;

        // Brûle uniquement les 10 %
        _burn(disburser, burnAmount);

        emit DisbursedWithBurn(amount, burnAmount);
    }

    // ==== RELAYED PoS & REWARDS ====
    function relay_master(address validator, uint256 delegatedAmount) external onlyOwner returns (uint256) {
        totalRelayPower -= validatorRelayPower[validator];
        uint256 newPower = balanceOf(validator) + delegatedAmount;
        validatorRelayPower[validator] = newPower;
        totalRelayPower += newPower;

        emit RelayPowerUpdated(validator, delegatedAmount, newPower);
        return newPower;
    }

    function reward_lurosonie_holder(address holder, uint256 rewardAmount) external onlyOwner {
        require(holder != address(0) && rewardAmount > 0 && rewardAmount <= MAX_SAFE_AMOUNT, "Invalid reward");
        _mint(holder, rewardAmount);
        emit LurosonieRewardDistributed(holder, rewardAmount, block.timestamp);
    }

    // ==== BLACKLIST & PAUSE ====
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

    // ==== GESTION DES UPGRADES (UUPS) ====
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
    string public lienIpfs;
    uint256 public lastUpdate;

    event ReservesUpdated(uint256 supplySolde, string lienIpfs, uint256 date);

    constructor(address _VEZIssuer, address _VEZasset, address _priceFeed) {
        VEZIssuer = _VEZIssuer;
        VEZasset = _VEZasset;
        priceFeed = EACAggregatorProxy(_priceFeed);
    }

    function updateReserves(uint256 _supplySolde, string calldata _lienIpfs) external {
        require(msg.sender == VEZIssuer, "Only VEZIssuer");

        (, int256 price, , , ) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        supplySolde = _supplySolde;
        lienIpfs = _lienIpfs;
        lastUpdate = block.timestamp;

        emit ReservesUpdated(_supplySolde, _lienIpfs, block.timestamp);
    }
}
