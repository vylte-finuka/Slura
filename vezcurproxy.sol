// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./EACAggregatorProxy.sol";

///______________________________________________________________________________
///                             PROOF OF RESERVE
///______________________________________________________________________________

contract ProofOfReserve {
    address public owner;
    uint256 public totalValue;
    AggregatorV3Interface public priceFeed;

    constructor(address _priceFeed) {
        owner = 0x53Ae54b11251D5003e9aA51422405bC35A2eF32D;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    ///____ Mise à jour de l'oracle de prix (réservé au owner)
    function setPriceFeed(address _priceFeed) external {
        require(msg.sender == owner, "Only owner");
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    ///____ Vérifie si la réserve est prouvée (balance × prix = totalValue)
    function proveReserve() external view returns (bool) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 balance = address(this).balance;
        return (balance * uint256(price) == totalValue * 10**18);
    }

    ///____ Dépôt de fonds (augmente totalValue)
    function deposit() external payable {
        totalValue += msg.value;
    }

    ///____ Retrait total par le owner
    function withdrawTo() external {
        require(msg.sender == owner, "Only owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

///______________________________________________________________________________
///                                 VEZ TOKEN
///                    Token upgradable – déflationniste Solana-style
///______________________________________________________________________________

contract VEZproxy is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {

    ///____ Constantes déflationnistes (inspirées Solana : burn sur usage)
    uint256 private constant TRANSFER_BURN_PCT   = 10;  // 10% burn sur chaque transfert
    uint256 private constant DISBURSE_BURN_PCT   = 10;  // 10% burn sur disburse
    uint256 private constant MAX_SAFE_AMOUNT     = type(uint256).max / 10;

    ///____ Variables de stockage
    EACAggregatorProxy public priceFeed;
    string public currency;
    address public me;
    uint256 public complet_quant;

    ///____ Blacklist & Pausable
    address public blacklister;
    mapping(address => bool) private _blacklisted;
    bool private _paused;

    ///____ Events (transparence maximale)
    event TransferWithBurn(address indexed from, address indexed to, uint256 amount, uint256 burned);
    event DisbursedWithBurn(uint256 amount, uint256 burned);
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event BlacklisterChanged(address indexed newBlacklister);
    event Paused(address account);
    event Unpaused(address account);

    ///____ Modificateurs
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

    ///__________________________________________________________________________
    ///                           INITIALISATION
    ///__________________________________________________________________________

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
    }

    ///__________________________________________________________________________
    ///                           MINT (contrôlé)
    ///__________________________________________________________________________

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    ///__________________________________________________________________________
    ///                   TRANSFER & TRANSFER_FROM (avec burn 10%)
    ///__________________________________________________________________________

    function transfer(address to, uint256 amount)
        public
        virtual
        override
        whenNotPaused
        returns (bool)
    {
        require(!_blacklisted[msg.sender], "Sender is blacklisted");
        require(!_blacklisted[to],       "Recipient is blacklisted");
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
        require(!_blacklisted[to],   "Recipient is blacklisted");
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

    ///__________________________________________________________________________
    ///                        DISBURSE (burn 10% – sécurisé)
    ///__________________________________________________________________________

    function disburse(uint256 amount) external whenNotPaused {
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= MAX_SAFE_AMOUNT, "Amount too large (burn overflow risk)");

        uint256 burnAmount      = amount * DISBURSE_BURN_PCT / 100;
        uint256 distributeAmount = amount - burnAmount;

        _burn(address(this), burnAmount);
        _burn(address(this), distributeAmount);

        emit DisbursedWithBurn(amount, burnAmount);
    }

    ///__________________________________________________________________________
    ///                           BLACKLIST LOGIC
    ///__________________________________________________________________________

    function isBlacklisted(address account) external view returns (bool) {
        return _blacklisted[account];
    }

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
        require(newBlacklister != address(0), "New blacklister cannot be zero address");
        blacklister = newBlacklister;
        emit BlacklisterChanged(newBlacklister);
    }

    ///__________________________________________________________________________
    ///                             PAUSABLE LOGIC
    ///__________________________________________________________________________

    function paused() public view virtual returns (bool) {
        return _paused;
    }

    function _pause() internal virtual whenNotPaused onlyOwner {
        _paused = true;
        emit Paused(_msgSender());
    }

    function _unpause() internal virtual whenPaused onlyOwner {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    ///__________________________________________________________________________
    ///                          UUPS UPGRADE CONTROL
    ///__________________________________________________________________________

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Ajoutez ici des vérifications supplémentaires si nécessaire (ex: timelock)
    }
}