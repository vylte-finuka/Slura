// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./EACAggregatorProxy.sol";

// ========================= Externals Functions ==================================
contract ProofOfReserve {
    address public owner;
    uint256 public totalValue;
    AggregatorV3Interface public priceFeed;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function setPriceFeed(address _priceFeed) public {
        require(msg.sender == owner, "Only owner");
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function proveReserve() public view returns (bool) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        uint256 balance = address(this).balance;
        return (balance * uint256(price) == totalValue * 10**18);
    }

    function deposit() public payable {
        totalValue += msg.value;
    }

    function withdrawTo() public {
        require(msg.sender == owner, "Only owner");
        payable(msg.sender).transfer(address(this).balance);
    }
}

// ============================= Main Contract ===================================   
contract VEZproxy is Initializable, ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    EACAggregatorProxy public priceFeed;
    string public currency = "EUR";

    //@custom:oz-upgrades-unsafe-allow constructor
    constructor() {
    }

    function initialize() initializer public {
        __ERC20_init("Vyft Enhancing ZER", "VEZ");
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    // ============================ External Mint Function ==============================
    function mintToLuzia(address recipient, uint256 amount) external onlyOwner {
        _mint(recipient, amount);
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    // ============================ Blacklist Logic ==============================

    address public blacklister;
    mapping(address => bool) private _blacklisted;

    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event BlacklisterChanged(address indexed newBlacklister);

    modifier onlyBlacklister() {
        require(msg.sender == blacklister, "Caller is not the blacklister");
        _;
    }

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

    // ============================ Pausable Logic ==============================

    bool private _paused;

    event Paused(address account);
    event Unpaused(address account);

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    modifier whenPaused() {
        require(_paused, "Pausable: not paused");
        _;
    }

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

    // ============================ ERC20 Standard Functions ==============================
    // On garde les fonctions publiques classiques, mais on n'override plus inutilement

    function transfer(address to, uint256 amount) 
        public 
        virtual 
        override 
        whenNotPaused 
        returns (bool) 
    {
        require(!_blacklisted[msg.sender], "Sender is blacklisted");
        require(!_blacklisted[to], "Recipient is blacklisted");
        return super.transfer(to, amount);
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
        return super.transferFrom(from, to, amount);
    }

    // ============================ Upgrade Control ==============================

    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner 
    {
        // optionnel : vous pouvez ajouter une vérification supplémentaire ici si besoin
    }
}