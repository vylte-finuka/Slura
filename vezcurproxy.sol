// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./EACAggregatorProxy.sol";

// ========================= ProofOfReserve (inchangé) =========================
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

// ============================== Contrat principal VEZ ==============================
contract VEZ is ERC20, Ownable {
  
    string private constant TOKEN_NAME     = "Vyft Enhancing ZER";
    string private constant TOKEN_SYMBOL   = "VEZ";
    uint8  private constant TOKEN_DECIMALS = 18;

    // Adresse owner initiale hardcodée
    address private constant INITIAL_OWNER = 0x53Ae54b11251D5003e9aA51422405bC35A2eF32D;

    EACAggregatorProxy public priceFeed;
    string public currency = "EUR";

    // Blacklist
    address public blacklister;
    mapping(address => bool) private _blacklisted;

    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event BlacklisterChanged(address indexed newBlacklister);

    // Pause
    bool private _paused;

    event Paused(address account);
    event Unpaused(address account);

    modifier onlyBlacklister() {
        require(msg.sender == blacklister, "Caller is not the blacklister");
        _;
    }

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    // ──────────────────────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────────────────────
    constructor(address _initialBlacklister, address _priceFeed) 
        ERC20(TOKEN_NAME, TOKEN_SYMBOL) 
        Ownable(INITIAL_OWNER) 
    {
        blacklister = _initialBlacklister;
        priceFeed = EACAggregatorProxy(_priceFeed);
        emit BlacklisterChanged(_initialBlacklister);
    }

    function name() public view virtual override returns (string memory) {
        return TOKEN_NAME;
    }

    function symbol() public view virtual override returns (string memory) {
        return TOKEN_SYMBOL;
    }

    function decimals() public view virtual override returns (uint8) {
        return TOKEN_DECIMALS;
    }

    // ──────────────────────────────────────────────────────────────
    //  Blacklist functions
    // ──────────────────────────────────────────────────────────────
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

    // ──────────────────────────────────────────────────────────────
    //  Pause functions
    // ──────────────────────────────────────────────────────────────
    function paused() public view virtual returns (bool) {
        return _paused;
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

    // ──────────────────────────────────────────────────────────────
    //  Mint (owner only)
    // ──────────────────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function mintToLuzia(address recipient, uint256 amount) external onlyOwner {
        _mint(recipient, amount);
    }

    // ──────────────────────────────────────────────────────────────
    //  Transfer avec checks blacklist + pause
    // ──────────────────────────────────────────────────────────────
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
}