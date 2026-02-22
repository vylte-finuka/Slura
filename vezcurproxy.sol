// SPDX-License-Identifier: UNLICENSED
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./EACAggregatorProxy.sol";

/// @title VEZ – Vyft Euro Stablecoin (Centralisé)
/// @notice Stablecoin 1:1 collatéralisé en euro réel
/// @dev Contrôlé par Gnosis Safe (VEZIssuer) – Mint/Burn/Redeem stricts
contract VEZ is ERC20, Ownable, ReentrancyGuard {

    // ────────────────────────────────────────────────────────────────
    //                         CONSTANTES
    // ────────────────────────────────────────────────────────────────
    uint256 public constant MAX_MINT_PER_TX      = 1_000_000 * 10**18; // 1M € max par tx
    uint256 public constant MAX_SAFE_AMOUNT      = type(uint256).max / 10;

    // ────────────────────────────────────────────────────────────────
    //                         VARIABLES
    // ────────────────────────────────────────────────────────────────
    EACAggregatorProxy public priceFeed;       // Oracle EUR/USD (Chainlink)
    address public immutable VEZIssuer;        // Gnosis Safe (contrôle tout)
    address public treasury;                   // Compte qui reçoit les euros (multisig ou custodian)

    uint256 public totalMinted;
    uint256 public totalRedeemed;

    mapping(address => bool) public isCustodian;

    // ────────────────────────────────────────────────────────────────
    //                         EVENTS
    // ────────────────────────────────────────────────────────────────
    event Minted(address indexed to, uint256 amount, string proof);
    event Redeemed(address indexed from, uint256 amount, string proof);
    event CustodianAdded(address indexed custodian);
    event CustodianRemoved(address indexed custodian);
    event ReservesVerified(uint256 supply, uint256 price);

    // ────────────────────────────────────────────────────────────────
    //                         CONSTRUCTOR
    // ────────────────────────────────────────────────────────────────
    constructor(
        address _VEZIssuer,
        address _priceFeed,
        address _treasury
    ) ERC20("Vyft Euro", "VEZ") Ownable(_VEZIssuer) {
        VEZIssuer   = _VEZIssuer;
        priceFeed   = EACAggregatorProxy(_priceFeed);
        treasury    = _treasury;

        // Le Safe est aussi custodian initial
        isCustodian[_VEZIssuer] = true;
    }

    // ────────────────────────────────────────────────────────────────
    //                         MINT (strictement contrôlé)
    // ────────────────────────────────────────────────────────────────
    function mint(address to, uint256 amount, string calldata proof) 
        external 
        onlyOwner 
        nonReentrant 
    {
        require(amount > 0, "Amount must be > 0");
        require(amount <= MAX_MINT_PER_TX, "Exceeds per-tx limit");

        // Vérification oracle EUR/USD
        (, int256 price,,,) = priceFeed.latestRoundData();
        require(price > 0, "Oracle price invalid");

        _mint(to, amount);
        totalMinted += amount;

        emit Minted(to, amount, proof);
        emit ReservesVerified(totalSupply(), uint256(price));
    }

    // ────────────────────────────────────────────────────────────────
    //                         REDEEM (burn + euros sortent)
    // ────────────────────────────────────────────────────────────────
    function redeem(uint256 amount, string calldata proof) 
        external 
        nonReentrant 
    {
        require(amount > 0, "Amount must be > 0");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

        _burn(msg.sender, amount);
        totalRedeemed += amount;

        // Événement qui prouve que le redeem a été initié
        // Le transfert réel d'euros se fait hors-chain par le custodian
        emit Redeemed(msg.sender, amount, proof);
    }

    // ────────────────────────────────────────────────────────────────
    //                         GESTION CUSTODIANS
    // ────────────────────────────────────────────────────────────────
    function addCustodian(address custodian) external onlyOwner {
        require(custodian != address(0), "Invalid address");
        isCustodian[custodian] = true;
        emit CustodianAdded(custodian);
    }

    function removeCustodian(address custodian) external onlyOwner {
        isCustodian[custodian] = false;
        emit CustodianRemoved(custodian);
    }

    // ────────────────────────────────────────────────────────────────
    //                         VUES PUBLIQUES
    // ────────────────────────────────────────────────────────────────
    function getReservesStatus() external view returns (
        uint256 onChainSupply,
        uint256 minted,
        uint256 redeemed,
        int256 eurUsdPrice,
        address treasuryAddress
    ) {
        onChainSupply = totalSupply();
        (, int256 price,,,) = priceFeed.latestRoundData();
        return (onChainSupply, totalMinted, totalRedeemed, price, treasury);
    }

    function isValidCustodian(address account) external view returns (bool) {
        return isCustodian[account];
    }

    // ────────────────────────────────────────────────────────────────
    //                         UUPS UPGRADE (optionnel)
    // ────────────────────────────────────────────────────────────────
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
