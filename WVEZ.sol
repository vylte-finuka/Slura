// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title WVEZ – Wrapped Vyft Enhancing ZER
/// @notice Wrapper 1:1 compatible Uniswap V3 (pas de burn/fee sur transfer)
contract WVEZ is Initializable, ERC20Upgradeable, OwnableUpgradeable {

    address public immutable VEZ;

    // Blacklist (contrôlé par blacklister)
    address public blacklister;
    mapping(address => bool) private _blacklisted;

    // Relayed PoS
    mapping(address => uint256) public validatorRelayPower;
    uint256 public totalRelayPower;

    event Withdrawal(address indexed src, uint256 wad);
    event Blacklisted(address indexed account);
    event UnBlacklisted(address indexed account);
    event RelayPowerUpdated(address indexed validator, uint256 power, uint256 total);

    modifier onlyBlacklister() {
        require(msg.sender == blacklister, "Not blacklister");
        _;
    }

    constructor(address _vez) initializer {
        VEZ = _vez;
    }

    function initialize(address initialOwner, address initialBlacklister) public initializer {
        __ERC20_init("Wrapped Vyft Enhancing ZER", "WVEZ");
        __Ownable_init(initialOwner);
        blacklister = initialBlacklister;
    }

    // ─── WRAP / UNWRAP ──────────────────────────────────────────────

    function deposit() public payable {
        require(msg.value > 0, "Deposit > 0");
        require(IERC20(VEZ).transferFrom(msg.sender, address(this), msg.value), "VEZ transfer failed");
        _mint(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) external {
        require(wad > 0, "Withdraw > 0");
        _burn(msg.sender, wad);
        require(IERC20(VEZ).transfer(msg.sender, wad), "VEZ withdraw failed");
        emit Withdrawal(msg.sender, wad);
    }

    // ─── TRANSFER SANS BURN/FEE ─────────────────────────────────────

    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[msg.sender] && !_blacklisted[to], "Blacklisted");
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(!_blacklisted[from] && !_blacklisted[to], "Blacklisted");
        return super.transferFrom(from, to, amount);
    }

    // ─── RELAYED PoS ────────────────────────────────────────────────

    function relay_master(address validator, uint256 delegatedAmount)
        external
        onlyOwner
        returns (uint256)
    {
        totalRelayPower -= validatorRelayPower[validator];
        uint256 newPower = balanceOf(validator) + delegatedAmount;
        validatorRelayPower[validator] = newPower;
        totalRelayPower += newPower;
        emit RelayPowerUpdated(validator, newPower, totalRelayPower);
        return newPower;
    }

    // ─── BLACKLIST ──────────────────────────────────────────────────

    function blacklist(address account) external onlyBlacklister {
        _blacklisted[account] = true;
        emit Blacklisted(account);
    }

    function unBlacklist(address account) external onlyBlacklister {
        _blacklisted[account] = false;
        emit UnBlacklisted(account);
    }

    // Wrapping
    receive() external payable {
        deposit();
    }

    fallback() external payable {
        deposit();
    }

    // Vues utiles
    function isBlacklisted(address account) external view returns (bool) {
        return _blacklisted[account];
    }
}