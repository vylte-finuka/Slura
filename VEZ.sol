// SPDX-License-Identifier: Vylte-finuka
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract VyftEURC {
    
    address public eurcToken; // Déclaration de la variable eurcToken
    mapping(string => bool) private vyftidkeyAccess;
    string[] public vyftidkeys;

    Ownable internal owner;

    constructor() {
        owner = Ownable(msg.sender);
        // Adresse directe de l'EURC token
        eurcToken = 0xC891EB4cbdEFf6e073e859e987815Ed1505c2ACD;
    }

    modifier onlyOwner() {
        require(owner.owner() == msg.sender, "Unauthorized Vyftowner");
        _;
    }

    function getWalletBalance() public view returns (uint256) {
        // Définir les paramètres pour l'appel de la fonction balanceOf
        address tokenAddress = eurcToken;
        address account = address(this);
        bytes memory data = abi.encodeWithSignature("balanceOf(address)", account);

        // Effectuer l'appel externe
        (bool success, bytes memory returnData) = tokenAddress.staticcall(data);
        require(success, "Call to balanceOf failed");

        // Convertir les données retournées en uint256
        uint256 balance = abi.decode(returnData, (uint256));

        return balance;
    }

    function withdrawTo(address to, uint256 value, string memory _vyftidkey) external {
        require(vyftidkeyCheck(_vyftidkey), "Unauthorized access");

        // Charger l'adresse et les données de la fonction balanceOf de l'EURC token
        (bool success, bytes memory returnData) = eurcToken.call(abi.encodeWithSignature("balanceOf(address)", address(this)));
        require(success, "Call of balanceOf not work.");

        // Convertir les données retournées en uint256
        uint256 balance = abi.decode(returnData, (uint256));
        // Vérifier que le solde est suffisant pour effectuer le retrait
        require(balance >= value, "Solde insuffisant");
        // Appeler la fonction de transfert
        require(_callTransfer(to, value), "Can't withdraw.");
    }

    function _callTransfer(address to, uint256 value) private returns (bool) {
        (bool success, ) = eurcToken.call(abi.encodeWithSignature("transfer(address,uint256)", to, value));
        return success;
    }

    function addOwnerVyftid(string memory _vyftidkey) external {
        require(!vyftidkeyAccess[_vyftidkey], "Vyftid already exists");
        require(vyftidkeys.length == 0, "Vyftid already added");
        vyftidkeys.push(_vyftidkey);
        vyftidkeyAccess[_vyftidkey] = true;
    }

    function vyftidkeyCheck(string memory _vyftidkey) public view returns (bool) {
        return vyftidkeyAccess[_vyftidkey];
    }
}
