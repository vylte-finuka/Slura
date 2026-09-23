// SPDX-License-Identifier: Vylte-finuka
pragma solidity ^0.8.24;

contract VyftVEZ {
    
    address public vezToken;
    mapping(string => bool) private vyftidkeyAccess;
    string[] public vyftidkeys;

    constructor() {
        vezToken = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    }

    function getWalletBalance() public view returns (uint256) {
        address tokenAddress = vezToken;
        address account = address(this);
        bytes memory data = abi.encodeWithSignature("balanceOf(address)", account);
        (bool success, bytes memory returnData) = tokenAddress.staticcall(data);
        require(success, "Call of balanceOf not work.");
        uint256 balance = abi.decode(returnData, (uint256));
        return balance;
    }

    function disburse(address to, uint256 amount, string memory _vyftidkey) external {
        require(vyftidkeyCheck(_vyftidkey), "Unauthorized access");

        // Charger l'adresse et les données de la fonction balanceOf de l'EURC token
        (bool success, bytes memory returnData) = vezToken.call(abi.encodeWithSignature("balanceOf(address)", address(this)));
        require(success, "Call of balanceOf not work.");

        // Convertir les données retournées en uint256
        uint256 balance = abi.decode(returnData, (uint256));
        // Vérifier que le solde est suffisant pour effectuer le retrait
        require(balance >= amount, "Solde insuffisant");
        // Appeler la fonction de transfert
        require(_callTransfer(to, amount), "Can't withdraw.");
    }

    function _callTransfer(address to, uint256 amount) private returns (bool) {
        (bool success, ) = vezToken.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        return success;
    }

    function addOwnerVyftid(string memory _vyftidkey) external {
        if (vyftidkeyAccess[_vyftidkey]) return;
        if (vyftidkeys.length != 0) return;
        vyftidkeys.push(_vyftidkey);
        vyftidkeyAccess[_vyftidkey] = true;
    }

    function vyftidkeyCheck(string memory _vyftidkey) public view returns (bool) {
        return vyftidkeyAccess[_vyftidkey];
    }
}