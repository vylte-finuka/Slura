// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

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

/// @title EACAggregatorProxy - Proxy fixe pour Chainlink Aggregator
/// @notice Version avec adresse d'agrégateur HARDCODÉE à 0x55555...
/// @dev Plus besoin de passer d'adresse en paramètre du constructeur
contract EACAggregatorProxy {
    
    address public constant AGGREGATOR = 0x5555555555555555555555555555555555555555;

    AggregatorV3Interface public immutable aggregator;

    constructor() {
        aggregator = AggregatorV3Interface(AGGREGATOR);
    }

    /// @notice Retourne uniquement le prix (answer) du dernier round
    /// @return Le prix actuel (int256) provenant de l'agrégateur hardcodé
    function latestRoundData() external view returns (int256) {
        (, int256 answer, , , ) = aggregator.latestRoundData();
        return answer;
    }

    /// @notice Permet de vérifier l'adresse hardcodée (utile pour debug/front)
    function getAggregatorAddress() external pure returns (address) {
        return AGGREGATOR;
    }
}