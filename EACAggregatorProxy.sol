// SPDX-License-Identifier: MIT
// Copyright (C) Vyft, SAS

pragma solidity ^0.8.26;

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
/// @notice Ce contrat est le VRAI oracle on-chain pour le Proof of Reserve.
///         Il remplace le placeholder 0x555... et publie directement
///         les données de réserve EUR pour le stablecoin VEZ.
///         Le propriétaire (custodian) peut mettre à jour les données via
///         une transaction déclenchée par le workflow CRE.
contract EACAggregatorProxy is AggregatorV3Interface {

    ///====≈====≈=== DONNÉES ORACLE
    uint80 public roundId;
    int256 public answer;
    uint256 public startedAt;
    uint256 public updatedAt;
    uint80 public answeredInRound;

    ///====≈====≈=== ADMIN
    address public owner;

    ///====≈====≈=== EVENTS
    event RoundUpdated(
        uint80 indexed roundId,
        int256 answer,
        uint256 updatedAt
    );

    ///====≈====≈=== CONSTRUCTOR
    constructor() {
        owner = msg.sender;
        roundId = 1;
        answer = 1000000000000000000000000; // 1 EUR avec 18 décimales
        startedAt = block.timestamp;
        updatedAt = block.timestamp;
        answeredInRound = 1;
    }

    ///====≈====≈=== MISE À JOUR DES DONNÉES PoR
    /// Seul le propriétaire (custodian / oracle) peut mettre à jour.
    function updateRoundData(
        int256 _answer,
        uint256 _timestamp
    ) external {
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

    ///====≈====≈=== LATEST ROUND DATA
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
        return (
            roundId,
            answer,
            startedAt,
            updatedAt,
            answeredInRound
        );
    }

    ///====≈====≈=== GET FULL ROUND DATA
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

    ///====≈====≈=== ORACLE HEALTH
    function isOracleValid()
        external
        view
        returns (bool)
    {
        return answer > 0 && updatedAt > 0;
    }

    ///====≈====≈=== TRANSFERT DE PROPRIÉTÉ
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Only owner");
        owner = newOwner;
    }

    ///====≈====≈=== COMPATIBILITÉ AVEC L'ANCIENNE INTERFACE
    /// @notice Retourne l'adresse de l'agrégateur (ce contrat lui-même).
    /// @dev Cette fonction est conservée pour la compatibilité avec les contrats
    ///      qui attendent une fonction getAggregatorAddress().
    function getAggregatorAddress()
        external
        view
        returns (address)
    {
        return address(this);
    }
}
