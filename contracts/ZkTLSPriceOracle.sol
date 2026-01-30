// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./ZkTLSVerifier.sol";

/**
 * @title ZkTLSPriceOracle
 * @notice On-chain price oracle backed by zkTLS proofs from Primus
 * @dev Verifies UltraHonk proofs that attestation came from a trusted attestor
 */
contract ZkTLSPriceOracle {
    // The HonkVerifier contract (generated from Noir circuit)
    HonkVerifier public immutable verifier;
    
    // Trusted attestor address (Primus attestor)
    address public trustedAttestor;
    
    // Owner for admin functions
    address public owner;
    
    // Price storage (scaled by 1e6)
    struct PriceData {
        uint256 price;
        uint256 timestamp;
        bytes32 proofHash;
    }
    
    // Latest verified price
    PriceData public latestPrice;
    
    // Events
    event PriceUpdated(uint256 price, bytes32 packedInputsHash, uint256 timestamp);
    event AttestorUpdated(address indexed oldAttestor, address indexed newAttestor);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    
    // Errors
    error InvalidProof();
    error InvalidAttestor();
    error OnlyOwner();
    
    constructor(address _verifier, address _trustedAttestor) {
        verifier = HonkVerifier(_verifier);
        trustedAttestor = _trustedAttestor;
        owner = msg.sender;
    }
    
    /**
     * @notice Submit a zkTLS proof to update the price
     * @param proof The UltraHonk proof bytes
     * @param publicInputs The public inputs array (attestor address, price, packed hash)
     */
    function updatePrice(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        // Verify the proof
        bool valid = verifier.verify(proof, publicInputs);
        if (!valid) revert InvalidProof();
        
        // Extract attestor address from public inputs (first 20 bytes of first input)
        // The circuit packs: [attestor (20 bytes), price (u64), packed_hash (32 bytes)]
        address proofAttestor = address(bytes20(publicInputs[0]));
        if (proofAttestor != trustedAttestor) revert InvalidAttestor();
        
        // Extract price from public inputs
        uint256 price = uint256(publicInputs[1]);
        
        // Extract packed inputs hash (returned from circuit)
        bytes32 packedHash = publicInputs[publicInputs.length - 1];
        
        // Update storage
        latestPrice = PriceData({
            price: price,
            timestamp: block.timestamp,
            proofHash: packedHash
        });
        
        emit PriceUpdated(price, packedHash, block.timestamp);
    }
    
    /**
     * @notice Get the latest verified price
     * @return price The ETH/USD price scaled by 1e6
     * @return timestamp When the price was last updated
     */
    function getPrice() external view returns (uint256 price, uint256 timestamp) {
        return (latestPrice.price, latestPrice.timestamp);
    }
    
    /**
     * @notice Update the trusted attestor address
     * @param newAttestor The new attestor address
     */
    function setTrustedAttestor(address newAttestor) external {
        if (msg.sender != owner) revert OnlyOwner();
        emit AttestorUpdated(trustedAttestor, newAttestor);
        trustedAttestor = newAttestor;
    }
    
    /**
     * @notice Transfer ownership
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert OnlyOwner();
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }
}
