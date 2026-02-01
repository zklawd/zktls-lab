// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "./ZkTLSVerifier.sol";

/**
 * @title ZkTLSPriceOracle
 * @notice On-chain price oracle backed by zkTLS proofs from Primus
 * @dev Verifies UltraHonk proofs that attestation came from a trusted attestor
 * 
 * Security fixes applied:
 * - Issue #1: Fixed public input extraction (each byte is separate field element)
 * - Issue #3: Added attestation staleness check (MAX_ATTESTATION_AGE)
 * - Issue #5: Response data hash is now a public input for integrity verification
 * - Issue #6: Zero-address validation in constructor and setters
 * - Issue #7: 2-day timelock on attestor changes
 * - Issue #9: Replay protection via proof hash tracking
 */
contract ZkTLSPriceOracle {
    // ============================================================================
    // STATE VARIABLES
    // ============================================================================
    
    // The HonkVerifier contract (generated from Noir circuit)
    HonkVerifier public immutable verifier;
    
    // Trusted attestor address (Primus attestor)
    address public trustedAttestor;
    
    // Owner for admin functions
    address public owner;
    
    // Timelock for attestor changes (Issue #7)
    uint256 public constant ATTESTOR_TIMELOCK = 2 days;
    
    // Maximum age of attestation (Issue #3 - staleness protection)
    uint256 public constant MAX_ATTESTATION_AGE = 5 minutes;
    
    // Number of public inputs expected from the circuit
    // Layout: attestor(20) + price(1) + timestamp(1) + response_hash(32) + packed_hash(32) = 86
    uint256 public constant EXPECTED_PUBLIC_INPUTS = 86;
    
    // Pending attestor change (Issue #7 - timelock)
    struct PendingAttestorChange {
        address newAttestor;
        uint256 executeAfter;
    }
    PendingAttestorChange public pendingAttestorChange;
    
    // Replay protection: track used proof hashes (Issue #9)
    mapping(bytes32 => bool) public usedProofHashes;
    
    // Price storage (scaled by 1e6)
    struct PriceData {
        uint256 price;
        uint256 attestationTimestamp;
        uint256 blockTimestamp;
        bytes32 responseDataHash;
        bytes32 packedHash;
    }
    
    // Latest verified price
    PriceData public latestPrice;
    
    // ============================================================================
    // EVENTS
    // ============================================================================
    
    event PriceUpdated(
        uint256 price, 
        uint256 attestationTimestamp,
        bytes32 responseDataHash,
        bytes32 packedHash, 
        uint256 blockTimestamp
    );
    event AttestorChangeProposed(address indexed proposedAttestor, uint256 executeAfter);
    event AttestorChangeExecuted(address indexed oldAttestor, address indexed newAttestor);
    event AttestorChangeCancelled(address indexed cancelledAttestor);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    
    // ============================================================================
    // ERRORS
    // ============================================================================
    
    error InvalidProof();
    error InvalidAttestor();
    error InvalidPublicInputsLength();
    error AttestationTooOld();
    error OnlyOwner();
    error ZeroAddress();
    error ProofAlreadyUsed();
    error NoPendingChange();
    error TimelockNotExpired();
    
    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================
    
    constructor(address _verifier, address _trustedAttestor) {
        // Issue #6: Zero-address validation
        if (_verifier == address(0)) revert ZeroAddress();
        if (_trustedAttestor == address(0)) revert ZeroAddress();
        
        verifier = HonkVerifier(_verifier);
        trustedAttestor = _trustedAttestor;
        owner = msg.sender;
    }
    
    // ============================================================================
    // PRICE UPDATE
    // ============================================================================
    
    /**
     * @notice Submit a zkTLS proof to update the price
     * @param proof The UltraHonk proof bytes
     * @param publicInputs The public inputs array (86 elements)
     * @dev Public inputs layout (Noir types → field elements):
     *      [0..19]:  expected_attestor   [u8; 20] → 20 field elements (1 byte each)
     *      [20]:     claimed_price       u64      → 1 field element
     *      [21]:     attestation_timestamp u64    → 1 field element (Issue #3)
     *      [22..53]: expected_response_hash [u8; 32] → 32 field elements (Issue #5)
     *      [54..85]: packed_hash (return) [u8; 32] → 32 field elements
     */
    function updatePrice(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        // Validate public inputs length
        if (publicInputs.length != EXPECTED_PUBLIC_INPUTS) revert InvalidPublicInputsLength();
        
        // Verify the proof
        bool valid = verifier.verify(proof, publicInputs);
        if (!valid) revert InvalidProof();
        
        // Issue #1 fix: Reconstruct attestor address from first 20 public inputs
        // Each publicInputs[i] contains a single byte value as bytes32
        address proofAttestor = _extractAddress(publicInputs, 0);
        if (proofAttestor != trustedAttestor) revert InvalidAttestor();
        
        // Extract price from publicInputs[20]
        uint256 price = uint256(publicInputs[20]);
        
        // Issue #3 fix: Extract and validate attestation timestamp
        uint256 attestationTimestamp = uint256(publicInputs[21]);
        if (block.timestamp > attestationTimestamp + MAX_ATTESTATION_AGE) {
            revert AttestationTooOld();
        }
        
        // Issue #5 fix: Extract response data hash (for integrity verification)
        bytes32 responseDataHash = _extractBytes32(publicInputs, 22);
        
        // Extract packed hash from last 32 public inputs (indices 54-85)
        bytes32 packedHash = _extractBytes32(publicInputs, 54);
        
        // Issue #9 fix: Replay protection
        if (usedProofHashes[packedHash]) revert ProofAlreadyUsed();
        usedProofHashes[packedHash] = true;
        
        // Update storage
        latestPrice = PriceData({
            price: price,
            attestationTimestamp: attestationTimestamp,
            blockTimestamp: block.timestamp,
            responseDataHash: responseDataHash,
            packedHash: packedHash
        });
        
        emit PriceUpdated(price, attestationTimestamp, responseDataHash, packedHash, block.timestamp);
    }
    
    /**
     * @notice Extract an address from 20 consecutive public inputs (bytes)
     * @param publicInputs The full public inputs array
     * @param startIndex Starting index in the array
     */
    function _extractAddress(bytes32[] calldata publicInputs, uint256 startIndex) internal pure returns (address) {
        uint160 addr = 0;
        for (uint256 i = 0; i < 20; i++) {
            // Each public input is a bytes32 containing a single byte value
            uint8 byteVal = uint8(uint256(publicInputs[startIndex + i]));
            addr = (addr << 8) | uint160(byteVal);
        }
        return address(addr);
    }
    
    /**
     * @notice Extract a bytes32 from 32 consecutive public inputs (bytes)
     * @param publicInputs The full public inputs array
     * @param startIndex Starting index in the array
     */
    function _extractBytes32(bytes32[] calldata publicInputs, uint256 startIndex) internal pure returns (bytes32) {
        uint256 result = 0;
        for (uint256 i = 0; i < 32; i++) {
            // Each public input is a bytes32 containing a single byte value
            uint8 byteVal = uint8(uint256(publicInputs[startIndex + i]));
            result = (result << 8) | uint256(byteVal);
        }
        return bytes32(result);
    }
    
    // ============================================================================
    // GETTERS
    // ============================================================================
    
    /**
     * @notice Get the latest verified price
     * @return price The ETH/USD price scaled by 1e6
     * @return timestamp When the attestation was created
     */
    function getPrice() external view returns (uint256 price, uint256 timestamp) {
        return (latestPrice.price, latestPrice.attestationTimestamp);
    }
    
    /**
     * @notice Get full price data including all verification info
     */
    function getPriceData() external view returns (PriceData memory) {
        return latestPrice;
    }
    
    // ============================================================================
    // ATTESTOR MANAGEMENT (Issue #7 - Timelock)
    // ============================================================================
    
    /**
     * @notice Propose a new trusted attestor (starts 2-day timelock)
     * @param newAttestor The new attestor address
     */
    function proposeAttestor(address newAttestor) external {
        if (msg.sender != owner) revert OnlyOwner();
        if (newAttestor == address(0)) revert ZeroAddress();
        
        uint256 executeAfter = block.timestamp + ATTESTOR_TIMELOCK;
        pendingAttestorChange = PendingAttestorChange({
            newAttestor: newAttestor,
            executeAfter: executeAfter
        });
        
        emit AttestorChangeProposed(newAttestor, executeAfter);
    }
    
    /**
     * @notice Execute the pending attestor change after timelock expires
     */
    function executeAttestorChange() external {
        if (msg.sender != owner) revert OnlyOwner();
        
        PendingAttestorChange memory pending = pendingAttestorChange;
        if (pending.newAttestor == address(0)) revert NoPendingChange();
        if (block.timestamp < pending.executeAfter) revert TimelockNotExpired();
        
        address oldAttestor = trustedAttestor;
        trustedAttestor = pending.newAttestor;
        
        // Clear pending change
        delete pendingAttestorChange;
        
        emit AttestorChangeExecuted(oldAttestor, pending.newAttestor);
    }
    
    /**
     * @notice Cancel a pending attestor change
     */
    function cancelAttestorChange() external {
        if (msg.sender != owner) revert OnlyOwner();
        
        address cancelledAttestor = pendingAttestorChange.newAttestor;
        if (cancelledAttestor == address(0)) revert NoPendingChange();
        
        delete pendingAttestorChange;
        
        emit AttestorChangeCancelled(cancelledAttestor);
    }
    
    // ============================================================================
    // OWNERSHIP
    // ============================================================================
    
    /**
     * @notice Transfer ownership
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert OnlyOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        
        emit OwnerUpdated(owner, newOwner);
        owner = newOwner;
    }
}
