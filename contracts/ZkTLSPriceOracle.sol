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
    
    // Timelock for attestor changes (2 days)
    uint256 public constant ATTESTOR_TIMELOCK = 2 days;
    
    // Pending attestor change
    struct PendingAttestorChange {
        address newAttestor;
        uint256 executeAfter;
    }
    PendingAttestorChange public pendingAttestorChange;
    
    // Replay protection: track used proof hashes
    mapping(bytes32 => bool) public usedProofHashes;
    
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
    event AttestorChangeProposed(address indexed proposedAttestor, uint256 executeAfter);
    event AttestorChangeExecuted(address indexed oldAttestor, address indexed newAttestor);
    event AttestorChangeCancelled(address indexed cancelledAttestor);
    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);
    
    // Errors
    error InvalidProof();
    error InvalidAttestor();
    error OnlyOwner();
    error ZeroAddress();
    error ProofAlreadyUsed();
    error NoPendingChange();
    error TimelockNotExpired();
    
    constructor(address _verifier, address _trustedAttestor) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_trustedAttestor == address(0)) revert ZeroAddress();
        
        verifier = HonkVerifier(_verifier);
        trustedAttestor = _trustedAttestor;
        owner = msg.sender;
    }
    
    /**
     * @notice Submit a zkTLS proof to update the price
     * @param proof The UltraHonk proof bytes
     * @param publicInputs The public inputs array (69 elements total)
     * @dev Public inputs layout (Noir [u8; N] → N separate field elements):
     *      - [0..19]: attestor address (20 bytes, each as separate field element)
     *      - [20]: price (u64 as single field element)
     *      - [21..52]: packed_hash placeholder (we reconstruct from [37..68])
     *      - [37..68]: actual packed hash bytes (32 bytes, each as separate field element)
     */
    function updatePrice(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        // Verify the proof
        bool valid = verifier.verify(proof, publicInputs);
        if (!valid) revert InvalidProof();
        
        // Reconstruct attestor address from first 20 public inputs
        // Each publicInputs[i] contains a single byte value as bytes32
        address proofAttestor;
        assembly {
            let addr := 0
            // publicInputs is calldata array, first 32 bytes at offset is length
            // actual data starts at publicInputs.offset
            let dataOffset := publicInputs.offset
            
            for { let i := 0 } lt(i, 20) { i := add(i, 1) } {
                // Load each bytes32, extract the byte value, shift into position
                let byteVal := and(calldataload(add(dataOffset, mul(i, 32))), 0xff)
                addr := or(shl(mul(sub(19, i), 8), byteVal), addr)
            }
            proofAttestor := addr
        }
        
        if (proofAttestor != trustedAttestor) revert InvalidAttestor();
        
        // Extract price from publicInputs[20] (u64 fits in single field element)
        uint256 price = uint256(publicInputs[20]);
        
        // Reconstruct packed hash from last 32 public inputs (indices 37-68)
        bytes32 packedHash;
        assembly {
            let hash := 0
            let dataOffset := publicInputs.offset
            // Last 32 inputs: indices 37 to 68 (69 total, 69-32=37)
            let startIdx := 37
            
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let byteVal := and(calldataload(add(dataOffset, mul(add(startIdx, i), 32))), 0xff)
                hash := or(shl(mul(sub(31, i), 8), byteVal), hash)
            }
            packedHash := hash
        }
        
        // Replay protection: check if this proof hash was already used
        if (usedProofHashes[packedHash]) revert ProofAlreadyUsed();
        usedProofHashes[packedHash] = true;
        
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
     * @notice Propose a new trusted attestor (starts timelock)
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
