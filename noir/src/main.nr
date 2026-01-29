// zkTLS Attestation Verifier - Noir Circuit
use std::hash::keccak256;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // Public inputs
    message_hash: pub [u8; 32],
    attestor_address: pub [u8; 20],
    
    // Private inputs  
    signature: [u8; 64],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32]
) {
    // 1. Verify ECDSA signature
    let valid = verify_signature(public_key_x, public_key_y, signature, message_hash);
    assert(valid, "Invalid signature");
    
    // 2. Derive address from public key and verify
    let mut pub_key: [u8; 64] = [0; 64];
    for i in 0..32 {
        pub_key[i] = public_key_x[i];
        pub_key[i + 32] = public_key_y[i];
    }
    
    let hash = keccak256(pub_key, 64);
    
    // Check last 20 bytes match attestor address
    for i in 0..20 {
        assert(hash[i + 12] == attestor_address[i], "Address mismatch");
    }
}
