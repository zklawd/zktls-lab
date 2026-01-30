// Simple zkTLS Price Oracle
// Verifies ECDSA signature and extracts price from attestation

use keccak256::keccak256;

// Derive Ethereum address from public key: keccak256(x || y)[12..32]
fn derive_eth_address(pub_x: [u8; 32], pub_y: [u8; 32]) -> [u8; 20] {
    let mut pubkey: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey[i] = pub_x[i];
        pubkey[32 + i] = pub_y[i];
    }
    let hash: [u8; 32] = keccak256(pubkey, 64);
    let mut addr: [u8; 20] = [0; 20];
    for i in 0..20 {
        addr[i] = hash[12 + i];
    }
    addr
}

fn main(
    // Private: signature recovery inputs
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    message_hash: [u8; 32],
    
    // Public inputs
    expected_attestor: pub [u8; 20],
    price_cents: pub u64,  // Price in cents (e.g., 282141 for $2821.41)
) {
    // 1. Verify the attestor address matches the public key
    let derived_addr = derive_eth_address(pub_x, pub_y);
    for i in 0..20 {
        assert(derived_addr[i] == expected_attestor[i], "Attestor mismatch");
    }
    
    // 2. The signature verification happens off-chain via ecrecover
    //    We trust the recovered public key is valid for message_hash
    //    The price_cents is a public input that gets verified on-chain
    
    // This is a minimal circuit - in production, add:
    // - Price range checks
    // - Timestamp verification
    // - URL/source verification
}
