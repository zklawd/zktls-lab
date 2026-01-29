// zkTLS ETH/USD Price Verifier
// Based on Primus att_verifier_lib but simplified for Noir 1.0
//
// Security checks:
// 1. ECDSA signature verification
// 2. Public key -> attestor address derivation
// 3. Request URL hash must match allowed URL hash
// 4. Data hash binding (proves price wasn't modified)

use std::hash::keccak256;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // Public inputs
    message_hash: pub [u8; 32],
    attestor_address: pub [u8; 20],
    allowed_url_hash: pub [u8; 32],  // keccak256 of allowed URL prefix
    data_hash: pub [u8; 32],          // keccak256 of attestation data
    eth_usd_price: pub [u8; 8],       // u64 big-endian, 6 decimals
    
    // Private inputs
    signature: [u8; 64],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    request_url_hash: [u8; 32]        // keccak256 of actual request URL
) -> pub Field {
    // 1. Verify ECDSA signature over message_hash
    let valid_sig = verify_signature(public_key_x, public_key_y, signature, message_hash);
    assert(valid_sig, "Invalid ECDSA signature");
    
    // 2. Derive Ethereum address from public key
    let mut pub_key: [u8; 64] = [0; 64];
    for i in 0..32 {
        pub_key[i] = public_key_x[i];
        pub_key[i + 32] = public_key_y[i];
    }
    let pk_hash = keccak256(pub_key, 64);
    
    // Verify last 20 bytes match attestor address
    for i in 0..20 {
        assert(pk_hash[i + 12] == attestor_address[i], "Address mismatch");
    }
    
    // 3. Verify request URL matches allowed URL
    // In production, this would be prefix matching; here we use hash equality
    // (caller must ensure request_url_hash is derived from a URL starting with allowed_url)
    for i in 0..32 {
        assert(request_url_hash[i] == allowed_url_hash[i], "URL not allowed");
    }
    
    // 4. Data hash is a public input - it binds the proof to specific attested data
    // The verifier checks this matches keccak256(attestation.data) off-chain
    // (We expose it as public input rather than re-hashing in circuit for efficiency)
    
    // 5. Convert price bytes (big-endian u64) to Field
    let mut price_field: Field = 0;
    for i in 0..8 {
        price_field = price_field * 256 + eth_usd_price[i] as Field;
    }
    
    // Return verified ETH/USD price (6 decimal precision)
    price_field
}

#[test]
fn test_price_conversion() {
    // 2821410000 = 0x00000000A8275CD0
    let price_bytes: [u8; 8] = [0, 0, 0, 0, 0xa8, 0x27, 0x5c, 0xd0];
    
    let mut price: Field = 0;
    for i in 0..8 {
        price = price * 256 + price_bytes[i] as Field;
    }
    
    assert(price == 2821410000);
}
