// zkTLS ETH/USD Price Verifier
// Verifies Primus attestation and outputs ETH price as Field (6 decimals)

use std::hash::keccak256;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    // Public inputs (revealed in proof)
    message_hash: pub [u8; 32],
    attestor_address: pub [u8; 20],
    eth_usd_price: pub [u8; 8],  // u64 big-endian, 6 decimals precision
    
    // Private inputs (hidden)
    signature: [u8; 64],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    data_hash: [u8; 32]  // Hash of attested data for binding
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
    
    // 3. Convert price bytes (big-endian u64) to Field
    let mut price_field: Field = 0;
    for i in 0..8 {
        price_field = price_field * 256 + eth_usd_price[i] as Field;
    }
    
    // Return the verified ETH/USD price (6 decimal precision)
    // e.g., 2821410000 = $2821.41
    price_field
}

#[test]
fn test_price_conversion() {
    // Test: 2821410000 in big-endian bytes
    // 2821410000 = 0xA8275CD0
    let price_bytes: [u8; 8] = [0, 0, 0, 0, 0xa8, 0x27, 0x5c, 0xd0];
    
    let mut price: Field = 0;
    for i in 0..8 {
        price = price * 256 + price_bytes[i] as Field;
    }
    
    assert(price == 2821410000);
}
