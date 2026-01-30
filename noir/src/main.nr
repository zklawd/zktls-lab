// zkTLS ETH/USD Price Verifier
// Based on Primus att_verifier_lib verify_attestation_hashing

use std::hash::sha256;
use std::ecdsa_secp256k1::verify_signature;
use string_search::{StringBody, SubString, StringBody256, SubString256};

global MAX_URL_LEN: u32 = 256;
global MAX_DATA_LEN: u32 = 256;

fn main(
    // Public inputs
    hash: pub [u8; 32],                    // Message hash (keccak256 of attestation)
    allowed_url: pub [u8; MAX_URL_LEN],    // Allowed URL prefix (zero-padded)
    allowed_url_len: pub u32,              // Actual length of allowed URL
    data_hash: pub [u8; 32],               // SHA256 of zero-padded response
    eth_usd_price: pub [u8; 8],            // Price as u64 (6 decimals)
    
    // Private inputs
    signature: [u8; 64],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    request_url: [u8; MAX_URL_LEN],        // Actual request URL (zero-padded)
    request_url_len: u32,                   // Actual length
    plain_response: [u8; MAX_DATA_LEN],    // Plaintext JSON response (zero-padded)
    plain_response_len: u32                 // Actual length (unused but kept for compatibility)
) -> pub Field {
    // 1. Verify ECDSA signature
    assert(verify_signature(public_key_x, public_key_y, signature, hash), "Invalid signature");

    // 2. Verify request URL starts with allowed URL (prefix match)
    let haystack: StringBody256 = StringBody::new(request_url, request_url_len);
    let needle: SubString256 = SubString::new(allowed_url, allowed_url_len);
    let (found, position) = haystack.substring_match(needle);
    assert(found & (position == 0), "URL not allowed");

    // 3. Verify plaintext response hashes to data_hash
    // Note: We hash the full zero-padded array for simplicity
    let computed_hash = sha256(plain_response);
    for i in 0..32 {
        assert(computed_hash[i] == data_hash[i], "Data hash mismatch");
    }

    // 4. Return price as Field
    let mut price: Field = 0;
    for i in 0..8 {
        price = price * 256 + eth_usd_price[i] as Field;
    }
    price
}
