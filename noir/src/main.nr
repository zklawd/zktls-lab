// zkTLS ETH/USD Price Verifier with packed public inputs
// Uses Primus att_verifier_lib + attestor verification + efficient packing

use att_verifier_lib::verify_attestation_hashing;
use sha256::sha256_var;
use keccak256::keccak256;

global MAX_URL_LEN: u32 = 1024;
global MAX_CONTENT_LEN: u32 = 1000;

// ============================================================================
// EFFICIENT PACKING (avoid conditional RAM explosion)
// See: github.com/Mach-34/noir-conditional-ram-best-practices
// ============================================================================

/// Unconstrained packing - builds array without constraints
unconstrained fn __pack_public_inputs(
    price: u64,
    attestor_address: [u8; 20],
    url_hash_0: [u8; 32],
    url_hash_1: [u8; 32],
) -> [u8; 92] {
    let mut packed: [u8; 92] = [0; 92];
    
    // Pack price (8 bytes, big-endian)
    let mut p = price;
    for i in 0..8 {
        packed[7 - i] = (p & 0xFF) as u8;
        p >>= 8;
    }
    
    // Pack attestor address (20 bytes)
    for i in 0..20 {
        packed[8 + i] = attestor_address[i];
    }
    
    // Pack url_hash_0 (32 bytes)
    for i in 0..32 {
        packed[28 + i] = url_hash_0[i];
    }
    
    // Pack url_hash_1 (32 bytes)
    for i in 0..32 {
        packed[60 + i] = url_hash_1[i];
    }
    
    packed
}

/// Constrained verification of packing
fn pack_public_inputs(
    price: u64,
    attestor_address: [u8; 20],
    url_hash_0: [u8; 32],
    url_hash_1: [u8; 32],
) -> [u8; 92] {
    // Safety: unconstrained packing is verified by subsequent reads
    let packed = unsafe { __pack_public_inputs(price, attestor_address, url_hash_0, url_hash_1) };
    
    // Verify price packing
    let mut reconstructed_price: u64 = 0;
    for i in 0..8 {
        reconstructed_price = reconstructed_price * 256 + packed[i] as u64;
    }
    assert(reconstructed_price == price, "Price packing mismatch");
    
    // Verify attestor address packing
    for i in 0..20 {
        assert(packed[8 + i] == attestor_address[i], "Attestor packing mismatch");
    }
    
    // Verify url_hash_0 packing
    for i in 0..32 {
        assert(packed[28 + i] == url_hash_0[i], "URL hash 0 packing mismatch");
    }
    
    // Verify url_hash_1 packing
    for i in 0..32 {
        assert(packed[60 + i] == url_hash_1[i], "URL hash 1 packing mismatch");
    }
    
    packed
}

// ============================================================================
// ATTESTOR VERIFICATION
// ============================================================================

/// Derive Ethereum address from secp256k1 public key
/// Address = keccak256(pubkey_x || pubkey_y)[12..32]
fn derive_eth_address(public_key_x: [u8; 32], public_key_y: [u8; 32]) -> [u8; 20] {
    // Concatenate x and y coordinates
    let mut pubkey_bytes: [u8; 64] = [0; 64];
    for i in 0..32 {
        pubkey_bytes[i] = public_key_x[i];
        pubkey_bytes[32 + i] = public_key_y[i];
    }
    
    // Keccak256 hash
    let hash: [u8; 32] = keccak256(pubkey_bytes, 64);
    
    // Take last 20 bytes as address
    let mut address: [u8; 20] = [0; 20];
    for i in 0..20 {
        address[i] = hash[12 + i];
    }
    
    address
}

// ============================================================================
// PRICE PARSING
// ============================================================================

/// Parse price from JSON: {"eth_usd_price":"\"DDDD.DDDDD\""}
fn parse_price(data: BoundedVec<u8, MAX_CONTENT_LEN>) -> u64 {
    let mut integer_part: u64 = 0;
    let mut decimal_part: u64 = 0;
    let mut decimal_count: u64 = 0;
    let mut in_decimal = false;
    let mut done = false;
    
    let price_start: u32 = 20;
    let data_len = data.len();
    
    for i in 0..MAX_CONTENT_LEN {
        if (i >= price_start) & (i < data_len) & !done {
            let c = data.get(i);
            
            if c == 34 { // '"'
                done = true;
            } else if c == 46 { // '.'
                in_decimal = true;
            } else if (c >= 48) & (c <= 57) { // '0'-'9'
                let digit = (c - 48) as u64;
                if in_decimal {
                    if decimal_count < 6 {
                        decimal_part = decimal_part * 10 + digit;
                        decimal_count += 1;
                    }
                } else {
                    integer_part = integer_part * 10 + digit;
                }
            }
        }
    }
    
    let multiplier = if decimal_count == 0 { 1000000 }
        else if decimal_count == 1 { 100000 }
        else if decimal_count == 2 { 10000 }
        else if decimal_count == 3 { 1000 }
        else if decimal_count == 4 { 100 }
        else if decimal_count == 5 { 10 }
        else { 1 };
    
    integer_part * 1000000 + decimal_part * multiplier
}

/// Convert Field to bytes for hashing
fn field_to_bytes(f: Field) -> [u8; 32] {
    f.to_be_bytes()
}

// ============================================================================
// MAIN CIRCUIT
// ============================================================================

fn main(
    // Private inputs
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
    
    // Public inputs (will be packed into hash)
    expected_attestor: pub [u8; 20],
    claimed_price: pub u64,
) -> pub [u8; 32] {  // Returns packed inputs hash
    // 1. Verify attestor address matches derived address from signature pubkey
    let derived_address = derive_eth_address(public_key_x, public_key_y);
    for i in 0..20 {
        assert(derived_address[i] == expected_attestor[i], "Attestor address mismatch");
    }
    
    // 2. Verify attestation using Primus library
    let url_hashes: [Field; 2] = verify_attestation_hashing(
        public_key_x,
        public_key_y,
        hash,
        signature,
        request_urls,
        allowed_urls,
        data_hashes,
        plain_json_response_contents,
    );
    
    // 3. Parse and verify price from response data
    let parsed_price = parse_price(plain_json_response_contents[0]);
    assert(parsed_price == claimed_price, "Price mismatch");
    
    // 4. Convert url_hashes to bytes for packing
    let url_hash_bytes_0 = field_to_bytes(url_hashes[0]);
    let url_hash_bytes_1 = field_to_bytes(url_hashes[1]);
    
    // 5. Pack all public inputs efficiently
    let packed = pack_public_inputs(
        claimed_price,
        expected_attestor,
        url_hash_bytes_0,
        url_hash_bytes_1,
    );
    
    // 6. Hash packed inputs and return as public output
    let packed_hash: [u8; 32] = sha256_var(packed, 92);
    packed_hash
}
