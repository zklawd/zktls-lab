// zkTLS ETH/USD Price Verifier
// Properly constrains price extraction from attested data

use std::hash::sha256;
use std::ecdsa_secp256k1::verify_signature;
use string_search::{StringBody, SubString, StringBody256, SubString256};

global MAX_URL_LEN: u32 = 256;
global MAX_DATA_LEN: u32 = 256;

// Parse price from JSON data: {"eth_usd_price":"\"DDDD.DDDDD\""}
// Returns price as u64 with 6 decimal places
fn parse_price_from_json(data: [u8; MAX_DATA_LEN], data_len: u32) -> u64 {
    // The format is: {"eth_usd_price":"\"2821.41000\""}
    // Price starts at index 20 (after {"eth_usd_price":"\")
    
    let mut integer_part: u64 = 0;
    let mut decimal_part: u64 = 0;
    let mut decimal_count: u64 = 0;
    let mut in_decimal = false;
    let mut done = false;
    
    let price_start: u32 = 20;
    
    for i in 0..MAX_DATA_LEN {
        if (i >= price_start) & (i < data_len) & !done {
            let c = data[i];
            
            if c == 34 { // '"' - end of price
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
    
    // Pad decimal to 6 places using multiplication
    // If we have 5 decimals, multiply by 10^1
    // If we have 4 decimals, multiply by 10^2, etc.
    let multiplier = if decimal_count == 0 { 1000000 }
        else if decimal_count == 1 { 100000 }
        else if decimal_count == 2 { 10000 }
        else if decimal_count == 3 { 1000 }
        else if decimal_count == 4 { 100 }
        else if decimal_count == 5 { 10 }
        else { 1 };
    
    integer_part * 1000000 + decimal_part * multiplier
}

fn main(
    // Public inputs
    hash: pub [u8; 32],                    // Message hash (keccak256 of attestation)
    allowed_url: pub [u8; MAX_URL_LEN],    // Allowed URL prefix (zero-padded)
    allowed_url_len: pub u32,
    data_hash: pub [u8; 32],               // SHA256 of zero-padded response
    eth_usd_price: pub [u8; 8],            // Price as u64 (6 decimals) - MUST match parsed
    
    // Private inputs
    signature: [u8; 64],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    request_url: [u8; MAX_URL_LEN],
    request_url_len: u32,
    plain_response: [u8; MAX_DATA_LEN],
    plain_response_len: u32
) -> pub u64 {
    // 1. Verify ECDSA signature
    assert(verify_signature(public_key_x, public_key_y, signature, hash), "Invalid signature");

    // 2. Verify request URL starts with allowed URL
    let haystack: StringBody256 = StringBody::new(request_url, request_url_len);
    let needle: SubString256 = SubString::new(allowed_url, allowed_url_len);
    let (found, position) = haystack.substring_match(needle);
    assert(found & (position == 0), "URL not allowed");

    // 3. Verify plaintext response hashes to data_hash
    let computed_hash = sha256(plain_response);
    for i in 0..32 {
        assert(computed_hash[i] == data_hash[i], "Data hash mismatch");
    }

    // 4. Parse price from the JSON data
    let parsed_price = parse_price_from_json(plain_response, plain_response_len);
    
    // 5. Convert input price bytes to u64
    let mut input_price: u64 = 0;
    for i in 0..8 {
        input_price = input_price * 256 + eth_usd_price[i] as u64;
    }
    
    // 6. CRITICAL: Verify parsed price matches claimed price
    assert(parsed_price == input_price, "Price mismatch - parsed does not match claimed");

    parsed_price
}
