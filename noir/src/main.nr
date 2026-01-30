// zkTLS ETH/USD Price Verifier using Primus att_verifier_lib
use att_verifier_lib::verify_attestation_hashing;

global MAX_URL_LEN: u32 = 1024;
global MAX_CONTENT_LEN: u32 = 1000;

// Parse price from JSON: {"eth_usd_price":"\"DDDD.DDDDD\""}
fn parse_price(data: BoundedVec<u8, MAX_CONTENT_LEN>) -> u64 {
    // Price starts at index 20 after {"eth_usd_price":"\"
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

fn main(
    // Attestation verification inputs
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
    
    // Price constraint
    claimed_price: pub u64,
) -> pub [Field; 2] {
    // 1. Verify attestation using Primus library
    let url_hashes = verify_attestation_hashing(
        public_key_x,
        public_key_y,
        hash,
        signature,
        request_urls,
        allowed_urls,
        data_hashes,
        plain_json_response_contents,
    );
    
    // 2. Parse and constrain price from first response
    let parsed_price = parse_price(plain_json_response_contents[0]);
    assert(parsed_price == claimed_price, "Price mismatch");
    
    url_hashes
}
