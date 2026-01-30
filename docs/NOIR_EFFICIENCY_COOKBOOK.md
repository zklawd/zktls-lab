# Noir Efficiency Cookbook

Patterns for writing efficient Noir circuits. Gate count matters for proving time and on-chain verification cost.

## 1. Conditional RAM / Array Writes

**Problem:** Writing to arrays with conditional indices explodes gate count.

```noir
// BAD: 641,340 gates
for i in 0..N {
    if i < length {
        output[index] = input[i];  // Conditional write = expensive!
        index += 1;
    }
}
```

**Solution:** Use unconstrained functions to build arrays, then verify with reads.

```noir
// GOOD: 6,073 gates (100x cheaper!)

unconstrained fn __pack(item_1: [u8; N], len_1: u32, item_2: [u8; M], len_2: u32) -> [u8; N+M] {
    let mut packed = [0; N + M];
    let mut idx = 0;
    for i in 0..N {
        if i < len_1 { packed[idx] = item_1[i]; idx += 1; }
    }
    for i in 0..M {
        if i < len_2 { packed[idx] = item_2[i]; idx += 1; }
    }
    packed
}

fn pack(item_1: [u8; N], len_1: u32, item_2: [u8; M], len_2: u32) -> [u8; N+M] {
    // Safety: unconstrained build, verified by reads below
    let packed = unsafe { __pack(item_1, len_1, item_2, len_2) };
    
    // Verify with reads only (cheap!)
    for i in 0..N {
        let out_of_bounds = i >= len_1;
        let matched = item_1[i] == packed[i];
        assert(out_of_bounds | matched);
    }
    for i in 0..M {
        let out_of_bounds = i >= len_2;
        let matched = item_2[i] == packed[len_1 + i];
        assert(out_of_bounds | matched);
    }
    packed
}
```

**Reference:** https://github.com/Mach-34/noir-conditional-ram-best-practices

---

## 2. Packed Public Inputs

**Problem:** Many public inputs = expensive on-chain verification.

Each public input costs gas in the verifier contract. If you have 10+ public values, costs add up.

**Solution:** Pack all public values, hash them, output single hash.

```noir
fn main(
    // Private inputs...
    
    // Values that would be public (but passed as private)
    price: u64,
    attestor: [u8; 20],
    url_hash: [u8; 32],
    
    // Single public output
    packed_hash: pub [u8; 32],
) {
    // ... verify everything ...
    
    // Pack values
    let packed = pack_values(price, attestor, url_hash);
    
    // Hash and verify against public input
    let computed_hash = sha256_var(packed, packed.len());
    assert(computed_hash == packed_hash);
}
```

**On-chain verification:**
```solidity
function verify(
    bytes calldata proof,
    bytes32 packedHash,
    // Unpacked values for use after verification
    uint64 price,
    address attestor,
    bytes32 urlHash
) external {
    // Recompute hash from provided values
    bytes32 computed = sha256(abi.encodePacked(price, attestor, urlHash));
    require(computed == packedHash, "Hash mismatch");
    
    // Verify proof with single public input
    require(verifier.verify(proof, packedHash), "Invalid proof");
    
    // Now use the verified values
    emit PriceVerified(price, attestor);
}
```

**Benefit:** 1 public input instead of N, massive gas savings.

---

## 3. Use Field Operations When Possible

**Problem:** Byte-level operations are expensive.

```noir
// Expensive: byte-by-byte comparison
for i in 0..32 {
    assert(a[i] == b[i]);
}
```

**Solution:** When comparing hashes, convert to Field first.

```noir
// Cheaper: single field comparison
let a_field = bytes_to_field(a);
let b_field = bytes_to_field(b);
assert(a_field == b_field);
```

---

## 4. Avoid Unnecessary Hashing

**Problem:** Re-hashing the same data multiple times.

**Solution:** Pass pre-computed hashes as inputs and verify once.

```noir
fn main(
    data: [u8; N],
    data_hash: [u8; 32],  // Pre-computed off-chain
) {
    // Verify hash once
    let computed = sha256_var(data, N);
    assert(computed == data_hash);
    
    // Use data_hash everywhere else (no re-hashing)
}
```

---

## 5. BoundedVec vs Fixed Arrays

**Problem:** BoundedVec has overhead for length tracking.

**Solution:** Use fixed arrays when length is known at compile time.

```noir
// If you always have exactly 32 bytes:
fn process(data: [u8; 32]) { ... }  // Cheaper

// If length varies at runtime:
fn process(data: BoundedVec<u8, 1024>) { ... }  // Use BoundedVec
```

---

## Summary

| Pattern | Savings |
|---------|---------|
| Unconstrained pack + verify reads | 100x |
| Packed public inputs | Gas proportional to # inputs |
| Field comparisons | 10-30x for hash comparisons |
| Avoid re-hashing | Depends on hash function |
