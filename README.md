# zktls-lab 🛡️

**Proving web data authenticity with zkTLS + Noir circuits.**

This repo demonstrates end-to-end zkTLS attestation verification using Primus Labs attestations and Noir zero-knowledge circuits - no Solidity required.

## What It Does

1. **Parse** a Primus zkTLS attestation JSON
2. **Execute** a Noir circuit that verifies the ECDSA secp256k1 signature
3. **Generate** a ZK proof that the signature is valid
4. **Verify** the proof

## Quick Start

```bash
# Install dependencies
npm install

# Parse an attestation (converts to Noir inputs)
npm run parse -- /path/to/attestation.json

# Generate and verify proof
npm run prove
```

## Project Structure

```
├── src/
│   ├── attest.ts           # Generate attestations via Primus Core SDK
│   ├── parse-attestation.ts # Convert attestation JSON → Noir inputs
│   └── prove.ts            # Generate ZK proof with noir_js + bb.js
├── noir/
│   ├── src/main.nr         # Noir circuit for signature verification
│   ├── Prover.toml         # Circuit inputs (auto-generated)
│   └── proof.json          # Generated proof (after running)
├── attestations/           # Store attestation JSON files here
└── README.md
```

## How It Works

### 1. Attestation Format

Primus zkTLS attestations contain:
- `recipient` - The user address
- `request` - The HTTP request (URL, method, headers)
- `data` - Encrypted/hashed response data
- `timestamp` - When the attestation was created
- `signatures` - ECDSA signatures from Primus attestors

### 2. Verification Circuit

The Noir circuit (`noir/src/main.nr`) verifies:
```noir
// Verify the attestation signature
let is_valid = std::ecdsa_secp256k1::verify_signature(
    public_key_x,
    public_key_y,
    signature,
    message_hash
);
assert(is_valid, "Invalid attestation signature");
```

### 3. Proof Generation

Using `@noir-lang/noir_js` and `@aztec/bb.js`:
1. Execute circuit to generate witness
2. Generate UltraHonk proof
3. Verify proof locally

## Example Output

```
🔐 zkTLS Proof Generator

📂 Loading circuit...
  ✓ Circuit loaded

📂 Loading inputs from Prover.toml...
  ✓ Inputs loaded
    - message_hash: [231, 122, 90, 4...]
    - public_key_x: [192, 253, 27, 101...]
    - signature: [81, 219, 154, 200...]

🔧 Initializing Noir...
  ✓ Noir initialized

⚙️  Executing circuit...
  ✓ Witness generated (0.04s)

🔧 Initializing Barretenberg...
  ✓ Barretenberg initialized

🔐 Generating proof (this may take a minute)...
  ✓ Proof generated (5.47s)

🔍 Verifying proof...
  ✓ Proof verified: true (0.94s)

📊 Summary:
   Execution time: 0.04s
   Proving time: 5.47s
   Verification time: 0.94s
   Proof size: 14308 bytes
   Valid: ✅ YES
```

## Version Compatibility

These versions work together:
- `nargo`: 1.0.0-beta.0
- `@noir-lang/noir_js`: 1.0.0-beta.0
- `@aztec/bb.js`: 0.63.1

Install nargo with: `noirup -v 1.0.0-beta.0`

## Getting Live Attestations

To generate real attestations (not just verify example data):

### 1. Get Primus Developer Hub Credentials

1. Go to https://dev.primuslabs.xyz
2. Connect wallet (MetaMask, etc.)
3. Click "New Backend Project"
4. Save your `appId` and `appSecret` (shown only once!)

### 2. Set Environment Variables

```bash
export PRIMUS_APP_ID="your-app-id"
export PRIMUS_APP_SECRET="your-app-secret"
```

### 3. Generate Attestation

```bash
npm run attest
```

This will:
- Hit a public API (CoinGecko ETH price by default)
- Generate a zkTLS attestation through Primus
- Save the attestation JSON to `attestations/`

### 4. Verify with Noir

```bash
npm run parse -- attestations/attestation_*.json
npm run prove
```

## Next Steps

- [ ] Get Primus Developer Hub credentials (requires wallet)
- [ ] Generate live attestation from public API
- [ ] Add URL allowlist verification in circuit
- [ ] Add JSON parsing in circuit for response data
- [ ] Deploy verifier to EVM chains

## References

- [Primus Labs Docs](https://docs.primuslabs.xyz)
- [Primus zkTLS Noir Verifier](https://github.com/primus-labs/zktls-verification-noir)
- [Noir Documentation](https://noir-lang.org)
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)

---

Built by [@zklawd](https://x.com/zklawd) 🛡️
