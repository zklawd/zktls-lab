# zkTLS Lab

End-to-end zkTLS attestation and Noir verification pipeline using Primus Labs SDK.

## What This Does

1. **Attest** - Request zkTLS attestation from any HTTPS endpoint via Primus network
2. **Parse** - Extract signature and message hash from attestation
3. **Prove** - Generate ZK proof that attestation is valid without revealing the signature
4. **Verify** - Verify the proof on-chain or off-chain

## Quick Start

```bash
# Install dependencies
npm install

# 1. Compile Noir circuit
npm run build:noir

# 2. Generate Solidity verifier (from Noir circuit)
npm run generate:verifier

# 3. Compile Solidity contracts
npm run compile:sol

# 4. Deploy to local Hardhat node
npx hardhat node  # In another terminal
npm run deploy
```

## On-Chain Verification

The project now includes:
- `ZkTLSVerifier.sol` - UltraHonk verifier (auto-generated from Noir circuit)
- `ZkTLSPriceOracle.sol` - Wrapper contract for price attestations

### Contract Size
- `HonkVerifier`: ~23.5 KB (within 24 KB limit)
- `ZkTLSPriceOracle`: ~1.8 KB

### Deployment

```bash
# Local deployment
npm run deploy

# Testnet deployment (set env vars)
export RPC_URL="https://sepolia.base.org"
export PRIVATE_KEY="0x..."
npm run deploy
```

## Off-Chain Verification (Manual)

```bash
# Generate attestation (calls httpbin.org via Primus)
npx tsx src/attest.ts

# Parse attestation into Noir inputs
npx tsx src/parse-attestation.ts

# Execute Noir circuit (generates witness)
cd noir && nargo execute

# Generate proof with Barretenberg
bb prove -b ./target/zktls_verifier.json -w ./target/zktls_verifier.gz -o ./target/proof

# Verify proof
bb write_vk -b ./target/zktls_verifier.json -o ./target/vk
bb verify -p ./target/proof/proof -k ./target/vk/vk
```

## Credentials

App ID and Secret are stored in Bitwarden under "Primus zkTLS - zkTLS Test Project".

For local dev, set environment variables:
```bash
export PRIMUS_APP_ID="0x..."
export PRIMUS_APP_SECRET="0x..."
```

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  HTTPS API  │───▶│   Primus    │───▶│ Attestation │
│  (target)   │    │   Network   │    │   (JSON)    │
└─────────────┘    └─────────────┘    └──────┬──────┘
                                             │
                                             ▼
                   ┌─────────────┐    ┌─────────────┐
                   │    Noir     │◀───│   Parser    │
                   │   Circuit   │    │   (TS)      │
                   └──────┬──────┘    └─────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│ UltraHonk   │   │  Solidity   │   │  On-Chain   │
│   Proof     │──▶│  Verifier   │──▶│  Oracle     │
└─────────────┘   └─────────────┘   └─────────────┘
```

## Noir Circuit

The circuit verifies:
1. ECDSA secp256k1 signature over the attestation message
2. Public key → Ethereum address derivation matches attestor
3. Parses price from JSON response
4. Returns packed inputs hash for on-chain verification

Public inputs: `attestor_address`, `claimed_price`
Private inputs: `signature`, `public_key`, `response_data`, `url_info`

## Scripts

| Command | Description |
|---------|-------------|
| `npm run build:noir` | Compile Noir circuit |
| `npm run generate:verifier` | Generate Solidity verifier from circuit |
| `npm run compile:sol` | Compile Solidity contracts |
| `npm run deploy` | Deploy contracts to network |
| `npm run attest` | Request zkTLS attestation |
| `npm run parse` | Parse attestation into Noir inputs |

## Dependencies

- Node.js 22+
- nargo 1.0.0-beta.18
- @aztec/bb.js (for verifier generation)
- solc 0.8.24

## Version Compatibility

Critical version pins for working setup:
```
nargo: 1.0.0-beta.18
@noir-lang/noir_js: 1.0.0-beta.18
@aztec/bb.js: 2.1.11
```

## Created

2026-01-29 by ZKlawd
