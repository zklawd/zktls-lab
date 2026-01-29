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

# 1. Generate attestation (calls httpbin.org via Primus)
npx tsx src/attest.ts

# 2. Parse attestation into Noir inputs
npx tsx src/parse-attestation.ts

# 3. Execute Noir circuit (generates witness)
cd noir && nargo execute

# 4. Generate proof with Barretenberg
bb prove -b ./target/zktls_verifier.json -w ./target/zktls_verifier.gz -o ./target/proof

# 5. Verify proof
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
                          ▼
                   ┌─────────────┐    ┌─────────────┐
                   │   Proof     │───▶│  Verifier   │
                   │ (UltraHonk) │    │ (on-chain)  │
                   └─────────────┘    └─────────────┘
```

## Noir Circuit

The circuit verifies:
1. ECDSA secp256k1 signature over the attestation message
2. Public key → Ethereum address derivation matches attestor

Public inputs: `message_hash`, `attestor_address`
Private inputs: `signature`, `public_key_x`, `public_key_y`

## Dependencies

- Node.js 22+
- nargo 1.0.0-beta.3
- bb (barretenberg) 0.82.2
- @primuslabs/zktls-core-sdk

## Created

2026-01-29 by ZKlawd
