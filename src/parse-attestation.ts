/**
 * Parse Primus zkTLS attestation into Noir circuit inputs
 * Includes URL hash and data hash for security binding
 */
import * as fs from 'fs';
import { ethers } from 'ethers';
import { Attestation, encodeAttestation, verifyAttestationSignature } from './lib/encoding';
import { parsePrice } from './lib/price';

function hexToArray(hex: string): number[] {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const arr: number[] = [];
  for (let i = 0; i < h.length; i += 2) arr.push(parseInt(h.substr(i, 2), 16));
  return arr;
}

async function main() {
  const att: Attestation = JSON.parse(fs.readFileSync('./attestation-output.json', 'utf-8'));
  
  console.log('=== zkTLS ETH/USD Price Attestation Parser ===\n');
  
  // Verify signature
  const sigResult = verifyAttestationSignature(att);
  console.log('Signature valid:', sigResult.valid);
  if (!sigResult.valid) {
    console.error('FATAL: Signature verification failed!');
    process.exit(1);
  }
  
  // Parse price
  const data = JSON.parse(att.data);
  const price = parsePrice(data.eth_usd_price);
  console.log('\n📊 ETH/USD Price:', price.raw);
  console.log('   As u64 (6 decimals):', price.u64);
  
  // Compute hashes
  const msgHash = encodeAttestation(att);
  const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(att.data));
  const urlHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(att.request.url));
  
  // For this example, allowed URL = request URL (in production, use a prefix)
  const allowedUrlHash = urlHash;
  
  console.log('\nMessage hash:', msgHash);
  console.log('Data hash:', dataHash);
  console.log('URL hash:', urlHash);
  
  // Get public key
  const sig = att.signatures[0];
  const pubKey = ethers.utils.recoverPublicKey(msgHash, sig);
  const sigBytes = hexToArray(sig);
  const pubKeyBytes = hexToArray(pubKey);
  
  const signature = sigBytes.slice(0, 64);
  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);
  const attestorAddr = hexToArray(att.attestors[0].attestorAddr);
  
  const toml = `# Prover.toml - zkTLS ETH/USD Price Verification
# Price: ${price.raw} USD (${price.u64} with 6 decimals)
# URL: ${att.request.url}

# Public inputs
message_hash = [${hexToArray(msgHash).join(', ')}]
attestor_address = [${attestorAddr.join(', ')}]
allowed_url_hash = [${hexToArray(allowedUrlHash).join(', ')}]
data_hash = [${hexToArray(dataHash).join(', ')}]
eth_usd_price = [${price.bytes.join(', ')}]

# Private inputs
signature = [${signature.join(', ')}]
public_key_x = [${pubKeyX.join(', ')}]
public_key_y = [${pubKeyY.join(', ')}]
request_url_hash = [${hexToArray(urlHash).join(', ')}]
`;
  
  fs.writeFileSync('./noir/Prover.toml', toml);
  console.log('\n✅ Prover.toml saved');
}

main().catch(console.error);
