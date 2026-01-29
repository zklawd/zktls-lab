/**
 * Parse Primus zkTLS attestation into Noir circuit inputs
 * Extracts ETH/USD price as a Field with 6 decimals
 */
import * as fs from 'fs';
import { ethers } from 'ethers';

interface Attestation {
  recipient: string;
  request: { url: string; header: string; method: string; body: string };
  reponseResolve: Array<{ keyName: string; parseType: string; parsePath: string }>;
  data: string;
  attConditions: string;
  timestamp: number;
  additionParams: string;
  attestors: Array<{ attestorAddr: string; url: string }>;
  signatures: string[];
  parsedPrice?: { raw: string; u64_6decimals: number };
}

function encodeRequest(r: Attestation['request']): string {
  return ethers.utils.keccak256(ethers.utils.solidityPack(
    ["string", "string", "string", "string"], [r.url, r.header, r.method, r.body]
  ));
}

function encodeResponse(res: Attestation['reponseResolve']): string {
  let data = "0x";
  for (const r of res) {
    data = ethers.utils.solidityPack(["bytes", "string", "string", "string"], [data, r.keyName, r.parseType, r.parsePath]);
  }
  return ethers.utils.keccak256(data);
}

function encodeAttestation(att: Attestation): string {
  return ethers.utils.keccak256(ethers.utils.solidityPack(
    ["address", "bytes32", "bytes32", "string", "string", "uint64", "string"],
    [att.recipient, encodeRequest(att.request), encodeResponse(att.reponseResolve),
     att.data, att.attConditions, att.timestamp, att.additionParams]
  ));
}

function hexToArray(hex: string): number[] {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const arr: number[] = [];
  for (let i = 0; i < h.length; i += 2) arr.push(parseInt(h.substr(i, 2), 16));
  return arr;
}

function parsePriceFromData(data: string): { raw: string; u64: number } {
  const parsed = JSON.parse(data);
  let priceStr = parsed.eth_usd_price;
  // Remove extra quotes if present
  if (priceStr.startsWith('"') && priceStr.endsWith('"')) {
    priceStr = priceStr.slice(1, -1);
  }
  const priceFloat = parseFloat(priceStr);
  const priceU64 = Math.round(priceFloat * 1_000_000);
  return { raw: priceStr, u64: priceU64 };
}

async function main() {
  const att: Attestation = JSON.parse(fs.readFileSync('./attestation-output.json', 'utf-8'));
  
  const msgHash = encodeAttestation(att);
  const sig = att.signatures[0];
  const recovered = ethers.utils.recoverAddress(msgHash, sig);
  
  console.log('=== zkTLS ETH/USD Price Attestation Parser ===\n');
  console.log('Message hash:', msgHash);
  console.log('Recovered:', recovered);
  console.log('Expected:', att.attestors[0].attestorAddr);
  console.log('Match:', recovered.toLowerCase() === att.attestors[0].attestorAddr.toLowerCase());
  
  // Parse price from attestation data
  const price = parsePriceFromData(att.data);
  console.log('\n📊 ETH/USD Price:', price.raw);
  console.log('   As u64 (6 decimals):', price.u64);
  
  const pubKey = ethers.utils.recoverPublicKey(msgHash, sig);
  const sigBytes = hexToArray(sig);
  const pubKeyBytes = hexToArray(pubKey);
  
  const signature = sigBytes.slice(0, 64);
  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);
  const attestorAddr = hexToArray(att.attestors[0].attestorAddr);
  
  // Convert price to bytes (8 bytes for u64)
  const priceBytes: number[] = [];
  let p = BigInt(price.u64);
  for (let i = 0; i < 8; i++) {
    priceBytes.unshift(Number(p & 0xFFn));
    p >>= 8n;
  }
  
  // Hash of the attested data (to verify in circuit)
  const dataHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(att.data));
  
  const toml = `# Prover.toml - zkTLS ETH/USD Price Verification
# Price: ${price.raw} USD (${price.u64} with 6 decimals)

message_hash = [${hexToArray(msgHash).join(', ')}]
attestor_address = [${attestorAddr.join(', ')}]
signature = [${signature.join(', ')}]
public_key_x = [${pubKeyX.join(', ')}]
public_key_y = [${pubKeyY.join(', ')}]
eth_usd_price = [${priceBytes.join(', ')}]
data_hash = [${hexToArray(dataHash).join(', ')}]
`;
  
  fs.writeFileSync('./noir/Prover.toml', toml);
  console.log('\n✅ Prover.toml saved');
  
  // Also save JSON
  const inputs = {
    message_hash: hexToArray(msgHash),
    attestor_address: attestorAddr,
    signature,
    public_key_x: pubKeyX,
    public_key_y: pubKeyY,
    eth_usd_price: priceBytes,
    eth_usd_price_u64: price.u64,
    data_hash: hexToArray(dataHash)
  };
  fs.writeFileSync('./noir/noir-inputs.json', JSON.stringify(inputs, null, 2));
  console.log('✅ noir-inputs.json saved');
}

main().catch(console.error);
