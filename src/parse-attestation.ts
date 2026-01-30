/**
 * Parse Primus zkTLS attestation into Noir circuit inputs
 * Compatible with verify_attestation_hashing pattern
 * Updated for ethers v6
 */
import * as fs from 'fs';
import { ethers, SigningKey } from 'ethers';
import * as crypto from 'crypto';

const MAX_URL_LEN = 256;
const MAX_DATA_LEN = 256;

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
}

function hexToArray(hex: string): number[] {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const arr: number[] = [];
  for (let i = 0; i < h.length; i += 2) arr.push(parseInt(h.substr(i, 2), 16));
  return arr;
}

function stringToBytes(str: string, maxLen: number): number[] {
  const bytes = Buffer.from(str, 'utf-8');
  const padded = new Array(maxLen).fill(0);
  for (let i = 0; i < Math.min(bytes.length, maxLen); i++) {
    padded[i] = bytes[i];
  }
  return padded;
}

function encodeAttestation(att: Attestation): string {
  const encodeRequest = (r: any) => ethers.keccak256(
    ethers.solidityPacked(["string", "string", "string", "string"], [r.url, r.header, r.method, r.body])
  );
  const encodeResponse = (res: any[]) => {
    let data = "0x";
    for (const r of res) {
      data = ethers.solidityPacked(["bytes", "string", "string", "string"], [data, r.keyName, r.parseType, r.parsePath]);
    }
    return ethers.keccak256(data);
  };
  return ethers.keccak256(ethers.solidityPacked(
    ["address", "bytes32", "bytes32", "string", "string", "uint64", "string"],
    [att.recipient, encodeRequest(att.request), encodeResponse(att.reponseResolve),
     att.data, att.attConditions, att.timestamp, att.additionParams]
  ));
}

function parsePrice(data: string): { raw: string; u64: number; bytes: number[] } {
  const parsed = JSON.parse(data);
  let priceStr = parsed.eth_usd_price;
  if (priceStr.startsWith('"')) priceStr = priceStr.slice(1, -1);
  const u64 = Math.round(parseFloat(priceStr) * 1_000_000);
  const bytes: number[] = [];
  let v = BigInt(u64);
  for (let i = 0; i < 8; i++) { bytes.unshift(Number(v & 0xFFn)); v >>= 8n; }
  return { raw: priceStr, u64, bytes };
}

async function main() {
  const att: Attestation = JSON.parse(fs.readFileSync('./attestation-output.json', 'utf-8'));
  
  console.log('=== zkTLS Attestation Parser ===\n');
  
  // Compute hashes
  const msgHash = encodeAttestation(att);
  const sig = att.signatures[0];
  
  // ethers v6: recoverPublicKey is on SigningKey
  const pubKey = SigningKey.recoverPublicKey(msgHash, sig);
  
  // Verify signature
  const recovered = ethers.recoverAddress(msgHash, sig);
  console.log('Attestor:', att.attestors[0].attestorAddr);
  console.log('Recovered:', recovered);
  console.log('Match:', recovered.toLowerCase() === att.attestors[0].attestorAddr.toLowerCase());
  
  // Parse price
  const price = parsePrice(att.data);
  console.log('\n📊 ETH/USD:', price.raw, '→', price.u64);
  
  // SHA256 of zero-padded response (matches Noir circuit)
  const paddedResponse = Buffer.alloc(MAX_DATA_LEN, 0);
  Buffer.from(att.data).copy(paddedResponse, 0, 0, Math.min(att.data.length, MAX_DATA_LEN));
  const dataHash = crypto.createHash('sha256').update(paddedResponse).digest();
  console.log('Data SHA256 (padded):', dataHash.toString('hex'));
  
  // URL
  const requestUrl = att.request.url;
  const allowedUrl = "https://api.kraken.com/"; // Prefix we allow
  console.log('Request URL:', requestUrl);
  console.log('Allowed prefix:', allowedUrl);
  
  const sigBytes = hexToArray(sig);
  const pubKeyBytes = hexToArray(pubKey);

  const toml = `# Prover.toml - zkTLS ETH/USD Price (${price.raw})

# Public inputs
hash = [${hexToArray(msgHash).join(', ')}]
allowed_url = [${stringToBytes(allowedUrl, MAX_URL_LEN).join(', ')}]
allowed_url_len = ${Buffer.from(allowedUrl).length}
data_hash = [${Array.from(dataHash).join(', ')}]
eth_usd_price = [${price.bytes.join(', ')}]

# Private inputs
signature = [${sigBytes.slice(0, 64).join(', ')}]
public_key_x = [${pubKeyBytes.slice(1, 33).join(', ')}]
public_key_y = [${pubKeyBytes.slice(33, 65).join(', ')}]
request_url = [${stringToBytes(requestUrl, MAX_URL_LEN).join(', ')}]
request_url_len = ${Buffer.from(requestUrl).length}
plain_response = [${stringToBytes(att.data, MAX_DATA_LEN).join(', ')}]
plain_response_len = ${Buffer.from(att.data).length}
`;
  
  fs.writeFileSync('./noir/Prover.toml', toml);
  console.log('\n✅ Prover.toml saved');
}

main().catch(console.error);
