/**
 * Parse Primus zkTLS attestation into Noir circuit inputs
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

async function main() {
  const att: Attestation = JSON.parse(fs.readFileSync('./attestation-output.json', 'utf-8'));
  
  const msgHash = encodeAttestation(att);
  const sig = att.signatures[0];
  const recovered = ethers.utils.recoverAddress(msgHash, sig);
  
  console.log('Message hash:', msgHash);
  console.log('Recovered:', recovered);
  console.log('Expected:', att.attestors[0].attestorAddr);
  console.log('Match:', recovered.toLowerCase() === att.attestors[0].attestorAddr.toLowerCase());
  
  const pubKey = ethers.utils.recoverPublicKey(msgHash, sig);
  const sigBytes = hexToArray(sig);
  const pubKeyBytes = hexToArray(pubKey);
  
  // Build signature (r || s, 64 bytes - skip v)
  const signature = sigBytes.slice(0, 64);
  const pubKeyX = pubKeyBytes.slice(1, 33);
  const pubKeyY = pubKeyBytes.slice(33, 65);
  const attestorAddr = hexToArray(att.attestors[0].attestorAddr);
  
  const toml = `# Prover.toml for zkTLS Attestation
message_hash = [${hexToArray(msgHash).join(', ')}]
attestor_address = [${attestorAddr.join(', ')}]
signature = [${signature.join(', ')}]
public_key_x = [${pubKeyX.join(', ')}]
public_key_y = [${pubKeyY.join(', ')}]
`;
  
  fs.writeFileSync('./noir/Prover.toml', toml);
  console.log('\n✅ Prover.toml saved');
}

main().catch(console.error);
