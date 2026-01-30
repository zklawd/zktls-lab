import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PrimusCoreTLS } from '@primuslabs/zktls-core-sdk';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { ethers } from 'ethers';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const NOIR_DIR = path.join(process.cwd(), 'noir');
const MAX_URL_LEN = 256;
const MAX_DATA_LEN = 256;

const APP_ID = process.env.PRIMUS_APP_ID;
const APP_SECRET = process.env.PRIMUS_APP_SECRET;

function loadCircuit() {
  const circuitPath = path.join(NOIR_DIR, 'target', 'zktls_verifier.json');
  return JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
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

function encodeAttestation(att: any): string {
  const encodeRequest = (r: any) => ethers.utils.keccak256(
    ethers.utils.solidityPack(["string", "string", "string", "string"], [r.url, r.header, r.method, r.body])
  );
  const encodeResponse = (res: any[]) => {
    let data = "0x";
    for (const r of res) {
      data = ethers.utils.solidityPack(["bytes", "string", "string", "string"], [data, r.keyName, r.parseType, r.parsePath]);
    }
    return ethers.utils.keccak256(data);
  };
  return ethers.utils.keccak256(ethers.utils.solidityPack(
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

describe('zkTLS end-to-end', () => {
  let circuit: any;
  let backend: UltraHonkBackend;
  let noir: Noir;

  beforeAll(async () => {
    if (!APP_ID || !APP_SECRET) {
      throw new Error('Set PRIMUS_APP_ID and PRIMUS_APP_SECRET env vars');
    }
    circuit = loadCircuit();
    noir = new Noir(circuit);
    backend = new UltraHonkBackend(circuit.bytecode);
  }, 30000);

  afterAll(async () => {
    if (backend) await backend.destroy();
  });

  it('fetches attestation, generates proof, verifies', async () => {
    // 1. Get fresh attestation from Primus
    const zkTLS = new PrimusCoreTLS();
    await zkTLS.init(APP_ID!, APP_SECRET!);

    const request = {
      url: "https://api.kraken.com/0/public/Ticker?pair=ETHUSD",
      method: "GET",
      header: { "Accept": "application/json" },
      body: ""
    };
    const responseResolves = [{ keyName: 'eth_usd_price', parsePath: '$.result.XETHZUSD.c[0]' }];
    
    const generateRequest = zkTLS.generateRequestParams(request, responseResolves);
    generateRequest.setAttMode({ algorithmType: "proxytls" });
    
    const attestation = await zkTLS.startAttestation(generateRequest);
    const price = parsePrice(attestation.data);
    console.log('\n📊 Attested ETH/USD:', price.raw);
    
    // Verify SDK signature check passes
    expect(zkTLS.verifyAttestation(attestation)).toBe(true);

    // 2. Parse attestation into circuit inputs
    const msgHash = encodeAttestation(attestation);
    const sig = attestation.signatures[0];
    const pubKey = ethers.utils.recoverPublicKey(msgHash, sig);
    
    // SHA256 of zero-padded response
    const paddedResponse = Buffer.alloc(MAX_DATA_LEN, 0);
    Buffer.from(attestation.data).copy(paddedResponse, 0, 0, Math.min(attestation.data.length, MAX_DATA_LEN));
    const dataHash = crypto.createHash('sha256').update(paddedResponse).digest();
    
    const allowedUrl = "https://api.kraken.com/";
    const sigBytes = hexToArray(sig);
    const pubKeyBytes = hexToArray(pubKey);

    const inputs = {
      hash: hexToArray(msgHash),
      allowed_url: stringToBytes(allowedUrl, MAX_URL_LEN),
      allowed_url_len: Buffer.from(allowedUrl).length,
      data_hash: Array.from(dataHash),
      eth_usd_price: price.bytes,
      signature: sigBytes.slice(0, 64),
      public_key_x: pubKeyBytes.slice(1, 33),
      public_key_y: pubKeyBytes.slice(33, 65),
      request_url: stringToBytes(attestation.request.url, MAX_URL_LEN),
      request_url_len: Buffer.from(attestation.request.url).length,
      plain_response: stringToBytes(attestation.data, MAX_DATA_LEN),
      plain_response_len: Buffer.from(attestation.data).length,
    };

    // 3. Execute circuit
    const { witness, returnValue } = await noir.execute(inputs);
    console.log('✓ Circuit executed, price:', returnValue);
    expect(witness.length).toBeGreaterThan(0);

    // 4. Generate proof
    const proof = await backend.generateProof(witness);
    console.log('✓ Proof generated');
    expect(proof.proof.length).toBeGreaterThan(0);

    // 5. Verify proof
    const valid = await backend.verifyProof(proof);
    console.log('✓ Proof verified:', valid);
    expect(valid).toBe(true);
  }, 120000);
});
