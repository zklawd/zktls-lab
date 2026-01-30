import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PrimusCoreTLS } from '@primuslabs/zktls-core-sdk';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { ethers } from 'ethers';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const NOIR_DIR = path.join(process.cwd(), 'noir');
const MAX_URL_LEN = 1024;
const MAX_CONTENT_LEN = 1000;

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

function toBoundedVec(str: string, maxLen: number): { len: number; storage: number[] } {
  const bytes = Buffer.from(str, 'utf-8');
  const storage = new Array(maxLen).fill(0);
  for (let i = 0; i < Math.min(bytes.length, maxLen); i++) {
    storage[i] = bytes[i];
  }
  return { len: bytes.length, storage };
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

function parsePrice(data: string): { raw: string; u64: number } {
  const parsed = JSON.parse(data);
  let priceStr = parsed.eth_usd_price;
  if (priceStr.startsWith('"')) priceStr = priceStr.slice(1, -1);
  const u64 = Math.round(parseFloat(priceStr) * 1_000_000);
  return { raw: priceStr, u64 };
}

function sha256Hash(data: Buffer): number[] {
  return Array.from(crypto.createHash('sha256').update(data).digest());
}

describe('zkTLS with packed public inputs', () => {
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

  it('verifies attestation with packed public inputs', async () => {
    // 1. Get attestation
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

    // 2. Build circuit inputs
    const msgHash = encodeAttestation(attestation);
    const sig = attestation.signatures[0];
    const pubKey = ethers.utils.recoverPublicKey(msgHash, sig);
    const sigBytes = hexToArray(sig);
    const pubKeyBytes = hexToArray(pubKey);

    // Attestor address
    const attestorAddr = hexToArray(attestation.attestors[0].attestorAddr);
    console.log('Attestor:', attestation.attestors[0].attestorAddr);

    // URLs
    const requestUrl = toBoundedVec(attestation.request.url, MAX_URL_LEN);
    const allowedUrl = toBoundedVec("https://api.kraken.com/", MAX_URL_LEN);

    // Response data
    const responseData = toBoundedVec(attestation.data, MAX_CONTENT_LEN);
    const dataHash = sha256Hash(Buffer.from(attestation.data));

    const inputs = {
      public_key_x: pubKeyBytes.slice(1, 33),
      public_key_y: pubKeyBytes.slice(33, 65),
      hash: hexToArray(msgHash),
      signature: sigBytes.slice(0, 64),
      request_urls: [requestUrl, requestUrl],
      allowed_urls: [allowedUrl, allowedUrl, allowedUrl],
      data_hashes: [dataHash, dataHash],
      plain_json_response_contents: [responseData, responseData],
      expected_attestor: attestorAddr,
      claimed_price: price.u64,
    };

    // 3. Execute - returns packed_inputs_hash
    const { witness, returnValue } = await noir.execute(inputs);
    console.log('✓ Circuit executed');
    console.log('  Packed inputs hash:', returnValue);

    // 4. Generate proof
    const proof = await backend.generateProof(witness);
    console.log('✓ Proof generated');

    // 5. Verify proof
    const valid = await backend.verifyProof(proof);
    console.log('✓ Proof verified:', valid);
    expect(valid).toBe(true);

    // 6. Show what on-chain verification would check
    console.log('\n📋 On-chain verification would check:');
    console.log('  - Proof is valid');
    console.log('  - Public inputs: attestor, price, packed_hash');
    console.log('  - Recompute packed_hash from (price, attestor, url_hashes)');
    console.log('  - Verify url_hashes are in allowed list');
  }, 300000);
});
