import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import {
  encodeRequest,
  encodeResponse,
  encodeAttestation,
  verifyAttestationSignature,
  type Attestation
} from './encoding';

// Real attestation from Kraken ETH/USD (truncated signature for testing)
const REAL_ATTESTATION: Attestation = {
  recipient: "0x0000000000000000000000000000000000000000",
  request: {
    url: "https://api.kraken.com/0/public/Ticker?pair=ETHUSD",
    header: "",
    method: "GET",
    body: ""
  },
  reponseResolve: [{
    keyName: "eth_usd_price",
    parseType: "",
    parsePath: "$.result.XETHZUSD.c[0]"
  }],
  data: '{"eth_usd_price":"\\"2821.41000\\""}',
  attConditions: '[{"op":"REVEAL_STRING","field":"$.result.XETHZUSD.c[0]"}]',
  timestamp: 1769730039405,
  additionParams: '{"algorithmType":"proxytls"}',
  attestors: [{
    attestorAddr: "0xdb736b13e2f522dbe18b2015d0291e4b193d8ef6",
    url: "https://primuslabs.xyz"
  }],
  signatures: [
    "0x85bb1af028b80f5f5ab9282bc82c5e8204677ed4757c9f56ee0f63a6ebed6014280d1dc946e6f4c5f2b1c2a59514e097d8d671805092d9464b8e2b6fbd4344be1c"
  ]
};

describe('encodeRequest', () => {
  it('produces consistent hash for same input', () => {
    const hash1 = encodeRequest(REAL_ATTESTATION.request);
    const hash2 = encodeRequest(REAL_ATTESTATION.request);
    expect(hash1).toBe(hash2);
  });

  it('produces 32-byte hash', () => {
    const hash = encodeRequest(REAL_ATTESTATION.request);
    expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('different URLs produce different hashes', () => {
    const hash1 = encodeRequest(REAL_ATTESTATION.request);
    const hash2 = encodeRequest({
      ...REAL_ATTESTATION.request,
      url: "https://different.api.com"
    });
    expect(hash1).not.toBe(hash2);
  });
});

describe('encodeResponse', () => {
  it('handles single response resolve', () => {
    const hash = encodeResponse(REAL_ATTESTATION.reponseResolve);
    expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('handles multiple response resolves', () => {
    const multiResolve = [
      { keyName: "price", parseType: "", parsePath: "$.price" },
      { keyName: "volume", parseType: "", parsePath: "$.volume" }
    ];
    const hash = encodeResponse(multiResolve);
    expect(hash).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('order matters for multiple resolves', () => {
    const resolve1 = [
      { keyName: "a", parseType: "", parsePath: "$.a" },
      { keyName: "b", parseType: "", parsePath: "$.b" }
    ];
    const resolve2 = [
      { keyName: "b", parseType: "", parsePath: "$.b" },
      { keyName: "a", parseType: "", parsePath: "$.a" }
    ];
    expect(encodeResponse(resolve1)).not.toBe(encodeResponse(resolve2));
  });
});

describe('encodeAttestation', () => {
  it('produces deterministic hash', () => {
    const hash1 = encodeAttestation(REAL_ATTESTATION);
    const hash2 = encodeAttestation(REAL_ATTESTATION);
    expect(hash1).toBe(hash2);
  });

  it('matches signature recovery', () => {
    // This is the critical test - if encoding doesn't match SDK,
    // signature verification will fail
    const result = verifyAttestationSignature(REAL_ATTESTATION);
    expect(result.valid).toBe(true);
    expect(result.recoveredAddress.toLowerCase()).toBe(
      REAL_ATTESTATION.attestors[0].attestorAddr.toLowerCase()
    );
  });
});

describe('verifyAttestationSignature', () => {
  it('returns valid for real attestation', () => {
    const result = verifyAttestationSignature(REAL_ATTESTATION);
    expect(result.valid).toBe(true);
  });

  it('returns invalid for tampered data', () => {
    const tampered = {
      ...REAL_ATTESTATION,
      data: '{"eth_usd_price":"9999.99"}'  // Changed price
    };
    const result = verifyAttestationSignature(tampered);
    expect(result.valid).toBe(false);
  });

  it('returns invalid for tampered timestamp', () => {
    const tampered = {
      ...REAL_ATTESTATION,
      timestamp: 1234567890  // Changed timestamp
    };
    const result = verifyAttestationSignature(tampered);
    expect(result.valid).toBe(false);
  });

  it('returns invalid for wrong attestor address', () => {
    const tampered = {
      ...REAL_ATTESTATION,
      attestors: [{
        attestorAddr: "0x1111111111111111111111111111111111111111",
        url: "https://fake.xyz"
      }]
    };
    const result = verifyAttestationSignature(tampered);
    expect(result.valid).toBe(false);
  });
});
