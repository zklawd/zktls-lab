import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend, type ProofData } from '@aztec/bb.js';
import * as fs from 'fs';
import * as path from 'path';

const NOIR_DIR = path.join(process.cwd(), 'noir');

// Load circuit and inputs
function loadCircuit() {
  const circuitPath = path.join(NOIR_DIR, 'target', 'zktls_verifier.json');
  return JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
}

function loadInputs() {
  const tomlPath = path.join(NOIR_DIR, 'Prover.toml');
  const content = fs.readFileSync(tomlPath, 'utf-8');
  
  // Parse TOML manually (simple arrays only)
  const inputs: Record<string, any> = {};
  for (const line of content.split('\n')) {
    const match = line.match(/^(\w+)\s*=\s*\[([^\]]+)\]/);
    if (match) {
      const [, key, values] = match;
      inputs[key] = values.split(',').map(v => parseInt(v.trim()));
    }
  }
  return inputs;
}

describe('Noir circuit verification with bb.js', () => {
  let circuit: any;
  let backend: UltraHonkBackend;
  let noir: Noir;
  let validInputs: Record<string, any>;
  let validProof: ProofData;
  
  beforeAll(async () => {
    circuit = loadCircuit();
    validInputs = loadInputs();
    
    // Initialize Noir and backend
    noir = new Noir(circuit);
    backend = new UltraHonkBackend(circuit.bytecode);
  }, 30000);
  
  afterAll(async () => {
    if (backend) await backend.destroy();
  });

  it('executes circuit and returns correct price', async () => {
    const { witness, returnValue } = await noir.execute(validInputs);
    
    expect(witness).toBeInstanceOf(Uint8Array);
    expect(witness.length).toBeGreaterThan(0);
    
    // Return value should be the ETH price (2821410000)
    expect(returnValue).toBeDefined();
  }, 30000);

  it('generates valid proof', async () => {
    const { witness } = await noir.execute(validInputs);
    validProof = await backend.generateProof(witness);
    
    expect(validProof).toBeDefined();
    expect(validProof.proof).toBeInstanceOf(Uint8Array);
    expect(validProof.proof.length).toBeGreaterThan(0);
  }, 60000);

  it('verifies valid proof', async () => {
    const isValid = await backend.verifyProof(validProof);
    expect(isValid).toBe(true);
  }, 30000);

  it('rejects proof with tampered public inputs', async () => {
    // Tamper with the public inputs in the proof
    const tamperedProof: ProofData = {
      ...validProof,
      publicInputs: validProof.publicInputs.map((v, i) => 
        i === 0 ? '0x00' : v  // Tamper first public input
      )
    };
    
    const isValid = await backend.verifyProof(tamperedProof);
    expect(isValid).toBe(false);
  }, 30000);

  it('rejects execution with wrong signature', async () => {
    const badInputs = {
      ...validInputs,
      signature: validInputs.signature.map((v: number, i: number) => 
        i === 0 ? 0 : v  // Tamper first byte
      )
    };
    
    await expect(noir.execute(badInputs)).rejects.toThrow();
  }, 30000);

  it('rejects execution with wrong attestor address', async () => {
    const badInputs = {
      ...validInputs,
      attestor_address: validInputs.attestor_address.map(() => 0)
    };
    
    await expect(noir.execute(badInputs)).rejects.toThrow();
  }, 30000);

  it('rejects execution with wrong URL hash', async () => {
    const badInputs = {
      ...validInputs,
      request_url_hash: validInputs.request_url_hash.map(() => 0)
    };
    
    await expect(noir.execute(badInputs)).rejects.toThrow();
  }, 30000);
});
