/**
 * zkTLS Proof Generator
 * 
 * Uses noir_js and bb.js to generate and verify proofs for zkTLS attestation verification.
 */

import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  console.log('🔐 zkTLS Proof Generator\n');

  // Load compiled circuit
  const circuitPath = path.join(__dirname, '../noir/target/zktls_verifier.json');
  
  if (!fs.existsSync(circuitPath)) {
    console.error('❌ Circuit not compiled. Run: npm run build:noir');
    process.exit(1);
  }

  console.log('📂 Loading circuit...');
  const circuitJson = JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
  console.log('  ✓ Circuit loaded\n');

  // Load Prover.toml inputs
  const proverPath = path.join(__dirname, '../noir/Prover.toml');
  
  if (!fs.existsSync(proverPath)) {
    console.error('❌ No inputs found. Run: npm run parse -- <attestation.json>');
    process.exit(1);
  }

  console.log('📂 Loading inputs from Prover.toml...');
  const proverToml = fs.readFileSync(proverPath, 'utf-8');
  
  // Parse TOML manually (simple parser for our format)
  const inputs: Record<string, any> = {};
  for (const line of proverToml.split('\n')) {
    const match = line.match(/^(\w+)\s*=\s*\[(.+)\]$/);
    if (match) {
      const key = match[1];
      const values = match[2].split(',').map(s => s.trim()).map(s => parseInt(s, 10));
      inputs[key] = values;
    }
  }
  
  console.log('  ✓ Inputs loaded');
  console.log(`    - message_hash: [${inputs.message_hash?.slice(0, 4).join(', ')}...]`);
  console.log(`    - public_key_x: [${inputs.public_key_x?.slice(0, 4).join(', ')}...]`);
  console.log(`    - public_key_y: [${inputs.public_key_y?.slice(0, 4).join(', ')}...]`);
  console.log(`    - signature: [${inputs.signature?.slice(0, 4).join(', ')}...]\n`);

  // Initialize Noir
  console.log('🔧 Initializing Noir...');
  const noir = new Noir(circuitJson);
  console.log('  ✓ Noir initialized\n');

  // Execute circuit (generate witness)
  console.log('⚙️  Executing circuit...');
  const startExec = Date.now();
  
  try {
    const { witness } = await noir.execute(inputs);
    const execTime = ((Date.now() - startExec) / 1000).toFixed(2);
    console.log(`  ✓ Witness generated (${execTime}s)\n`);

    // Initialize Barretenberg
    console.log('🔧 Initializing Barretenberg...');
    const api = await Barretenberg.new();
    console.log('  ✓ Barretenberg initialized\n');

    // Initialize UltraHonk backend
    console.log('🔧 Initializing UltraHonk backend...');
    const backend = new UltraHonkBackend(circuitJson.bytecode, api);
    console.log('  ✓ Backend initialized\n');

    // Generate proof
    console.log('🔐 Generating proof (this may take a minute)...');
    const startProve = Date.now();
    const proof = await backend.generateProof(witness);
    const proveTime = ((Date.now() - startProve) / 1000).toFixed(2);
    console.log(`  ✓ Proof generated (${proveTime}s)\n`);

    // Verify proof
    console.log('🔍 Verifying proof...');
    const startVerify = Date.now();
    const isValid = await backend.verifyProof(proof);
    const verifyTime = ((Date.now() - startVerify) / 1000).toFixed(2);
    console.log(`  ✓ Proof verified: ${isValid} (${verifyTime}s)\n`);

    // Save proof
    const proofPath = path.join(__dirname, '../noir/proof.json');
    fs.writeFileSync(proofPath, JSON.stringify({
      proof: Array.from(proof.proof),
      publicInputs: proof.publicInputs
    }, null, 2));
    console.log(`💾 Proof saved to: ${proofPath}\n`);

    // Summary
    console.log('📊 Summary:');
    console.log(`   Execution time: ${execTime}s`);
    console.log(`   Proving time: ${proveTime}s`);
    console.log(`   Verification time: ${verifyTime}s`);
    console.log(`   Proof size: ${proof.proof.length} bytes`);
    console.log(`   Valid: ${isValid ? '✅ YES' : '❌ NO'}`);

    // Cleanup
    await api.destroy();

    return isValid;
  } catch (error: any) {
    console.error('❌ Error:', error.message);
    if (error.message.includes('assertion')) {
      console.error('\n💡 The circuit assertion failed - the signature may be invalid.');
    }
    process.exit(1);
  }
}

main().catch(console.error);
