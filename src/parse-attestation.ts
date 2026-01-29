/**
 * Parse Attestation to Noir Inputs
 * 
 * Converts a Primus zkTLS attestation JSON to Noir circuit inputs (Prover.toml).
 * The circuit then proves the attestation signature is valid.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';

interface Attestation {
  recipient: string;
  request: {
    url: string;
    header: string;
    method: string;
    body: string;
  } | Array<{
    url: string;
    header: string;
    method: string;
    body: string;
  }>;
  reponseResolve?: Array<{
    keyName: string;
    parseType: string;
    parsePath: string;
  }>;
  responseResolves?: Array<{
    oneUrlResponseResolve: Array<{
      keyName: string;
      parseType: string;
      parsePath: string;
    }>;
  }>;
  data: string;
  attConditions: string;
  timestamp: number;
  additionParams: string;
  attestors: Array<{
    attestorAddr: string;
    url: string;
  }>;
  signatures: string[];
}

/**
 * Encode attestation data for hashing (matches Primus SDK)
 */
function encodeAttestation(attestation: Attestation): Uint8Array {
  const abiCoder = new ethers.utils.AbiCoder();

  // Handle single vs multiple requests
  const requests = Array.isArray(attestation.request) 
    ? attestation.request 
    : [attestation.request];
  
  const requestUrls = requests.map(r => r.url);
  const requestHeaders = requests.map(r => r.header);
  const requestMethods = requests.map(r => r.method);
  const requestBodies = requests.map(r => r.body);

  // Encode the attestation data
  const encoded = abiCoder.encode(
    ['address', 'string[]', 'string[]', 'string[]', 'string[]', 'string', 'string', 'uint256', 'string'],
    [
      attestation.recipient,
      requestUrls,
      requestHeaders,
      requestMethods,
      requestBodies,
      attestation.data,
      attestation.attConditions,
      attestation.timestamp,
      attestation.additionParams
    ]
  );

  return ethers.utils.arrayify(ethers.utils.keccak256(encoded));
}

/**
 * Parse signature and recover public key
 */
function parseSignature(signature: string, messageHash: Uint8Array): {
  r: string;
  s: string;
  v: number;
  publicKeyX: number[];
  publicKeyY: number[];
  signatureBytes: number[];
} {
  // Parse the signature
  const sig = ethers.utils.splitSignature(signature);
  
  // Recover the public key
  const recoveredAddress = ethers.utils.recoverAddress(messageHash, signature);
  const recoveredPubKey = ethers.utils.recoverPublicKey(messageHash, signature);
  
  // Public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
  const pubKeyBytes = ethers.utils.arrayify(recoveredPubKey);
  const publicKeyX = Array.from(pubKeyBytes.slice(1, 33));
  const publicKeyY = Array.from(pubKeyBytes.slice(33, 65));
  
  // Signature for Noir: r (32 bytes) || s (32 bytes)
  const rBytes = ethers.utils.arrayify(ethers.utils.hexZeroPad(sig.r, 32));
  const sBytes = ethers.utils.arrayify(ethers.utils.hexZeroPad(sig.s, 32));
  const signatureBytes = [...Array.from(rBytes), ...Array.from(sBytes)];

  console.log(`  Recovered address: ${recoveredAddress}`);
  
  return {
    r: sig.r,
    s: sig.s,
    v: sig.v,
    publicKeyX,
    publicKeyY,
    signatureBytes
  };
}

/**
 * Format array for TOML
 */
function formatTomlArray(arr: number[]): string {
  return `[${arr.join(', ')}]`;
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length < 1) {
    console.log('Usage: tsx parse-attestation.ts <attestation.json> [output-dir]');
    console.log('\nConverts attestation JSON to Noir circuit inputs (Prover.toml)');
    process.exit(1);
  }

  const inputFile = args[0];
  const outputDir = args[1] || path.join(process.cwd(), 'noir');

  console.log('🔐 Attestation to Noir Input Converter\n');

  // Read attestation file
  console.log(`📂 Reading: ${inputFile}`);
  const rawData = fs.readFileSync(inputFile, 'utf-8');
  const attestationFile = JSON.parse(rawData);

  // Handle different attestation formats
  let attestation: Attestation;
  if (attestationFile.public_data) {
    // Format with public_data wrapper
    if (Array.isArray(attestationFile.public_data)) {
      attestation = attestationFile.public_data[0].attestation || attestationFile.public_data[0];
    } else {
      attestation = attestationFile.public_data.attestation || attestationFile.public_data;
    }
    // Get signature from public_data if not in attestation
    if (!attestation.signatures && attestationFile.public_data[0]?.signature) {
      attestation.signatures = [attestationFile.public_data[0].signature];
    }
  } else {
    attestation = attestationFile;
  }

  console.log(`  Recipient: ${attestation.recipient}`);
  console.log(`  Timestamp: ${new Date(attestation.timestamp).toISOString()}`);
  
  // Compute message hash
  console.log('\n📊 Computing message hash...');
  const messageHash = encodeAttestation(attestation);
  console.log(`  Hash: 0x${Buffer.from(messageHash).toString('hex')}`);

  // Parse signature
  console.log('\n🔑 Parsing signature...');
  const signature = attestation.signatures[0];
  const sigData = parseSignature(signature, messageHash);

  // Generate Prover.toml content
  console.log('\n📝 Generating Prover.toml...');
  
  const proverToml = `# Auto-generated from attestation
# Source: ${inputFile}
# Generated: ${new Date().toISOString()}

# Public inputs
message_hash = ${formatTomlArray(Array.from(messageHash))}
public_key_x = ${formatTomlArray(sigData.publicKeyX)}
public_key_y = ${formatTomlArray(sigData.publicKeyY)}

# Private inputs  
signature = ${formatTomlArray(sigData.signatureBytes)}
`;

  const outputFile = path.join(outputDir, 'Prover.toml');
  fs.writeFileSync(outputFile, proverToml);
  console.log(`  Written to: ${outputFile}`);

  // Summary
  console.log('\n✅ Conversion complete!');
  console.log('\nNext steps:');
  console.log('  1. cd noir');
  console.log('  2. nargo prove');
  console.log('  3. nargo verify');

  return {
    messageHash: Array.from(messageHash),
    publicKeyX: sigData.publicKeyX,
    publicKeyY: sigData.publicKeyY,
    signature: sigData.signatureBytes
  };
}

main().catch(console.error);
