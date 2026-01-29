/**
 * zkTLS Attestation Generator
 * 
 * Generates a zkTLS attestation for a public API endpoint using Primus Core SDK.
 * The attestation can then be verified with a Noir circuit.
 */

import { PrimusCoreTLS } from '@primuslabs/zktls-core-sdk';
import * as fs from 'fs';
import * as path from 'path';

// Configuration - set via environment variables
const APP_ID = process.env.PRIMUS_APP_ID;
const APP_SECRET = process.env.PRIMUS_APP_SECRET;
const USER_ADDRESS = process.env.USER_ADDRESS || '0x0000000000000000000000000000000000000000';

// Target API - CoinGecko public endpoint (no auth required)
const TARGET_REQUEST = {
  url: 'https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd',
  method: 'GET',
  header: '',
  body: ''
};

// What to extract from the response
// Response format: {"ethereum":{"usd":3456.78}}
const RESPONSE_RESOLVES = [
  {
    keyName: 'eth_price_usd',
    parsePath: '$.ethereum.usd'
  }
];

async function main() {
  console.log('🔐 zkTLS Attestation Generator\n');

  // Validate credentials
  if (!APP_ID || !APP_SECRET) {
    console.error('❌ Missing credentials!');
    console.error('Set PRIMUS_APP_ID and PRIMUS_APP_SECRET environment variables.');
    console.error('\nGet credentials from: https://dev.primuslabs.xyz');
    process.exit(1);
  }

  console.log('📋 Configuration:');
  console.log(`   App ID: ${APP_ID.substring(0, 8)}...`);
  console.log(`   Target: ${TARGET_REQUEST.url}`);
  console.log(`   Extract: ${RESPONSE_RESOLVES.map(r => r.keyName).join(', ')}\n`);

  // Initialize SDK
  console.log('🚀 Initializing Primus Core SDK...');
  const primus = new PrimusCoreTLS();
  
  try {
    await primus.init(APP_ID, APP_SECRET);
    console.log('✅ SDK initialized\n');
  } catch (error) {
    console.error('❌ Failed to initialize SDK:', error);
    process.exit(1);
  }

  // Generate attestation request
  console.log('📝 Generating attestation request...');
  const attRequest = primus.generateRequestParams(
    TARGET_REQUEST,
    RESPONSE_RESOLVES,
    USER_ADDRESS
  );

  // Set attestation mode (proxy is faster, mpc is more secure)
  attRequest.setAttMode({ algorithmType: 'proxytls' });
  
  console.log('✅ Request generated\n');
  console.log('Request:', JSON.stringify(JSON.parse(attRequest.toJsonString()), null, 2), '\n');

  // Start attestation
  console.log('⏳ Starting attestation (this may take 30-60 seconds)...');
  const startTime = Date.now();
  
  try {
    const attestation = await primus.startAttestation(attRequest, 120000); // 2 min timeout
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    
    console.log(`✅ Attestation complete! (${elapsed}s)\n`);
    
    // Verify the attestation locally
    console.log('🔍 Verifying attestation signature...');
    const isValid = primus.verifyAttestation(attestation);
    console.log(`✅ Signature valid: ${isValid}\n`);

    // Save attestation to file
    const filename = `attestation_${Date.now()}.json`;
    const filepath = path.join(process.cwd(), 'attestations', filename);
    
    fs.writeFileSync(filepath, JSON.stringify(attestation, null, 2));
    console.log(`💾 Saved to: ${filepath}\n`);

    // Print summary
    console.log('📊 Attestation Summary:');
    console.log(`   Recipient: ${attestation.recipient}`);
    console.log(`   Timestamp: ${new Date(attestation.timestamp).toISOString()}`);
    console.log(`   Attestor: ${attestation.attestors?.[0]?.attestorAddr || 'N/A'}`);
    console.log(`   Data: ${JSON.stringify(attestation.data || attestation.reponseResolve)}`);

    return attestation;
  } catch (error: any) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.error(`❌ Attestation failed after ${elapsed}s:`, error.message || error);
    
    if (error.code) {
      console.error(`   Error code: ${error.code}`);
    }
    
    process.exit(1);
  }
}

main().catch(console.error);
