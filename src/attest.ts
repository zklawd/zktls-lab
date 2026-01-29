/**
 * zkTLS Attestation - Using Primus SDK to generate attestations
 * 
 * Project: zkTLS Test
 * Created: 2026-01-29
 */

import { PrimusCoreTLS } from "@primuslabs/zktls-core-sdk";

// Credentials from Primus Developer Hub (Backend Project)
// Store in Bitwarden: "Primus zkTLS - zkTLS Test"
const APP_ID = process.env.PRIMUS_APP_ID;
const APP_SECRET = process.env.PRIMUS_APP_SECRET;

if (!APP_ID || !APP_SECRET) {
  console.error("Missing PRIMUS_APP_ID or PRIMUS_APP_SECRET environment variables");
  console.error("Get them from Bitwarden: rbw get --full 'Primus zkTLS - zkTLS Test'");
  process.exit(1);
}

async function main() {
  console.log("=== Primus zkTLS Attestation Demo ===\n");

  // Initialize the SDK
  console.log("1. Initializing PrimusCoreTLS...");
  const zkTLS = new PrimusCoreTLS();
  const initResult = await zkTLS.init(APP_ID, APP_SECRET);
  console.log("   Init result:", initResult);

  // Set up request to a public API
  // Using httpbin.org for reliable testing
  const request = {
    url: "https://httpbin.org/json",
    method: "GET",
    header: {
      "Accept": "application/json"
    },
    body: ""
  };

  // Define what we want to prove about the response
  // httpbin returns: { "slideshow": { "author": "...", "title": "..." } }
  const responseResolves = [
    {
      keyName: 'slideshow_title',
      parsePath: '$.slideshow.title'
    }
  ];

  console.log("\n2. Configuring attestation request...");
  console.log("   URL:", request.url);
  console.log("   Extracting:", responseResolves[0].parsePath);

  // Generate attestation request
  const generateRequest = zkTLS.generateRequestParams(request, responseResolves);

  // Set zkTLS mode (proxy mode is the default)
  generateRequest.setAttMode({
    algorithmType: "proxytls"
  });

  console.log("\n3. Starting attestation process...");
  console.log("   (This may take a moment...)\n");

  try {
    // Start attestation - this contacts Primus network
    const attestation = await zkTLS.startAttestation(generateRequest);
    
    console.log("=== ATTESTATION RECEIVED ===");
    console.log(JSON.stringify(attestation, null, 2));

    // Verify the attestation
    console.log("\n4. Verifying attestation...");
    const verifyResult = zkTLS.verifyAttestation(attestation);
    console.log("   Verification result:", verifyResult);

    if (verifyResult === true) {
      console.log("\n✅ SUCCESS: Attestation verified!");
      
      // Extract the attested data
      if (attestation.data?.response) {
        console.log("\n📊 Attested Data:");
        console.log("   ETH/USD price:", attestation.data.response.ethereum_usd_price);
      }

      // Save attestation for later use with Noir circuit
      const fs = await import('fs');
      const outputPath = './attestation-output.json';
      fs.writeFileSync(outputPath, JSON.stringify(attestation, null, 2));
      console.log(`\n💾 Attestation saved to: ${outputPath}`);

    } else {
      console.log("\n❌ FAILED: Attestation verification failed");
    }

  } catch (error) {
    console.error("\n❌ Error during attestation:", error);
    throw error;
  }
}

main().catch(console.error);
