/**
 * zkTLS Attestation - ETH/USD Price from CryptoCompare
 */

import { PrimusCoreTLS } from "@primuslabs/zktls-core-sdk";
import * as fs from 'fs';

const APP_ID = process.env.PRIMUS_APP_ID;
const APP_SECRET = process.env.PRIMUS_APP_SECRET;

if (!APP_ID || !APP_SECRET) {
  console.error("Missing PRIMUS_APP_ID or PRIMUS_APP_SECRET");
  console.error("Get from Bitwarden: rbw get --full 'Primus zkTLS - zkTLS Test'");
  process.exit(1);
}

async function main() {
  console.log("=== zkTLS ETH/USD Price Attestation ===\n");

  const zkTLS = new PrimusCoreTLS();
  const initResult = await zkTLS.init(APP_ID, APP_SECRET);
  console.log("SDK initialized:", initResult.retcode === "0" ? "✓" : "✗");

  // Kraken returns: {"result":{"XETHZUSD":{"c":["2822.36000",...]}}}
  const request = {
    url: "https://api.kraken.com/0/public/Ticker?pair=ETHUSD",
    method: "GET",
    header: { "Accept": "application/json" },
    body: ""
  };

  const responseResolves = [{
    keyName: 'eth_usd_price',
    parsePath: '$.result.XETHZUSD.c[0]'
  }];

  console.log("Requesting ETH/USD price from Kraken...");

  const generateRequest = zkTLS.generateRequestParams(request, responseResolves);
  generateRequest.setAttMode({ algorithmType: "proxytls" });

  try {
    const attestation = await zkTLS.startAttestation(generateRequest);
    
    console.log("\n=== ATTESTATION ===");
    console.log(JSON.stringify(attestation, null, 2));

    const verifyResult = zkTLS.verifyAttestation(attestation);
    console.log("\nVerified:", verifyResult ? "✓" : "✗");

    if (verifyResult) {
      // Parse the attested price (comes with extra quotes: "\"2821.41000\"")
      const data = JSON.parse(attestation.data);
      let priceStr = data.eth_usd_price;
      // Remove extra quotes if present
      if (priceStr.startsWith('"') && priceStr.endsWith('"')) {
        priceStr = priceStr.slice(1, -1);
      }
      console.log("\n📊 Attested ETH/USD:", priceStr);
      
      // Convert to integer with 6 decimals (e.g., 2823.02 -> 2823020000)
      const priceFloat = parseFloat(priceStr);
      const priceU64 = Math.round(priceFloat * 1_000_000);
      console.log("   As u64 (6 decimals):", priceU64);

      // Add price info to attestation for circuit
      (attestation as any).parsedPrice = {
        raw: priceStr,
        u64_6decimals: priceU64
      };

      fs.writeFileSync('./attestation-output.json', JSON.stringify(attestation, null, 2));
      console.log("\n💾 Saved to attestation-output.json");
    }
  } catch (error) {
    console.error("Error:", error);
  }
}

main().catch(console.error);
