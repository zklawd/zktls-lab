import { UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function main() {
  console.log("Loading circuit...");
  const circuitPath = join(__dirname, "../noir/target/zktls_verifier.json");
  const circuit = JSON.parse(readFileSync(circuitPath, "utf-8"));

  console.log("Initializing UltraHonk backend...");
  const backend = new UltraHonkBackend(circuit.bytecode);
  
  console.log("Generating verification key (this may take a while for large circuits)...");
  const vk = await backend.getVerificationKey();
  
  console.log("Generating Solidity verifier contract...");
  const contract = await backend.getSolidityVerifier(vk);
  
  // Save the contract
  mkdirSync(join(__dirname, "../contracts"), { recursive: true });
  const outputPath = join(__dirname, "../contracts/ZkTLSVerifier.sol");
  writeFileSync(outputPath, contract);
  
  console.log(`Solidity verifier written to: ${outputPath}`);
  console.log(`Contract size: ${contract.length} bytes`);
  
  // Also save the VK as a JSON for reference
  const vkPath = join(__dirname, "../contracts/vk.json");
  writeFileSync(vkPath, JSON.stringify(Array.from(vk), null, 2));
  console.log(`Verification key saved to: ${vkPath}`);
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});
