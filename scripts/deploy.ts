import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { ethers } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Primus attestor on Base mainnet
const PRIMUS_ATTESTOR = "0xC7276e8F5DF11B7f57Be5f5D4D8f5d5d5C5A5A5A"; // TODO: Replace with actual

async function main() {
  // Load compiled contracts
  const verifierBin = readFileSync(
    join(__dirname, "../build/contracts_ZkTLSVerifier_sol_HonkVerifier.bin"),
    "utf-8"
  );
  const verifierAbi = JSON.parse(
    readFileSync(
      join(__dirname, "../build/contracts_ZkTLSVerifier_sol_HonkVerifier.abi"),
      "utf-8"
    )
  );

  // Get provider and signer
  const rpcUrl = process.env.RPC_URL || "http://127.0.0.1:8545";
  const privateKey = process.env.PRIVATE_KEY;
  
  if (!privateKey) {
    console.log("No PRIVATE_KEY set. Deploying to local Hardhat node...");
    console.log("Start local node: npx hardhat node");
  }
  
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const signer = privateKey 
    ? new ethers.Wallet(privateKey, provider) 
    : await provider.getSigner(0);
  
  console.log(`Deploying from: ${await signer.getAddress()}`);
  
  // Deploy HonkVerifier
  console.log("Deploying HonkVerifier...");
  const VerifierFactory = new ethers.ContractFactory(verifierAbi, "0x" + verifierBin, signer);
  const verifier = await VerifierFactory.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log(`HonkVerifier deployed to: ${verifierAddress}`);
  
  // TODO: Deploy ZkTLSPriceOracle
  // const OracleFactory = new ethers.ContractFactory(oracleAbi, oracleBin, signer);
  // const oracle = await OracleFactory.deploy(verifierAddress, PRIMUS_ATTESTOR);
  // await oracle.waitForDeployment();
  // console.log(`ZkTLSPriceOracle deployed to: ${await oracle.getAddress()}`);
  
  // Save deployment info
  const deployment = {
    network: (await provider.getNetwork()).chainId.toString(),
    verifier: verifierAddress,
    deployer: await signer.getAddress(),
    timestamp: new Date().toISOString()
  };
  
  writeFileSync(
    join(__dirname, "../deployments.json"),
    JSON.stringify(deployment, null, 2)
  );
  
  console.log("Deployment saved to deployments.json");
}

main().catch(console.error);
