import { expect } from "chai";
import hre from "hardhat";
import { readFileSync } from "fs";

const { ethers } = hre;

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Encode attestation exactly like Primus contracts
function encodeAttestationHash(att) {
  const requestHash = ethers.keccak256(
    ethers.solidityPacked(
      ["string", "string", "string", "string"],
      [att.request.url, att.request.header, att.request.method, att.request.body]
    )
  );
  
  let responseData = "0x";
  for (const r of att.reponseResolve) {
    responseData = ethers.concat([
      responseData,
      ethers.toUtf8Bytes(r.keyName),
      ethers.toUtf8Bytes(r.parseType),
      ethers.toUtf8Bytes(r.parsePath)
    ]);
  }
  const responseHash = ethers.keccak256(responseData);
  
  const encoded = ethers.solidityPacked(
    ["address", "bytes32", "bytes32", "string", "string", "uint64", "string"],
    [att.recipient, requestHash, responseHash, att.data, att.attConditions, att.timestamp, att.additionParams]
  );
  
  return ethers.keccak256(encoded);
}

describe("Simple Price Oracle (e2e)", function () {
  this.timeout(180000);

  it("proves attestation and verifies on-chain", async function () {
    // Load attestation
    const att = JSON.parse(readFileSync("./attestation-output.json", "utf-8"));
    console.log("📄 Price:", att.parsedPrice.raw, "USD");

    // Compute message hash
    const messageHashHex = encodeAttestationHash(att);
    console.log("📝 Message hash:", messageHashHex);

    // Recover public key from signature
    const pubkeyHex = ethers.SigningKey.recoverPublicKey(messageHashHex, att.signatures[0]);
    const pubkeyBytes = hexToBytes(pubkeyHex.slice(4)); // Remove 0x04
    const pub_x = Array.from(pubkeyBytes.slice(0, 32));
    const pub_y = Array.from(pubkeyBytes.slice(32, 64));

    // Verify recovered address matches attestor
    const recoveredAddr = ethers.recoverAddress(messageHashHex, att.signatures[0]);
    console.log("📝 Recovered:", recoveredAddr);
    console.log("📝 Expected:", att.attestors[0].attestorAddr);
    expect(recoveredAddr.toLowerCase()).to.eq(att.attestors[0].attestorAddr.toLowerCase());

    // Load circuit
    const { noir, backend } = await hre.noir.getCircuit("simple_price");
    console.log("🔧 Backend:", backend.constructor.name);

    // Build inputs
    const input = {
      pub_x,
      pub_y,
      message_hash: Array.from(hexToBytes(messageHashHex)),
      expected_attestor: Array.from(hexToBytes(att.attestors[0].attestorAddr)),
      price_cents: Math.floor(parseFloat(att.parsedPrice.raw) * 100).toString(),
    };
    console.log("💰 Price cents:", input.price_cents);

    // Generate witness
    console.log("📝 Generating witness...");
    const { witness } = await noir.execute(input);
    console.log("✅ Witness generated");

    // Generate proof
    console.log("🔐 Generating proof...");
    const { proof, publicInputs } = await backend.generateProof(witness, { keccak: true });
    console.log("✅ Proof size:", proof.length, "bytes");
    console.log("📤 Public inputs:", publicInputs);

    // Verify in JS
    console.log("🔍 Verifying in JS...");
    const validJs = await backend.verifyProof({ proof, publicInputs }, { keccak: true });
    expect(validJs).to.be.true;
    console.log("✅ JS verification passed");

    // Deploy verifier
    console.log("📦 Deploying verifier...");
    const Verifier = await ethers.getContractFactory("noir/target/simple_price.sol:HonkVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    console.log("✅ Deployed at:", await verifier.getAddress());

    // Verify on-chain
    const publicInputsBytes32 = publicInputs.map(pi => 
      ethers.zeroPadValue(ethers.toBeHex(BigInt(pi)), 32)
    );
    console.log("⛓️ Verifying on-chain...");
    const validOnChain = await verifier.verify(proof, publicInputsBytes32);
    expect(validOnChain).to.be.true;
    console.log("🎉 ON-CHAIN VERIFICATION PASSED!");
    console.log("");
    console.log("=== SUMMARY ===");
    console.log("ETH/USD Price: $" + att.parsedPrice.raw);
    console.log("Attestor:", att.attestors[0].attestorAddr);
    console.log("Proof verified on-chain ✓");
  });
});
