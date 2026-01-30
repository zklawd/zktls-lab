import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;

describe("Simple ZK Flow (e2e)", function () {
  this.timeout(120000);

  it("proves x != y and verifies on-chain", async function () {
    // 1. Load circuit
    console.log("🔧 Loading circuit...");
    const { noir, backend } = await hre.noir.getCircuit("simple_test");
    console.log("✅ Backend:", backend.constructor.name);

    // 2. Generate witness
    const input = { x: 1, y: 2 };
    console.log("📝 Generating witness for x=1, y=2...");
    const { witness } = await noir.execute(input);
    console.log("✅ Witness generated");

    // 3. Generate proof
    console.log("🔐 Generating proof...");
    const { proof, publicInputs } = await backend.generateProof(witness, { keccak: true });
    console.log("✅ Proof size:", proof.length, "bytes");
    console.log("📤 Public inputs:", publicInputs);
    expect(BigInt(publicInputs[0])).to.eq(BigInt(input.y));

    // 4. Verify in JS
    console.log("🔍 Verifying in JS...");
    const validJs = await backend.verifyProof({ proof, publicInputs }, { keccak: true });
    expect(validJs).to.be.true;
    console.log("✅ JS verification passed");

    // 5. Deploy verifier
    console.log("📦 Deploying verifier...");
    const Verifier = await ethers.getContractFactory("noir/target/simple_test.sol:HonkVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    console.log("✅ Deployed at:", await verifier.getAddress());

    // 6. Verify on-chain
    console.log("⛓️ Verifying on-chain...");
    const publicInputsBytes32 = publicInputs.map(pi => 
      ethers.zeroPadValue(ethers.toBeHex(BigInt(pi)), 32)
    );
    const validOnChain = await verifier.verify(proof, publicInputsBytes32);
    expect(validOnChain).to.be.true;
    console.log("🎉 ON-CHAIN VERIFICATION PASSED!");
  });
});
