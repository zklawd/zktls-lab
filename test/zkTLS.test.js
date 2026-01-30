import { expect } from "chai";
import hre from "hardhat";

describe("zkTLS Verifier", function () {
  it("should load the circuit and backend", async function () {
    this.timeout(120000);

    const { noir, backend } = await hre.noir.getCircuit("zktls_verifier");
    
    console.log("✅ Circuit loaded successfully");
    console.log("Backend:", backend.constructor.name);
    
    expect(noir).to.exist;
    expect(backend).to.exist;
  });
});
