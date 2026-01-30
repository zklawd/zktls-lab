import { expect } from "chai";
import hre from "hardhat";
import { readFileSync } from "fs";

const { ethers } = hre;

// Helper: Convert hex string to Uint8Array
function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// Helper: Create BoundedVec for Noir {storage: [...], len: N}
function toBoundedVec(str, maxLen) {
  const storage = new Array(maxLen).fill(0);
  const len = typeof str === 'string' ? str.length : str.length;
  for (let i = 0; i < len && i < maxLen; i++) {
    storage[i] = typeof str === 'string' ? str.charCodeAt(i) : str[i];
  }
  return { storage, len };
}

// Helper: Recover public key from signature using ethers
function recoverPublicKey(messageHashHex, signatureHex) {
  const pubkeyHex = ethers.SigningKey.recoverPublicKey(messageHashHex, signatureHex);
  const pubkeyBytes = hexToBytes(pubkeyHex.slice(4)); // Remove "0x04" prefix
  return {
    x: Array.from(pubkeyBytes.slice(0, 32)),
    y: Array.from(pubkeyBytes.slice(32, 64))
  };
}

// Encode attestation exactly like Primus contracts
function encodeAttestationHash(att) {
  // encodeRequest = keccak256(url + header + method + body)
  const requestHash = ethers.keccak256(
    ethers.solidityPacked(
      ["string", "string", "string", "string"],
      [att.request.url, att.request.header, att.request.method, att.request.body]
    )
  );
  
  // encodeResponse = keccak256(keyName + parseType + parsePath for each)
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
  
  // Full attestation encoding
  const encoded = ethers.solidityPacked(
    ["address", "bytes32", "bytes32", "string", "string", "uint64", "string"],
    [
      att.recipient,
      requestHash,
      responseHash,
      att.data,
      att.attConditions,
      att.timestamp,
      att.additionParams
    ]
  );
  
  return ethers.keccak256(encoded);
}

describe("zkTLS Full Integration", function () {
  this.timeout(300000);

  let attestation;
  let noir, backend;

  before(async function () {
    attestation = JSON.parse(readFileSync("./attestation-output.json", "utf-8"));
    console.log("📄 Loaded attestation for price:", attestation.parsedPrice.raw);

    const circuit = await hre.noir.getCircuit("zktls_verifier");
    noir = circuit.noir;
    backend = circuit.backend;
    console.log("🔧 Circuit loaded, backend:", backend.constructor.name);
  });

  it("should generate a valid ZK proof from attestation", async function () {
    const MAX_URL_LEN = 1024;
    const MAX_CONTENT_LEN = 1000;

    // Compute message hash exactly like Primus contracts
    const messageHashHex = encodeAttestationHash(attestation);
    console.log("📝 Attestation hash:", messageHashHex);
    
    // Recover public key from signature
    const pubkey = recoverPublicKey(messageHashHex, attestation.signatures[0]);
    
    // Verify recovered address matches attestor
    const recoveredAddr = ethers.recoverAddress(messageHashHex, attestation.signatures[0]);
    console.log("📝 Recovered address:", recoveredAddr);
    console.log("📝 Expected attestor:", attestation.attestors[0].attestorAddr);
    expect(recoveredAddr.toLowerCase()).to.eq(attestation.attestors[0].attestorAddr.toLowerCase());

    const attestorAddr = Array.from(hexToBytes(attestation.attestors[0].attestorAddr));
    const signature = Array.from(hexToBytes(attestation.signatures[0]));
    const messageHash = Array.from(hexToBytes(messageHashHex));
    const requestUrl = attestation.request.url;
    const responseData = attestation.data;
    
    const input = {
      public_key_x: pubkey.x,
      public_key_y: pubkey.y,
      hash: messageHash,
      signature: signature.slice(0, 64),
      
      // Only use first slots - fill unused with dummy non-empty data
      request_urls: [
        toBoundedVec(requestUrl, MAX_URL_LEN),
        toBoundedVec("unused", MAX_URL_LEN),  // Non-empty placeholder
      ],
      allowed_urls: [
        toBoundedVec("https://api.kraken.com/", MAX_URL_LEN),
        toBoundedVec("unused", MAX_URL_LEN),
        toBoundedVec("unused", MAX_URL_LEN),
      ],
      data_hashes: [
        Array.from(hexToBytes(ethers.keccak256(ethers.toUtf8Bytes(responseData)))),
        Array.from(hexToBytes(ethers.keccak256(ethers.toUtf8Bytes("unused")))),
      ],
      plain_json_response_contents: [
        toBoundedVec(responseData, MAX_CONTENT_LEN),
        toBoundedVec("{}", MAX_CONTENT_LEN),  // Valid empty JSON
      ],
      
      expected_attestor: attestorAddr,
      claimed_price: attestation.parsedPrice.u64_6decimals.toString(),
    };

    console.log("📝 Generating witness...");
    const { witness } = await noir.execute(input);
    console.log("✅ Witness generated");

    console.log("🔐 Generating proof...");
    const { proof, publicInputs } = await backend.generateProof(witness, { keccak: true });
    console.log("✅ Proof size:", proof.length, "bytes");

    console.log("🔍 Verifying in JS...");
    const validJs = await backend.verifyProof({ proof, publicInputs }, { keccak: true });
    expect(validJs).to.be.true;
    console.log("✅ JS verification passed");

    this.proof = proof;
    this.publicInputs = publicInputs;
  });

  it("should verify the proof on-chain", async function () {
    if (!this.proof) this.skip();

    console.log("📦 Deploying HonkVerifier...");
    const Verifier = await ethers.getContractFactory("noir/target/zktls_verifier.sol:HonkVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
    console.log("✅ Deployed at:", await verifier.getAddress());

    const publicInputsBytes32 = this.publicInputs.map(pi => 
      ethers.zeroPadValue(ethers.toBeHex(BigInt(pi)), 32)
    );

    console.log("⛓️ Verifying on-chain...");
    const validOnChain = await verifier.verify(this.proof, publicInputsBytes32);
    expect(validOnChain).to.be.true;
    console.log("🎉 ON-CHAIN VERIFICATION PASSED!");
  });
});
