/**
 * Attestation encoding - must match Primus SDK exactly
 */
import { ethers } from 'ethers';

export interface AttestationRequest {
  url: string;
  header: string;
  method: string;
  body: string;
}

export interface ResponseResolve {
  keyName: string;
  parseType: string;
  parsePath: string;
}

export interface Attestation {
  recipient: string;
  request: AttestationRequest;
  reponseResolve: ResponseResolve[];
  data: string;
  attConditions: string;
  timestamp: number;
  additionParams: string;
  attestors: Array<{ attestorAddr: string; url: string }>;
  signatures: string[];
}

export function encodeRequest(request: AttestationRequest): string {
  const encoded = ethers.utils.solidityPack(
    ["string", "string", "string", "string"],
    [request.url, request.header, request.method, request.body]
  );
  return ethers.utils.keccak256(encoded);
}

export function encodeResponse(response: ResponseResolve[]): string {
  let data = "0x";
  for (const r of response) {
    data = ethers.utils.solidityPack(
      ["bytes", "string", "string", "string"],
      [data, r.keyName, r.parseType, r.parsePath]
    );
  }
  return ethers.utils.keccak256(data);
}

export function encodeAttestation(att: Attestation): string {
  const encoded = ethers.utils.solidityPack(
    ["address", "bytes32", "bytes32", "string", "string", "uint64", "string"],
    [
      att.recipient,
      encodeRequest(att.request),
      encodeResponse(att.reponseResolve),
      att.data,
      att.attConditions,
      att.timestamp,
      att.additionParams
    ]
  );
  return ethers.utils.keccak256(encoded);
}

export function verifyAttestationSignature(att: Attestation): {
  valid: boolean;
  recoveredAddress: string;
  expectedAddress: string;
} {
  const msgHash = encodeAttestation(att);
  const recoveredAddress = ethers.utils.recoverAddress(msgHash, att.signatures[0]);
  const expectedAddress = att.attestors[0].attestorAddr;
  
  return {
    valid: recoveredAddress.toLowerCase() === expectedAddress.toLowerCase(),
    recoveredAddress,
    expectedAddress
  };
}
