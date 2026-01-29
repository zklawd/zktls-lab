import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const NOIR_DIR = path.join(process.cwd(), 'noir');
const PROVER_TOML = path.join(NOIR_DIR, 'Prover.toml');
const TARGET_DIR = path.join(NOIR_DIR, 'target');
const NARGO = `${process.env.HOME}/.nargo/bin/nargo`;
const BB = `${process.env.HOME}/.bb/bb`;

// Helper to run nargo execute and check result
function runNargoExecute(): { success: boolean; output: string } {
  try {
    const output = execSync(`${NARGO} execute`, {
      cwd: NOIR_DIR,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return { success: true, output };
  } catch (error: any) {
    return { success: false, output: error.stderr || error.message };
  }
}

// Helper to run bb prove
function runBbProve(): { success: boolean; output: string } {
  try {
    execSync(`mkdir -p ${TARGET_DIR}/proof ${TARGET_DIR}/vk`, { cwd: NOIR_DIR });
    const output = execSync(
      `${BB} prove -b ./target/zktls_verifier.json -w ./target/zktls_verifier.gz -o ./target/proof`,
      { cwd: NOIR_DIR, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    return { success: true, output };
  } catch (error: any) {
    return { success: false, output: error.stderr || error.message };
  }
}

// Helper to run bb verify
function runBbVerify(): { success: boolean; output: string } {
  try {
    // First generate VK if needed
    execSync(
      `${BB} write_vk -b ./target/zktls_verifier.json -o ./target/vk`,
      { cwd: NOIR_DIR, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const output = execSync(
      `${BB} verify -p ./target/proof/proof -k ./target/vk/vk`,
      { cwd: NOIR_DIR, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    return { success: true, output };
  } catch (error: any) {
    return { success: false, output: error.stderr || error.message };
  }
}

// Helper to modify Prover.toml
function modifyProverToml(find: RegExp, replace: string): string {
  const original = fs.readFileSync(PROVER_TOML, 'utf-8');
  const modified = original.replace(find, replace);
  fs.writeFileSync(PROVER_TOML, modified);
  return original;
}

function restoreProverToml(original: string) {
  fs.writeFileSync(PROVER_TOML, original);
}

describe('Noir circuit verification', () => {
  it('accepts valid attestation', () => {
    const result = runNargoExecute();
    expect(result.success).toBe(true);
    expect(result.output).toContain('Circuit output: Field(2821410000)');
  });

  it('generates valid proof', () => {
    // First execute to generate witness
    const execResult = runNargoExecute();
    expect(execResult.success).toBe(true);
    
    // Then prove
    const proveResult = runBbProve();
    expect(proveResult.success).toBe(true);
    
    // Check proof file exists
    const proofPath = path.join(TARGET_DIR, 'proof', 'proof');
    expect(fs.existsSync(proofPath)).toBe(true);
  }, 60000); // 60s timeout for proving

  it('verifies valid proof', () => {
    const verifyResult = runBbVerify();
    expect(verifyResult.success).toBe(true);
  }, 30000); // 30s timeout for verification

  it('rejects tampered signature', () => {
    const original = modifyProverToml(
      /signature = \[\d+,/,
      'signature = [0,'
    );
    try {
      const result = runNargoExecute();
      expect(result.success).toBe(false);
      expect(result.output).toContain('Invalid ECDSA signature');
    } finally {
      restoreProverToml(original);
    }
  });

  it('rejects wrong attestor address', () => {
    const original = modifyProverToml(
      /attestor_address = \[\d+,/,
      'attestor_address = [0,'
    );
    try {
      const result = runNargoExecute();
      expect(result.success).toBe(false);
      expect(result.output).toContain('Address mismatch');
    } finally {
      restoreProverToml(original);
    }
  });

  it('rejects wrong URL hash', () => {
    const original = modifyProverToml(
      /request_url_hash = \[\d+,/,
      'request_url_hash = [0,'
    );
    try {
      const result = runNargoExecute();
      expect(result.success).toBe(false);
      expect(result.output).toContain('URL not allowed');
    } finally {
      restoreProverToml(original);
    }
  });

  it('rejects tampered message hash', () => {
    const original = modifyProverToml(
      /message_hash = \[\d+,/,
      'message_hash = [0,'
    );
    try {
      const result = runNargoExecute();
      expect(result.success).toBe(false);
      expect(result.output).toContain('Invalid ECDSA signature');
    } finally {
      restoreProverToml(original);
    }
  });
});
