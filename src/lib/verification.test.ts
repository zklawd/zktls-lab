import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

const NOIR_DIR = path.join(process.cwd(), 'noir');
const PROVER_TOML = path.join(NOIR_DIR, 'Prover.toml');
const NARGO = `${process.env.HOME}/.nargo/bin/nargo`;

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
