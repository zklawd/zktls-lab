import { describe, it, expect } from 'vitest';
import {
  parsePrice,
  u64ToBytes,
  bytesToU64,
  formatPrice,
  DECIMALS,
  MULTIPLIER
} from './price';

describe('parsePrice', () => {
  it('parses simple decimal string', () => {
    const result = parsePrice("2821.41");
    expect(result.raw).toBe("2821.41");
    expect(result.float).toBe(2821.41);
    expect(result.u64).toBe(2821410000);
  });

  it('handles Primus escaped quotes', () => {
    // Primus returns: "\"2821.41000\""
    const result = parsePrice('"2821.41000"');
    expect(result.raw).toBe("2821.41000");
    expect(result.u64).toBe(2821410000);
  });

  it('handles number input', () => {
    const result = parsePrice(2821.41);
    expect(result.u64).toBe(2821410000);
  });

  it('handles integer prices', () => {
    const result = parsePrice("3000");
    expect(result.u64).toBe(3000000000);
  });

  it('handles very small prices', () => {
    const result = parsePrice("0.000001");
    expect(result.u64).toBe(1);
  });

  it('rounds correctly at precision boundary', () => {
    // 6 decimals means 0.0000005 should round to 1
    const result = parsePrice("0.0000005");
    expect(result.u64).toBe(1);
    
    // 0.0000004 should round to 0
    const result2 = parsePrice("0.0000004");
    expect(result2.u64).toBe(0);
  });

  it('throws on invalid input', () => {
    expect(() => parsePrice("not-a-number")).toThrow("Invalid price");
    expect(() => parsePrice("")).toThrow("Invalid price");
  });

  it('generates correct bytes', () => {
    const result = parsePrice("2821.41");
    // 2821410000 = 0x00000000A8275CD0 in big-endian
    expect(result.bytes).toHaveLength(8);
    expect(bytesToU64(result.bytes)).toBe(2821410000);
  });
});

describe('u64ToBytes', () => {
  it('converts zero', () => {
    expect(u64ToBytes(0)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('converts small number', () => {
    expect(u64ToBytes(255)).toEqual([0, 0, 0, 0, 0, 0, 0, 255]);
  });

  it('converts typical price', () => {
    const bytes = u64ToBytes(2821410000);
    // Verify roundtrip
    expect(bytesToU64(bytes)).toBe(2821410000);
  });

  it('converts max safe integer', () => {
    const bytes = u64ToBytes(Number.MAX_SAFE_INTEGER);
    expect(bytes).toHaveLength(8);
    expect(bytesToU64(bytes)).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('throws on negative', () => {
    expect(() => u64ToBytes(-1)).toThrow("out of u64 range");
  });
});

describe('bytesToU64', () => {
  it('converts zero bytes', () => {
    expect(bytesToU64([0, 0, 0, 0, 0, 0, 0, 0])).toBe(0);
  });

  it('converts max single byte', () => {
    expect(bytesToU64([0, 0, 0, 0, 0, 0, 0, 255])).toBe(255);
  });

  it('converts multi-byte value', () => {
    // 0x0102030405060708 = 72623859790382856
    expect(bytesToU64([1, 2, 3, 4, 5, 6, 7, 8])).toBe(72623859790382856);
  });

  it('throws on wrong length', () => {
    expect(() => bytesToU64([1, 2, 3])).toThrow("Expected 8 bytes");
    expect(() => bytesToU64([])).toThrow("Expected 8 bytes");
  });
});

describe('formatPrice', () => {
  it('formats typical price', () => {
    expect(formatPrice(2821410000)).toBe("$2821.41");
  });

  it('formats whole dollar amount', () => {
    expect(formatPrice(3000000000)).toBe("$3000.0");
  });

  it('formats zero', () => {
    expect(formatPrice(0)).toBe("$0.0");
  });

  it('formats sub-dollar amount', () => {
    expect(formatPrice(500000)).toBe("$0.5");
  });

  it('preserves precision', () => {
    expect(formatPrice(1234567)).toBe("$1.234567");
  });
});

describe('constants', () => {
  it('DECIMALS is 6', () => {
    expect(DECIMALS).toBe(6);
  });

  it('MULTIPLIER is 1_000_000', () => {
    expect(MULTIPLIER).toBe(1_000_000);
  });
});
