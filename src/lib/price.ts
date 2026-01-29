/**
 * Price parsing utilities
 */

export const DECIMALS = 6;
export const MULTIPLIER = 10 ** DECIMALS; // 1_000_000

export interface ParsedPrice {
  raw: string;
  float: number;
  u64: number;
  bytes: number[]; // 8 bytes, big-endian
}

/**
 * Parse price string from attestation data
 * Handles: "2821.41000", "\"2821.41000\"", 2821.41
 */
export function parsePrice(value: string | number): ParsedPrice {
  let raw: string;
  
  if (typeof value === 'number') {
    raw = value.toString();
  } else {
    raw = value;
    // Remove surrounding quotes if present (Primus adds these)
    if (raw.startsWith('"') && raw.endsWith('"')) {
      raw = raw.slice(1, -1);
    }
  }
  
  const float = parseFloat(raw);
  if (isNaN(float)) {
    throw new Error(`Invalid price value: ${value}`);
  }
  
  const u64 = Math.round(float * MULTIPLIER);
  
  // Convert to big-endian bytes
  const bytes = u64ToBytes(u64);
  
  return { raw, float, u64, bytes };
}

/**
 * Convert u64 to 8 big-endian bytes
 */
export function u64ToBytes(value: number): number[] {
  if (value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new Error(`Value out of u64 range: ${value}`);
  }
  
  const bytes: number[] = [];
  let v = BigInt(value);
  
  for (let i = 0; i < 8; i++) {
    bytes.unshift(Number(v & 0xFFn));
    v >>= 8n;
  }
  
  return bytes;
}

/**
 * Convert 8 big-endian bytes back to u64
 */
export function bytesToU64(bytes: number[]): number {
  if (bytes.length !== 8) {
    throw new Error(`Expected 8 bytes, got ${bytes.length}`);
  }
  
  let value = 0n;
  for (const b of bytes) {
    value = (value << 8n) | BigInt(b);
  }
  
  return Number(value);
}

/**
 * Format u64 price (6 decimals) as human-readable string
 */
export function formatPrice(u64: number): string {
  const dollars = Math.floor(u64 / MULTIPLIER);
  const cents = u64 % MULTIPLIER;
  return `$${dollars}.${cents.toString().padStart(DECIMALS, '0').replace(/0+$/, '') || '0'}`;
}
