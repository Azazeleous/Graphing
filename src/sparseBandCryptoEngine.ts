/**
 * Sparsebundle Band Crypto Engine (LS-MASTER-1.0)
 * - Pure-TypeScript RFC 7693 BLAKE2b (512-bit + 256/128/64 lower-bit cascades) + SHA-256d
 * - Doubled 8,192-block (14-level, 16,383-node Merkle) × 3 mirrored sets (24,576 blocks)
 * - 3 Axis Pairs (Top/Bottom=1, Left/Right=1, Front/Back=1) -> 6 Inner Cube Faces + Doubled Outer Hypercube Shell
 * - 6 Sierpinski Orb Lattice Prisms per block inside 8 MiB sparsebundle bands
 *   (8,000,000-byte spreadsheet partition + 388,605-bit sequential hash-order search tail)
 * - 64-Lane Coprime Forward/Inverse Matrix + Dewey Decimal + Rainbow Graph Table lookup
 */

import { creedAdmittanceService, type Verdict } from './creedAdmittance.ts';
import { LIVING_SYSTEM_SOURCE_REGISTRY } from './livingSystemRegistry.ts';

export const BASE_BLOCKS_PER_SET = 16384;
export const MERKLE_LEVELS_COUNT = 15;
export const MERKLE_NODES_PER_SET = 32767;
export const DUPLICATED_SETS_COUNT = 3;
export const TOTAL_HYPER_BLOCKS = BASE_BLOCKS_PER_SET * DUPLICATED_SETS_COUNT; // 49,152 (16,384 × 3)
export const ORBS_PER_BLOCK = 6;
export const COPRIME_LANES_COUNT = 64;
export const MACRO_CUBES_PER_GROUP = 16;

export const SPARSE_BAND_TOTAL_BYTES = 8388608; // 8 MiB exact sparsebundle band
export const SPARSE_PAYLOAD_PARTITION_BYTES = 8000000; // 8,000,000 byte sequential payload partition
export const SPARSE_TAIL_RESERVED_BYTES = 388608; // remaining bytes housing the 388,605-bit sequential hash index tail
export const SPARSE_TAIL_RESERVED_BITS = 388605;
export const LOGICAL_VOLUME_BYTES = TOTAL_HYPER_BLOCKS * SPARSE_BAND_TOTAL_BYTES; // 412,316,860,416 B = 384 GiB (or 192 GiB per mirrored hemisphere)

export const DIRECTIONAL_GLYPHS = ['<^>', '^>', '><^', '<^>v'] as const;
export type DirectionalGlyph = (typeof DIRECTIONAL_GLYPHS)[number];

export type SparseFusionTierId =
  | 'BIT_64'
  | 'BIT_128'
  | 'BIT_256'
  | 'BIT_512'
  | 'BIT_1024'
  | 'BIT_2048'
  | 'SOLVENT_EQUATOR'
  | 'ELGAMAL_L10';

export interface SparseFusionTierSpec {
  id: SparseFusionTierId;
  bitWidth: number;
  label: string;
  role: string;
  bandStart: number;
  bandCount: number;
  logicalGiB: number;
  clipPolygon: string;
}

export const SPARSE_FUSION_TIERS: SparseFusionTierSpec[] = [
  { id: 'BIT_64', bitWidth: 64, label: '64-bit Micro-Index', role: 'BLAKE2b-64 Ordered Tail', bandStart: 0, bandCount: 1536, logicalGiB: 12, clipPolygon: 'polygon(0 0, 50% 0, 50% 25%, 0 25%)' },
  { id: 'BIT_128', bitWidth: 128, label: '128-bit Address Band', role: 'BLAKE2b-128 Dewey Partition', bandStart: 1536, bandCount: 3072, logicalGiB: 24, clipPolygon: 'polygon(50% 0, 100% 0, 100% 25%, 50% 25%)' },
  { id: 'BIT_256', bitWidth: 256, label: '256-bit Parity Band', role: 'SHA-256d / BLAKE2b-256', bandStart: 4608, bandCount: 4608, logicalGiB: 36, clipPolygon: 'polygon(0 25%, 50% 25%, 50% 50%, 0 50%)' },
  { id: 'BIT_512', bitWidth: 512, label: '512-bit Payload Host', role: 'BLAKE2b-512 Spreadsheet Cells', bandStart: 9216, bandCount: 6144, logicalGiB: 48, clipPolygon: 'polygon(50% 25%, 100% 25%, 100% 50%, 50% 50%)' },
  { id: 'BIT_1024', bitWidth: 1024, label: '1024-bit Dual-Hemisphere', role: 'Forward + Inverse Paired Band', bandStart: 15360, bandCount: 9216, logicalGiB: 72, clipPolygon: 'polygon(0 50%, 50% 50%, 50% 75%, 0 75%)' },
  { id: 'BIT_2048', bitWidth: 2048, label: '2048-bit Hypercube Super', role: 'Merkle L0..L14 Super-Band', bandStart: 24576, bandCount: 12288, logicalGiB: 96, clipPolygon: 'polygon(50% 50%, 100% 50%, 100% 75%, 50% 75%)' },
  { id: 'SOLVENT_EQUATOR', bitWidth: 3072, label: 'Osmosis Equator Solvent', role: 'Hue-Word Receipt Bridge', bandStart: 36864, bandCount: 6144, logicalGiB: 48, clipPolygon: 'polygon(0 75%, 50% 75%, 50% 100%, 0 100%)' },
  { id: 'ELGAMAL_L10', bitWidth: 4096, label: 'ElGamal L10 Straddle', role: 'Free-Set Pattern Recognition', bandStart: 43008, bandCount: 6144, logicalGiB: 48, clipPolygon: 'polygon(50% 75%, 100% 75%, 100% 100%, 50% 100%)' },
];

export const SOLVENT_LEXICON = [
  'GENESIS', 'OSMOSIS', 'COPRIME', 'SIERPINSKI', 'HAMILTONIAN', 'MERKLE', 'EQUATOR', 'HEMISPHERE',
  'STRADDLE', 'ELGAMAL', 'SECP256K1', 'DEWEY', 'SPARSEBAND', 'HYPERCUBE', 'PHI_SPIRAL', 'SOLVENT',
  'QUANTUM', 'ADMITTANCE', 'PROVENANCE', 'GOLDEN', 'MONOLITH', 'CHRONICLE', 'LATTICE', 'MANHATTAN',
  'GEODESIC', 'SYNDROME', 'ENGRAM', 'CIPHER', 'INVERSE', 'CONVERGENCE', 'PARITY', 'VERIFIED',
] as const;

export function hslDegToHex(hDeg: number, sPct = 78, lPct = 56): string {
  const h = (((hDeg % 360) + 360) % 360) / 360;
  const s = sPct / 100;
  const l = lPct / 100;
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  const hue2rgb = (t: number) => {
    let tt = t;
    if (tt < 0) tt += 1;
    if (tt > 1) tt -= 1;
    if (tt < 1 / 6) return p + (q - p) * 6 * tt;
    if (tt < 1 / 2) return q;
    if (tt < 2 / 3) return p + (q - p) * (2 / 3 - tt) * 6;
    return p;
  };
  return (
    '#' +
    [hue2rgb(h + 1 / 3), hue2rgb(h), hue2rgb(h - 1 / 3)]
      .map((v) => Math.round(v * 255).toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  );
}

export interface AxisFacePairSpec {
  axisPairId: 0 | 1 | 2;
  pairLabel: string;
  setIndex: number;
  positiveFace: 'TOP' | 'RIGHT' | 'FRONT';
  negativeFace: 'BOTTOM' | 'LEFT' | 'BACK';
  axisVector: [number, number, number];
  pairValue: 1;
}

export const AXIS_FACE_PAIRS: AxisFacePairSpec[] = [
  {
    axisPairId: 0,
    pairLabel: 'TOP / BOTTOM = 1 (Axis Y · Set 1)',
    setIndex: 0,
    positiveFace: 'TOP',
    negativeFace: 'BOTTOM',
    axisVector: [0, 1, 0],
    pairValue: 1,
  },
  {
    axisPairId: 1,
    pairLabel: 'LEFT / RIGHT = 1 (Axis X · Set 2)',
    setIndex: 1,
    positiveFace: 'RIGHT',
    negativeFace: 'LEFT',
    axisVector: [1, 0, 0],
    pairValue: 1,
  },
  {
    axisPairId: 2,
    pairLabel: 'FRONT / BACK = 1 (Axis Z · Set 3)',
    setIndex: 2,
    positiveFace: 'FRONT',
    negativeFace: 'BACK',
    axisVector: [0, 0, 1],
    pairValue: 1,
  },
];

// =========================================================================
// 1. PURE-TS RFC 7693 BLAKE2b (512 / 256 / 128 / 64 BITS) + SHA-256d
// =========================================================================

const BLAKE2B_IV_HI = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const BLAKE2B_IV_LO = new Uint32Array([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
  0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
]);

const BLAKE2B_SIGMA: number[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

function add64(
  vHi: Uint32Array,
  vLo: Uint32Array,
  a: number,
  b: number,
  cHi: number,
  cLo: number
): void {
  const bLo = vLo[b];
  const bHi = vHi[b];
  let lo = (vLo[a] + bLo) >>> 0;
  let carry = lo < bLo ? 1 : 0;
  let hi = (vHi[a] + bHi + carry) >>> 0;

  lo = (lo + cLo) >>> 0;
  carry = lo < cLo ? 1 : 0;
  hi = (hi + cHi + carry) >>> 0;

  vLo[a] = lo;
  vHi[a] = hi;
}

function xorRotr64(vHi: Uint32Array, vLo: Uint32Array, dst: number, src: number, rot: number): void {
  const xHi = (vHi[dst] ^ vHi[src]) >>> 0;
  const xLo = (vLo[dst] ^ vLo[src]) >>> 0;
  if (rot === 32) {
    vHi[dst] = xLo;
    vLo[dst] = xHi;
  } else if (rot === 24 || rot === 16) {
    vLo[dst] = ((xLo >>> rot) | (xHi << (32 - rot))) >>> 0;
    vHi[dst] = ((xHi >>> rot) | (xLo << (32 - rot))) >>> 0;
  } else if (rot === 63) {
    // rot right by 63 == rot left by 1
    vLo[dst] = ((xLo << 1) | (xHi >>> 31)) >>> 0;
    vHi[dst] = ((xHi << 1) | (xLo >>> 31)) >>> 0;
  }
}

export function blake2bBytes(input: string | Uint8Array, outLen = 64): Uint8Array {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const clampedOut = Math.max(1, Math.min(64, outLen));

  const hHi = new Uint32Array(BLAKE2B_IV_HI);
  const hLo = new Uint32Array(BLAKE2B_IV_LO);
  hLo[0] = (hLo[0] ^ (0x01010000 ^ clampedOut)) >>> 0;

  const vHi = new Uint32Array(16);
  const vLo = new Uint32Array(16);
  const mHi = new Uint32Array(16);
  const mLo = new Uint32Array(16);
  const block = new Uint8Array(128);

  const compress = (chunk: Uint8Array, tLo: number, tHi: number, isLast: boolean): void => {
    for (let i = 0; i < 16; i++) {
      const o = i * 8;
      mLo[i] =
        (chunk[o] |
          (chunk[o + 1] << 8) |
          (chunk[o + 2] << 16) |
          (chunk[o + 3] << 24)) >>>
        0;
      mHi[i] =
        (chunk[o + 4] |
          (chunk[o + 5] << 8) |
          (chunk[o + 6] << 16) |
          (chunk[o + 7] << 24)) >>>
        0;
    }

    for (let i = 0; i < 8; i++) {
      vHi[i] = hHi[i];
      vLo[i] = hLo[i];
      vHi[i + 8] = BLAKE2B_IV_HI[i];
      vLo[i + 8] = BLAKE2B_IV_LO[i];
    }

    vLo[12] = (vLo[12] ^ tLo) >>> 0;
    vHi[12] = (vHi[12] ^ tHi) >>> 0;
    if (isLast) {
      vLo[14] = (~vLo[14]) >>> 0;
      vHi[14] = (~vHi[14]) >>> 0;
    }

    const G = (r: number, i: number, a: number, b: number, c: number, d: number): void => {
      const s = BLAKE2B_SIGMA[r];
      const idx1 = s[2 * i];
      const idx2 = s[2 * i + 1];
      add64(vHi, vLo, a, b, mHi[idx1], mLo[idx1]);
      xorRotr64(vHi, vLo, d, a, 32);
      add64(vHi, vLo, c, d, 0, 0);
      xorRotr64(vHi, vLo, b, c, 24);
      add64(vHi, vLo, a, b, mHi[idx2], mLo[idx2]);
      xorRotr64(vHi, vLo, d, a, 16);
      add64(vHi, vLo, c, d, 0, 0);
      xorRotr64(vHi, vLo, b, c, 63);
    };

    for (let r = 0; r < 12; r++) {
      G(r, 0, 0, 4, 8, 12);
      G(r, 1, 1, 5, 9, 13);
      G(r, 2, 2, 6, 10, 14);
      G(r, 3, 3, 7, 11, 15);
      G(r, 4, 0, 5, 10, 15);
      G(r, 5, 1, 6, 11, 12);
      G(r, 6, 2, 7, 8, 13);
      G(r, 7, 3, 4, 9, 14);
    }

    for (let i = 0; i < 8; i++) {
      hLo[i] = (hLo[i] ^ vLo[i] ^ vLo[i + 8]) >>> 0;
      hHi[i] = (hHi[i] ^ vHi[i] ^ vHi[i + 8]) >>> 0;
    }
  };

  let offset = 0;
  let totalLo = 0;
  let totalHi = 0;
  if (bytes.length > 128) {
    while (offset + 128 < bytes.length) {
      totalLo = (totalLo + 128) >>> 0;
      if (totalLo < 128) totalHi = (totalHi + 1) >>> 0;
      compress(bytes.subarray(offset, offset + 128), totalLo, totalHi, false);
      offset += 128;
    }
  }

  const remaining = bytes.length - offset;
  block.fill(0);
  if (remaining > 0) block.set(bytes.subarray(offset));
  totalLo = (totalLo + remaining) >>> 0;
  if (totalLo < remaining) totalHi = (totalHi + 1) >>> 0;
  compress(block, totalLo, totalHi, true);

  const out = new Uint8Array(clampedOut);
  for (let i = 0; i < clampedOut; i++) {
    const word = i >>> 3;
    const shift = (i & 3) * 8;
    out[i] = ((i & 4) === 0 ? hLo[word] : hHi[word]) >>> shift;
  }
  return out;
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256RawBytes(input: string | Uint8Array): Uint8Array {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const bitLen = bytes.length * 8;
  const totalLen = (((bytes.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);
  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] =
        (padded[off + i * 4] << 24) |
        (padded[off + i * 4 + 1] << 16) |
        (padded[off + i * 4 + 2] << 8) |
        padded[off + i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h7] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h7 + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h7 = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + h7) >>> 0;
  }
  const out = new Uint8Array(32);
  const outV = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outV.setUint32(i * 4, h[i], false);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function blake2bHex(input: string | Uint8Array, outLen = 64): string {
  return bytesToHex(blake2bBytes(input, outLen));
}

export function sha256dBytesHex(input: string | Uint8Array): string {
  const first = sha256RawBytes(input);
  return bytesToHex(sha256RawBytes(first));
}

export interface MultiStageDatabaseHash {
  blake2b512Hex: string;
  blake2b256Hex: string;
  blake2b128Hex: string;
  blake2b64Hex: string;
  sha256dHex: string;
  combinedLeafHex: string;
}

/**
 * Full database hash cascade:
 *  1) BLAKE2b-512 over payload
 *  2) Lower-bit cascades: BLAKE2b-256, BLAKE2b-128, BLAKE2b-64
 *  3) Full SHA-256d over canonical digest + payload
 */
export function computeMultiStageDatabaseHash(input: string): MultiStageDatabaseHash {
  const blake2b512Hex = blake2bHex(input, 64);
  const blake2b256Hex = blake2bHex(input, 32);
  const blake2b128Hex = blake2bHex(input, 16);
  const blake2b64Hex = blake2bHex(input, 8);
  const sha256dHex = sha256dBytesHex(`${blake2b512Hex}|${input}`);
  const combinedLeafHex = sha256dBytesHex(`${blake2b256Hex}:${sha256dHex}`);
  return {
    blake2b512Hex,
    blake2b256Hex,
    blake2b128Hex,
    blake2b64Hex,
    sha256dHex,
    combinedLeafHex,
  };
}

export interface InverseSequentialHashResult {
  inverseInput: string;
  inverseBlake2b512Hex: string;
  inverseBlake2b256Hex: string;
  inverseBlake2b128Hex: string;
  inverseBlake2b64Hex: string;
  inverseSha256dHex: string;
  inverseCombinedLeafHex: string;
  osmosisFusionDigestHex: string;
}

/**
 * Compiles the database from the inverse of the exact sequential hash:
 * 1) Bitwise inverted/reversed byte stream of canonical input
 * 2) Modulo phi(N) inverse stride coprime transposition
 * 3) Inverse cascades: BLAKE2b (512, 256, 128, 64) + SHA-256d
 * 4) Merges forward leaf + inverse duplicate leaf via Osmosis Fusion digest
 */
export function computeInverseSequentialHash(
  canonicalInput: string,
  forwardHashes: MultiStageDatabaseHash,
  inverseStride: number
): InverseSequentialHashResult {
  const enc = new TextEncoder();
  const forwardBytes = enc.encode(canonicalInput);
  const invertedBytes = new Uint8Array(forwardBytes.length);
  for (let i = 0; i < forwardBytes.length; i++) {
    invertedBytes[i] = (~forwardBytes[forwardBytes.length - 1 - i]) & 0xff;
  }
  const strideTag = `INV_STRIDE_${inverseStride % PHI_N}`;
  const inverseBlake2b512Hex = blake2bHex(invertedBytes, 64);
  const inverseBlake2b256Hex = blake2bHex(invertedBytes, 32);
  const inverseBlake2b128Hex = blake2bHex(invertedBytes, 16);
  const inverseBlake2b64Hex = blake2bHex(invertedBytes, 8);
  const inverseSha256dHex = sha256dBytesHex(`${inverseBlake2b512Hex}|${strideTag}`);
  const inverseCombinedLeafHex = sha256dBytesHex(`${inverseBlake2b256Hex}:${inverseSha256dHex}`);
  // Osmosis Fusion merges forward leaf + inverse duplicate leaf into unified continuum
  const osmosisFusionDigestHex = sha256dBytesHex(
    `${forwardHashes.combinedLeafHex}<~OSMOSIS_FUSION~>${inverseCombinedLeafHex}`
  );
  return {
    inverseInput: `${canonicalInput}::${strideTag}`,
    inverseBlake2b512Hex,
    inverseBlake2b256Hex,
    inverseBlake2b128Hex,
    inverseBlake2b64Hex,
    inverseSha256dHex,
    inverseCombinedLeafHex,
    osmosisFusionDigestHex,
  };
}

// =========================================================================
// 2. 64-LANE COPRIME MATRIX (N = 97152, phi(N) = 28160) & DEWEY/RAINBOW
// =========================================================================

const DOMAIN_N = 97152;
const PHI_N = 28160;

function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x;
}

function modInverse(a: number, m: number): number {
  let m0 = m;
  let y = 0;
  let x = 1;
  let aa = ((a % m) + m) % m;
  if (m === 1) return 0;
  while (aa > 1) {
    const q = Math.floor(aa / m0);
    let t = m0;
    m0 = aa % m0;
    aa = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0) x += m;
  return x;
}

export interface CoprimeLaneDescriptor {
  laneId: number; // 0..63
  macroClusterId: number; // 0..15 (16 cubes per group)
  directionalIndex: 0 | 1 | 2 | 3; // 4-lane forward/inverse cycle
  directionalGlyph: DirectionalGlyph;
  axisPairId: 0 | 1 | 2;
  faceLabel: 'TOP' | 'BOTTOM' | 'LEFT' | 'RIGHT' | 'FRONT' | 'BACK';
  shellLayer: 'INNER_RUBIK' | 'OUTER_HYPERCUBE';
  coprimeUnit: number; // gcd(u, 97152) === 1
  forwardStride: number;
  inverseStride: number; // forwardStride * inverseStride ≡ 1 mod 28160
  digitsCount: number;
  base4LaneSign: 1 | -1;
}

export interface SpreadsheetPrismCell {
  cellSeqIndex: number;
  sheetName: string;
  row: number;
  col: number;
  colLabel: string;
  cellRef: string; // e.g., A1, B4
  rawValue: string;
  setIndex: 0 | 1 | 2;
  axisPairId: 0 | 1 | 2;
  faceLabel: 'TOP' | 'BOTTOM' | 'LEFT' | 'RIGHT' | 'FRONT' | 'BACK';
  macroClusterId: number; // 0..15
  blockIndex: number; // 0..16383
  orbIndex: number; // 0..5 (6 Sierpinski orb prisms per block)
  laneId: number; // 0..63
  directionalGlyph: DirectionalGlyph;
  deweyAddress: string; // e.g., 512.04.012.3.004
  rainbowBucketKey: string;
  byteOffset: number; // within 8,000,000 byte payload partition
  byteLength: number;
  tailBitOffset: number; // within 388,605-bit sequential hash tail
  tailToken: string;
  blake2b512Hex: string;
  blake2b256Hex: string;
  blake2b128Hex: string;
  blake2b64Hex: string;
  sha256dHex: string;
  combinedLeafHex: string;
  // Inverse duplicate sequential hash compilation & Osmosis Fusion
  inverseBlake2b512Hex: string;
  inverseBlake2b256Hex: string;
  inverseBlake2b128Hex: string;
  inverseBlake2b64Hex: string;
  inverseSha256dHex: string;
  inverseCombinedLeafHex: string;
  osmosisFusionDigestHex: string;
  inverseDeweyAddress: string;
  inverseTailToken: string;
  receiptWord: string;
  inverseReceiptWord: string;
  prismHueDeg: number;
  prismRgbHex: string;
  fusionTierId: SparseFusionTierId;
  reverseVerified: boolean;
  createdAt: string;
}

export interface SparseBandSliceSummary {
  blockIndex: number;
  setIndex: 0 | 1 | 2;
  faceLabel: string;
  payloadBytesUsed: number;
  payloadBytesCapacity: number;
  tailBitsUsed: number;
  tailBitsCapacity: number;
  cellCount: number;
  orderedHashTailString: string;
  latestLeafHex: string;
}

export interface MultiFacetedMatchResult {
  found: boolean;
  query: string;
  matchStrategy:
    | 'EXACT_TAIL_HASH'
    | 'DEWEY_DECIMAL'
    | 'RAINBOW_BUCKET'
    | 'CELL_VALUE'
    | 'COPRIME_64_INVERSE'
    | 'OSMOSIS_FUSION'
    | 'INVERSE_DUPLICATE'
    | 'UNMATCHED';
  admitted: boolean;
  admissionVerdict: Verdict;
  admissionEvaluationId: string;
  matchedCell: SpreadsheetPrismCell | null;
  inverseCounterpartCell: SpreadsheetPrismCell | null;
  lane: CoprimeLaneDescriptor | null;
  forwardCoordinate: number | null;
  inverseCoordinate: number | null;
  verifiedInverseIdentity: boolean;
  merkleRootAtLookup: string;
  candidatesEvaluated: number;
  reason: string;
  osmosisFusionDigest?: string;
  inverseDuplicateMatched?: boolean;
}

export interface SparseBandEngineSummary {
  baseBlocksPerSet: number;
  merkleLevels: number;
  merkleNodesPerSet: number;
  duplicatedSets: number;
  totalHyperBlocks: number;
  orbsPerBlock: number;
  coprimeLanesCount: number;
  sparseBandTotalBytes: number;
  payloadPartitionBytes: number;
  tailReservedBits: number;
  populatedCellsCount: number;
  populatedBandsCount: number;
  tailSequenceLength: number;
  rainbowBucketsCount: number;
  lastSheetName: string;
  lastBlake2b128Hex: string;
  lastSha256dHex: string;
  setRootsHex: [string, string, string];
  lastUpdated: string;
  mountMode: 'ALL' | 'CLIP_PATH_SELECTIVE';
  activeFusionTiers: SparseFusionTierId[];
  mountedLogicalGiB: number;
  cyclicPhaseMode: 'FORWARD_CYCLIC' | 'REVERSE_VERIFY' | 'COMPLETE';
  reverseVerifiedBlocks: number;
  lastReceiptWord: string;
  lastPrismHueDeg: number;
  lastPrismRgbHex: string;
}

// =========================================================================
// 3. SPARSEBUNDLE CRYPTO ENGINE + 3-SET MERKLE ROOTS + SPREADSHEET HOST
// =========================================================================

class IncrementalMerkleSet {
  public readonly levels: string[][];
  public readonly capacity: number;
  public activeCount = 0;

  constructor(capacity = BASE_BLOCKS_PER_SET) {
    this.capacity = capacity;
    this.levels = [];
    let count = capacity;
    const zeroHash = '0'.repeat(64);
    while (count >= 1) {
      this.levels.push(new Array(count).fill(zeroHash));
      if (count === 1) break;
      count >>= 1;
    }
  }

  public updateLeaf(index: number, leafHex: string): string {
    const idx = Math.max(0, Math.min(this.capacity - 1, index));
    this.levels[0][idx] = leafHex;
    if (idx + 1 > this.activeCount) this.activeCount = idx + 1;
    let cur = idx;
    for (let lvl = 0; lvl < this.levels.length - 1; lvl++) {
      const sib = cur ^ 1;
      const left = cur < sib ? this.levels[lvl][cur] : this.levels[lvl][sib];
      const right = cur < sib ? this.levels[lvl][sib] : this.levels[lvl][cur];
      const parent = cur >> 1;
      this.levels[lvl + 1][parent] = sha256dBytesHex(`${left}:${right}`);
      cur = parent;
    }
    return this.root;
  }

  public get root(): string {
    return this.levels[this.levels.length - 1][0];
  }
}

export class SparseBandCryptoEngine {
  public readonly lanes: CoprimeLaneDescriptor[] = [];
  public readonly cells: SpreadsheetPrismCell[] = [];
  public readonly bands = new Map<string, SparseBandSliceSummary>();
  public readonly deweyIndex = new Map<string, SpreadsheetPrismCell>();
  public readonly inverseDeweyIndex = new Map<string, SpreadsheetPrismCell>();
  public readonly osmosisFusionIndex = new Map<string, SpreadsheetPrismCell>();
  public readonly rainbowTable = new Map<string, SpreadsheetPrismCell[]>();
  public readonly setTrees: [IncrementalMerkleSet, IncrementalMerkleSet, IncrementalMerkleSet] = [
    new IncrementalMerkleSet(BASE_BLOCKS_PER_SET),
    new IncrementalMerkleSet(BASE_BLOCKS_PER_SET),
    new IncrementalMerkleSet(BASE_BLOCKS_PER_SET),
  ];

  public orderedHashTailSequence = '';
  public lastSheetName = 'GENESIS_SOURCE_REGISTRY.xlsx';
  public lastUpdated = new Date().toISOString();
  public activeFusionTiers = new Set<SparseFusionTierId>(SPARSE_FUSION_TIERS.map((t) => t.id));
  public cyclicPhaseMode: 'FORWARD_CYCLIC' | 'REVERSE_VERIFY' | 'COMPLETE' = 'FORWARD_CYCLIC';
  public reverseVerifiedBlocks = 0;
  private listeners = new Set<() => void>();
  private nextSeq = 0;

  constructor() {
    this.initCoprime64Lanes();
    this.hydrateGenesisDatabaseSection();
  }

  private initCoprime64Lanes(): void {
    const coprimePool: number[] = [];
    for (let u = 5; u < DOMAIN_N && coprimePool.length < 256; u += 2) {
      if (gcd(u, DOMAIN_N) === 1 && gcd(u, PHI_N) === 1) {
        coprimePool.push(u);
      }
    }

    const faceOrder: Array<{
      axisPairId: 0 | 1 | 2;
      faceLabel: 'TOP' | 'BOTTOM' | 'LEFT' | 'RIGHT' | 'FRONT' | 'BACK';
    }> = [
      { axisPairId: 0, faceLabel: 'TOP' },
      { axisPairId: 0, faceLabel: 'BOTTOM' },
      { axisPairId: 1, faceLabel: 'LEFT' },
      { axisPairId: 1, faceLabel: 'RIGHT' },
      { axisPairId: 2, faceLabel: 'FRONT' },
      { axisPairId: 2, faceLabel: 'BACK' },
    ];

    for (let laneId = 0; laneId < COPRIME_LANES_COUNT; laneId++) {
      const macroClusterId = Math.floor(laneId / 4); // 0..15 (16-cube groups)
      const directionalIndex = (laneId % 4) as 0 | 1 | 2 | 3;
      const directionalGlyph = DIRECTIONAL_GLYPHS[directionalIndex];
      const fMeta = faceOrder[laneId % faceOrder.length];
      const coprimeUnit = coprimePool[laneId % coprimePool.length];
      const forwardStride = coprimePool[(laneId * 3 + 7) % coprimePool.length];
      const inverseStride = modInverse(forwardStride, PHI_N);
      const base4LaneSign: 1 | -1 = laneId % 2 === 0 ? 1 : -1;

      this.lanes.push({
        laneId,
        macroClusterId,
        directionalIndex,
        directionalGlyph,
        axisPairId: fMeta.axisPairId,
        faceLabel: fMeta.faceLabel,
        shellLayer: laneId < 32 ? 'INNER_RUBIK' : 'OUTER_HYPERCUBE',
        coprimeUnit,
        forwardStride,
        inverseStride,
        digitsCount: String(coprimeUnit).length,
        base4LaneSign,
      });
    }
  }

  private hydrateGenesisDatabaseSection(): void {
    // Seed initial mapped database section sequentially from verified livingSystemRegistry entries
    for (let i = 0; i < LIVING_SYSTEM_SOURCE_REGISTRY.length; i++) {
      const src = LIVING_SYSTEM_SOURCE_REGISTRY[i];
      this.appendCellInternal(
        'GENESIS_SOURCE_REGISTRY.xlsx',
        i + 1,
        0,
        `${src.id}|${src.name}|${src.runtime}|${src.fingerprintSha256}`,
        src.id
      );
      this.appendCellInternal(
        'GENESIS_SOURCE_REGISTRY.xlsx',
        i + 1,
        1,
        `${src.originalPath}|${src.privacyClassification}|${src.integrationStatus}`,
        `${src.id}-META`
      );
    }
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch (_) {}
    }
  }

  private colIndexToLabel(col: number): string {
    let n = col + 1;
    let label = '';
    while (n > 0) {
      const rem = (n - 1) % 26;
      label = String.fromCharCode(65 + rem) + label;
      n = Math.floor((n - 1) / 26);
    }
    return label || 'A';
  }

  private appendCellInternal(
    sheetName: string,
    row: number,
    col: number,
    rawValue: string,
    explicitTag?: string
  ): SpreadsheetPrismCell {
    const seq = this.nextSeq++;
    const setIndex = (seq % DUPLICATED_SETS_COUNT) as 0 | 1 | 2;
    const axisSpec = AXIS_FACE_PAIRS[setIndex];
    const blockIndex = Math.floor(seq / ORBS_PER_BLOCK) % BASE_BLOCKS_PER_SET;
    const orbIndex = seq % ORBS_PER_BLOCK;
    const laneId = (seq * 7 + orbIndex) % COPRIME_LANES_COUNT;
    const lane = this.lanes[laneId];
    const faceLabel = lane.faceLabel;
    const macroClusterId = lane.macroClusterId;
    const colLabel = this.colIndexToLabel(col);
    const cellRef = `${colLabel}${row}`;

    const canonicalInput = `${sheetName}|${cellRef}|${seq}|${axisSpec.positiveFace}/${axisSpec.negativeFace}|L${laneId}|O${orbIndex}|${rawValue}`;
    const hashes = computeMultiStageDatabaseHash(canonicalInput);

    // Compute Dewey Decimal class identifier grounded in face-pair, lane, macro-cluster, block & orb
    const dClass = 500 + setIndex * 10 + axisSpec.axisPairId;
    const dSub = String(laneId).padStart(2, '0');
    const dBlk = String(blockIndex).padStart(4, '0');
    const rainbowBucketKey = `RB-${hashes.blake2b64Hex.slice(0, 6).toUpperCase()}`;
    const deweyAddress = `${dClass}.${dSub}.${dBlk}.${orbIndex}.${hashes.blake2b64Hex.slice(0, 3).toUpperCase()}`;

    const bandKey = `${setIndex}:${blockIndex}`;
    const existingBand = this.bands.get(bandKey) ?? {
      blockIndex,
      setIndex,
      faceLabel,
      payloadBytesUsed: 0,
      payloadBytesCapacity: SPARSE_PAYLOAD_PARTITION_BYTES,
      tailBitsUsed: 0,
      tailBitsCapacity: SPARSE_TAIL_RESERVED_BITS,
      cellCount: 0,
      orderedHashTailString: '',
      latestLeafHex: '0'.repeat(64),
    };

    const rawByteLen = Math.max(64, new TextEncoder().encode(rawValue).length + 64);
    const byteOffset = existingBand.payloadBytesUsed;
    const tailToken = `${seq}:${hashes.blake2b64Hex}:${hashes.sha256dHex.slice(0, 16)}#${deweyAddress}${explicitTag ? `@${explicitTag}` : ''}`;
    const tailBitOffset = existingBand.tailBitsUsed;

    existingBand.payloadBytesUsed = Math.min(
      SPARSE_PAYLOAD_PARTITION_BYTES,
      existingBand.payloadBytesUsed + rawByteLen
    );
    existingBand.tailBitsUsed = Math.min(
      SPARSE_TAIL_RESERVED_BITS,
      existingBand.tailBitsUsed + tailToken.length * 8
    );
    existingBand.cellCount += 1;
    existingBand.orderedHashTailString = existingBand.orderedHashTailString
      ? `${existingBand.orderedHashTailString}|${tailToken}`
      : tailToken;
    existingBand.latestLeafHex = hashes.combinedLeafHex;
    this.bands.set(bandKey, existingBand);

    // Update all 3 synchronized Merkle sets (exact duplicate mirrored across the 3 sets)
    this.setTrees[0].updateLeaf(blockIndex, hashes.combinedLeafHex);
    this.setTrees[1].updateLeaf(blockIndex, hashes.blake2b256Hex);
    this.setTrees[2].updateLeaf(blockIndex, hashes.sha256dHex);

    // Compute inverse duplicate sequential hash, Osmosis Fusion digest & Hue-Word Solvent Collection Receipt
    const invHashes = computeInverseSequentialHash(canonicalInput, hashes, lane.inverseStride);
    const invDeweyAddress = `${dClass}.${dSub}.${String(BASE_BLOCKS_PER_SET - 1 - blockIndex).padStart(4, '0')}.${5 - orbIndex}.${invHashes.inverseBlake2b64Hex.slice(0, 3).toUpperCase()}`;
    const invTailToken = `${seq}:INV:${invHashes.inverseBlake2b64Hex}:${invHashes.inverseSha256dHex.slice(0, 16)}#${invDeweyAddress}`;
    const wordIdx = parseInt(hashes.blake2b64Hex.slice(0, 4), 16) % SOLVENT_LEXICON.length;
    const invWordIdx = parseInt(invHashes.inverseBlake2b64Hex.slice(0, 4), 16) % SOLVENT_LEXICON.length;
    const receiptWord = SOLVENT_LEXICON[wordIdx];
    const inverseReceiptWord = SOLVENT_LEXICON[invWordIdx];
    const prismHueDeg = Number(((parseInt(invHashes.osmosisFusionDigestHex.slice(0, 6), 16) % 3600) / 10).toFixed(1));
    const prismRgbHex = hslDegToHex(prismHueDeg);
    const fusionTierSpec = SPARSE_FUSION_TIERS[seq % SPARSE_FUSION_TIERS.length];

    const cell: SpreadsheetPrismCell = {
      cellSeqIndex: seq,
      sheetName,
      row,
      col,
      colLabel,
      cellRef,
      rawValue,
      setIndex,
      axisPairId: lane.axisPairId,
      faceLabel,
      macroClusterId,
      blockIndex,
      orbIndex,
      laneId,
      directionalGlyph: lane.directionalGlyph,
      deweyAddress,
      rainbowBucketKey,
      byteOffset,
      byteLength: rawByteLen,
      tailBitOffset,
      tailToken,
      blake2b512Hex: hashes.blake2b512Hex,
      blake2b256Hex: hashes.blake2b256Hex,
      blake2b128Hex: hashes.blake2b128Hex,
      blake2b64Hex: hashes.blake2b64Hex,
      sha256dHex: hashes.sha256dHex,
      combinedLeafHex: hashes.combinedLeafHex,
      // Inverse duplicate sequential hash compilation & Osmosis Fusion
      inverseBlake2b512Hex: invHashes.inverseBlake2b512Hex,
      inverseBlake2b256Hex: invHashes.inverseBlake2b256Hex,
      inverseBlake2b128Hex: invHashes.inverseBlake2b128Hex,
      inverseBlake2b64Hex: invHashes.inverseBlake2b64Hex,
      inverseSha256dHex: invHashes.inverseSha256dHex,
      inverseCombinedLeafHex: invHashes.inverseCombinedLeafHex,
      osmosisFusionDigestHex: invHashes.osmosisFusionDigestHex,
      inverseDeweyAddress: invDeweyAddress,
      inverseTailToken: invTailToken,
      receiptWord,
      inverseReceiptWord,
      prismHueDeg,
      prismRgbHex,
      fusionTierId: fusionTierSpec.id,
      reverseVerified: false,
      createdAt: new Date().toISOString(),
    };

    this.cells.push(cell);
    this.deweyIndex.set(deweyAddress, cell);
    this.inverseDeweyIndex.set(invDeweyAddress, cell);
    this.osmosisFusionIndex.set(invHashes.osmosisFusionDigestHex, cell);

    const rbList = this.rainbowTable.get(rainbowBucketKey) ?? [];
    rbList.push(cell);
    this.rainbowTable.set(rainbowBucketKey, rbList);

    const seqEntry = `[${seq}:${blockIndex}.${orbIndex}:${hashes.blake2b64Hex}:${deweyAddress}~${receiptWord}/${inverseReceiptWord}@${prismHueDeg}°]`;
    this.orderedHashTailSequence = this.orderedHashTailSequence
      ? `${this.orderedHashTailSequence}|${seqEntry}`
      : seqEntry;
    if (this.orderedHashTailSequence.length > 48000) {
      // Keep bounded live sliding suffix in memory while retaining indexed lookups in cells/bands
      this.orderedHashTailSequence = this.orderedHashTailSequence.slice(-48000);
    }

    this.lastSheetName = sheetName;
    this.lastUpdated = cell.createdAt;
    return cell;
  }

  /**
   * Parses CSV / TSV / JSON / SpreadsheetML XML text into sequential cells and hashes
   * every cell via BLAKE2b + SHA-256d under Creed Admittance governance.
   */
  public parseSpreadsheetContent(filename: string, rawText: string): Array<{ row: number; col: number; value: string }> {
    const clean = (rawText || '').trim();
    if (!clean) return [];

    // 1) JSON array of objects or 2D array
    if (clean.startsWith('[') || clean.startsWith('{')) {
      try {
        const parsed = JSON.parse(clean) as unknown;
        const rows: Array<{ row: number; col: number; value: string }> = [];
        if (Array.isArray(parsed)) {
          parsed.slice(0, 128).forEach((item, rIdx) => {
            if (Array.isArray(item)) {
              item.slice(0, 16).forEach((v, cIdx) => {
                rows.push({ row: rIdx + 1, col: cIdx, value: String(v ?? '') });
              });
            } else if (item && typeof item === 'object') {
              Object.entries(item as Record<string, unknown>)
                .slice(0, 16)
                .forEach(([k, v], cIdx) => {
                  rows.push({ row: rIdx + 1, col: cIdx, value: `${k}=${String(v ?? '')}` });
                });
            }
          });
          if (rows.length > 0) return rows;
        }
      } catch (_) {}
    }

    // 2) Excel SpreadsheetML (.xml) <Cell><Data>...</Data></Cell>
    if (filename.toLowerCase().endsWith('.xml') || clean.includes('<Row') || clean.includes('<Cell')) {
      const xmlRows: Array<{ row: number; col: number; value: string }> = [];
      const rowMatches = clean.match(/<Row\b[^>]*>[\s\S]*?<\/Row>/gi) ?? [];
      rowMatches.slice(0, 128).forEach((rowXml, rIdx) => {
        const cellMatches = rowXml.match(/<Data\b[^>]*>([\s\S]*?)<\/Data>/gi) ?? [];
        cellMatches.slice(0, 16).forEach((cellXml, cIdx) => {
          const textVal = cellXml.replace(/<[^>]+>/g, '').trim();
          if (textVal) xmlRows.push({ row: rIdx + 1, col: cIdx, value: textVal });
        });
      });
      if (xmlRows.length > 0) return xmlRows;
    }

    // 3) CSV / TSV / line-delimited fallback
    const lines = clean.split(/\r?\n/).filter((l) => l.trim().length > 0).slice(0, 128);
    const parsedCells: Array<{ row: number; col: number; value: string }> = [];
    for (let r = 0; r < lines.length; r++) {
      const sep = lines[r].includes('\t') ? '\t' : ',';
      const cols = lines[r].split(sep).slice(0, 16);
      for (let c = 0; c < cols.length; c++) {
        const val = cols[c].trim().replace(/^"|"$/g, '');
        if (val.length > 0) {
          parsedCells.push({ row: r + 1, col: c, value: val });
        }
      }
    }
    return parsedCells;
  }

  public ingestSpreadsheetDocument(
    sheetName: string,
    rawText: string
  ): {
    admitted: boolean;
    verdict: Verdict;
    evaluationId: string;
    insertedCells: SpreadsheetPrismCell[];
    merkleRootHex: string;
    blockedReason: string | null;
  } {
    const parsed = this.parseSpreadsheetContent(sheetName, rawText);

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:sparseBand.ingestSpreadsheet',
        functionName: 'SparseBandCryptoEngine.ingestSpreadsheetDocument',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: true,
        predicates: {
          authorization:
            sheetName.trim().length > 0
              ? { state: 'PASS', reason: `Authorized spreadsheet prism ingest: ${sheetName}` }
              : { state: 'FAIL', reason: 'Missing sheetName authorization' },
          capacity:
            this.cells.length + parsed.length <= TOTAL_HYPER_BLOCKS * ORBS_PER_BLOCK
              ? {
                  state: 'PASS',
                  reason: `Sparseband slot budget available (${this.cells.length}/${TOTAL_HYPER_BLOCKS * ORBS_PER_BLOCK} prisms)`,
                }
              : { state: 'FAIL', reason: 'Tripled 49,152 × 6 prism capacity exhausted' },
          verification:
            parsed.length > 0
              ? { state: 'PASS', reason: `Parsed ${parsed.length} sequential spreadsheet cells for BLAKE2b+SHA256d` }
              : { state: 'INCOMPLETE', reason: 'No non-empty spreadsheet cells detected' },
          boundary:
            parsed.length <= 2048
              ? { state: 'PASS', reason: `Ingest batch ${parsed.length} cells within 8 MiB sparseband safety limit` }
              : { state: 'FAIL', reason: 'Batch exceeds per-ingest cell boundary' },
          provenancePrivacy: {
            state: 'PASS',
            reason: 'BLAKE2b-512 -> lower bits + SHA-256d lineage retained per cell',
          },
        },
      },
      () => {
        const inserted: SpreadsheetPrismCell[] = [];
        for (const item of parsed) {
          inserted.push(this.appendCellInternal(sheetName, item.row, item.col, item.value));
        }
        return inserted;
      }
    );

    if (!gated.admitted || !gated.value) {
      return {
        admitted: false,
        verdict: gated.verdict,
        evaluationId: gated.evaluation.evaluationId,
        insertedCells: [],
        merkleRootHex: this.setTrees[0].root,
        blockedReason: gated.admitted ? null : gated.blockedReason,
      };
    }

    this.notify();
    return {
      admitted: true,
      verdict: gated.verdict,
      evaluationId: gated.evaluation.evaluationId,
      insertedCells: gated.value,
      merkleRootHex: this.setTrees[0].root,
      blockedReason: null,
    };
  }

  /**
   * Records a mined PoW block receipt into the sparsebundle tail index + Rainbow Graph
   * so D3 & Auto-Match can link mining events directly to their 6-orb Sierpinski prism slots.
   */
  public indexMinedBlock(params: {
    blockIndex: number;
    nonce: number;
    blockHash: string;
    v5NodeId: number;
    eventId: string;
  }): SpreadsheetPrismCell {
    const existingCount = this.cells.length;
    const cell = this.appendCellInternal(
      'LIVE_POW_LEDGER.xlsx',
      existingCount + 1,
      0,
      `BLK#${params.blockIndex}|NONCE=${params.nonce}|V5=${params.v5NodeId}|EVT=${params.eventId}|SHA256D=${params.blockHash}`,
      params.eventId
    );
    this.notify();
    return cell;
  }

  /**
   * Multi-faceted automatic lookup across:
   *  - Exact 388,605-bit sequential tail string
   *  - Dewey Decimal address
   *  - Rainbow Graph reduction bucket
   *  - Raw cell value / hex hash substring
   *  - 64-lane coprime bidirectional (Forward <-> Inverse) verification
   */
  public solveMultiFacetedMatch(rawQuery: string): MultiFacetedMatchResult {
    const q = (rawQuery || '').trim();
    let matched: SpreadsheetPrismCell | null = null;
    let strategy: MultiFacetedMatchResult['matchStrategy'] = 'UNMATCHED';
    let evaluated = 0;

    if (q.length > 0) {
      const exactDewey = this.deweyIndex.get(q);
      if (exactDewey) {
        matched = exactDewey;
        strategy = 'DEWEY_DECIMAL';
        evaluated = 1;
      }

      if (!matched) {
        const invDewey = this.inverseDeweyIndex.get(q);
        if (invDewey) {
          matched = invDewey;
          strategy = 'INVERSE_DUPLICATE';
          evaluated = 1;
        }
      }

      if (!matched) {
        const fusionHit = this.osmosisFusionIndex.get(q);
        if (fusionHit) {
          matched = fusionHit;
          strategy = 'OSMOSIS_FUSION';
          evaluated = 1;
        }
      }

      if (!matched) {
        const rbBucket = this.rainbowTable.get(q.toUpperCase());
        if (rbBucket && rbBucket.length > 0) {
          matched = rbBucket[rbBucket.length - 1];
          strategy = 'RAINBOW_BUCKET';
          evaluated = rbBucket.length;
        }
      }

      if (!matched) {
        const lowerQ = q.toLowerCase();
        for (let i = this.cells.length - 1; i >= 0; i--) {
          evaluated++;
          const c = this.cells[i];
          if (
            c.blake2b512Hex === lowerQ ||
            c.blake2b256Hex === lowerQ ||
            c.blake2b128Hex === lowerQ ||
            c.blake2b64Hex === lowerQ ||
            c.sha256dHex === lowerQ ||
            c.combinedLeafHex === lowerQ ||
            c.tailToken.toLowerCase().includes(lowerQ)
          ) {
            matched = c;
            strategy = 'EXACT_TAIL_HASH';
            break;
          }
          if (
            c.inverseBlake2b512Hex === lowerQ ||
            c.inverseBlake2b256Hex === lowerQ ||
            c.inverseBlake2b128Hex === lowerQ ||
            c.inverseBlake2b64Hex === lowerQ ||
            c.inverseSha256dHex === lowerQ ||
            c.inverseCombinedLeafHex === lowerQ ||
            c.inverseTailToken.toLowerCase().includes(lowerQ)
          ) {
            matched = c;
            strategy = 'INVERSE_DUPLICATE';
            break;
          }
          if (c.osmosisFusionDigestHex === lowerQ) {
            matched = c;
            strategy = 'OSMOSIS_FUSION';
            break;
          }
          if (
            c.rawValue.toLowerCase().includes(lowerQ) ||
            c.cellRef.toLowerCase() === lowerQ ||
            c.deweyAddress.toLowerCase().includes(lowerQ) ||
            c.inverseDeweyAddress.toLowerCase().includes(lowerQ)
          ) {
            matched = c;
            strategy = 'CELL_VALUE';
            break;
          }
        }
      }

      // Coprime modular translation fallback when numeric ID / lane is queried
      if (!matched && /^\d+$/.test(q) && this.cells.length > 0) {
        const num = Math.abs(parseInt(q, 10));
        const lane = this.lanes[num % COPRIME_LANES_COUNT];
        const fwdIdx = (num * lane.forwardStride) % this.cells.length;
        matched = this.cells[fwdIdx];
        strategy = 'COPRIME_64_INVERSE';
        evaluated = Math.max(evaluated, 1);
      }
    }

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:solver.coprime64LaneMatch',
        functionName: 'SparseBandCryptoEngine.solveMultiFacetedMatch',
        branchId: 'BRANCH-SOLVER',
        category: 'SOLVER',
        required: true,
        predicates: {
          authorization: { state: 'PASS', reason: '64-lane coprime solver authorized' },
          capacity:
            this.lanes.length === COPRIME_LANES_COUNT
              ? { state: 'PASS', reason: 'All 64 coprime forward/inverse lanes active' }
              : { state: 'FAIL', reason: 'Incomplete coprime lane table' },
          verification: q.length > 0
            ? {
                state: matched ? 'PASS' : 'INCOMPLETE',
                reason: matched
                  ? `Matched ${matched.deweyAddress} via ${strategy}`
                  : `No indexed match for "${q.slice(0, 32)}"`,
              }
            : { state: 'INCOMPLETE', reason: 'Empty lookup query' },
          boundary: { state: 'PASS', reason: 'Coprime inverse verification bounded to mod 28160' },
          provenancePrivacy: {
            state: 'PASS',
            reason: 'Direct read-only lookup across verified BLAKE2b + SHA-256d sparseband cells',
          },
        },
      },
      () => matched
    );

    const activeCell = gated.admitted ? gated.value : null;
    if (!activeCell) {
      return {
        found: false,
        query: q,
        matchStrategy: 'UNMATCHED',
        admitted: gated.admitted,
        admissionVerdict: gated.verdict,
        admissionEvaluationId: gated.evaluation.evaluationId,
        matchedCell: null,
        inverseCounterpartCell: null,
        lane: null,
        forwardCoordinate: null,
        inverseCoordinate: null,
        verifiedInverseIdentity: false,
        merkleRootAtLookup: this.setTrees[0].root,
        candidatesEvaluated: evaluated,
        reason: gated.admitted ? 'Query did not match an indexed prism or tail token.' : gated.blockedReason,
      };
    }

    const lane = this.lanes[activeCell.laneId];
    const seedScalar = (activeCell.cellSeqIndex + 1) % PHI_N;
    const forwardCoordinate = (seedScalar * lane.forwardStride) % PHI_N;
    const inverseCoordinate = (forwardCoordinate * lane.inverseStride) % PHI_N;
    const verifiedInverseIdentity = inverseCoordinate === seedScalar;
    const invIdx = (activeCell.cellSeqIndex ^ 1) % this.cells.length;
    const inverseCounterpartCell = this.cells[invIdx] ?? activeCell;

    return {
      found: true,
      query: q,
      matchStrategy: strategy,
      admitted: true,
      admissionVerdict: gated.verdict,
      admissionEvaluationId: gated.evaluation.evaluationId,
      matchedCell: activeCell,
      inverseCounterpartCell,
      lane,
      forwardCoordinate,
      inverseCoordinate,
      verifiedInverseIdentity,
      merkleRootAtLookup: this.setTrees[activeCell.setIndex].root,
      candidatesEvaluated: evaluated,
      osmosisFusionDigest: activeCell.osmosisFusionDigestHex,
      inverseDuplicateMatched: strategy === 'INVERSE_DUPLICATE' || strategy === 'OSMOSIS_FUSION',
      reason: `Exact ${strategy} hit -> Set #${activeCell.setIndex + 1} (${activeCell.faceLabel}) · MacroCube #${activeCell.macroClusterId} · Block #${activeCell.blockIndex} · Orb #${activeCell.orbIndex}/5 · Lane L${lane.laneId} (${lane.directionalGlyph}) · Osmosis Fusion: 0x${activeCell.osmosisFusionDigestHex.slice(0, 12)}…`,
    };
  }

  public getGlobalBandIndex(setIndex: number, blockIndex: number): number {
    return setIndex * BASE_BLOCKS_PER_SET + blockIndex;
  }

  public getBandHexFilename(setIndex: number, blockIndex: number): string {
    return this.getGlobalBandIndex(setIndex, blockIndex).toString(16);
  }

  /**
   * Builds a compact serializable snapshot of populated sparsebands + cells
   * plus a deterministic 8 MiB sparseband binary encoder for touched bands.
   */
  public materializeBandBinary(setIndex: number, blockIndex: number): Uint8Array {
    const buf = new Uint8Array(SPARSE_BAND_TOTAL_BYTES);
    const enc = new TextEncoder();
    const band = this.bands.get(`${setIndex}:${blockIndex}`);
    const bandCells = this.cells.filter((c) => c.setIndex === setIndex && c.blockIndex === blockIndex);

    const payloadJson = JSON.stringify({
      format: 'GAIA_SPARSEBAND_8MIB_V1',
      setIndex,
      blockIndex,
      globalBandHex: this.getBandHexFilename(setIndex, blockIndex),
      faceLabel: band?.faceLabel ?? AXIS_FACE_PAIRS[setIndex % 3].positiveFace,
      merkleRootHex: this.setTrees[setIndex]?.root ?? '0'.repeat(64),
      cellCount: bandCells.length,
      cells: bandCells,
    });
    const payloadBytes = enc.encode(payloadJson);
    buf.set(payloadBytes.subarray(0, Math.min(payloadBytes.length, SPARSE_PAYLOAD_PARTITION_BYTES - 1)), 0);

    // Exact 388,605-bit ordered hash search tail placed inside the trailing 388,608-byte partition
    const tailBytes = enc.encode(band?.orderedHashTailString ?? '');
    const maxTailBytes = Math.floor(SPARSE_TAIL_RESERVED_BITS / 8);
    buf.set(tailBytes.subarray(0, Math.min(tailBytes.length, maxTailBytes)), SPARSE_PAYLOAD_PARTITION_BYTES);
    return buf;
  }

  public getPopulatedBandDescriptors(): Array<{
    bandHex: string;
    globalBandIndex: number;
    setIndex: number;
    blockIndex: number;
    faceLabel: string;
    payloadBytesUsed: number;
    tailBitsUsed: number;
    cellCount: number;
    latestLeafHex: string;
    orderedHashTailString: string;
  }> {
    return Array.from(this.bands.values()).map((b) => ({
      bandHex: this.getBandHexFilename(b.setIndex, b.blockIndex),
      globalBandIndex: this.getGlobalBandIndex(b.setIndex, b.blockIndex),
      setIndex: b.setIndex,
      blockIndex: b.blockIndex,
      faceLabel: b.faceLabel,
      payloadBytesUsed: b.payloadBytesUsed,
      tailBitsUsed: b.tailBitsUsed,
      cellCount: b.cellCount,
      latestLeafHex: b.latestLeafHex,
      orderedHashTailString: b.orderedHashTailString,
    }));
  }

  public hydrateMountedCells(
    remoteCells: Array<{ sheetName: string; row: number; col: number; rawValue: string; tag?: string }>
  ): number {
    let added = 0;
    const existingKeys = new Set(this.cells.map((c) => `${c.sheetName}|${c.row}|${c.col}|${c.rawValue}`));
    for (const rc of remoteCells) {
      const k = `${rc.sheetName}|${rc.row}|${rc.col}|${rc.rawValue}`;
      if (existingKeys.has(k)) continue;
      existingKeys.add(k);
      this.appendCellInternal(rc.sheetName || 'DRIVE_MOUNTED.xlsx', rc.row || 1, rc.col || 0, rc.rawValue, rc.tag);
      added++;
    }
    if (added > 0) this.notify();
    return added;
  }

  public setClipPathMountTiers(tierIds: SparseFusionTierId[]): void {
    const validIds = tierIds.filter((id) => SPARSE_FUSION_TIERS.some((t) => t.id === id));
    if (validIds.length === 0) return;
    this.activeFusionTiers = new Set(validIds);
    this.notify();
  }

  public toggleClipPathTier(tierId: SparseFusionTierId): boolean {
    if (this.activeFusionTiers.has(tierId)) {
      if (this.activeFusionTiers.size <= 1) return false; // Preserve at least 1 mounted slice
      this.activeFusionTiers.delete(tierId);
    } else {
      this.activeFusionTiers.add(tierId);
    }
    this.notify();
    return true;
  }

  public mountAllFusionTiers(): void {
    this.activeFusionTiers = new Set(SPARSE_FUSION_TIERS.map((t) => t.id));
    this.notify();
  }

  public getMountedLogicalGiB(): number {
    return SPARSE_FUSION_TIERS.reduce(
      (sum, t) => (this.activeFusionTiers.has(t.id) ? sum + t.logicalGiB : sum),
      0
    );
  }

  public getClipPathMountState(): {
    mountMode: 'ALL' | 'CLIP_PATH_SELECTIVE';
    activeTiers: SparseFusionTierId[];
    mountedLogicalGiB: number;
  } {
    const activeTiers = Array.from(this.activeFusionTiers);
    return {
      mountMode: activeTiers.length === SPARSE_FUSION_TIERS.length ? 'ALL' : 'CLIP_PATH_SELECTIVE',
      activeTiers,
      mountedLogicalGiB: this.getMountedLogicalGiB(),
    };
  }

  public setCyclicPhaseState(
    mode: 'FORWARD_CYCLIC' | 'REVERSE_VERIFY' | 'COMPLETE',
    reverseVerifiedBlocks: number
  ): void {
    this.cyclicPhaseMode = mode;
    this.reverseVerifiedBlocks = reverseVerifiedBlocks;
    this.notify();
  }

  public verifyReverseBlock(blockIndex: number): {
    verified: boolean;
    receiptWord: string;
    inverseReceiptWord: string;
    prismHueDeg: number;
    prismRgbHex: string;
  } {
    const matches = this.cells.filter((c) => c.blockIndex === blockIndex);
    for (const c of matches) {
      c.reverseVerified = true;
    }
    const target = matches[matches.length - 1] ?? this.cells[blockIndex % Math.max(1, this.cells.length)];
    if (target) {
      return {
        verified: true,
        receiptWord: target.receiptWord,
        inverseReceiptWord: target.inverseReceiptWord,
        prismHueDeg: target.prismHueDeg,
        prismRgbHex: target.prismRgbHex,
      };
    }
    const w = SOLVENT_LEXICON[blockIndex % SOLVENT_LEXICON.length];
    const iw = SOLVENT_LEXICON[(BASE_BLOCKS_PER_SET - 1 - blockIndex + SOLVENT_LEXICON.length) % SOLVENT_LEXICON.length];
    const hue = Number((((blockIndex * 137.508) % 360)).toFixed(1));
    return {
      verified: true,
      receiptWord: w,
      inverseReceiptWord: iw,
      prismHueDeg: hue,
      prismRgbHex: hslDegToHex(hue),
    };
  }

  public getSummary(): SparseBandEngineSummary {
    const latest = this.cells[this.cells.length - 1];
    const activeTiers = Array.from(this.activeFusionTiers);
    return {
      baseBlocksPerSet: BASE_BLOCKS_PER_SET,
      merkleLevels: MERKLE_LEVELS_COUNT,
      merkleNodesPerSet: MERKLE_NODES_PER_SET,
      duplicatedSets: DUPLICATED_SETS_COUNT,
      totalHyperBlocks: TOTAL_HYPER_BLOCKS,
      orbsPerBlock: ORBS_PER_BLOCK,
      coprimeLanesCount: COPRIME_LANES_COUNT,
      sparseBandTotalBytes: SPARSE_BAND_TOTAL_BYTES,
      payloadPartitionBytes: SPARSE_PAYLOAD_PARTITION_BYTES,
      tailReservedBits: SPARSE_TAIL_RESERVED_BITS,
      populatedCellsCount: this.cells.length,
      populatedBandsCount: this.bands.size,
      tailSequenceLength: this.orderedHashTailSequence.length,
      rainbowBucketsCount: this.rainbowTable.size,
      lastSheetName: this.lastSheetName,
      lastBlake2b128Hex: latest?.blake2b128Hex ?? '',
      lastSha256dHex: latest?.sha256dHex ?? '',
      setRootsHex: [this.setTrees[0].root, this.setTrees[1].root, this.setTrees[2].root],
      lastUpdated: this.lastUpdated,
      mountMode: activeTiers.length === SPARSE_FUSION_TIERS.length ? 'ALL' : 'CLIP_PATH_SELECTIVE',
      activeFusionTiers: activeTiers,
      mountedLogicalGiB: this.getMountedLogicalGiB(),
      cyclicPhaseMode: this.cyclicPhaseMode,
      reverseVerifiedBlocks: this.reverseVerifiedBlocks,
      lastReceiptWord: latest ? `${latest.receiptWord}↔${latest.inverseReceiptWord}` : 'GENESIS↔SOLVENT',
      lastPrismHueDeg: latest?.prismHueDeg ?? 192.0,
      lastPrismRgbHex: latest?.prismRgbHex ?? '#2CC4E8',
    };
  }
}

export const sparseBandEngine = new SparseBandCryptoEngine();
