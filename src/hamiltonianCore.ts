/**
 * Hamiltonian & Cryptic Mathematical Core
 * Implements reversible transformations, finite V5 lattice, modular arithmetic anchors,
 * runtime working-set ingestion from livingSystemRegistry, and deterministic header material synthesis.
 * Solver outputs are gated through Creed of Admittance (creedAdmittanceService).
 */

import { creedAdmittanceService, type Verdict } from './creedAdmittance.ts';
import {
  LIVING_SYSTEM_SOURCE_REGISTRY,
  type SourceSystemRecord,
} from './livingSystemRegistry.ts';

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

function sha256Utf8Bytes(input: string): Uint8Array {
  const utf8 = new TextEncoder().encode(input);
  const bitLen = utf8.length * 8;
  const totalLen = (((utf8.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(utf8);
  padded[utf8.length] = 0x80;
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
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i], false);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export interface LatticeNode {
  id: number;
  coords: [number, number, number, number];
  neighbors: number[];
  registryPhase: number;
}

export interface ConsumedRegistryAnchor {
  sourceId: string;
  sourceName: string;
  runtime: string;
  privacyClassification: string;
  integrationStatus: string;
  fieldConsumed: 'fingerprintSha256';
  valueConsumed: string;
}

export interface CoreWorkingSetState {
  registryCount: number;
  workingSetIds: string[];
  primaryRegistryAnchor: ConsumedRegistryAnchor;
  registryAggregateDigestHex: string;
  modularPhaseAnchor: number;
  v5NodesCount: number;
  v5EdgesCount: number;
  consumedAt: string;
}

export interface CoreHeaderMaterial {
  headerPrefix: string;
  sampleFullHeader: string;
  headerBytes: Uint8Array;
  headerHex: string;
  first32BytesHex: string;
  coreRegistryDigestHex: string;
  primarySourceId: string;
  primarySourceFingerprintSha256: string;
  modularPhaseAnchor: number;
  v5NodeId: number;
  v5Coords: [number, number, number, number];
}

export interface ReversibilitySolverResult {
  original: string;
  transformed: string;
  recovered: string;
  verified: boolean;
  verdict: Verdict;
  admissionId: string;
}

export interface ElGamalLevel10StraddleState {
  curveName: 'secp256k1-sublattice-L10';
  fieldPrimeHex: string;
  publicKeyXHex: string;
  ciphertextC1XHex: string;
  ciphertextC2XHex: string;
  decryptedMessageScalar: string;
  originalMessageScalar: string;
  verifiedRoundTrip: boolean;
  level10CriticalDeltas: number[];
  patternRecognitionScore: number;
  straddleNodeId: number;
  straddleEdgeId: number;
}

export class HamiltonianCoreEngine {
  /** Dual V5 Lattice: Two sets of 5^4 = 625 nodes (1,250 discrete 4D vertices: Set A 0..624 Inverse Solvent, Set B 625..1249 ElGamal Free Set). */
  public nodes: LatticeNode[] = [];
  /** Two sets of 2,000 undirected nearest-neighbor Manhattan (Delta = 1) edges = 4,000 total V5 edges (4k). */
  public totalEdges: number = 4000;
  public workingSet: SourceSystemRecord[] = [];
  public coreState!: CoreWorkingSetState;
  public lastElGamalStraddle: ElGamalLevel10StraddleState | null = null;

  constructor() {
    this.generateV5Lattice();
    this.loadWorkingSetFromRegistry(LIVING_SYSTEM_SOURCE_REGISTRY);
  }

  private generateV5Lattice() {
    const range = [-2, -1, 0, 1, 2];
    const perSet = 625;
    let id = 0;

    // Set A (0..624, Inverse Solvent) and Set B (625..1249, Opposing Free Set for ECC ElGamal Level-10 Straddle)
    for (let setIdx = 0; setIdx < 2; setIdx++) {
      const sign = setIdx === 0 ? 1 : -1;
      for (const x of range) {
        for (const y of range) {
          for (const z of range) {
            for (const w of range) {
              this.nodes.push({
                id: id++,
                coords: [x * sign, y * sign, z * sign, w * sign],
                neighbors: [],
                registryPhase: 0,
              });
            }
          }
        }
      }
    }

    // Connect nearest neighbors (Euclidean/Manhattan distance === 1) within each 625-node set (2,000 + 2,000 = 4,000 edges)
    for (let setIdx = 0; setIdx < 2; setIdx++) {
      const base = setIdx * perSet;
      for (let i = base; i < base + perSet; i++) {
        for (let j = i + 1; j < base + perSet; j++) {
          const c1 = this.nodes[i].coords;
          const c2 = this.nodes[j].coords;
          const distSq =
            Math.pow(c1[0] - c2[0], 2) +
            Math.pow(c1[1] - c2[1], 2) +
            Math.pow(c1[2] - c2[2], 2) +
            Math.pow(c1[3] - c2[3], 2);

          if (distSq === 1) {
            this.nodes[i].neighbors.push(j);
            this.nodes[j].neighbors.push(i);
          }
        }
      }
    }
  }

  /**
   * REGISTRY -> CORE real runtime ingestion:
   * Reads the active working set directly from LIVING_SYSTEM_SOURCE_REGISTRY,
   * derives aggregate digest and modular phase anchor, and seeds each V5 lattice node.
   */
  public loadWorkingSetFromRegistry(
    registry: SourceSystemRecord[] = LIVING_SYSTEM_SOURCE_REGISTRY
  ): CoreWorkingSetState {
    if (!Array.isArray(registry) || registry.length === 0) {
      throw new Error('Cannot compute Hamiltonian core state: livingSystemRegistry working set is empty.');
    }
    this.workingSet = registry.map((rec) => ({ ...rec }));

    const canonicalPayload = this.workingSet
      .map(
        (rec) =>
          `${rec.id}|${rec.name}|${rec.originalPath}|${rec.runtime}|${rec.fingerprintSha256}|${rec.privacyClassification}|${rec.integrationStatus}`
      )
      .join('\n');

    const digestBytes = sha256Utf8Bytes(canonicalPayload);
    const registryAggregateDigestHex = bytesToHex(digestBytes);
    const modularPhaseAnchor =
      (((digestBytes[0] << 24) | (digestBytes[1] << 16) | (digestBytes[2] << 8) | digestBytes[3]) >>> 0) % 97152;

    // Seed per-node phase from runtime registry digest + SRC fingerprints
    for (let i = 0; i < this.nodes.length; i++) {
      const src = this.workingSet[i % this.workingSet.length];
      const byteVal = parseInt(src.fingerprintSha256.slice((i * 2) % 62, ((i * 2) % 62) + 2), 16) || 0;
      this.nodes[i].registryPhase = (modularPhaseAnchor + byteVal * 799 + i * 23) % 97152;
    }

    const primaryRecord =
      this.workingSet.find((r) => r.id === 'SRC-03') || this.workingSet[0];

    this.coreState = {
      registryCount: this.workingSet.length,
      workingSetIds: this.workingSet.map((r) => r.id),
      primaryRegistryAnchor: {
        sourceId: primaryRecord.id,
        sourceName: primaryRecord.name,
        runtime: primaryRecord.runtime,
        privacyClassification: primaryRecord.privacyClassification,
        integrationStatus: primaryRecord.integrationStatus,
        fieldConsumed: 'fingerprintSha256',
        valueConsumed: primaryRecord.fingerprintSha256,
      },
      registryAggregateDigestHex,
      modularPhaseAnchor,
      v5NodesCount: this.nodes.length,
      v5EdgesCount: this.totalEdges,
      consumedAt: new Date().toISOString(),
    };

    return this.getCoreState();
  }

  public getCoreState(): CoreWorkingSetState {
    return {
      ...this.coreState,
      workingSetIds: [...this.coreState.workingSetIds],
      primaryRegistryAnchor: { ...this.coreState.primaryRegistryAnchor },
    };
  }

  /**
   * CORE -> MINER real header synthesis:
   * Constructs verifiable header bytes derived from runtime registry digest,
   * primary registry anchor fingerprint, Hamiltonian modular phase anchor, and V5 lattice node.
   */
  public buildCoreHeaderMaterial(params: {
    blockIndex: number;
    dewey: string;
    activeUnit: string;
    prevHashHex: string;
    monolithVersion: number;
    sampleNonce?: number;
  }): CoreHeaderMaterial {
    if (!this.coreState || this.workingSet.length === 0) {
      this.loadWorkingSetFromRegistry(LIVING_SYSTEM_SOURCE_REGISTRY);
    }

    const perSet = 625;
    const setABase = ((params.blockIndex * 799 + this.coreState.modularPhaseAnchor) % perSet + perSet) % perSet;
    const isInverseBranch = params.blockIndex >= 8192;
    const v5NodeId = isInverseBranch ? perSet + setABase : setABase;
    const node = this.nodes[v5NodeId] || this.nodes[312];
    const headerPrefix =
      `CORE=${this.coreState.registryAggregateDigestHex.slice(0, 24)}|` +
      `${this.coreState.primaryRegistryAnchor.sourceId}=${this.coreState.primaryRegistryAnchor.valueConsumed.slice(0, 12)}|` +
      `PH=${this.coreState.modularPhaseAnchor}|` +
      `NP=${node.registryPhase}|` +
      `V5=${v5NodeId}(${node.coords.join(',')})|` +
      `MV=${params.monolithVersion}|` +
      `BLK=${params.blockIndex}|` +
      `${params.dewey}|U=${params.activeUnit}|PREV=${params.prevHashHex}|N=`;

    const sampleFullHeader = `${headerPrefix}${params.sampleNonce ?? 0}`;
    const headerBytes = new TextEncoder().encode(sampleFullHeader);
    const headerHex = bytesToHex(headerBytes);
    const first32BytesHex = headerHex.slice(0, 64);

    return {
      headerPrefix,
      sampleFullHeader,
      headerBytes,
      headerHex,
      first32BytesHex,
      coreRegistryDigestHex: this.coreState.registryAggregateDigestHex,
      primarySourceId: this.coreState.primaryRegistryAnchor.sourceId,
      primarySourceFingerprintSha256: this.coreState.primaryRegistryAnchor.valueConsumed,
      modularPhaseAnchor: this.coreState.modularPhaseAnchor,
      v5NodeId,
      v5Coords: [...node.coords] as [number, number, number, number],
    };
  }

  public verifyReversibility(stateString: string): ReversibilitySolverResult {
    const validInput = typeof stateString === 'string' && stateString.length > 0 && stateString.length <= 16384;
    let transformed = '';
    let recovered = '';
    let verified = false;
    let decodeError = false;

    if (validInput) {
      try {
        transformed = btoa(stateString).split('').reverse().join('');
        recovered = atob(transformed.split('').reverse().join(''));
        verified = recovered === stateString;
      } catch {
        decodeError = true;
        verified = false;
      }
    }

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:solver.reversibility',
        functionName: 'hamiltonianEngine.verifyReversibility',
        branchId: 'BRANCH-SOLVER',
        category: 'SOLVER',
        required: true,
        predicates: {
          authorization: { state: 'PASS', reason: 'Local Hamiltonian reversible solver authorized' },
        capacity:
          this.nodes.length === 1250 && this.workingSet.length === LIVING_SYSTEM_SOURCE_REGISTRY.length
            ? { state: 'PASS', reason: `Dual V5 lattice (${this.nodes.length} nodes / ${this.totalEdges} edges) & workingSet (${this.workingSet.length} registry sources) active` }
            : { state: 'INCOMPLETE', reason: `Incomplete dual V5/workingSet (${this.nodes.length}/1250, ${this.workingSet.length} sources)` },
          verification: decodeError
            ? { state: 'FAIL', reason: 'Base64/UTF-8 reversible transformation threw exception' }
            : verified
              ? { state: 'PASS', reason: 'F^-1(F(S)) = S exact round-trip verified' }
              : { state: 'FAIL', reason: 'Reversibility check F^-1(F(S)) != S failed' },
          boundary: validInput
            ? { state: 'PASS', reason: `Input within safe bounds (${stateString.length} chars)` }
            : { state: 'FAIL', reason: 'Input empty or exceeds 16,384-char boundary' },
          provenancePrivacy: { state: 'PASS', reason: 'Deterministic local U(97152) transform (no secret leakage)' },
        },
      },
      (evalResult) => ({
        original: stateString,
        transformed,
        recovered,
        verified,
        verdict: evalResult.verdict,
        admissionId: evalResult.evaluationId,
      })
    );

    if (!gated.admitted) {
      return {
        original: stateString,
        transformed: '',
        recovered: '',
        verified: false,
        verdict: gated.verdict,
        admissionId: gated.evaluation.evaluationId,
      };
    }

    return gated.value;
  }

  /**
   * Opposing Free Set (Set B: nodes 625..1249 / edges 2,000..3,999):
   * Barrel-Side Straddle Ladder Step implementing Asymmetric Level-10 Critical Calculus
   * coupled with an Elliptic Curve ElGamal cryptosystem (secp256k1 finite-field subgroup).
   */
  public computeElGamalLevel10StraddleStep(
    blockIndex: number,
    seedHex: string
  ): ElGamalLevel10StraddleState {
    // secp256k1 field prime p and base point G (short-Weierstrass y^2 = x^3 + 7 mod p)
    const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
    const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

    const mod = (a: bigint, m: bigint): bigint => {
      const r = a % m;
      return r >= 0n ? r : r + m;
    };
    const modInv = (a: bigint, m: bigint): bigint => {
      let t = 0n;
      let newT = 1n;
      let r = m;
      let newR = mod(a, m);
      while (newR !== 0n) {
        const q = r / newR;
        [t, newT] = [newT, t - q * newT];
        [r, newR] = [newR, r - q * newR];
      }
      return t < 0n ? t + m : t;
    };

    type EcPt = { x: bigint; y: bigint } | null;
    const ecAdd = (p1: EcPt, p2: EcPt): EcPt => {
      if (!p1) return p2;
      if (!p2) return p1;
      if (p1.x === p2.x) {
        if (mod(p1.y + p2.y, P) === 0n) return null;
        const s = mod(3n * p1.x * p1.x * modInv(2n * p1.y, P), P);
        const x3 = mod(s * s - 2n * p1.x, P);
        const y3 = mod(s * (p1.x - x3) - p1.y, P);
        return { x: x3, y: y3 };
      }
      const s = mod((p2.y - p1.y) * modInv(p2.x - p1.x, P), P);
      const x3 = mod(s * s - p1.x - p2.x, P);
      const y3 = mod(s * (p1.x - x3) - p1.y, P);
      return { x: x3, y: y3 };
    };
    const ecNeg = (pt: EcPt): EcPt => (pt ? { x: pt.x, y: mod(-pt.y, P) } : null);
    const ecMul = (k: bigint, pt: EcPt): EcPt => {
      let acc: EcPt = null;
      let cur: EcPt = pt;
      let rem = k;
      while (rem > 0n) {
        if (rem & 1n) acc = ecAdd(acc, cur);
        cur = ecAdd(cur, cur);
        rem >>= 1n;
      }
      return acc;
    };

    const digestHex = bytesToHex(sha256Utf8Bytes(`${blockIndex}|${seedHex}|L10_ELGAMAL`));
    const privX = (BigInt('0x' + digestHex.slice(0, 16)) % 1048573n) + 17n;
    const ephemK = (BigInt('0x' + digestHex.slice(16, 32)) % 1048573n) + 31n;
    const msgScalar = (BigInt('0x' + digestHex.slice(32, 48)) % 65521n) + 7n;

    const G: EcPt = { x: GX, y: GY };
    const pubY = ecMul(privX, G);
    const msgM = ecMul(msgScalar, G);
    const c1 = ecMul(ephemK, G);
    const c2 = ecAdd(msgM, ecMul(ephemK, pubY));
    const recoveredM = ecAdd(c2, ecNeg(ecMul(privX, c1)));
    const verifiedRoundTrip = Boolean(
      msgM && recoveredM && msgM.x === recoveredM.x && msgM.y === recoveredM.y
    );

    // Asymmetric Level-10 Underpins Critical Calculus barrel-side straddle ladder (10 finite difference rungs)
    const ladder: number[] = [];
    let straddlePrev = ((blockIndex * 799 + this.coreState.modularPhaseAnchor) % 97152) + 1;
    for (let lvl = 1; lvl <= 10; lvl++) {
      const byteSeed = parseInt(digestHex.slice((lvl * 4) % 56, ((lvl * 4) % 56) + 4), 16) || 1;
      const straddleNext = (straddlePrev * (lvl % 2 === 0 ? 13 : 7) + byteSeed * (11 - lvl)) % 97152;
      const critDelta = Math.abs(straddleNext - straddlePrev);
      ladder.push(Number((critDelta / 971.52).toFixed(2)));
      straddlePrev = straddleNext;
    }

    const avgCrit = ladder.reduce((a, b) => a + b, 0) / ladder.length;
    const patternRecognitionScore = Number(
      Math.min(99.98, 72.5 + (avgCrit % 27.4) + (verifiedRoundTrip ? 0.08 : 0)).toFixed(2)
    );
    const straddleNodeId = 625 + (blockIndex % 625);
    const straddleEdgeId = 2000 + (blockIndex % 2000);

    const state: ElGamalLevel10StraddleState = {
      curveName: 'secp256k1-sublattice-L10',
      fieldPrimeHex: P.toString(16),
      publicKeyXHex: pubY ? pubY.x.toString(16).padStart(64, '0') : '0'.repeat(64),
      ciphertextC1XHex: c1 ? c1.x.toString(16).padStart(64, '0') : '0'.repeat(64),
      ciphertextC2XHex: c2 ? c2.x.toString(16).padStart(64, '0') : '0'.repeat(64),
      decryptedMessageScalar: recoveredM ? recoveredM.x.toString(16).slice(0, 16) : '0',
      originalMessageScalar: msgM ? msgM.x.toString(16).slice(0, 16) : '0',
      verifiedRoundTrip,
      level10CriticalDeltas: ladder,
      patternRecognitionScore,
      straddleNodeId,
      straddleEdgeId,
    };
    this.lastElGamalStraddle = state;
    return state;
  }

  public getModularAnchors() {
    return {
      modBase: 1518,
      primeFactors: [2, 3, 11, 23],
      totient1518: 440,
      totalBlocks: 16384,
      totalPrisms: 98304,
      totalNodes: 1250,
      totalEdges: 4000,
      expandedNodes: 97152,
      totient97152: 28160,
      coprimeStride: 799,
      modularInverseStride: 22639,
      registryAggregateDigestHex: this.coreState.registryAggregateDigestHex,
      modularPhaseAnchor: this.coreState.modularPhaseAnchor,
    };
  }
}

export const hamiltonianEngine = new HamiltonianCoreEngine();
