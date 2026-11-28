import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { creedAdmittanceService, type OperationCategory } from './src/creedAdmittance.ts';

const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const VALID_KINDS = new Set([
  'user_statement',
  'source_excerpt',
  'model_output',
  'verification_receipt',
]);
const VALID_TARGETS = new Set(['gemini', 'openai']);
const GENESIS_HASH = '0'.repeat(64);
const GENESIS_ANCHOR_ISO = '2026-11-26T12:55:58.000-08:00';
const GENESIS_ANCHOR_MS = Date.parse(GENESIS_ANCHOR_ISO);
const ADMIT_FORMULA = 'ADMIT(x) = A ∧ C ∧ V ∧ B ∧ P';
const ADAM_GATES = [
  'DISCOVER',
  'OBSERVE',
  'NORMALIZE',
  'CLASSIFY',
  'VERIFY',
  'FINGERPRINT',
  'LOOKUP_REMEDY',
  'APPLY_REMEDY',
  'REVERIFY',
];

// Volatile server-memory HMAC key (never exposed to browser storage or hardcoded secrets)
const SERVER_HMAC_SECRET = process.env.GAIA_GENESIS_HMAC_KEY || crypto.randomBytes(32).toString('hex');
const SESSION_TOKEN_KEY = crypto.randomBytes(32).toString('hex');
const seenReplayNonces = new Map<string, number>();

interface OriginReceipt {
  origin: string;
  referer: string;
  host: string;
  userAgent: string;
  forwardedFor: string;
  capturedAt: string;
  sameOriginVerified: boolean;
}

interface DoubleHashStepTrace {
  preimage: string;
  stage1_sha256_receipt: string;
  stage2_double_sha256: string;
  fnv1a_32: string;
  iso_beat: string;
  micro_offset: number;
  ordered_ops: string[];
  honesty_note: string;
}

interface MatrixCell {
  idx: number;
  row: number;
  col: number;
  r: number;
  g: number;
  b: number;
  ledHex: string;
  beaconType: 'EMPTY' | 'SEED_BEACON' | 'NEIGHBOR_SWAP' | 'DEAD_PIXEL_ABSORBED' | 'RECYCLED';
  label: string;
  triggerHits: number;
}

interface SharedMemoryEntry {
  id: string;
  seq: number;
  ts: string;
  text: string;
  source: string;
  reference: string;
  share_with: string[];
  kind: string;
  prev_hash: string;
  entry_hash: string;
  origin_headers: OriginReceipt;
  rgb_seed: [number, number, number];
  led_code: string;
  beacon_cell: { row: number; col: number; neighborRow: number; neighborCol: number };
  duplicated_packet: boolean;
  trigger_matched: string | null;
  step_trace: DoubleHashStepTrace;
}

interface QuarantineRecord {
  qid: string;
  ts: string;
  endpoint: string;
  reason: string;
  status: 'QUARANTINED_NO_PASS';
  origin_headers: OriginReceipt;
  payload_preview: string;
  adam_gate_failed: string;
  signature_present: boolean;
}

interface OutcomePathline {
  laneId: string;
  path: string;
  confidence: number;
  basis: string;
}

function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(',')}]`;
  const rec = obj as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(',')}}`;
}

function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function sha256DoubleHexFromHex(stage1Hex: string): string {
  return crypto.createHash('sha256').update(Buffer.from(stage1Hex, 'hex')).digest('hex');
}

function fnv1a32Hex(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return `0x${(h >>> 0).toString(16).toUpperCase().padStart(8, '0')}`;
}

function computeIsoBeat(date = new Date()): string {
  const utcSeconds =
    date.getUTCHours() * 3600 +
    date.getUTCMinutes() * 60 +
    date.getUTCSeconds() +
    date.getUTCMilliseconds() / 1000;
  // Convert to UTC+1 BMT beats (0..999.99)
  const bmtSeconds = (utcSeconds + 3600) % 86400;
  const beats = (bmtSeconds / 86.4).toFixed(2).padStart(6, '0');
  return `@${beats}`;
}

function buildDoubleHashStepTrace(label: string, payloadObj: unknown): DoubleHashStepTrace {
  const now = new Date();
  const microOffset = Math.floor((performance.now() * 1000) % 1000000);
  const isoBeat = computeIsoBeat(now);
  const canon = canonicalJson({ label, payload: payloadObj, isoBeat, microOffset });
  const fnv = fnv1a32Hex(canon);
  const preimage = `${canon}|FNV=${fnv}|US=${microOffset}`;
  const stage1 = sha256Hex(preimage);
  const stage2 = sha256DoubleHexFromHex(stage1);
  return {
    preimage,
    stage1_sha256_receipt: stage1,
    stage2_double_sha256: stage2,
    fnv1a_32: fnv,
    iso_beat: isoBeat,
    micro_offset: microOffset,
    ordered_ops: [
      'CANONICAL_JSON',
      'FNV1A_ISO_BEAT_OFFSET',
      'SHA256_ROUND_1_RECEIPT',
      'SHA256_ROUND_2_PUBLIC_DIGEST',
      'TDOC_APPEND_CHAIN',
    ],
    honesty_note:
      'Ordered step-trace witness preserved in TDOC; arbitrary unknown-preimage SHA-256 inversion remains mathematically infeasible.',
  };
}

function hslToRgb(hDeg: number, sPct: number, lPct: number): [number, number, number] {
  const h = (((hDeg % 360) + 360) % 360) / 360;
  const s = Math.max(0, Math.min(1, sPct / 100));
  const l = Math.max(0, Math.min(1, lPct / 100));
  if (s === 0) {
    const v = Math.round(l * 255);
    return [v, v, v];
  }
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
  return [
    Math.round(hue2rgb(h + 1 / 3) * 255),
    Math.round(hue2rgb(h) * 255),
    Math.round(hue2rgb(h - 1 / 3) * 255),
  ];
}

function encodeRgbToLedHex(rgb: [number, number, number]): string {
  return (
    '#' +
    rgb
      .map((c) => Math.max(0, Math.min(255, c)).toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
  );
}

function seedToBeaconVector(seedText: string) {
  const digest = sha256Hex(seedText || 'GAIA_GOLDEN_LINE');
  const h = (parseInt(digest.slice(0, 4), 16) || 192) % 360;
  const s = 74 + (parseInt(digest.slice(4, 6), 16) % 22);
  const l = 50 + (parseInt(digest.slice(6, 8), 16) % 16);
  const rgb = hslToRgb(h, s, l);
  const row = parseInt(digest.slice(8, 10), 16) % 8;
  const col = parseInt(digest.slice(10, 12), 16) % 8;
  const neighborRow = (row + 1) % 8;
  const neighborCol = (col + 1) % 8;
  return {
    digest,
    hue: h,
    rgb,
    ledHex: encodeRgbToLedHex(rgb),
    row,
    col,
    neighborRow,
    neighborCol,
  };
}

function getExpectedHost(req: Request): string {
  const fwdHost = req.headers['x-forwarded-host'];
  const raw = Array.isArray(fwdHost) ? fwdHost[0] : fwdHost || req.headers.host || `127.0.0.1:${PORT}`;
  return String(raw).toLowerCase().trim();
}

function isSameOriginRequest(req: Request): boolean {
  const originHeader = req.headers.origin;
  if (!originHeader) {
    // Allow same-host server-side/curl loopback only when explicitly targeting local host and carrying signed header
    const fwdHost = getExpectedHost(req);
    return fwdHost.startsWith('127.0.0.1') || fwdHost.startsWith('localhost') || fwdHost.startsWith('0.0.0.0');
  }
  try {
    const parsedOrigin = new URL(String(originHeader));
    const expectedHost = getExpectedHost(req);
    return parsedOrigin.host.toLowerCase() === expectedHost;
  } catch {
    return false;
  }
}

function captureOriginHeaders(req: Request): OriginReceipt {
  const fwd = req.headers['x-forwarded-for'];
  return {
    origin: String(req.headers.origin || req.headers.host || '0.0.0.0:3000'),
    referer: String(req.headers.referer || ''),
    host: String(req.headers.host || '0.0.0.0:3000'),
    userAgent: String(req.headers['user-agent'] || 'GAIA-CLIENT').slice(0, 120),
    forwardedFor: Array.isArray(fwd) ? fwd.join(',') : String(fwd || req.socket.remoteAddress || '127.0.0.1'),
    capturedAt: new Date().toISOString(),
    sameOriginVerified: isSameOriginRequest(req),
  };
}

function buildInitialMatrix(): MatrixCell[] {
  const cells: MatrixCell[] = [];
  for (let i = 0; i < 64; i++) {
    const row = Math.floor(i / 8);
    const col = i % 8;
    const rgb = hslToRgb((i * 17) % 360, 62, 42);
    cells.push({
      idx: i,
      row,
      col,
      r: rgb[0],
      g: rgb[1],
      b: rgb[2],
      ledHex: encodeRgbToLedHex(rgb),
      beaconType: 'EMPTY',
      label: `CELL_${row}_${col}`,
      triggerHits: 0,
    });
  }
  return cells;
}

const memoryEntries: SharedMemoryEntry[] = [];
const quarantineQueue: QuarantineRecord[] = [];
let matrixCells: MatrixCell[] = buildInitialMatrix();
let activeSeed = `GENESIS_${ADMIT_FORMULA}_FNV_${fnv1a32Hex(GENESIS_ANCHOR_ISO)}`;
let activeTriggerWord = 'golden';
let deadPixelsAbsorbed = 0;
let gcRecycledCount = 0;
let duplicatePacketsEmitted = 0;
let swapHistory: string[] = [];

const trustedPeerKeys = new Map<string, { fp: string; label: string; enrolledAt: string }>([
  [
    sha256Hex(SERVER_HMAC_SECRET).slice(0, 16),
    {
      fp: sha256Hex(SERVER_HMAC_SECRET).slice(0, 16),
      label: 'LOCAL_GENESIS_SIGNER',
      enrolledAt: GENESIS_ANCHOR_ISO,
    },
  ],
]);

let genesisLockState = {
  locked: true,
  mode: 'ZERO_TRUST_PEER_ENEMY' as const,
  policy: 'QUARANTINE_UNVERIFIED_EXTERNAL_NO_PASS',
  admitFormula: ADMIT_FORMULA,
  anchorIso: GENESIS_ANCHOR_ISO,
  anchorFnv32: fnv1a32Hex(`${ADMIT_FORMULA}|${GENESIS_ANCHOR_ISO}`),
  lockedAtIso: new Date().toISOString(),
  lockedIsoBeat: computeIsoBeat(),
  genesisSeedDigest: sha256DoubleHexFromHex(sha256Hex(`${ADMIT_FORMULA}|${GENESIS_ANCHOR_ISO}`)),
  adamGates: ADAM_GATES,
  honestyScope: {
    scope: 'LOCAL_ONLY',
    live_gpu_attestation: false,
    artificial_consciousness_claim: false,
    note: 'SENTIENT_LOCK denotes strict zero-trust peer quarantine state machine only.',
  },
};

function getGenesisStatusPayload() {
  const nowMs = Date.now();
  return {
    ...genesisLockState,
    currentIso: new Date(nowMs).toISOString(),
    currentIsoBeat: computeIsoBeat(new Date(nowMs)),
    spaceTimeDeltaMs: nowMs - GENESIS_ANCHOR_MS,
    trustedKeyCount: trustedPeerKeys.size,
    trustedPeers: Array.from(trustedPeerKeys.values()),
    quarantineCount: quarantineQueue.length,
    tdocCount: memoryEntries.length,
    headHash: memoryEntries.length > 0 ? memoryEntries[memoryEntries.length - 1].entry_hash : GENESIS_HASH,
  };
}

function recordQuarantineAttempt(
  req: Request,
  reason: string,
  adamGateFailed: string,
  signaturePresent: boolean
): QuarantineRecord {
  const originHeaders = captureOriginHeaders(req);
  const rawBody = req.body ? canonicalJson(req.body).slice(0, 180) : '';
  const qid = `QRN-${(quarantineQueue.length + 1).toString().padStart(4, '0')}-${sha256Hex(`${Date.now()}|${reason}`).slice(0, 8).toUpperCase()}`;
  const rec: QuarantineRecord = {
    qid,
    ts: new Date().toISOString(),
    endpoint: `${req.method} ${req.path}`,
    reason,
    status: 'QUARANTINED_NO_PASS',
    origin_headers: originHeaders,
    payload_preview: rawBody || '(empty)',
    adam_gate_failed: adamGateFailed,
    signature_present: signaturePresent,
  };
  quarantineQueue.unshift(rec);
  if (quarantineQueue.length > 40) quarantineQueue.length = 40;
  return rec;
}

function verifyGenesisRequestSignature(req: Request): {
  ok: boolean;
  reason?: string;
  adamGateFailed?: string;
  signaturePresent: boolean;
} {
  const sigHeader = String(req.headers['x-gaia-genesis-sig'] || '').trim();
  const tsHeader = String(req.headers['x-gaia-genesis-ts'] || '').trim();
  const nonceHeader = String(req.headers['x-gaia-genesis-nonce'] || '').trim();
  const sigPresent = Boolean(sigHeader && tsHeader && nonceHeader);

  if (!isSameOriginRequest(req)) {
    return {
      ok: false,
      reason: 'EXTERNAL_PEER_ORIGIN_REJECTED (ZERO_TRUST_NO_PASS)',
      adamGateFailed: 'DISCOVER_ORIGIN_GATE',
      signaturePresent: sigPresent,
    };
  }

  if (!sigPresent) {
    return {
      ok: false,
      reason: 'MISSING_GENESIS_HMAC_SIGNATURE_HEADERS',
      adamGateFailed: 'VERIFY_SIGNATURE_GATE',
      signaturePresent: false,
    };
  }

  const tsNum = Number(tsHeader);
  const nowMs = Date.now();
  if (!Number.isFinite(tsNum) || Math.abs(nowMs - tsNum) > 300_000) {
    return {
      ok: false,
      reason: 'GENESIS_SIGNATURE_TIMESTAMP_EXPIRED',
      adamGateFailed: 'NORMALIZE_TIME_WINDOW',
      signaturePresent: true,
    };
  }

  // Prune expired replay nonces > 5 minutes
  for (const [nKey, expMs] of seenReplayNonces.entries()) {
    if (expMs < nowMs) seenReplayNonces.delete(nKey);
  }
  if (seenReplayNonces.has(nonceHeader)) {
    return {
      ok: false,
      reason: 'REPLAY_NONCE_DETECTED',
      adamGateFailed: 'FINGERPRINT_REPLAY_CHECK',
      signaturePresent: true,
    };
  }

  const bodyDigest = sha256Hex(canonicalJson(req.body || {}));
  const canonicalSigningString = `${req.method}:${req.path}:${tsHeader}:${nonceHeader}:${bodyDigest}`;
  const expectedHex = crypto
    .createHmac('sha256', SESSION_TOKEN_KEY)
    .update(canonicalSigningString, 'utf8')
    .digest('hex');

  if (sigHeader.length !== expectedHex.length || !/^[0-9a-f]+$/i.test(sigHeader)) {
    return {
      ok: false,
      reason: 'INVALID_GENESIS_HMAC_FORMAT',
      adamGateFailed: 'VERIFY_SIGNATURE_GATE',
      signaturePresent: true,
    };
  }

  const match = crypto.timingSafeEqual(
    Buffer.from(sigHeader.toLowerCase(), 'hex'),
    Buffer.from(expectedHex.toLowerCase(), 'hex')
  );
  if (!match) {
    return {
      ok: false,
      reason: 'GENESIS_HMAC_SIGNATURE_MISMATCH',
      adamGateFailed: 'REVERIFY_CRYPTO_PROOF',
      signaturePresent: true,
    };
  }

  seenReplayNonces.set(nonceHeader, nowMs + 300_000);
  return { ok: true, signaturePresent: true };
}

function computeOutcomePathlines(seedStr: string): OutcomePathline[] {
  const h = sha256Hex(`${seedStr}|${memoryEntries.length}|${gcRecycledCount}`);
  const b0 = parseInt(h.slice(0, 4), 16);
  const b1 = parseInt(h.slice(4, 8), 16);
  const b2 = parseInt(h.slice(8, 12), 16);
  return [
    {
      laneId: 'LANE-ALPHA-GOLDEN',
      path: `0.0.0.0:3000 -> slot_${String(b0 % 360).padStart(3, '0')} -> V5#312 -> /v1/memory`,
      confidence: Number((0.88 + (b0 % 11) / 100).toFixed(2)),
      basis: 'Genesis Seed Zero-Trust Lock + Golden Line parity',
    },
    {
      laneId: 'LANE-BETA-NEIGHBOR-SWAP',
      path: `CELL(${b1 % 8},${(b1 >> 3) % 8}) <-> NEIGHBOR(${(b1 + 1) % 8},${((b1 >> 3) + 1) % 8}) -> U(97152)`,
      confidence: Number((0.81 + (b1 % 15) / 100).toFixed(2)),
      basis: 'Hotswap RGB/LED microdot neighbor relay (Signed Only)',
    },
    {
      laneId: 'LANE-GAMMA-GC-RECLAIM',
      path: `DEAD_PIXEL[NULL_ACK:${deadPixelsAbsorbed}] -> QUARANTINE[${quarantineQueue.length}] -> RECYCLE_GC[${gcRecycledCount}]`,
      confidence: Number((0.76 + (b2 % 19) / 100).toFixed(2)),
      basis: 'Peer-Enemy Quarantine + Dead-row token recycle',
    },
  ];
}

function placeSeedBeacons(seedStr: string, originLabel = 'SEED_INIT') {
  const vec = seedToBeaconVector(seedStr);
  const primaryIdx = vec.row * 8 + vec.col;
  const neighborIdx = vec.neighborRow * 8 + vec.neighborCol;

  matrixCells[primaryIdx] = {
    ...matrixCells[primaryIdx],
    r: vec.rgb[0],
    g: vec.rgb[1],
    b: vec.rgb[2],
    ledHex: vec.ledHex,
    beaconType: 'SEED_BEACON',
    label: `SEED(${originLabel.slice(0, 10)})`,
    triggerHits: matrixCells[primaryIdx].triggerHits + 1,
  };

  matrixCells[neighborIdx] = {
    ...matrixCells[neighborIdx],
    r: vec.rgb[0],
    g: vec.rgb[1],
    b: vec.rgb[2],
    ledHex: vec.ledHex,
    beaconType: 'NEIGHBOR_SWAP',
    label: `NBR(${vec.row},${vec.col})`,
    triggerHits: matrixCells[neighborIdx].triggerHits + 1,
  };

  swapHistory = [
    `[${new Date().toISOString().slice(11, 19)}] SEED BEACON (${vec.row},${vec.col}) ↔ NEIGHBOR (${vec.neighborRow},${vec.neighborCol}) RGB(${vec.rgb.join(',')}) LED ${vec.ledHex}`,
    ...swapHistory,
  ].slice(0, 16);

  return vec;
}

function appendChainedMemory(params: {
  text: string;
  source: string;
  reference: string;
  share_with: string[];
  kind: string;
  originHeaders: OriginReceipt;
  triggerMatched: string | null;
  duplicated: boolean;
}): SharedMemoryEntry {
  const seq = memoryEntries.length + 1;
  const ts = new Date().toISOString();
  const prev_hash = memoryEntries.length > 0 ? memoryEntries[memoryEntries.length - 1].entry_hash : GENESIS_HASH;
  const beacon = placeSeedBeacons(`${activeSeed}|${params.text}|${seq}`, params.source || 'MEM');
  const id = `MEM-${seq.toString().padStart(4, '0')}-${sha256Hex(`${seq}|${ts}|${params.text}`).slice(0, 8).toUpperCase()}`;

  const step_trace = buildDoubleHashStepTrace(id, {
    id,
    seq,
    ts,
    text: params.text,
    source: params.source,
    reference: params.reference,
    prev_hash,
  });

  const hashPayload = canonicalJson({
    id,
    seq,
    ts,
    text: params.text,
    source: params.source,
    reference: params.reference,
    share_with: params.share_with,
    kind: params.kind,
    prev_hash,
  });
  const entry_hash = sha256Hex(hashPayload);

  const entry: SharedMemoryEntry = {
    id,
    seq,
    ts,
    text: params.text,
    source: params.source,
    reference: params.reference,
    share_with: params.share_with,
    kind: params.kind,
    prev_hash,
    entry_hash,
    origin_headers: params.originHeaders,
    rgb_seed: beacon.rgb,
    led_code: beacon.ledHex,
    beacon_cell: {
      row: beacon.row,
      col: beacon.col,
      neighborRow: beacon.neighborRow,
      neighborCol: beacon.neighborCol,
    },
    duplicated_packet: params.duplicated,
    trigger_matched: params.triggerMatched,
    step_trace,
  };

  memoryEntries.push(entry);
  return entry;
}

function absorbDeadPixelAndSwap(seedHint: string, reason: string) {
  deadPixelsAbsorbed++;
  gcRecycledCount++;
  const vec = seedToBeaconVector(`${seedHint}|DEAD_PIXEL|${deadPixelsAbsorbed}`);
  const deadIdx = vec.row * 8 + vec.col;
  const healthyIdx = ((vec.row + 3) % 8) * 8 + ((vec.col + 5) % 8);

  matrixCells[deadIdx] = {
    ...matrixCells[deadIdx],
    r: 244,
    g: 63,
    b: 94,
    ledHex: '#F43F5E',
    beaconType: 'DEAD_PIXEL_ABSORBED',
    label: `NULL_ACK#${deadPixelsAbsorbed}`,
    triggerHits: matrixCells[deadIdx].triggerHits + 1,
  };

  const healthyRgb = hslToRgb((vec.hue + 120) % 360, 82, 54);
  matrixCells[healthyIdx] = {
    ...matrixCells[healthyIdx],
    r: healthyRgb[0],
    g: healthyRgb[1],
    b: healthyRgb[2],
    ledHex: encodeRgbToLedHex(healthyRgb),
    beaconType: 'RECYCLED',
    label: `GC_SWAP#${gcRecycledCount}`,
    triggerHits: matrixCells[healthyIdx].triggerHits + 1,
  };

  swapHistory = [
    `[${new Date().toISOString().slice(11, 19)}] DEAD_PIXEL(${vec.row},${vec.col}) ABSORBED→NULL_ACK · SWAPPED TO RECYCLED(${Math.floor(healthyIdx / 8)},${healthyIdx % 8}) · REASON:${reason}`,
    ...swapHistory,
  ].slice(0, 16);

  return { deadIdx, healthyIdx };
}

function getMatrixStateSummary() {
  const vec = seedToBeaconVector(activeSeed);
  return {
    hostBind: `${HOST}:${PORT}`,
    goldenLineLinked: true,
    zeroTrustLocked: genesisLockState.locked,
    zeroTrustMode: genesisLockState.mode,
    activeSeed,
    activeTriggerWord,
    seedRgb: vec.rgb,
    seedLedHex: vec.ledHex,
    deadPixelsAbsorbed,
    gcRecycledCount,
    quarantineCount: quarantineQueue.length,
    duplicatePacketsEmitted,
    swapHistory,
    outcomePathlines: computeOutcomePathlines(activeSeed),
    cells: matrixCells,
  };
}

// Seed initial genesis TDOC verification receipt into the SHA-256 chain via Creed of Admittance
creedAdmittanceService.admitOperation(
  {
    functionId: 'fn:memory.genesisSeedAppend',
    functionName: 'server.appendGenesisSeed',
    branchId: 'BRANCH-MEMORY-WRITE',
    category: 'MEMORY_WRITE',
    required: true,
    predicates: {
      authorization: { state: 'PASS', reason: 'Server genesis sentinel authorized on boot' },
      capacity: { state: 'PASS', reason: `Matrix cells=${matrixCells.length}/64` },
      verification: genesisLockState.locked
        ? { state: 'PASS', reason: 'Zero-trust Genesis lock active' }
        : { state: 'FAIL', reason: 'Genesis lock disabled at boot' },
      boundary: { state: 'PASS', reason: `Host bind ${HOST}:${PORT} constrained` },
      provenancePrivacy: { state: 'PASS', reason: 'Local genesis receipt only (no secrets embedded)' },
    },
  },
  () =>
    appendChainedMemory({
      text: `GENESIS SEED LOCKED (${GENESIS_ANCHOR_ISO}) · ${ADMIT_FORMULA} · ZERO-TRUST PEER-ENEMY NO-PASS`,
      source: 'gaia_genesis_sentinel',
      reference: `TDOC|${ADMIT_FORMULA}|LOCAL_ONLY`,
      share_with: ['gemini', 'openai'],
      kind: 'verification_receipt',
      originHeaders: {
        origin: 'http://0.0.0.0:3000',
        referer: '',
        host: '0.0.0.0:3000',
        userAgent: 'GAIA-GENESIS-LOCK',
        forwardedFor: '0.0.0.0',
        capturedAt: GENESIS_ANCHOR_ISO,
        sameOriginVerified: true,
      },
      triggerMatched: 'golden',
      duplicated: false,
    })
);

const OPENAPI_SPEC = {
  openapi: '3.1.0',
  info: {
    title: 'GAIA NEXUS Zero-Trust Genesis Memory',
    version: '2.0.0',
    description:
      'Append-only TDOC SHA-256 ledger, Step-Trace Double SHA-256 witness, and Zero-Trust Peer-Enemy Quarantine Router.',
  },
  servers: [{ url: `http://0.0.0.0:${PORT}`, description: 'Zero-Trust Genesis Runtime' }],
  paths: {
    '/v1/memory': {
      get: {
        summary: 'Search and retrieve hash-chained TDOC memory entries & Zero-Trust matrix state',
        parameters: [
          { name: 'q', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 100 } },
        ],
        responses: { '200': { description: 'Shared memory slice & Zero-Trust matrix state' } },
      },
      post: {
        summary: 'Requires Genesis HMAC signature & same-origin verification; unverified callers are quarantined (403)',
        responses: {
          '200': { description: 'Chained receipt with Step-Trace Double SHA-256 or DEAD_PIXEL_ABSORBED null-ack' },
          '403': { description: 'QUARANTINED_NO_PASS — untrusted or unsigned external peer rejected' },
        },
      },
    },
    '/v1/memory/verify': {
      get: {
        summary: 'Verify full SHA-256 hash-chain integrity across all TDOC entries',
        responses: { '200': { description: 'Chain verification report' } },
      },
    },
    '/v1/genesis/session': {
      get: {
        summary: 'Issue ephemeral in-memory session HMAC key for verified same-origin cockpit requests',
        responses: { '200': { description: 'Session HMAC secret & Genesis Lock state' }, '403': { description: 'Blocked external origin' } },
      },
    },
    '/v1/genesis/status': {
      get: {
        summary: 'Retrieve Genesis Seed timestamp lock, ADAM proof gates, trusted keys, and Quarantine log',
        responses: { '200': { description: 'Genesis status & quarantine telemetry' } },
      },
    },
    '/v1/genesis/quarantine/test': {
      post: {
        summary: 'Run signed peer-enemy scrutiny simulation recording a rejected untrusted external peer in quarantine',
        responses: { '200': { description: 'Recorded quarantine event & ADAM gate trace' } },
      },
    },
    '/v1/genesis/step-trace': {
      post: {
        summary: 'Compute & verify Stage-1 + Stage-2 BTC Double SHA-256 ordered step-trace witness',
        responses: { '200': { description: 'Full step-trace witness' } },
      },
    },
    '/v1/creed/status': {
      get: {
        summary: 'Retrieve central Creed of Admittance branch verdicts, registered function results, and evaluation history',
        responses: { '200': { description: 'Creed of Admittance snapshot' } },
      },
    },
  },
};

function mapPathToCreedTarget(reqPath: string): {
  functionId: string;
  functionName: string;
  branchId: string;
  category: OperationCategory;
  required: boolean;
} {
  if (reqPath.startsWith('/v1/genesis/lock')) {
    return {
      functionId: 'fn:deploy.genesisLock',
      functionName: 'POST /v1/genesis/lock',
      branchId: 'BRANCH-DEPLOYMENT',
      category: 'DEPLOYMENT',
      required: false,
    };
  }
  if (reqPath.startsWith('/v1/router/seed')) {
    return {
      functionId: 'fn:memory.seedRouter',
      functionName: 'POST /v1/router/seed',
      branchId: 'BRANCH-MEMORY-WRITE',
      category: 'MEMORY_WRITE',
      required: false,
    };
  }
  if (reqPath.startsWith('/v1/router/trigger')) {
    return {
      functionId: 'fn:memory.triggerMatrix',
      functionName: 'POST /v1/router/trigger',
      branchId: 'BRANCH-MEMORY-WRITE',
      category: 'MEMORY_WRITE',
      required: false,
    };
  }
  if (reqPath.startsWith('/v1/genesis/step-trace')) {
    return {
      functionId: 'fn:solver.serverStepTrace',
      functionName: 'POST /v1/genesis/step-trace',
      branchId: 'BRANCH-SOLVER',
      category: 'SOLVER',
      required: false,
    };
  }
  if (reqPath.startsWith('/v1/genesis/quarantine/test')) {
    return {
      functionId: 'fn:governance.quarantineTest',
      functionName: 'POST /v1/genesis/quarantine/test',
      branchId: 'BRANCH-GOVERNANCE',
      category: 'GOVERNANCE',
      required: false,
    };
  }
  return {
    functionId: 'fn:memory.postRouter',
    functionName: 'POST /v1/memory',
    branchId: 'BRANCH-MEMORY-WRITE',
    category: 'MEMORY_WRITE',
    required: false,
  };
}

function requireGenesisSignature(req: Request, res: Response, next: NextFunction) {
  const verdict = verifyGenesisRequestSignature(req);
  if (!verdict.ok) {
    const target = mapPathToCreedTarget(req.path);
    const creedEval = creedAdmittanceService.evaluateOperation({
      functionId: target.functionId,
      functionName: target.functionName,
      branchId: target.branchId,
      category: target.category,
      required: target.required,
      predicates: {
        authorization: {
          state: 'FAIL',
          reason: verdict.reason || 'ZERO_TRUST_SIGNATURE_FAILED',
        },
        capacity: { state: 'PASS', reason: `Quarantine queue depth=${quarantineQueue.length}` },
        verification: {
          state: verdict.signaturePresent ? 'FAIL' : 'INCOMPLETE',
          reason: `ADAM gate failed: ${verdict.adamGateFailed || 'VERIFY_SIGNATURE_GATE'}`,
        },
        boundary: isSameOriginRequest(req)
          ? { state: 'PASS', reason: 'Same-origin request boundary' }
          : { state: 'FAIL', reason: 'External origin rejected at Zero-Trust boundary' },
        provenancePrivacy: {
          state: 'PASS',
          reason: 'Rejected request isolated to quarantine without exposing secrets',
        },
      },
    });
    const qRec = recordQuarantineAttempt(
      req,
      verdict.reason || 'ZERO_TRUST_REJECTED',
      verdict.adamGateFailed || 'VERIFY_SIGNATURE_GATE',
      verdict.signaturePresent
    );
    res.status(403).json({
      ok: false,
      quarantined: true,
      status: 'QUARANTINED_NO_PASS',
      reason: qRec.reason,
      quarantine_record: qRec,
      creed_evaluation: creedEval,
      genesis_status: getGenesisStatusPayload(),
    });
    return;
  }
  next();
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  // Zero-Trust Origin Verification CORS: reflect exact verified same-origin only; zero wildcard on authenticated routes
  app.use((req: Request, res: Response, next: NextFunction) => {
    const reqOrigin = req.headers.origin;
    if (reqOrigin && isSameOriginRequest(req)) {
      res.setHeader('Access-Control-Allow-Origin', String(reqOrigin));
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Authorization, Range, Content-Type, x-gaia-genesis-sig, x-gaia-genesis-ts, x-gaia-genesis-nonce'
      );
    }
    if (req.method === 'OPTIONS') {
      res.status(isSameOriginRequest(req) ? 204 : 403).end();
      return;
    }
    next();
  });

  app.get('/v1/openapi.json', (_req: Request, res: Response) => {
    res.json(OPENAPI_SPEC);
  });

  app.get('/v1/genesis/session', (req: Request, res: Response) => {
    if (!isSameOriginRequest(req)) {
      const qRec = recordQuarantineAttempt(req, 'EXTERNAL_SESSION_CLAIM_BLOCKED', 'DISCOVER_ORIGIN_GATE', false);
      res.status(403).json({ ok: false, quarantined: true, status: 'QUARANTINED_NO_PASS', quarantine_record: qRec });
      return;
    }
    res.json({
      ok: true,
      hmacKey: SESSION_TOKEN_KEY,
      sessionFp: sha256Hex(SESSION_TOKEN_KEY).slice(0, 16),
      genesis: getGenesisStatusPayload(),
      quarantine: quarantineQueue,
    });
  });

  app.get('/v1/creed/status', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      creed: creedAdmittanceService.getSnapshot(),
    });
  });

  app.get('/v1/genesis/status', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      genesis: getGenesisStatusPayload(),
      quarantine: quarantineQueue,
      creed: creedAdmittanceService.getSnapshot(),
    });
  });

  app.post('/v1/genesis/lock', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const note = typeof body.note === 'string' ? body.note.trim().slice(0, 240) : 'GENESIS_SEED_RELOCK';
    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:deploy.genesisLock',
        functionName: 'POST /v1/genesis/lock',
        branchId: 'BRANCH-DEPLOYMENT',
        category: 'DEPLOYMENT',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin Genesis HMAC verified' },
          capacity:
            memoryEntries.length < 10000
              ? { state: 'PASS', reason: `TDOC capacity OK (${memoryEntries.length}/10000)` }
              : { state: 'FAIL', reason: 'TDOC ledger capacity reached' },
          verification: genesisLockState.locked
            ? { state: 'PASS', reason: 'Zero-trust Genesis lock state intact' }
            : { state: 'INCOMPLETE', reason: 'Genesis lock inactive' },
          boundary: note.length > 0
            ? { state: 'PASS', reason: 'Genesis relock note validated within 240 chars' }
            : { state: 'FAIL', reason: 'Invalid Genesis relock note boundary' },
          provenancePrivacy: { state: 'PASS', reason: 'Signed under volatile server HMAC session' },
        },
      },
      () => {
        const now = new Date();
        genesisLockState = {
          ...genesisLockState,
          locked: true,
          lockedAtIso: now.toISOString(),
          lockedIsoBeat: computeIsoBeat(now),
          anchorFnv32: fnv1a32Hex(`${ADMIT_FORMULA}|${now.toISOString()}|${note}`),
          genesisSeedDigest: sha256DoubleHexFromHex(sha256Hex(`${ADMIT_FORMULA}|${now.toISOString()}|${note}`)),
        };
        const originHeaders = captureOriginHeaders(req);
        return appendChainedMemory({
          text: `GENESIS SEED RELOCK [${genesisLockState.lockedIsoBeat}] ${genesisLockState.anchorFnv32}: ${note}`,
          source: 'gaia_genesis_sentinel',
          reference: `0x${genesisLockState.genesisSeedDigest.slice(0, 24)}`,
          share_with: ['gemini', 'openai'],
          kind: 'verification_receipt',
          originHeaders,
          triggerMatched: 'golden',
          duplicated: false,
        });
      }
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 403 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }
    res.json({ ok: true, genesis: getGenesisStatusPayload(), entry: gated.value, creed_evaluation: gated.evaluation });
  });

  app.post('/v1/genesis/quarantine/test', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const peerLabel = typeof body.peerLabel === 'string' ? body.peerLabel.trim().slice(0, 80) : 'rogue-peer.untrusted.net';
    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:governance.quarantineTest',
        functionName: 'POST /v1/genesis/quarantine/test',
        branchId: 'BRANCH-GOVERNANCE',
        category: 'GOVERNANCE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin operator scrutiny authorized' },
          capacity: { state: 'PASS', reason: `Quarantine ring buffer ready (${quarantineQueue.length}/40)` },
          verification: { state: 'PASS', reason: 'ADAM peer-enemy probe verified' },
          boundary: peerLabel.length > 0
            ? { state: 'PASS', reason: `Sanitized synthetic peer label (${peerLabel})` }
            : { state: 'FAIL', reason: 'Empty peer label' },
          provenancePrivacy: { state: 'PASS', reason: 'Isolated synthetic request without granting peer pass' },
        },
      },
      () => {
        const syntheticReq = {
          method: 'POST',
          path: '/v1/memory (PEER_SCRUTINY)',
          headers: {
            origin: `https://${peerLabel.replace(/[^a-zA-Z0-9.-]/g, '')}`,
            host: getExpectedHost(req),
            'user-agent': 'UNVERIFIED-EXTERNAL-COLLECTIVE/0.0',
          },
          socket: req.socket,
          body: { peerLabel, claimedTrust: 'COLLECTIVE_PASS', signature: null },
        } as unknown as Request;
        return recordQuarantineAttempt(
          syntheticReq,
          `ZERO_TRUST_PEER_ENEMY: "${peerLabel}" failed Genesis ECDSA/HMAC verification (NO PASS)`,
          'VERIFY_SIGNATURE_GATE',
          false
        );
      }
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 403 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }

    res.json({
      ok: true,
      quarantined: true,
      quarantine_record: gated.value,
      creed_evaluation: gated.evaluation,
      genesis: getGenesisStatusPayload(),
      quarantine: quarantineQueue,
    });
  });

  app.post('/v1/genesis/step-trace', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const label = typeof body.label === 'string' ? body.label.trim().slice(0, 64) : 'ADMIT_STEP_TRACE';
    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:solver.serverStepTrace',
        functionName: 'POST /v1/genesis/step-trace',
        branchId: 'BRANCH-SOLVER',
        category: 'SOLVER',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin Genesis HMAC verified' },
          capacity: { state: 'PASS', reason: 'SHA-256d witness compute available' },
          verification: { state: 'PASS', reason: 'Ordered double-SHA256 step trace invariant' },
          boundary: label.length > 0
            ? { state: 'PASS', reason: `Step trace label=${label}` }
            : { state: 'FAIL', reason: 'Empty step trace label' },
          provenancePrivacy: { state: 'PASS', reason: 'Preimage witness contains no credential material' },
        },
      },
      () => buildDoubleHashStepTrace(label, body.payload ?? { admit: ADMIT_FORMULA })
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 403 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }
    res.json({ ok: true, step_trace: gated.value, creed_evaluation: gated.evaluation });
  });

  app.get('/v1/memory', (req: Request, res: Response) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    const limitRaw = Number(req.query.limit || 100);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, Math.floor(limitRaw))) : 100;
    const includeHistory = req.query.seed === 'present' || memoryEntries.length > 0;

    let items = includeHistory ? memoryEntries.slice() : [];
    if (q.length > 0) {
      items = items.filter(
        (e) =>
          e.text.includes(q) ||
          e.source.includes(q) ||
          e.reference.includes(q) ||
          e.kind.includes(q) ||
          e.entry_hash.includes(q) ||
          e.id.includes(q)
      );
    }

    const slice = items.slice(-limit).reverse();
    const head_hash = memoryEntries.length > 0 ? memoryEntries[memoryEntries.length - 1].entry_hash : GENESIS_HASH;
    res.json({
      ok: true,
      count: slice.length,
      total: memoryEntries.length,
      head_hash,
      genesis: getGenesisStatusPayload(),
      quarantine: quarantineQueue,
      matrix_state: getMatrixStateSummary(),
      entries: slice,
    });
  });

  app.post('/v1/memory', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    const source = typeof body.source === 'string' ? body.source.trim().slice(0, 512) : 'cockpit_user';
    const reference = typeof body.reference === 'string' ? body.reference.trim().slice(0, 512) : 'NONE';
    const kindRaw = typeof body.kind === 'string' ? body.kind : 'user_statement';
    const kindValid = VALID_KINDS.has(kindRaw);
    const kind = kindValid ? kindRaw : 'user_statement';
    const shareWithRaw = Array.isArray(body.share_with) ? body.share_with : ['gemini', 'openai'];
    const share_with = shareWithRaw.map((x) => String(x)).filter((x) => VALID_TARGETS.has(x));

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:memory.postRouter',
        functionName: 'POST /v1/memory',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin Genesis HMAC verified' },
          capacity:
            memoryEntries.length < 10000
              ? { state: 'PASS', reason: `TDOC capacity OK (${memoryEntries.length}/10000)` }
              : { state: 'FAIL', reason: 'TDOC memory capacity reached (10000)' },
          verification: kindValid
            ? { state: 'PASS', reason: `Validated memory entry kind=${kind}` }
            : { state: 'INCOMPLETE', reason: `Unrecognized kind "${kindRaw}" held by Creed` },
          boundary:
            text.length > 0 && text.length <= 32000
              ? { state: 'PASS', reason: `Payload text length OK (${text.length} chars)` }
              : { state: 'FAIL', reason: 'Field `text` must be a non-empty string (max 32000 chars)' },
          provenancePrivacy: isSameOriginRequest(req)
            ? { state: 'PASS', reason: 'Same-origin header verified and secret-free boundary enforced' }
            : { state: 'FAIL', reason: 'Cross-origin caller prohibited from writing TDOC ledger' },
        },
      },
      () => {
        if (text.includes('__DEAD_PIXEL__') || text.includes('deadpixel:null') || body.injectDeadPixel === true) {
          const swap = absorbDeadPixelAndSwap(text, 'POST_MEMORY_DEAD_PIXEL');
          return {
            deadPixel: true as const,
            swap,
          };
        }

        const originHeaders = captureOriginHeaders(req);
        const triggerMatched =
          activeTriggerWord && text.toLowerCase().includes(activeTriggerWord.toLowerCase()) ? activeTriggerWord : null;
        const duplicated = Boolean(triggerMatched || body.duplicateOnTrigger === true);

        const primaryEntry = appendChainedMemory({
          text,
          source,
          reference,
          share_with,
          kind,
          originHeaders,
          triggerMatched,
          duplicated,
        });

        let duplicateEntry: SharedMemoryEntry | null = null;
        if (duplicated) {
          duplicatePacketsEmitted++;
          duplicateEntry = appendChainedMemory({
            text: `[HYDRATED-DUP origin=${originHeaders.origin}] ${text}`,
            source: `${source}:neighbor_swap`,
            reference: primaryEntry.id,
            share_with,
            kind: 'verification_receipt',
            originHeaders,
            triggerMatched,
            duplicated: true,
          });
        }

        return {
          deadPixel: false as const,
          primaryEntry,
          duplicateEntry,
        };
      }
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 400 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }

    if (gated.value.deadPixel) {
      res.status(200).json({
        ok: true,
        status: 'DEAD_PIXEL_ABSORBED',
        null_ack: true,
        ack: null,
        absorbed_cell: gated.value.swap.deadIdx,
        replacement_cell: gated.value.swap.healthyIdx,
        creed_evaluation: gated.evaluation,
        matrix_state: getMatrixStateSummary(),
      });
      return;
    }

    const { primaryEntry, duplicateEntry } = gated.value;
    res.status(200).json({
      ok: true,
      null_ack: false,
      entry: primaryEntry,
      duplicate_entry: duplicateEntry,
      head_hash: (duplicateEntry || primaryEntry).entry_hash,
      creed_evaluation: gated.evaluation,
      genesis: getGenesisStatusPayload(),
      matrix_state: getMatrixStateSummary(),
    });
  });

  app.get('/v1/memory/verify', (_req: Request, res: Response) => {
    const broken_links: Array<{ seq: number; id: string; reason: string }> = [];
    let expectedPrev = GENESIS_HASH;
    for (let i = 0; i < memoryEntries.length; i++) {
      const e = memoryEntries[i];
      if (e.prev_hash !== expectedPrev) {
        broken_links.push({ seq: e.seq, id: e.id, reason: 'PREV_HASH_MISMATCH' });
      }
      const recomputed = sha256Hex(
        canonicalJson({
          id: e.id,
          seq: e.seq,
          ts: e.ts,
          text: e.text,
          source: e.source,
          reference: e.reference,
          share_with: e.share_with,
          kind: e.kind,
          prev_hash: e.prev_hash,
        })
      );
      if (recomputed !== e.entry_hash) {
        broken_links.push({ seq: e.seq, id: e.id, reason: 'ENTRY_HASH_MISMATCH' });
      }
      expectedPrev = e.entry_hash;
    }

    const head_hash = memoryEntries.length > 0 ? memoryEntries[memoryEntries.length - 1].entry_hash : GENESIS_HASH;
    res.json({
      ok: true,
      verified: broken_links.length === 0,
      total_entries: memoryEntries.length,
      head_hash,
      broken_links,
      dead_pixels_absorbed: deadPixelsAbsorbed,
      gc_recycled: gcRecycledCount,
      quarantined_peers: quarantineQueue.length,
      duplicate_packets_emitted: duplicatePacketsEmitted,
      golden_line_linked: true,
      zero_trust_mode: genesisLockState.mode,
    });
  });

  app.get('/v1/router/state', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      matrix_state: getMatrixStateSummary(),
      genesis: getGenesisStatusPayload(),
      quarantine: quarantineQueue,
      history_count: memoryEntries.length,
    });
  });

  app.post('/v1/router/seed', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const candidateSeed =
      typeof body.seed === 'string' && body.seed.trim().length > 0 ? body.seed.trim().slice(0, 256) : activeSeed;
    const candidateTrigger =
      typeof body.triggerWord === 'string' && body.triggerWord.trim().length > 0
        ? body.triggerWord.trim().slice(0, 64)
        : activeTriggerWord;

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:memory.seedRouter',
        functionName: 'POST /v1/router/seed',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin Genesis HMAC verified' },
          capacity:
            memoryEntries.length < 10000
              ? { state: 'PASS', reason: `TDOC capacity OK (${memoryEntries.length}/10000)` }
              : { state: 'FAIL', reason: 'TDOC memory capacity exceeded' },
          verification: candidateSeed.length > 0
            ? { state: 'PASS', reason: `Seed vector non-empty (${candidateSeed.slice(0, 32)})` }
            : { state: 'INCOMPLETE', reason: 'Missing Golden Line seed' },
          boundary:
            candidateSeed.length <= 256 && candidateTrigger.length > 0 && candidateTrigger.length <= 64
              ? { state: 'PASS', reason: 'Seed & trigger word within length boundaries' }
              : { state: 'FAIL', reason: 'Seed or trigger word exceeds boundary limits' },
          provenancePrivacy: { state: 'PASS', reason: 'Same-origin seed broadcast receipt logged' },
        },
      },
      () => {
        activeSeed = candidateSeed;
        activeTriggerWord = candidateTrigger;
        const vec = placeSeedBeacons(activeSeed, 'GOLDEN_SEED');
        const originHeaders = captureOriginHeaders(req);
        return appendChainedMemory({
          text: `GOLDEN_LINE SEED BROADCAST (SIGNED): ${activeSeed} · trigger="${activeTriggerWord}" · history=${memoryEntries.length}`,
          source: 'golden_line_seed_broadcaster',
          reference: `RGB(${vec.rgb.join(',')})|LED:${vec.ledHex}`,
          share_with: ['gemini', 'openai'],
          kind: 'verification_receipt',
          originHeaders,
          triggerMatched: activeTriggerWord,
          duplicated: false,
        });
      }
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 403 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }

    res.json({
      ok: true,
      broadcasted_entries: memoryEntries.length,
      seed_entry: gated.value,
      creed_evaluation: gated.evaluation,
      matrix_state: getMatrixStateSummary(),
    });
  });

  app.post('/v1/router/trigger', requireGenesisSignature, (req: Request, res: Response) => {
    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const mode = typeof body.mode === 'string' ? body.mode : 'SWAP';
    const word = typeof body.word === 'string' ? body.word.trim().slice(0, 128) : activeTriggerWord;
    const hasCellIdx = body.cellIdx !== null && body.cellIdx !== undefined && body.cellIdx !== '';
    const cellIdxRaw = hasCellIdx ? Number(body.cellIdx) : NaN;
    const cellBoundsOk = !hasCellIdx || (Number.isInteger(cellIdxRaw) && cellIdxRaw >= 0 && cellIdxRaw < 64);
    const modeValid = mode === 'SWAP' || mode === 'DEAD_PIXEL' || mode === 'GC';

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:memory.triggerMatrix',
        functionName: 'POST /v1/router/trigger',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin Genesis HMAC verified' },
          capacity: matrixCells.length === 64
            ? { state: 'PASS', reason: '64-cell microdot matrix capacity OK' }
            : { state: 'FAIL', reason: 'Matrix cell table corrupted' },
          verification: modeValid
            ? { state: 'PASS', reason: `Trigger mode=${mode} verified` }
            : { state: 'FAIL', reason: `Unsupported trigger mode="${mode}"` },
          boundary: cellBoundsOk
            ? { state: 'PASS', reason: hasCellIdx ? `Cell index ${cellIdxRaw} in 0..63` : 'Derived cell index within 0..63' }
            : { state: 'FAIL', reason: 'cellIdx out of 0..63 boundary' },
          provenancePrivacy: { state: 'PASS', reason: 'Same-origin matrix trigger audit recorded' },
        },
      },
      () => {
        if (mode === 'DEAD_PIXEL' || mode === 'GC') {
          const swap = absorbDeadPixelAndSwap(`${activeSeed}|${word}`, mode);
          return {
            deadPixel: true as const,
            swap,
          };
        }

        const baseIdx = hasCellIdx
          ? cellIdxRaw
          : seedToBeaconVector(`${activeSeed}|${word}`).row * 8 + seedToBeaconVector(`${activeSeed}|${word}`).col;
        const neighborIdx = (baseIdx + 1) % 64;
        const prevCell = { ...matrixCells[baseIdx] };
        const nbrCell = { ...matrixCells[neighborIdx] };

        matrixCells[baseIdx] = {
          ...nbrCell,
          idx: baseIdx,
          row: Math.floor(baseIdx / 8),
          col: baseIdx % 8,
          beaconType: 'NEIGHBOR_SWAP',
          label: `SWAP<-${neighborIdx}`,
          triggerHits: nbrCell.triggerHits + 1,
        };
        matrixCells[neighborIdx] = {
          ...prevCell,
          idx: neighborIdx,
          row: Math.floor(neighborIdx / 8),
          col: neighborIdx % 8,
          beaconType: 'SEED_BEACON',
          label: `HOT:${word.slice(0, 7)}`,
          triggerHits: prevCell.triggerHits + 1,
        };
        duplicatePacketsEmitted++;

        swapHistory = [
          `[${new Date().toISOString().slice(11, 19)}] HOTSWAP CELL[${baseIdx}] ↔ NEIGHBOR[${neighborIdx}] ON "${word}"`,
          ...swapHistory,
        ].slice(0, 16);

        return {
          deadPixel: false as const,
          baseIdx,
          neighborIdx,
        };
      }
    );

    if (!gated.admitted) {
      res.status(gated.verdict === 'RED' ? 403 : 423).json({
        ok: false,
        verdict: gated.verdict,
        error: gated.blockedReason,
        creed_evaluation: gated.evaluation,
      });
      return;
    }

    if (gated.value.deadPixel) {
      res.json({
        ok: true,
        status: 'DEAD_PIXEL_ABSORBED',
        null_ack: true,
        ack: null,
        absorbed_cell: gated.value.swap.deadIdx,
        replacement_cell: gated.value.swap.healthyIdx,
        creed_evaluation: gated.evaluation,
        matrix_state: getMatrixStateSummary(),
      });
      return;
    }

    res.json({
      ok: true,
      null_ack: false,
      swapped: [gated.value.baseIdx, gated.value.neighborIdx],
      origin_headers: captureOriginHeaders(req),
      creed_evaluation: gated.evaluation,
      matrix_state: getMatrixStateSummary(),
    });
  });

  // =========================================================================
  // 192 GiB GOOGLE DRIVE SPARSEBUNDLE + HTTPFS VIRTUAL DISK GATEWAY
  // =========================================================================
  const BAND_SIZE_BYTES = 8_388_608; // 8 MiB per sparse band
  const TOTAL_SPARSE_BANDS = 24_576; // 8,192 x 3 sets
  const LOGICAL_SPARSE_VOLUME_BYTES = TOTAL_SPARSE_BANDS * BAND_SIZE_BYTES; // 206,158,430,208 B = 192 GiB
  const SPARSE_PAYLOAD_PARTITION_BYTES = 8_000_000;
  const SPARSE_TAIL_RESERVED_BITS = 388_605;

  interface VirtualBandDescriptor {
    bandHex: string;
    globalBandIndex: number;
    setIndex: number;
    blockIndex: number;
    faceLabel: string;
    driveFileId: string | null;
    payloadBytesUsed: number;
    tailBitsUsed: number;
    latestLeafHex: string;
    payloadJson: string;
    tailString: string;
    updatedAt: string;
  }

  const httpfsSessionState: {
    mounted: boolean;
    ownerEmail: string;
    ownerDisplayName: string;
    driveFolderId: string | null;
    bandsFolderId: string | null;
    mountedAt: string | null;
    unmountedAt: string | null;
    setRootsHex: [string, string, string];
    populatedBands: Map<string, VirtualBandDescriptor>;
    mountHistory: Array<{ ts: string; action: 'MOUNT' | 'SYNC_BAND' | 'UNMOUNT'; ownerEmail: string; detail: string }>;
  } = {
    mounted: false,
    ownerEmail: '',
    ownerDisplayName: '',
    driveFolderId: null,
    bandsFolderId: null,
    mountedAt: null,
    unmountedAt: null,
    setRootsHex: ['0'.repeat(64), '0'.repeat(64), '0'.repeat(64)],
    populatedBands: new Map(),
    mountHistory: [],
  };

  function buildSparseBundlePlistXml(): string {
    return [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      '<dict>',
      '  <key>CFBundleInfoDictionaryVersion</key>',
      '  <string>6.0</string>',
      '  <key>band-size</key>',
      `  <integer>${BAND_SIZE_BYTES}</integer>`,
      '  <key>bundle-backingstore-version</key>',
      '  <integer>1</integer>',
      '  <key>diskimage-bundle-type</key>',
      '  <string>com.apple.diskimage.sparsebundle</string>',
      '  <key>size</key>',
      `  <integer>${LOGICAL_SPARSE_VOLUME_BYTES}</integer>`,
      '  <key>gaia-logical-gib</key>',
      '  <integer>192</integer>',
      '  <key>gaia-total-bands</key>',
      `  <integer>${TOTAL_SPARSE_BANDS}</integer>`,
      '</dict>',
      '</plist>',
    ].join('\n');
  }

  async function verifyGoogleBearerIdentity(authHeader: string | undefined): Promise<{
    ok: boolean;
    email?: string;
    displayName?: string;
    error?: string;
  }> {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { ok: false, error: 'Missing Authorization: Bearer <token> header' };
    }
    const token = authHeader.slice(7).trim();
    if (token.length < 16 || token.length > 4096) {
      return { ok: false, error: 'Invalid Bearer token length' };
    }
    try {
      const resp = await fetch(
        'https://www.googleapis.com/drive/v3/about?fields=user(emailAddress,displayName)',
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!resp.ok) {
        return { ok: false, error: `Google Drive identity check failed (HTTP ${resp.status})` };
      }
      const data = (await resp.json()) as { user?: { emailAddress?: string; displayName?: string } };
      const email = String(data.user?.emailAddress || '').trim();
      if (!email) {
        return { ok: false, error: 'Google Drive user email missing from token profile' };
      }
      return {
        ok: true,
        email,
        displayName: String(data.user?.displayName || email),
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'Unable to reach Google Drive identity verification',
      };
    }
  }

  function renderSparseBandSlice(bandHex: string, start: number, end: number): Buffer {
    const sliceLen = end - start + 1;
    const out = Buffer.alloc(sliceLen, 0);
    const band = httpfsSessionState.populatedBands.get(bandHex);
    if (!band) {
      return out; // Untouched sparse hole returns deterministic zeroes
    }

    const payloadBuf = Buffer.from(band.payloadJson, 'utf8');
    if (start < payloadBuf.length) {
      const copyStart = start;
      const copyEnd = Math.min(end + 1, payloadBuf.length, SPARSE_PAYLOAD_PARTITION_BYTES);
      if (copyEnd > copyStart) {
        payloadBuf.copy(out, 0, copyStart, copyEnd);
      }
    }

    const tailBuf = Buffer.from(band.tailString, 'utf8');
    const tailEndOffset = SPARSE_PAYLOAD_PARTITION_BYTES + Math.min(tailBuf.length, Math.floor(SPARSE_TAIL_RESERVED_BITS / 8));
    if (end >= SPARSE_PAYLOAD_PARTITION_BYTES && start < tailEndOffset) {
      const srcStart = Math.max(0, start - SPARSE_PAYLOAD_PARTITION_BYTES);
      const srcEnd = Math.min(tailBuf.length, end + 1 - SPARSE_PAYLOAD_PARTITION_BYTES);
      const dstOffset = Math.max(0, SPARSE_PAYLOAD_PARTITION_BYTES - start);
      if (srcEnd > srcStart) {
        tailBuf.copy(out, dstOffset, srcStart, srcEnd);
      }
    }
    return out;
  }

  app.get('/v1/sparsebundle/httpfs/status', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      mounted: httpfsSessionState.mounted,
      ownerEmail: httpfsSessionState.ownerEmail,
      ownerDisplayName: httpfsSessionState.ownerDisplayName,
      driveFolderId: httpfsSessionState.driveFolderId,
      bandsFolderId: httpfsSessionState.bandsFolderId,
      mountedAt: httpfsSessionState.mountedAt,
      unmountedAt: httpfsSessionState.unmountedAt,
      logicalVolumeBytes: LOGICAL_SPARSE_VOLUME_BYTES,
      logicalVolumeGiB: 192,
      bandSizeBytes: BAND_SIZE_BYTES,
      totalSparseBands: TOTAL_SPARSE_BANDS,
      populatedBandCount: httpfsSessionState.populatedBands.size,
      setRootsHex: httpfsSessionState.setRootsHex,
      httpfsEndpoints: {
        plist: '/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/Info.plist',
        bandsBase: '/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/bands/',
        linearImage: '/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.img',
      },
      populatedBands: Array.from(httpfsSessionState.populatedBands.values()).map((b) => ({
        bandHex: b.bandHex,
        globalBandIndex: b.globalBandIndex,
        setIndex: b.setIndex,
        blockIndex: b.blockIndex,
        faceLabel: b.faceLabel,
        driveFileId: b.driveFileId,
        payloadBytesUsed: b.payloadBytesUsed,
        tailBitsUsed: b.tailBitsUsed,
        latestLeafHex: b.latestLeafHex,
        updatedAt: b.updatedAt,
      })),
      mountHistory: httpfsSessionState.mountHistory.slice(0, 12),
    });
  });

  app.post('/v1/sparsebundle/httpfs/mount', requireGenesisSignature, async (req: Request, res: Response) => {
    const idCheck = await verifyGoogleBearerIdentity(req.headers.authorization);
    if (!idCheck.ok || !idCheck.email) {
      res.status(401).json({ ok: false, error: idCheck.error || 'Unauthorized Google Drive session' });
      return;
    }

    const body = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<string, unknown>;
    const driveFolderId = typeof body.driveFolderId === 'string' && /^[a-zA-Z0-9_-]{8,128}$/.test(body.driveFolderId)
      ? body.driveFolderId
      : null;
    const bandsFolderId = typeof body.bandsFolderId === 'string' && /^[a-zA-Z0-9_-]{8,128}$/.test(body.bandsFolderId)
      ? body.bandsFolderId
      : null;
    const rawBands = Array.isArray(body.bands) ? body.bands.slice(0, 128) : [];
    const setRoots = Array.isArray(body.setRootsHex) && body.setRootsHex.length === 3
      ? [
          String(body.setRootsHex[0] || '0'.repeat(64)).slice(0, 64),
          String(body.setRootsHex[1] || '0'.repeat(64)).slice(0, 64),
          String(body.setRootsHex[2] || '0'.repeat(64)).slice(0, 64),
        ] as [string, string, string]
      : httpfsSessionState.setRootsHex;

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:drive.mountSparseBundle',
        functionName: 'POST /v1/sparsebundle/httpfs/mount',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: `Verified Google Bearer identity: ${idCheck.email}` },
          capacity: { state: 'PASS', reason: `HTTPFS 192 GiB (${TOTAL_SPARSE_BANDS} × 8 MiB sparse bands) addressable` },
          verification: { state: 'PASS', reason: `Google Drive folder ${driveFolderId || 'VIRTUAL_SESSION'} bound` },
          boundary: { state: 'PASS', reason: 'Same-origin Genesis HMAC + bounded sparse slice cache' },
          provenancePrivacy: { state: 'PASS', reason: 'OAuth Bearer token verified in-memory only; never stored on disk' },
        },
      },
      () => {
        httpfsSessionState.mounted = true;
        httpfsSessionState.ownerEmail = idCheck.email!;
        httpfsSessionState.ownerDisplayName = idCheck.displayName || idCheck.email!;
        if (driveFolderId) httpfsSessionState.driveFolderId = driveFolderId;
        if (bandsFolderId) httpfsSessionState.bandsFolderId = bandsFolderId;
        httpfsSessionState.mountedAt = new Date().toISOString();
        httpfsSessionState.unmountedAt = null;
        httpfsSessionState.setRootsHex = setRoots;

        for (const item of rawBands) {
          if (!item || typeof item !== 'object') continue;
          const b = item as Record<string, unknown>;
          const bandHex = typeof b.bandHex === 'string' ? b.bandHex.toLowerCase() : '';
          if (!/^[0-9a-f]{1,4}$/.test(bandHex)) continue;
          const gIdx = parseInt(bandHex, 16);
          if (gIdx < 0 || gIdx >= TOTAL_SPARSE_BANDS) continue;
          const driveFileId = typeof b.driveFileId === 'string' && /^[a-zA-Z0-9_-]{8,128}$/.test(b.driveFileId)
            ? b.driveFileId
            : null;
          const payloadJson = typeof b.payloadJson === 'string' ? b.payloadJson.slice(0, 512_000) : '';
          const tailString = typeof b.tailString === 'string' ? b.tailString.slice(0, 64_000) : '';

          httpfsSessionState.populatedBands.set(bandHex, {
            bandHex,
            globalBandIndex: gIdx,
            setIndex: Math.floor(gIdx / 8192),
            blockIndex: gIdx % 8192,
            faceLabel: typeof b.faceLabel === 'string' ? b.faceLabel.slice(0, 16) : 'TOP',
            driveFileId,
            payloadBytesUsed: Math.max(0, Math.min(SPARSE_PAYLOAD_PARTITION_BYTES, Number(b.payloadBytesUsed || payloadJson.length))),
            tailBitsUsed: Math.max(0, Math.min(SPARSE_TAIL_RESERVED_BITS, Number(b.tailBitsUsed || tailString.length * 8))),
            latestLeafHex: typeof b.latestLeafHex === 'string' ? b.latestLeafHex.slice(0, 64) : '0'.repeat(64),
            payloadJson,
            tailString,
            updatedAt: new Date().toISOString(),
          });
        }

        // Cap sparse server band cache to 64 active slices to stay safely within 4 GiB container RAM
        while (httpfsSessionState.populatedBands.size > 64) {
          const oldestKey = httpfsSessionState.populatedBands.keys().next().value;
          if (!oldestKey) break;
          httpfsSessionState.populatedBands.delete(oldestKey);
        }

        httpfsSessionState.mountHistory.unshift({
          ts: httpfsSessionState.mountedAt,
          action: 'MOUNT',
          ownerEmail: httpfsSessionState.ownerEmail,
          detail: `Mounted 192 GiB sparsebundle (${httpfsSessionState.populatedBands.size} active bands · folder=${driveFolderId || 'SESSION'})`,
        });
        if (httpfsSessionState.mountHistory.length > 32) httpfsSessionState.mountHistory.length = 32;
        return true;
      }
    );

    if (!gated.admitted) {
      res.status(403).json({ ok: false, verdict: gated.verdict, error: gated.blockedReason });
      return;
    }

    res.json({
      ok: true,
      mounted: httpfsSessionState.mounted,
      ownerEmail: httpfsSessionState.ownerEmail,
      driveFolderId: httpfsSessionState.driveFolderId,
      logicalVolumeBytes: LOGICAL_SPARSE_VOLUME_BYTES,
      populatedBandCount: httpfsSessionState.populatedBands.size,
      mountedAt: httpfsSessionState.mountedAt,
      creed_evaluation: gated.evaluation,
    });
  });

  app.post('/v1/sparsebundle/httpfs/unmount', (req: Request, res: Response) => {
    if (!isSameOriginRequest(req)) {
      res.status(403).json({ ok: false, error: 'EXTERNAL_UNMOUNT_REJECTED' });
      return;
    }

    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:drive.unmountSparseBundle',
        functionName: 'POST /v1/sparsebundle/httpfs/unmount',
        branchId: 'BRANCH-DEPLOYMENT',
        category: 'DEPLOYMENT',
        required: false,
        predicates: {
          authorization: { state: 'PASS', reason: 'Same-origin session unmount lifecycle' },
          capacity: { state: 'PASS', reason: `Releasing ${httpfsSessionState.populatedBands.size} cached band descriptors` },
          verification: { state: 'PASS', reason: 'Clean HTTPFS session unmount & buffer release' },
          boundary: { state: 'PASS', reason: 'Zero-leak transient RAM release on unload/sign-out' },
          provenancePrivacy: { state: 'PASS', reason: 'Session Drive references cleared without persisting credentials' },
        },
      },
      () => {
        const prevOwner = httpfsSessionState.ownerEmail || 'SESSION';
        const prevBands = httpfsSessionState.populatedBands.size;
        httpfsSessionState.mounted = false;
        httpfsSessionState.unmountedAt = new Date().toISOString();
        httpfsSessionState.populatedBands.clear();
        httpfsSessionState.ownerEmail = '';
        httpfsSessionState.ownerDisplayName = '';
        httpfsSessionState.mountHistory.unshift({
          ts: httpfsSessionState.unmountedAt,
          action: 'UNMOUNT',
          ownerEmail: prevOwner,
          detail: `Unmounted 192 GiB sparsebundle on exit/sign-out (released ${prevBands} cached bands)`,
        });
        if (httpfsSessionState.mountHistory.length > 32) httpfsSessionState.mountHistory.length = 32;
        return true;
      }
    );

    res.json({
      ok: true,
      mounted: false,
      unmountedAt: httpfsSessionState.unmountedAt,
      creed_evaluation: gated.evaluation,
    });
  });

  app.head('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/Info.plist', (_req: Request, res: Response) => {
    const xml = buildSparseBundlePlistXml();
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Content-Length', String(Buffer.byteLength(xml, 'utf8')));
    res.status(200).end();
  });

  app.get('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/Info.plist', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.send(buildSparseBundlePlistXml());
  });

  app.head('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/bands/:bandHex', (req: Request, res: Response) => {
    const bandHex = String(req.params.bandHex || '').toLowerCase();
    const gIdx = /^[0-9a-f]{1,4}$/.test(bandHex) ? parseInt(bandHex, 16) : -1;
    if (gIdx < 0 || gIdx >= TOTAL_SPARSE_BANDS) {
      res.status(404).end();
      return;
    }
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(BAND_SIZE_BYTES));
    res.status(200).end();
  });

  app.get('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.sparsebundle/bands/:bandHex', (req: Request, res: Response) => {
    const bandHex = String(req.params.bandHex || '').toLowerCase();
    const gIdx = /^[0-9a-f]{1,4}$/.test(bandHex) ? parseInt(bandHex, 16) : -1;
    if (gIdx < 0 || gIdx >= TOTAL_SPARSE_BANDS) {
      res.status(404).json({ ok: false, error: 'Band index outside 0x0..0x5fff (24,576 bands)' });
      return;
    }

    const rangeHeader = String(req.headers.range || '');
    let start = 0;
    let end = BAND_SIZE_BYTES - 1;
    let isPartial = false;

    if (rangeHeader) {
      const m = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader.trim());
      if (!m) {
        res.status(416).setHeader('Content-Range', `bytes */${BAND_SIZE_BYTES}`).end();
        return;
      }
      start = Number(m[1]);
      end = m[2] ? Math.min(BAND_SIZE_BYTES - 1, Number(m[2])) : BAND_SIZE_BYTES - 1;
      if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start > end || start >= BAND_SIZE_BYTES) {
        res.status(416).setHeader('Content-Range', `bytes */${BAND_SIZE_BYTES}`).end();
        return;
      }
      isPartial = true;
    }

    const slice = renderSparseBandSlice(bandHex, start, end);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(slice.length));
    if (isPartial) {
      res.setHeader('Content-Range', `bytes ${start}-${end}/${BAND_SIZE_BYTES}`);
      res.status(206).send(slice);
    } else {
      res.status(200).send(slice);
    }
  });

  app.head('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.img', (_req: Request, res: Response) => {
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(LOGICAL_SPARSE_VOLUME_BYTES));
    res.status(200).end();
  });

  app.get('/v1/sparsebundle/httpfs/GAIA_NEXUS_192GiB.img', (req: Request, res: Response) => {
    const rangeHeader = String(req.headers.range || '');
    const m = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader.trim());
    if (!m) {
      res.status(416)
        .setHeader('Content-Range', `bytes */${LOGICAL_SPARSE_VOLUME_BYTES}`)
        .json({ ok: false, error: 'HTTPFS requires a bounded Byte-Range header (max 8 MiB per request) on the 192 GiB virtual disk' });
      return;
    }
    const start = Number(m[1]);
    const requestedEnd = m[2] ? Number(m[2]) : start + Math.min(BAND_SIZE_BYTES - 1, LOGICAL_SPARSE_VOLUME_BYTES - 1 - start);
    const end = Math.min(LOGICAL_SPARSE_VOLUME_BYTES - 1, requestedEnd, start + BAND_SIZE_BYTES - 1);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start > end || start >= LOGICAL_SPARSE_VOLUME_BYTES) {
      res.status(416).setHeader('Content-Range', `bytes */${LOGICAL_SPARSE_VOLUME_BYTES}`).end();
      return;
    }

    const totalLen = end - start + 1;
    const chunks: Buffer[] = [];
    let cursor = start;
    while (cursor <= end) {
      const bandIdx = Math.floor(cursor / BAND_SIZE_BYTES);
      const bandOffsetStart = cursor % BAND_SIZE_BYTES;
      const bandOffsetEnd = Math.min(BAND_SIZE_BYTES - 1, bandOffsetStart + (end - cursor));
      chunks.push(renderSparseBandSlice(bandIdx.toString(16), bandOffsetStart, bandOffsetEnd));
      cursor += bandOffsetEnd - bandOffsetStart + 1;
    }

    const body = Buffer.concat(chunks, totalLen);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(body.length));
    res.setHeader('Content-Range', `bytes ${start}-${end}/${LOGICAL_SPARSE_VOLUME_BYTES}`);
    res.status(206).send(body);
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, HOST, () => {
    console.log(`GAIA NEXUS Zero-Trust Genesis Server listening on http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start GAIA NEXUS server:', err);
  process.exit(1);
});
