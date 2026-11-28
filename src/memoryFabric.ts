/**
 * Memory Fabric & Provenance Ledger
 * Append-only event records, Merkle verification, and sparse bundle boundaries.
 * All writes are gated through Creed of Admittance (creedAdmittanceService).
 */

import {
  creedAdmittanceService,
  type FunctionAdmissionResult,
  type Verdict,
} from './creedAdmittance.ts';
import { canonicalErrorRegistry } from './canonicalErrorRegistry.ts';

export interface MiningBlockReceipt {
  blockIndex: number;
  nonce: number;
  blockHash: string;
  zeroBits: number;
  merkleRoot: string;
  activeMerkleNodes: number;
  ivcAccumulator: string;
  v5NodeId: number;
  prismsEncodedDelta: number;
  headerFirst32BytesHex: string;
  coreRegistryDigestHex: string;
  primaryRegistrySourceId: string;
  monolithVersion: number;
  creedPathVerdict: Verdict;
  creedEvaluationId: string;
  blake2b512Hex?: string;
  blake2b128Hex?: string;
  deweyAddress?: string;
  coprimeLaneId?: number;
  orbIndex?: number;
  sparseBandOffset?: number;
}

export interface SystemEventRecord {
  eventId: string;
  schemaVersion: string;
  correlationId: string;
  parentEventId: string;
  sourceModule: string;
  timestamp: string;
  monotonicElapsedMs: number;
  inputFingerprint: string;
  operation: string;
  outputFingerprint: string;
  verificationStatus: Verdict;
  privacyClassification: string;
  admissionEvaluationId: string;
  receipt?: MiningBlockReceipt;
}

export interface MemoryFabricMetrics {
  totalEvents: number;
  acceptedCandidateCount: number;
  prismsEncodedTotal: number;
  blockedWritesCount: number;
  latestCandidateEventId: string | null;
  latestBlockIndex: number | null;
  latestBlockHash: string | null;
  latestMerkleRoot: string | null;
  latestActiveMerkleNodes: number;
  latestHeaderFirst32BytesHex: string | null;
  lastUpdated: string | null;
}

export class MemoryFabricLedger {
  public events: SystemEventRecord[] = [];
  public blockedWrites: Array<{ timestamp: string; operation: string; verdict: Verdict; reason: string }> = [];
  public lastAdmissionResult: FunctionAdmissionResult | null = null;
  private listeners = new Set<() => void>();
  private startTime = Date.now();
  private readonly maxEvents = 10000;
  private acceptedCandidateTotal = 0;
  private prismsEncodedTotal = 0;
  private latestMiningEvent: SystemEventRecord | null = null;

  constructor() {
    this.recordEvent({
      operation: 'GENESIS_SEED_INIT',
      sourceModule: 'Mater',
      inputFingerprint: '0x0000000000000000',
      outputFingerprint: '0xadmit77777777777',
      verificationStatus: 'GREEN',
      privacyClassification: 'SENTIENT-LOCKED',
    });
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyChange(): void {
    for (const listener of this.listeners) {
      try {
        listener();
      } catch (_) {}
    }
  }

  public recordEvent(params: {
    operation: string;
    sourceModule: string;
    inputFingerprint: string;
    outputFingerprint: string;
    verificationStatus: Verdict;
    privacyClassification: string;
    parentEventId?: string;
    authorized?: boolean;
    receipt?: MiningBlockReceipt;
  }): SystemEventRecord | null {
    const gated = creedAdmittanceService.admitOperation(
      {
        functionId: 'fn:memory.recordEvent',
        functionName: 'MemoryFabricLedger.recordEvent',
        branchId: 'BRANCH-MEMORY-WRITE',
        category: 'MEMORY_WRITE',
        required: true,
        predicates: {
          authorization:
            params.authorized === false
              ? { state: 'FAIL', reason: 'Caller explicitly unauthorized for memory write' }
              : params.sourceModule && params.sourceModule.trim().length > 0
                ? { state: 'PASS', reason: `Authorized source module: ${params.sourceModule}` }
                : { state: 'FAIL', reason: 'Missing sourceModule authorization' },
          capacity:
            this.events.length < this.maxEvents
              ? {
                  state: 'PASS',
                  reason: `Ledger capacity OK (${this.events.length}/${this.maxEvents})`,
                  evidence: { currentCount: this.events.length, maxEvents: this.maxEvents },
                }
              : {
                  state: 'FAIL',
                  reason: `Ledger capacity exhausted (${this.events.length}/${this.maxEvents})`,
                },
          verification:
            params.verificationStatus === 'GREEN'
              ? { state: 'PASS', reason: 'Verified event state GREEN' }
              : params.verificationStatus === 'YELLOW'
                ? { state: 'INCOMPLETE', reason: 'Verification status is YELLOW (incomplete evidence)' }
                : { state: 'FAIL', reason: 'Verification status is RED (failed check)' },
          boundary:
            params.operation && params.inputFingerprint && params.outputFingerprint
              ? { state: 'PASS', reason: 'Operation and cryptographic I/O fingerprints present' }
              : { state: 'FAIL', reason: 'Missing required operation or input/output boundary fingerprints' },
          provenancePrivacy:
            params.privacyClassification && params.privacyClassification.trim().length > 0
              ? { state: 'PASS', reason: `Privacy class declared: ${params.privacyClassification}` }
              : { state: 'FAIL', reason: 'Missing privacy classification' },
        },
      },
      (evalResult) => {
        const eventId = 'EVT-' + Math.random().toString(36).substring(2, 10).toUpperCase();
        const record: SystemEventRecord = {
          eventId,
          schemaVersion: '1.0.0',
          correlationId: 'CORR-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
          parentEventId:
            params.parentEventId ||
            (this.events.length > 0 ? this.events[this.events.length - 1].eventId : 'ROOT'),
          sourceModule: params.sourceModule,
          timestamp: new Date().toISOString(),
          monotonicElapsedMs: Date.now() - this.startTime,
          inputFingerprint: params.inputFingerprint,
          operation: params.operation,
          outputFingerprint: params.outputFingerprint,
          verificationStatus: params.verificationStatus,
          privacyClassification: params.privacyClassification,
          admissionEvaluationId: evalResult.evaluationId,
          ...(params.receipt ? { receipt: { ...params.receipt } } : {}),
        };
        this.events.push(record);
        if (record.operation === 'POW_BLOCK_ACCEPTED' && record.receipt) {
          this.acceptedCandidateTotal++;
          this.prismsEncodedTotal += record.receipt.prismsEncodedDelta;
          this.latestMiningEvent = record;
        }
        return record;
      }
    );

    this.lastAdmissionResult = gated.evaluation;

    if (!gated.admitted) {
      this.blockedWrites.unshift({
        timestamp: new Date().toISOString(),
        operation: params.operation || 'UNKNOWN',
        verdict: gated.verdict,
        reason: gated.blockedReason,
      });
      if (this.blockedWrites.length > 50) this.blockedWrites.length = 50;
      if (gated.verdict === 'RED') {
        canonicalErrorRegistry.addError(
          'ERROR',
          'MemoryFabricLedger',
          `Creed denied memory write (${params.operation}): ${gated.blockedReason}`
        );
      }
      this.notifyChange();
      return null;
    }

    this.notifyChange();
    return gated.value;
  }

  public recordAcceptedCandidate(receipt: MiningBlockReceipt): SystemEventRecord | null {
    return this.recordEvent({
      operation: 'POW_BLOCK_ACCEPTED',
      sourceModule: 'monolithEngine.miningEngine',
      inputFingerprint: `0x${receipt.headerFirst32BytesHex}`,
      outputFingerprint: `0x${receipt.blockHash}`,
      verificationStatus: 'GREEN',
      privacyClassification: 'PUBLIC',
      receipt,
    });
  }

  public recordSparseBandEvent(params: {
    operation: 'SPARSE_BAND_INGEST' | 'COPRIME_INVERSE_SOLVE';
    sourceModule: string;
    blockIndex: number;
    merkleRoot: string;
    activeMerkleNodes: number;
    blake2b512Hex: string;
    blake2b128Hex: string;
    sha256dHex: string;
    deweyAddress: string;
    coprimeLaneId: number;
    orbIndex: number;
    sparseBandOffset: number;
    prismsEncodedDelta?: number;
    creedEvaluationId?: string;
  }): SystemEventRecord | null {
    return this.recordEvent({
      operation: params.operation,
      sourceModule: params.sourceModule,
      inputFingerprint: `0x${params.blake2b128Hex}`,
      outputFingerprint: `0x${params.sha256dHex}`,
      verificationStatus: 'GREEN',
      privacyClassification: 'RESTRICTED',
      receipt: {
        blockIndex: params.blockIndex,
        nonce: 0,
        blockHash: params.sha256dHex,
        zeroBits: 0,
        merkleRoot: params.merkleRoot,
        activeMerkleNodes: params.activeMerkleNodes,
        ivcAccumulator: params.merkleRoot,
        v5NodeId: 312,
        prismsEncodedDelta: params.prismsEncodedDelta ?? 0,
        headerFirst32BytesHex: params.blake2b128Hex,
        coreRegistryDigestHex: params.blake2b512Hex.slice(0, 64),
        primaryRegistrySourceId: params.deweyAddress,
        monolithVersion: 1,
        creedPathVerdict: 'GREEN',
        creedEvaluationId: params.creedEvaluationId ?? 'CREED-DIRECT',
        blake2b512Hex: params.blake2b512Hex,
        blake2b128Hex: params.blake2b128Hex,
        deweyAddress: params.deweyAddress,
        coprimeLaneId: params.coprimeLaneId,
        orbIndex: params.orbIndex,
        sparseBandOffset: params.sparseBandOffset,
      },
    });
  }

  public getRecordByEventId(eventId: string): SystemEventRecord | null {
    const found = this.events.find((e) => e.eventId === eventId);
    return found ? { ...found, ...(found.receipt ? { receipt: { ...found.receipt } } : {}) } : null;
  }

  public getLatestMiningRecord(): SystemEventRecord | null {
    if (!this.latestMiningEvent) return null;
    return {
      ...this.latestMiningEvent,
      ...(this.latestMiningEvent.receipt ? { receipt: { ...this.latestMiningEvent.receipt } } : {}),
    };
  }

  public getMiningRecords(limit = 20): SystemEventRecord[] {
    const res: SystemEventRecord[] = [];
    for (let i = this.events.length - 1; i >= 0 && res.length < limit; i--) {
      const ev = this.events[i];
      if (ev.operation === 'POW_BLOCK_ACCEPTED') {
        res.push({ ...ev, ...(ev.receipt ? { receipt: { ...ev.receipt } } : {}) });
      }
    }
    return res;
  }

  public getRecentEventsWithMerkle(limit = 40): SystemEventRecord[] {
    const start = Math.max(0, this.events.length - limit);
    return this.events.slice(start).map((ev) => ({
      ...ev,
      ...(ev.receipt ? { receipt: { ...ev.receipt } } : {}),
    }));
  }

  public getMetrics(): MemoryFabricMetrics {
    const latest = this.latestMiningEvent;
    return {
      totalEvents: this.events.length,
      acceptedCandidateCount: this.acceptedCandidateTotal,
      prismsEncodedTotal: this.prismsEncodedTotal,
      blockedWritesCount: this.blockedWrites.length,
      latestCandidateEventId: latest?.eventId ?? null,
      latestBlockIndex: latest?.receipt?.blockIndex ?? null,
      latestBlockHash: latest?.receipt?.blockHash ?? null,
      latestMerkleRoot: latest?.receipt?.merkleRoot ?? null,
      latestActiveMerkleNodes: latest?.receipt?.activeMerkleNodes ?? 0,
      latestHeaderFirst32BytesHex: latest?.receipt?.headerFirst32BytesHex ?? null,
      lastUpdated: latest?.timestamp ?? (this.events[this.events.length - 1]?.timestamp ?? null),
    };
  }
}

export const memoryFabric = new MemoryFabricLedger();
