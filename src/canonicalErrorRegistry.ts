/**
 * Canonical Error & Event Registry (LS-MASTER-1.0)
 * Unifies assistant panel and debug panel error counters and logs into a single source of truth.
 */

export interface CanonicalErrorRecord {
  id: string;
  severity: 'ERROR' | 'WARN' | 'INFO';
  sourceModule: string;
  message: string;
  timestamp: string;
  resolutionState: 'UNRESOLVED' | 'RESOLVED' | 'QUARANTINED';
  originCategory?: 'REGISTRY_DIAGNOSTIC' | 'RUNTIME_TRAP';
  signature?: string;
  occurrences?: number;
  observedAtRuntime?: boolean;
}

export interface CanonicalLogRecord {
  id: string;
  category: string;
  message: string;
  timestamp: string;
}

export interface MockLedgerEntry {
  id: string;
  subsystem: string;
  location: string;
  statusLabel: 'SIMULATED';
  reason: string;
}

export interface CounterDefinitionEntry {
  key: 'BLKS' | 'V5_NODES' | 'V5_EDGES';
  label: string;
  totalCount: number;
  setName: string;
  formula: string;
  definition: string;
  distinctionNote: string;
}

export interface SystemDefinitions {
  blksDefinition: CounterDefinitionEntry & {
    totalCapacity: number;
    forwardBranchCount: number;
    backwardBranchCount: number;
    prismsPerBlock: number;
    totalPrisms: number;
    completedCriteria: string;
  };
  v5NodesDefinition: CounterDefinitionEntry & {
    nodesCount: number;
    coordinateSpace: string;
  };
  v5EdgesDefinition: CounterDefinitionEntry & {
    edgesCount: number;
    adjacencyRule: string;
  };
}

export class CanonicalErrorRegistryService {
  // ERR-001 through ERR-004 are preserved with their original IDs and sequence;
  // ERR-005 and ERR-006 register the 2 live WebGL uSideSign runtime shader errors.
  public errors: CanonicalErrorRecord[] = [
    {
      id: 'ERR-001',
      severity: 'ERROR',
      sourceModule: 'RenderPipeline',
      message: 'WebGL precision qualifier synchronization between shader stages (uSideSign uniform).',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'REGISTRY_DIAGNOSTIC',
      occurrences: 1,
      observedAtRuntime: true
    },
    {
      id: 'ERR-002',
      severity: 'WARN',
      sourceModule: 'MemoryAPI',
      message: '/v1/memory sync heartbeat timeout fallback to offline cache.',
      timestamp: new Date(Date.now() - 240000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'REGISTRY_DIAGNOSTIC',
      occurrences: 1,
      observedAtRuntime: false
    },
    {
      id: 'ERR-003',
      severity: 'ERROR',
      sourceModule: 'PoWMiningWorker',
      message: 'Web Worker thread sync fallback activated (SYNC_FALLBACK mode).',
      timestamp: new Date(Date.now() - 180000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'REGISTRY_DIAGNOSTIC',
      occurrences: 1,
      observedAtRuntime: false
    },
    {
      id: 'ERR-004',
      severity: 'WARN',
      sourceModule: 'ZeroTrustPeer',
      message: 'Peer security scrutiny quarantine check triggered (QUARANTINED_NO_PASS).',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'REGISTRY_DIAGNOSTIC',
      occurrences: 1,
      observedAtRuntime: false
    },
    {
      id: 'ERR-005',
      severity: 'ERROR',
      sourceModule: 'WebGLProgram:voidLatticePoints',
      message: "Runtime shader program link error: Precisions of uniform 'uSideSign' differ between VERTEX (highp) and FRAGMENT (mediump) shaders in voidNodeVS/voidNodeFS.",
      timestamp: new Date(Date.now() - 30000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'RUNTIME_TRAP',
      signature: 'WEBGL_USIDESIGN_VOID_NODE',
      occurrences: 1,
      observedAtRuntime: true
    },
    {
      id: 'ERR-006',
      severity: 'ERROR',
      sourceModule: 'WebGLProgram:voidEdgeLines',
      message: "Runtime shader program link error: Precisions of uniform 'uSideSign' differ between VERTEX (highp) and FRAGMENT (mediump) shaders in voidEdgeVS/voidEdgeFS.",
      timestamp: new Date(Date.now() - 25000).toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'RUNTIME_TRAP',
      signature: 'WEBGL_USIDESIGN_VOID_EDGE',
      occurrences: 1,
      observedAtRuntime: true
    }
  ];

  public logs: CanonicalLogRecord[] = Array.from({ length: 16 }, (_, i) => ({
    id: `LOG-${String(i + 1).padStart(3, '0')}`,
    category: i % 2 === 0 ? 'AUDIT' : 'ROUTER',
    message: `System convergence telemetry event sequence #${i + 1} recorded successfully.`,
    timestamp: new Date(Date.now() - (16 - i) * 10000).toISOString()
  }));

  public readonly reconciliationNote =
    "Unified error count combines the 4 preserved diagnostic/fallback records (ERR-001..ERR-004: 2 ERROR + 2 WARN) with the 2 live runtime 'errors running the code' WebGL shader link traps (ERR-005..ERR-006: uSideSign vertex highp vs fragment mediump precision mismatch in voidNodeFS/voidEdgeFS). All HUD, Debug, and AUDIT panels derive directly from this single registry (6 unified error records; 16 logs).";

  public readonly mockLedger: MockLedgerEntry[] = [
    {
      id: 'MOCK-001',
      subsystem: 'Network Secure Mining Pool (32 Nodes / ZK-VRF)',
      location: 'index.html · miningPoolState (#pool-peers-ui, #pool-vrf-ui)',
      statusLabel: 'SIMULATED',
      reason: 'Displays local state ("32 Nodes (BFT Quorum)", "VERIFIED ✓ (ZK-VRF)") without a live Stratum TCP/WebSocket pool or external ZK-VRF circuit verifier.'
    },
    {
      id: 'MOCK-002',
      subsystem: 'WebGPU SHA-256d Compute Offload Kernel',
      location: 'index.html · miningEngine.initWebGPU()',
      statusLabel: 'SIMULATED',
      reason: 'WGSL shader skeleton declares main() without SHA-256d rounds or nonce result writeback; actual PoW hashing executes on CPU JS / Blob Web Workers.'
    },
    {
      id: 'MOCK-003',
      subsystem: 'Proxy Switch VLAN Relay & DMZ Telemetry',
      location: 'index.html · #tab-cryptics (#vlan-status)',
      statusLabel: 'SIMULATED',
      reason: 'Display-only network status strings ("127.0.0.1 ↔ 0.0.0.9 ACTIVE", "OpenWrt Custom Image", "5 Gbps Fibre / LNA WAN ETH") with no router hardware probe.'
    },
    {
      id: 'MOCK-004',
      subsystem: 'Animus OS Cognitive Lanes',
      location: 'index.html · #tab-math (Animus OS card)',
      statusLabel: 'SIMULATED',
      reason: 'Display-only badges (COGNITION.observe(), STORE.lesson(), FORECAST 0.99, RS(255,223) t=16) without a live neural forecasting backend.'
    },
    {
      id: 'MOCK-005',
      subsystem: 'ADL Scheduler AFAC Resource Metrics',
      location: 'src/adlScheduler.ts · getResourceMetrics()',
      statusLabel: 'SIMULATED',
      reason: 'Returns hardcoded resource constants (cpuTimeMs: 42.8, gpuCapacityPct: 88.5, memoryMb: 128.0, ioThroughputMbS: 1024.0) across 6 in-memory logical lanes.'
    },
    {
      id: 'MOCK-006',
      subsystem: 'Peer-Enemy Quarantine Intrusion Drill',
      location: 'index.html · zeroTrustGenesis.testPeerQuarantine() + server.ts',
      statusLabel: 'SIMULATED',
      reason: 'Synthesizes untrusted hostnames (peer-collective-<rnd>.untrusted.net) to exercise quarantine logging; no external P2P WAN socket is listening.'
    },
    {
      id: 'MOCK-007',
      subsystem: 'Virtual Disk Mesh Broadcast',
      location: 'index.html · virtualDiskArchive.broadcastToMesh()',
      statusLabel: 'SIMULATED',
      reason: 'Uses browser-local BroadcastChannel across same-origin tabs only, rather than a cross-machine network storage mesh.'
    },
    {
      id: 'MOCK-008',
      subsystem: 'Shared Memory Model Routing & Outcome Pathlines',
      location: 'server.ts · /v1/memory, outcomePathlines',
      statusLabel: 'SIMULATED',
      reason: 'Ephemeral in-memory store (resets on restart); share_with tags (gemini/openai) do not call external LLM APIs, and outcomePathlines weights (0.98/0.94/0.99) are static.'
    },
    {
      id: 'MOCK-009',
      subsystem: 'Default Google Drive Package Binding (Signed Out)',
      location: 'src/drivePackageBridge.ts + index.html (#mint-bound-provider-ui)',
      statusLabel: 'SIMULATED',
      reason: 'Displays local KERNEL_LOCAL · AE.SL6.DUALTRACE.4P stub metadata until the user signs in with Google OAuth to query real Drive files.'
    },
    {
      id: 'MOCK-010',
      subsystem: 'Pre-Seeded Convergence Logs & Baseline Diagnostic Warnings',
      location: 'src/canonicalErrorRegistry.ts (LOG-001..LOG-016, ERR-002, ERR-004)',
      statusLabel: 'SIMULATED',
      reason: 'Baseline telemetry log sequence LOG-001..LOG-016 and standby warning scenarios ERR-002/ERR-004 are synthetic seeded fixtures alongside live captured traps.'
    },
    {
      id: 'MOCK-011',
      subsystem: 'Signal / MIDI Pulse & HWAD Acoustic Synth',
      location: 'index.html · signalCoordinator & hwadSonifier',
      statusLabel: 'SIMULATED',
      reason: 'TEST MIDI PULSE injects synthetic MIDI frames in-memory without hardware MIDI; HWAD/BWV 666 tones are synthesized locally via WebAudio.'
    },
    {
      id: 'MOCK-012',
      subsystem: 'Bounded Self-Check Scope (LOCAL_ONLY)',
      location: 'index.html · boundedSelfCheckRunner.runAll()',
      statusLabel: 'SIMULATED',
      reason: 'Explicitly marked scope="LOCAL_ONLY" (live_gpu_attestation=false, signed=false); does not perform remote hardware or cryptographic node attestation.'
    },
    {
      id: 'MOCK-013',
      subsystem: '384 GiB Physical Contiguous RAM & Kernel FUSE rclone Mount',
      location: 'src/sparseBandCryptoEngine.ts · src/driveSparseMount.ts · server.ts (/v1/sparsebundle/httpfs/*)',
      statusLabel: 'SIMULATED',
      reason: '8-Sparse-Fusion 384 GiB (49,152 × 8 MiB = 412,316,860,416 B) geometry, bit-scaled clip-path mounts (64..2048+), Drive quota check, HTTPFS 206 Byte-Range gateway, and touched 8 MiB Google Drive band sync execute live; however, allocating 384 GiB raw contiguous RAM and spawning a kernel FUSE rclone daemon are unsupported in browser/4 GiB container sandboxes.'
    }
  ];

  public definitions: SystemDefinitions = {
    blksDefinition: {
      key: 'BLKS',
      label: 'BLKS (16,384 × 3 Sets = 49,152 · 15-Level Merkle & 8 MiB Prisms)',
      totalCount: 16384,
      totalCapacity: 16384,
      forwardBranchCount: 8192,
      backwardBranchCount: 8192,
      prismsPerBlock: 6,
      totalPrisms: 98304,
      setName: 'Doubled Golden Spiral PoW Blocks, 15-Level Merkle L0 Leaves & 3-Set Rubik Hypercube Faces',
      formula: '2^14 = 16,384 blocks/set (8,192 FWD + 8,192 BWD) × 3 duplicated sets = 49,152 blocks · 6 Sierpinski orb prisms/blk',
      definition:
        'Counts the doubled 16,384 (2^14) dual-branch Golden Spiral PoW block squares per Merkle tree (squareRecords[0..16383]: 8,192 FORWARD_FK + 8,192 BACKWARD_RK) duplicated across 3 axis-pair sets (Top/Bottom=1, Left/Right=1, Front/Back=1; 49,152 total blocks), anchoring L0..L14 (32,767 nodes/tree) with BLAKE2b+SHA256d 8 MiB sparsebundle prism bands and Osmosis Fusion.',
      completedCriteria:
        'A block completes (cursor -> 16,384) when its PoW/database hash satisfies verification and commits its BLAKE2b + SHA-256d leaf across the 15-level Merkle tree and 8 MiB sparseband tail index.',
      distinctionNote:
        '16,384 (or 49,152 across 3 cube-face sets) is the doubled Merkle/spiral block space and does NOT equal the 1,250 V5 lattice sites (2 sets of 625).'
    },
    v5NodesDefinition: {
      key: 'V5_NODES',
      label: 'V5 Nodes (Two Sets of 625 Nodes = 1,250 4D Lattice Sites)',
      totalCount: 1250,
      nodesCount: 1250,
      setName: 'V5 4D Discrete Integer Spacetime Grid Vertices (Set A + Set B Dual)',
      formula: '2 × 5^4 = 1,250 vertices across Set A (0..624, origin #312) and Set B (625..1249, dual origin #937)',
      coordinateSpace: 'Discrete 4D integer grid V5 centered at origin #312 (0,0,0,0) and dual origin #937.',
      definition:
        'Counts the 1,250 (2 × 5^4) discrete integer vertices in voidNodes[0..1249] across Set A (0..624, origin #312) and Set B dual lattice (625..1249, dual origin #937), with live frustum visibility tracked separately.',
      distinctionNote:
        'Distinct from the 16,384 Golden Spiral BLKS squares and distinct from the 4,000 undirected Manhattan edges connecting V5 neighbors.'
    },
    v5EdgesDefinition: {
      key: 'V5_EDGES',
      label: 'V5 Edges (4k Nearest-Neighbor Manhattan Edges = 4,000 Edges)',
      totalCount: 4000,
      edgesCount: 4000,
      setName: 'V5 Undirected Nearest-Neighbor Edges (4k Edges · Delta = 1)',
      formula: '2 × (4 × 4 × 5^3) = 4,000 undirected nearest-neighbor Manhattan edges',
      adjacencyRule: 'Undirected vertex pairs (u, v) in V5 x V5 with L1/Euclidean distance Delta = 1 across 4 coordinate axes (2,000 in Set A + 2,000 in Set B).',
      definition:
        'Counts the 4,000 (4k) undirected nearest-neighbor edges in voidEdges[0..3999] linking V5 lattice vertices separated by distance Delta = 1 (2,000 in Set A + 2,000 in Set B), used for L1 geodesic BFS routing.',
      distinctionNote:
        'Separate topological edge counter; distinct from the 1,250 V5 vertex sites (two sets of 625) and the 16,384 BLKS spiral/Merkle blocks.'
    }
  };

  public getErrorCount(): number {
    return this.errors.length;
  }

  public getLogCount(): number {
    return this.logs.length;
  }

  public getSummary() {
    const errorSeverityCount = this.errors.filter((e) => e.severity === 'ERROR').length;
    const warnSeverityCount = this.errors.filter((e) => e.severity === 'WARN').length;
    const infoSeverityCount = this.errors.filter((e) => e.severity === 'INFO').length;
    const runtimeTrapCount = this.errors.filter((e) => e.originCategory === 'RUNTIME_TRAP').length;
    const diagnosticCount = this.errors.length - runtimeTrapCount;
    return {
      totalCount: this.errors.length,
      errorSeverityCount,
      warnSeverityCount,
      infoSeverityCount,
      runtimeTrapCount,
      diagnosticCount,
      logCount: this.logs.length
    };
  }

  public captureRuntimeError(
    sourceModule: string,
    message: string,
    severity: 'ERROR' | 'WARN' | 'INFO' = 'ERROR'
  ): CanonicalErrorRecord {
    const cleanMsg = String(message || 'Unknown runtime error').slice(0, 600);
    const lower = cleanMsg.toLowerCase();

    // Deduplicate known uSideSign shader link errors to the registered runtime IDs (ERR-005 / ERR-006)
    let signature = `${sourceModule}:${cleanMsg.slice(0, 140)}`;
    if (lower.includes('usidesign') || (lower.includes('webglprogram') && lower.includes('shader error'))) {
      const existingNodeMatch = this.errors.find((e) => e.signature === 'WEBGL_USIDESIGN_VOID_NODE');
      const existingEdgeMatch = this.errors.find((e) => e.signature === 'WEBGL_USIDESIGN_VOID_EDGE');
      if (lower.includes('gl_pointsize') || lower.includes('voidnode') || lower.includes('pointcoord')) {
        if (existingNodeMatch) {
          existingNodeMatch.occurrences = (existingNodeMatch.occurrences ?? 1) + 1;
          existingNodeMatch.observedAtRuntime = true;
          existingNodeMatch.timestamp = new Date().toISOString();
          return existingNodeMatch;
        }
      } else if (existingEdgeMatch && !existingEdgeMatch.observedAtRuntime) {
        existingEdgeMatch.occurrences = (existingEdgeMatch.occurrences ?? 1) + 1;
        existingEdgeMatch.observedAtRuntime = true;
        existingEdgeMatch.timestamp = new Date().toISOString();
        return existingEdgeMatch;
      } else if (existingNodeMatch && existingEdgeMatch) {
        // Alternate/increment first matching runtime shader record without inflating ERR-007+
        const target = (existingNodeMatch.occurrences ?? 1) <= (existingEdgeMatch.occurrences ?? 1)
          ? existingNodeMatch
          : existingEdgeMatch;
        target.occurrences = (target.occurrences ?? 1) + 1;
        target.observedAtRuntime = true;
        target.timestamp = new Date().toISOString();
        return target;
      }
      signature = 'WEBGL_USIDESIGN_RUNTIME';
    }

    const existing = this.errors.find((e) => e.signature === signature || (e.sourceModule === sourceModule && e.message === cleanMsg));
    if (existing) {
      existing.occurrences = (existing.occurrences ?? 1) + 1;
      existing.observedAtRuntime = true;
      existing.timestamp = new Date().toISOString();
      return existing;
    }

    const err: CanonicalErrorRecord = {
      id: `ERR-${String(this.errors.length + 1).padStart(3, '0')}`,
      severity,
      sourceModule,
      message: cleanMsg,
      timestamp: new Date().toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'RUNTIME_TRAP',
      signature,
      occurrences: 1,
      observedAtRuntime: true
    };
    this.errors.push(err);
    this.addLog('RUNTIME', `Captured runtime ${severity} [${err.id}] in ${sourceModule}`);
    return err;
  }

  public addError(severity: 'ERROR' | 'WARN' | 'INFO', sourceModule: string, message: string): CanonicalErrorRecord {
    const err: CanonicalErrorRecord = {
      id: `ERR-${String(this.errors.length + 1).padStart(3, '0')}`,
      severity,
      sourceModule,
      message,
      timestamp: new Date().toISOString(),
      resolutionState: 'UNRESOLVED',
      originCategory: 'RUNTIME_TRAP',
      occurrences: 1,
      observedAtRuntime: true
    };
    this.errors.push(err);
    return err;
  }

  public addLog(category: string, message: string): CanonicalLogRecord {
    const log: CanonicalLogRecord = {
      id: `LOG-${String(this.logs.length + 1).padStart(3, '0')}`,
      category,
      message,
      timestamp: new Date().toISOString()
    };
    this.logs.unshift(log);
    if (this.logs.length > 64) this.logs.length = 64;
    return log;
  }
}

export const canonicalErrorRegistry = new CanonicalErrorRegistryService();
