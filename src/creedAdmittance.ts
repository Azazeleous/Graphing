/**
 * Creed of Admittance Governing Service (LS-MASTER-1.0)
 * Central admission service for every registered operation:
 * ADMIT(x) = A ∧ C ∧ V ∧ B ∧ P
 *
 * States:
 *  - GREEN:  all five predicates verified with passing evidence.
 *  - YELLOW: evidence missing, incomplete, unavailable, or unresolved. Hold execution.
 *  - RED:    required condition failed. Deny, isolate, or quarantine operation.
 *
 * Parents inherit the strictest required child state (RED > YELLOW > GREEN).
 * No mining job, solver result, memory write, or deployment may bypass this gate.
 */

export type Verdict = 'GREEN' | 'YELLOW' | 'RED';

export type PredicateKey =
  | 'authorization'
  | 'capacity'
  | 'verification'
  | 'boundary'
  | 'provenancePrivacy';

export type PredicateState = 'PASS' | 'INCOMPLETE' | 'FAIL';

export type OperationCategory =
  | 'GOVERNANCE'
  | 'MINING'
  | 'SOLVER'
  | 'MEMORY_WRITE'
  | 'DEPLOYMENT'
  | 'SCHEDULER'
  | 'EVIDENCE';

export interface PredicateInputDetail {
  state: PredicateState;
  reason: string;
  evidence?: Record<string, unknown>;
}

export type PredicateInput = boolean | PredicateInputDetail;

export interface AdmittancePredicatesInput {
  authorization: PredicateInput;      // A
  capacity: PredicateInput;           // C
  verification: PredicateInput;       // V
  boundary: PredicateInput;           // B
  provenancePrivacy: PredicateInput;  // P
}

export interface PredicateCheck {
  key: PredicateKey;
  symbol: 'A' | 'C' | 'V' | 'B' | 'P';
  label: string;
  state: PredicateState;
  verdict: Verdict;
  satisfied: boolean;
  reason: string;
  evidence?: Record<string, unknown>;
}

export interface AdmittanceEvaluation {
  evaluationId: string;
  functionId: string;
  branchId: string;
  category: OperationCategory;
  authorization: boolean; // A
  measuredCapacity: boolean; // C
  verification: boolean; // V
  executionBoundary: boolean; // B
  provenancePrivacy: boolean; // P
  predicates: Record<PredicateKey, PredicateCheck>;
  overallVerdict: Verdict;
  admitted: boolean;
  confidenceScore: number;
  blockedReason: string | null;
  timestamp: string;
  stepTrace: string[];
}

export interface FunctionAdmissionResult {
  evaluationId: string;
  functionId: string;
  functionName: string;
  branchId: string;
  category: OperationCategory;
  required: boolean;
  verdict: Verdict;
  admitted: boolean;
  evaluation: AdmittanceEvaluation;
  timestamp: string;
}

export interface RegisteredFunctionSpec {
  functionId: string;
  functionName: string;
  branchId: string;
  category: OperationCategory;
  required: boolean;
  verdict: Verdict;
  evaluationCount: number;
  latestResult: FunctionAdmissionResult | null;
}

export interface BranchVerdictNode {
  branchId: string;
  label: string;
  parentBranchId: string | null;
  required: boolean;
  childBranchIds: string[];
  functionIds: string[];
  ownVerdict: Verdict;
  inheritedVerdict: Verdict;
  verdict: Verdict;
  lastUpdated: string;
}

export interface OperationEvaluationSpec {
  functionId: string;
  functionName?: string;
  branchId: string;
  category: OperationCategory;
  required?: boolean;
  predicates: AdmittancePredicatesInput;
  context?: Record<string, unknown>;
}

export type AdmittedExecutionResult<T> =
  | {
      admitted: true;
      verdict: 'GREEN';
      evaluation: FunctionAdmissionResult;
      value: T;
    }
  | {
      admitted: false;
      verdict: 'YELLOW' | 'RED';
      evaluation: FunctionAdmissionResult;
      value: null;
      blockedReason: string;
    };

export type MiningPathExecutionResult<T> =
  | {
      admitted: true;
      verdict: 'GREEN' | 'YELLOW';
      evaluation: FunctionAdmissionResult;
      value: T;
    }
  | {
      admitted: false;
      verdict: 'RED';
      evaluation: FunctionAdmissionResult;
      value: null;
      blockedReason: string;
    };

export interface CreedFaultInjection {
  active: boolean;
  targetScope: 'MINING' | 'ALL';
  forcedVerdict: Verdict;
  reason: string;
  label: 'FAULT_INJECTION';
  activatedAt: string;
}

export interface ModuleVerdictDescriptor {
  moduleId: string;
  moduleName: string;
  verdict: Verdict;
  evaluation: AdmittanceEvaluation;
}

const VERDICT_RANK: Record<Verdict, number> = {
  GREEN: 0,
  YELLOW: 1,
  RED: 2,
};

const PREDICATE_META: Record<PredicateKey, { symbol: 'A' | 'C' | 'V' | 'B' | 'P'; label: string }> = {
  authorization: { symbol: 'A', label: 'AUTHORIZATION' },
  capacity: { symbol: 'C', label: 'MEASURED_CAPACITY' },
  verification: { symbol: 'V', label: 'VERIFICATION' },
  boundary: { symbol: 'B', label: 'EXECUTION_BOUNDARY' },
  provenancePrivacy: { symbol: 'P', label: 'PROVENANCE_PRIVACY' },
};

export function strictestVerdict(verdicts: Verdict[]): Verdict {
  if (verdicts.length === 0) return 'YELLOW';
  let strictest: Verdict = 'GREEN';
  for (const v of verdicts) {
    if (VERDICT_RANK[v] > VERDICT_RANK[strictest]) {
      strictest = v;
    }
  }
  return strictest;
}

export function aggregateBranchVerdicts(childVerdicts: Verdict[]): Verdict {
  return strictestVerdict(childVerdicts);
}

function normalizePredicate(
  key: PredicateKey,
  input: PredicateInput,
  missingMeansIncomplete = false
): PredicateCheck {
  const meta = PREDICATE_META[key];
  if (typeof input === 'boolean') {
    const state: PredicateState = input
      ? 'PASS'
      : missingMeansIncomplete
        ? 'INCOMPLETE'
        : 'FAIL';
    const verdict: Verdict = state === 'PASS' ? 'GREEN' : state === 'INCOMPLETE' ? 'YELLOW' : 'RED';
    return {
      key,
      symbol: meta.symbol,
      label: meta.label,
      state,
      verdict,
      satisfied: state === 'PASS',
      reason: state === 'PASS'
        ? `${meta.label} satisfied`
        : state === 'INCOMPLETE'
          ? `${meta.label} evidence incomplete`
          : `${meta.label} check failed`,
    };
  }

  const verdict: Verdict =
    input.state === 'PASS' ? 'GREEN' : input.state === 'INCOMPLETE' ? 'YELLOW' : 'RED';
  return {
    key,
    symbol: meta.symbol,
    label: meta.label,
    state: input.state,
    verdict,
    satisfied: input.state === 'PASS',
    reason: input.reason,
    evidence: input.evidence,
  };
}

export class CreedAdmittanceService {
  private branches = new Map<string, BranchVerdictNode>();
  private functions = new Map<string, RegisteredFunctionSpec>();
  private evaluationHistory: FunctionAdmissionResult[] = [];
  private faultInjection: CreedFaultInjection | null = null;
  private listeners = new Set<() => void>();
  private seq = 0;

  constructor() {
    this.bootstrapCanonicalHierarchy();
  }

  private bootstrapCanonicalHierarchy(): void {
    // Root governance tree
    this.registerBranch({ branchId: 'BRANCH-ROOT', label: 'Living System Root', parentBranchId: null, required: true });
    this.registerBranch({ branchId: 'BRANCH-GOVERNANCE', label: 'Governance & Creed Self-Check', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-MINING', label: 'PoW Mining & Prism Admission', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-SOLVER', label: 'Hamiltonian, Geodesic & ECC Solvers', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-MEMORY-WRITE', label: 'Memory Fabric & Durable Vault Writes', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-DEPLOYMENT', label: 'Snapshots, Mesh Exports & Evolution', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-SCHEDULER', label: 'ADL & Adaptive Fill-Order Scheduler', parentBranchId: 'BRANCH-ROOT', required: true });
    this.registerBranch({ branchId: 'BRANCH-EVIDENCE', label: 'GENESIS-3 Concurrent Evidence', parentBranchId: 'BRANCH-ROOT', required: false });

    // Pre-register canonical operations (start YELLOW until independently verified)
    this.registerFunction({ functionId: 'fn:creed.rootInit', functionName: 'initLivingSystemConvergence', branchId: 'BRANCH-GOVERNANCE', category: 'GOVERNANCE', required: true });
    this.registerFunction({ functionId: 'fn:creed.certifyGate', functionName: 'runCertifyGate', branchId: 'BRANCH-GOVERNANCE', category: 'GOVERNANCE', required: true });

    this.registerFunction({ functionId: 'fn:mining.dispatchJob', functionName: 'miningEngine.dispatchNextBlockJob', branchId: 'BRANCH-MINING', category: 'MINING', required: true });
    this.registerFunction({ functionId: 'fn:mining.commitBlock', functionName: 'miningEngine.commitVerifiedBlock', branchId: 'BRANCH-MINING', category: 'MINING', required: true });
    this.registerFunction({ functionId: 'fn:mining.mineSync', functionName: 'miningEngine.mineSingleBlockSync', branchId: 'BRANCH-MINING', category: 'MINING', required: false });
    this.registerFunction({ functionId: 'fn:mining.prismAdmit', functionName: 'admitGateEngine.evaluatePrism', branchId: 'BRANCH-MINING', category: 'MINING', required: true });

    this.registerFunction({ functionId: 'fn:solver.query', functionName: 'executeQuery', branchId: 'BRANCH-SOLVER', category: 'SOLVER', required: false });
    this.registerFunction({ functionId: 'fn:solver.geodesic', functionName: 'solveVoidManhattanGeodesic', branchId: 'BRANCH-SOLVER', category: 'SOLVER', required: true });
    this.registerFunction({ functionId: 'fn:solver.eccBenchmark', functionName: 'runThreeEccBenchmark', branchId: 'BRANCH-SOLVER', category: 'SOLVER', required: true });
    this.registerFunction({ functionId: 'fn:solver.reversibility', functionName: 'hamiltonianEngine.verifyReversibility', branchId: 'BRANCH-SOLVER', category: 'SOLVER', required: true });
    this.registerFunction({ functionId: 'fn:solver.coprime64LaneMatch', functionName: 'SparseBandCryptoEngine.solveMultiFacetedMatch', branchId: 'BRANCH-SOLVER', category: 'SOLVER', required: false });

    this.registerFunction({ functionId: 'fn:memory.recordEvent', functionName: 'MemoryFabricLedger.recordEvent', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: true });
    this.registerFunction({ functionId: 'fn:sparseBand.ingestSpreadsheet', functionName: 'SparseBandCryptoEngine.ingestSpreadsheetDocument', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.postRouter', functionName: 'POST /v1/memory', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.seedRouter', functionName: 'POST /v1/router/seed', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.triggerMatrix', functionName: 'POST /v1/router/trigger', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.vdiskCommit', functionName: 'virtualDiskArchive.commitEngram', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.vdiskAcceptPeer', functionName: 'virtualDiskArchive.acceptPeerItems', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:memory.scratchbinStore', functionName: 'scratchbinVault.storeEncryptedObject', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });
    this.registerFunction({ functionId: 'fn:drive.mountSparseBundle', functionName: 'driveSparseMount.mountOnDrive', branchId: 'BRANCH-MEMORY-WRITE', category: 'MEMORY_WRITE', required: false });

    this.registerFunction({ functionId: 'fn:deploy.exportSnapshot', functionName: 'exportSignedSnapshot', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:deploy.exportVdisk', functionName: 'virtualDiskArchive.exportBundle', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:deploy.broadcastMesh', functionName: 'virtualDiskArchive.broadcastToMesh', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:deploy.monolithEvolve', functionName: 'monolithEngine.evolve', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:deploy.exportReceipt', functionName: 'boundedSelfCheckRunner.exportReceiptJson', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:deploy.genesisLock', functionName: 'POST /v1/genesis/lock', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });
    this.registerFunction({ functionId: 'fn:drive.unmountSparseBundle', functionName: 'driveSparseMount.unmountOnExit', branchId: 'BRANCH-DEPLOYMENT', category: 'DEPLOYMENT', required: false });

    this.registerFunction({ functionId: 'fn:scheduler.stepLanes', functionName: 'adlScheduler.stepLanes', branchId: 'BRANCH-SCHEDULER', category: 'SCHEDULER', required: true });

    this.registerFunction({ functionId: 'fn:evidence.parent01', functionName: 'GENESIS-3.PARENT-01', branchId: 'BRANCH-EVIDENCE', category: 'EVIDENCE', required: true });
    this.registerFunction({ functionId: 'fn:evidence.parent02', functionName: 'GENESIS-3.PARENT-02', branchId: 'BRANCH-EVIDENCE', category: 'EVIDENCE', required: true });
    this.registerFunction({ functionId: 'fn:evidence.parent03', functionName: 'GENESIS-3.PARENT-03', branchId: 'BRANCH-EVIDENCE', category: 'EVIDENCE', required: false });
  }

  public registerBranch(spec: {
    branchId: string;
    label: string;
    parentBranchId: string | null;
    required?: boolean;
  }): BranchVerdictNode {
    const existing = this.branches.get(spec.branchId);
    if (existing) return existing;

    const node: BranchVerdictNode = {
      branchId: spec.branchId,
      label: spec.label,
      parentBranchId: spec.parentBranchId,
      required: spec.required ?? true,
      childBranchIds: [],
      functionIds: [],
      ownVerdict: 'YELLOW',
      inheritedVerdict: 'YELLOW',
      verdict: 'YELLOW',
      lastUpdated: new Date().toISOString(),
    };
    this.branches.set(spec.branchId, node);

    if (spec.parentBranchId && this.branches.has(spec.parentBranchId)) {
      const parent = this.branches.get(spec.parentBranchId)!;
      if (!parent.childBranchIds.includes(spec.branchId)) {
        parent.childBranchIds.push(spec.branchId);
      }
    }
    return node;
  }

  public registerFunction(spec: {
    functionId: string;
    functionName: string;
    branchId: string;
    category: OperationCategory;
    required?: boolean;
  }): RegisteredFunctionSpec {
    if (!this.branches.has(spec.branchId)) {
      this.registerBranch({
        branchId: spec.branchId,
        label: spec.branchId,
        parentBranchId: 'BRANCH-ROOT',
        required: spec.required ?? true,
      });
    }

    const existing = this.functions.get(spec.functionId);
    if (existing) {
      if (spec.required !== undefined) existing.required = spec.required;
      return existing;
    }

    const fnSpec: RegisteredFunctionSpec = {
      functionId: spec.functionId,
      functionName: spec.functionName,
      branchId: spec.branchId,
      category: spec.category,
      required: spec.required ?? true,
      verdict: 'YELLOW',
      evaluationCount: 0,
      latestResult: null,
    };
    this.functions.set(spec.functionId, fnSpec);

    const branch = this.branches.get(spec.branchId)!;
    if (!branch.functionIds.includes(spec.functionId)) {
      branch.functionIds.push(spec.functionId);
    }

    this.recomputeBranchHierarchy();
    return fnSpec;
  }

  public evaluateOperation(spec: OperationEvaluationSpec): FunctionAdmissionResult {
    const fnSpec = this.registerFunction({
      functionId: spec.functionId,
      functionName: spec.functionName || spec.functionId,
      branchId: spec.branchId,
      category: spec.category,
      required: spec.required,
    });

    const faultMatches =
      this.faultInjection?.active &&
      (this.faultInjection.targetScope === 'ALL' ||
        (this.faultInjection.targetScope === 'MINING' && spec.category === 'MINING'));

    const pAuth = normalizePredicate('authorization', spec.predicates.authorization, false);
    const pCap = normalizePredicate('capacity', spec.predicates.capacity, true);
    const pVer = faultMatches
      ? normalizePredicate(
          'verification',
          {
            state: this.faultInjection!.forcedVerdict === 'RED' ? 'FAIL' : 'INCOMPLETE',
            reason: `[${this.faultInjection!.label}] ${this.faultInjection!.reason}`,
            evidence: {
              faultInjection: true,
              forcedVerdict: this.faultInjection!.forcedVerdict,
              activatedAt: this.faultInjection!.activatedAt,
            },
          },
          true
        )
      : normalizePredicate('verification', spec.predicates.verification, true);
    const pBnd = normalizePredicate('boundary', spec.predicates.boundary, false);
    const pProv = normalizePredicate('provenancePrivacy', spec.predicates.provenancePrivacy, false);

    const predicates: Record<PredicateKey, PredicateCheck> = {
      authorization: pAuth,
      capacity: pCap,
      verification: pVer,
      boundary: pBnd,
      provenancePrivacy: pProv,
    };

    const allPredicateVerdicts: Verdict[] = [
      pAuth.verdict,
      pCap.verdict,
      pVer.verdict,
      pBnd.verdict,
      pProv.verdict,
    ];
    const overallVerdict = strictestVerdict(allPredicateVerdicts);
    const admitted = overallVerdict === 'GREEN';

    const failedOrIncomplete = Object.values(predicates).filter((p) => !p.satisfied);
    const blockedReason = admitted
      ? null
      : failedOrIncomplete.map((p) => `[${p.symbol}:${p.verdict}] ${p.reason}`).join(' | ');

    const ts = new Date().toISOString();
    this.seq++;
    const evaluationId = `ADM-${String(this.seq).padStart(6, '0')}`;

    const stepTrace: string[] = [
      `[OPERATION] ${fnSpec.functionId} (${fnSpec.category}) @ ${fnSpec.branchId}`,
      `[A:AUTHORIZATION] ${pAuth.verdict} (${pAuth.state}) — ${pAuth.reason}`,
      `[C:CAPACITY] ${pCap.verdict} (${pCap.state}) — ${pCap.reason}`,
      `[V:VERIFICATION] ${pVer.verdict} (${pVer.state}) — ${pVer.reason}`,
      `[B:BOUNDARY] ${pBnd.verdict} (${pBnd.state}) — ${pBnd.reason}`,
      `[P:PROVENANCE/PRIVACY] ${pProv.verdict} (${pProv.state}) — ${pProv.reason}`,
      `[VERDICT] ${overallVerdict} (admitted=${admitted})`,
    ];

    const evaluation: AdmittanceEvaluation = {
      evaluationId,
      functionId: fnSpec.functionId,
      branchId: fnSpec.branchId,
      category: fnSpec.category,
      authorization: pAuth.satisfied,
      measuredCapacity: pCap.satisfied,
      verification: pVer.satisfied,
      executionBoundary: pBnd.satisfied,
      provenancePrivacy: pProv.satisfied,
      predicates,
      overallVerdict,
      admitted,
      confidenceScore: overallVerdict === 'GREEN' ? 1.0 : overallVerdict === 'YELLOW' ? 0.5 : 0.0,
      blockedReason,
      timestamp: ts,
      stepTrace,
    };

    const result: FunctionAdmissionResult = {
      evaluationId,
      functionId: fnSpec.functionId,
      functionName: fnSpec.functionName,
      branchId: fnSpec.branchId,
      category: fnSpec.category,
      required: fnSpec.required,
      verdict: overallVerdict,
      admitted,
      evaluation,
      timestamp: ts,
    };

    fnSpec.verdict = overallVerdict;
    fnSpec.evaluationCount++;
    fnSpec.latestResult = result;

    this.evaluationHistory.unshift(result);
    if (this.evaluationHistory.length > 250) {
      this.evaluationHistory.length = 250;
    }

    this.recomputeBranchHierarchy();
    this.notifyChange();
    return result;
  }

  public admitOperation<T>(
    spec: OperationEvaluationSpec,
    executor: (evalResult: FunctionAdmissionResult) => T
  ): AdmittedExecutionResult<T> {
    const evalResult = this.evaluateOperation(spec);
    if (!evalResult.admitted) {
      return {
        admitted: false,
        verdict: evalResult.verdict === 'RED' ? 'RED' : 'YELLOW',
        evaluation: evalResult,
        value: null,
        blockedReason:
          evalResult.evaluation.blockedReason ||
          `Operation ${spec.functionId} denied/held under Creed verdict ${evalResult.verdict}.`,
      };
    }
    const value = executor(evalResult);
    return {
      admitted: true,
      verdict: 'GREEN',
      evaluation: evalResult,
      value,
    };
  }

  /**
   * Mining-path specific admission gate:
   *  - RED strictly halts mining execution.
   *  - GREEN and YELLOW allow mining execution to proceed.
   */
  public admitMiningPath<T>(
    spec: OperationEvaluationSpec,
    executor: (evalResult: FunctionAdmissionResult) => T
  ): MiningPathExecutionResult<T> {
    const evalResult = this.evaluateOperation(spec);
    if (evalResult.verdict === 'RED') {
      return {
        admitted: false,
        verdict: 'RED',
        evaluation: evalResult,
        value: null,
        blockedReason:
          evalResult.evaluation.blockedReason ||
          `Mining operation ${spec.functionId} halted under Creed verdict RED.`,
      };
    }
    const value = executor(evalResult);
    return {
      admitted: true,
      verdict: evalResult.verdict,
      evaluation: evalResult,
      value,
    };
  }

  public async admitOperationAsync<T>(
    spec: OperationEvaluationSpec,
    executor: (evalResult: FunctionAdmissionResult) => Promise<T>
  ): Promise<AdmittedExecutionResult<T>> {
    const evalResult = this.evaluateOperation(spec);
    if (!evalResult.admitted) {
      return {
        admitted: false,
        verdict: evalResult.verdict === 'RED' ? 'RED' : 'YELLOW',
        evaluation: evalResult,
        value: null,
        blockedReason:
          evalResult.evaluation.blockedReason ||
          `Operation ${spec.functionId} denied/held under Creed verdict ${evalResult.verdict}.`,
      };
    }
    const value = await executor(evalResult);
    return {
      admitted: true,
      verdict: 'GREEN',
      evaluation: evalResult,
      value,
    };
  }

  private recomputeBranch(branchId: string, visited = new Set<string>()): Verdict {
    if (visited.has(branchId)) return 'RED';
    visited.add(branchId);

    const branch = this.branches.get(branchId);
    if (!branch) return 'YELLOW';

    // Collect verdicts of required child functions
    const requiredFnVerdicts: Verdict[] = [];
    const optionalFnVerdicts: Verdict[] = [];
    for (const fnId of branch.functionIds) {
      const fn = this.functions.get(fnId);
      if (!fn) continue;
      if (fn.required) {
        requiredFnVerdicts.push(fn.verdict);
      } else if (fn.latestResult) {
        optionalFnVerdicts.push(fn.verdict);
      }
    }

    // Collect verdicts of required child branches
    const requiredChildVerdicts: Verdict[] = [];
    for (const childId of branch.childBranchIds) {
      const childNode = this.branches.get(childId);
      if (!childNode) continue;
      const childVerdict = this.recomputeBranch(childId, new Set(visited));
      if (childNode.required) {
        requiredChildVerdicts.push(childVerdict);
      }
    }

    // Own verdict comes from direct functions in this branch
    // (or optional evaluated functions if no required functions exist in the branch)
    if (requiredFnVerdicts.length > 0) {
      branch.ownVerdict = strictestVerdict(requiredFnVerdicts);
    } else if (optionalFnVerdicts.length > 0) {
      branch.ownVerdict = strictestVerdict(optionalFnVerdicts);
    } else {
      branch.ownVerdict = branch.childBranchIds.length > 0 ? 'GREEN' : 'YELLOW';
    }

    // Parent inherits strictest required child state
    const inheritancePool: Verdict[] = [...requiredFnVerdicts, ...requiredChildVerdicts];
    if (inheritancePool.length === 0) {
      branch.inheritedVerdict = branch.ownVerdict;
    } else {
      branch.inheritedVerdict = strictestVerdict(inheritancePool);
    }

    branch.verdict = strictestVerdict([branch.ownVerdict, branch.inheritedVerdict]);
    branch.lastUpdated = new Date().toISOString();
    return branch.verdict;
  }

  public recomputeBranchHierarchy(): void {
    this.recomputeBranch('BRANCH-ROOT');
  }

  public getBranchResult(branchId: string): BranchVerdictNode | null {
    return this.branches.get(branchId) || null;
  }

  public getFunctionResult(functionId: string): RegisteredFunctionSpec | null {
    return this.functions.get(functionId) || null;
  }

  public getRootVerdict(): Verdict {
    return this.branches.get('BRANCH-ROOT')?.verdict ?? 'YELLOW';
  }

  public getBranchTree(): BranchVerdictNode[] {
    return Array.from(this.branches.values()).map((b) => ({
      ...b,
      childBranchIds: [...b.childBranchIds],
      functionIds: [...b.functionIds],
    }));
  }

  public getAllFunctionResults(): RegisteredFunctionSpec[] {
    return Array.from(this.functions.values());
  }

  public getEvaluationLog(limit = 50): FunctionAdmissionResult[] {
    return this.evaluationHistory.slice(0, limit);
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

  public injectFault(
    verdict: Verdict | null,
    reason = 'Operator injected fault on Creed mining path',
    targetScope: 'MINING' | 'ALL' = 'MINING'
  ): CreedFaultInjection | null {
    if (verdict === null) {
      this.faultInjection = null;
      // Restore mining branch functions to READY/GREEN pending next live tick
      for (const fnId of ['fn:mining.dispatchJob', 'fn:mining.commitBlock', 'fn:mining.mineSync']) {
        const fnSpec = this.functions.get(fnId);
        if (fnSpec) {
          fnSpec.verdict = 'GREEN';
        }
      }
      this.recomputeBranchHierarchy();
      this.notifyChange();
      return null;
    }

    this.faultInjection = {
      active: true,
      targetScope,
      forcedVerdict: verdict,
      reason,
      label: 'FAULT_INJECTION',
      activatedAt: new Date().toISOString(),
    };

    const targetFns =
      targetScope === 'ALL'
        ? Array.from(this.functions.values())
        : Array.from(this.functions.values()).filter((f) => f.category === 'MINING');

    for (const fnSpec of targetFns) {
      this.evaluateOperation({
        functionId: fnSpec.functionId,
        functionName: fnSpec.functionName,
        branchId: fnSpec.branchId,
        category: fnSpec.category,
        required: fnSpec.required,
        predicates: {
          authorization: { state: 'PASS', reason: 'Operator fault drill context' },
          capacity: { state: 'PASS', reason: 'Subsystem capacity nominal' },
          verification: { state: 'PASS', reason: 'Pre-fault check' },
          boundary: { state: 'PASS', reason: 'Bounds nominal' },
          provenancePrivacy: { state: 'PASS', reason: 'Fault drill labelled FAULT_INJECTION' },
        },
      });
    }

    return this.faultInjection;
  }

  public getFaultInjection(): CreedFaultInjection | null {
    return this.faultInjection ? { ...this.faultInjection } : null;
  }

  public isMiningHalted(): boolean {
    if (this.faultInjection?.active && this.faultInjection.forcedVerdict === 'RED') {
      return true;
    }
    return this.getBranchResult('BRANCH-MINING')?.verdict === 'RED';
  }

  public getSnapshot() {
    const branches = this.getBranchTree();
    const functions = this.getAllFunctionResults();
    return {
      rootVerdict: this.getRootVerdict(),
      miningBranchVerdict: this.getBranchResult('BRANCH-MINING')?.verdict ?? 'YELLOW',
      faultInjection: this.getFaultInjection(),
      totalBranches: branches.length,
      totalFunctions: functions.length,
      evaluatedFunctions: functions.filter((f) => f.evaluationCount > 0).length,
      greenCount: functions.filter((f) => f.verdict === 'GREEN').length,
      yellowCount: functions.filter((f) => f.verdict === 'YELLOW').length,
      redCount: functions.filter((f) => f.verdict === 'RED').length,
      branches,
      functions,
      recentEvaluations: this.getEvaluationLog(20),
    };
  }
}

export const creedAdmittanceService = new CreedAdmittanceService();

export function evaluateAdmittance(
  moduleId: string,
  auth: PredicateInput,
  capacity: PredicateInput,
  verified: PredicateInput,
  boundary: PredicateInput,
  provenance: PredicateInput,
  branchId = 'BRANCH-GOVERNANCE',
  category: OperationCategory = 'GOVERNANCE'
): AdmittanceEvaluation {
  const res = creedAdmittanceService.evaluateOperation({
    functionId: `fn:${moduleId}`,
    functionName: moduleId,
    branchId,
    category,
    required: true,
    predicates: {
      authorization: auth,
      capacity,
      verification: verified,
      boundary,
      provenancePrivacy: provenance,
    },
  });
  return res.evaluation;
}
