/**
 * @file src/stage9/certificationKernel.ts
 * Trustworthy Certification Kernel for Stage 9 — Step 1 foundation.
 *
 * Core rule:
 *   THE CALLER MUST NOT BE ABLE TO MAKE A TEST PASS BY SIMPLY CLAIMING THAT IT PASSED.
 *
 * Free-form strings such as observed="detected=true" or evidenceRefs=["mutation-1"]
 * are NOT sufficient for PASS. Structured execution facts are required.
 *
 * Manifest is derived only from kernel records — never a writable PASS table.
 */

export type GateStatus =
  | 'NOT_STARTED'
  | 'RUNNING'
  | 'PASS'
  | 'FAIL'
  | 'NOT_VERIFIED'
  | 'NOT_EXECUTED'
  | 'ERROR'
  | 'ENVIRONMENT_FAILURE'
  | 'SKIPPED';

/** Structured facts produced by actual execution — not free-form claims. */
export interface StructuredEvidence {
  /** Machine-readable fact kind (e.g. ASSERTION_RESULT, STATE_SNAPSHOT, EXCEPTION). */
  kind: 'ASSERTION_RESULT' | 'STATE_SNAPSHOT' | 'EXCEPTION' | 'ENVIRONMENT' | 'SEQUENCE' | 'OTHER';
  /** Stable key identifying the fact (e.g. 'dispatch_claim_count', 'auth_blocked'). */
  key: string;
  /** Concrete value observed during execution. */
  value: string | number | boolean | null;
  /** Optional source of the fact (e.g. 'db.query', 'reference_model', 'runtime'). */
  source?: string;
}

export interface ExecutionRecord {
  id: string;
  category: string;
  gate?: string;
  startTime: string;
  endTime?: string;
  status: GateStatus;
  seed?: number;
  mutationId?: string;
  crashWindow?: string;
  raceId?: string;
  sequenceId?: string;
  expected?: string;
  /** Free-form notes only — never sufficient alone for PASS. */
  notes?: string;
  error?: string;
  /** Structured facts — required for PASS. */
  facts: StructuredEvidence[];
  /** Declared gate contract that was evaluated. */
  contractId?: string;
}

export interface GateContract {
  id: string;
  /** Minimum number of structured facts required. */
  minFacts: number;
  /** Required fact keys that must appear with matching values for PASS. */
  requiredFactKeys?: string[];
  /** If set, at least one fact must have kind in this list. */
  requiredKinds?: StructuredEvidence['kind'][];
  description: string;
}

export interface GateResult {
  gate: string;
  status: GateStatus;
  detail: string;
  recordIds: string[];
}

/** Built-in contracts for Step 1 and future gates. */
export const GATE_CONTRACTS: Record<string, GateContract> = {
  CERTIFICATION_KERNEL: {
    id: 'CERTIFICATION_KERNEL',
    minFacts: 1,
    requiredKinds: ['ASSERTION_RESULT'],
    description: 'Kernel itself is live and used',
  },
  CERTIFICATION_META: {
    id: 'CERTIFICATION_META',
    minFacts: 2,
    requiredFactKeys: ['meta_attack_rejected'],
    requiredKinds: ['ASSERTION_RESULT'],
    description: 'Meta-validation attacks were executed and rejected',
  },
  MUTATION_TESTS: {
    id: 'MUTATION_TESTS',
    minFacts: 1,
    requiredFactKeys: ['detector_observed_failure'],
    description: 'Mutation detector observed real failure',
  },
  DIFFERENTIAL: {
    id: 'DIFFERENTIAL',
    minFacts: 1,
    requiredFactKeys: ['semantic_comparison'],
    description: 'Reference vs production semantic comparison',
  },
  RANDOMIZED: {
    id: 'RANDOMIZED',
    minFacts: 1,
    requiredFactKeys: ['operations_executed'],
    description: 'Randomized sequence executed',
  },
  CRASH: {
    id: 'CRASH',
    minFacts: 1,
    requiredFactKeys: ['post_restart_state'],
    description: 'Crash/restart final state inspected',
  },
  CONCURRENCY: {
    id: 'CONCURRENCY',
    minFacts: 1,
    requiredFactKeys: ['authoritative_final_state'],
    description: 'Concurrent race final DB state inspected',
  },
  MINIMIZATION: {
    id: 'MINIMIZATION',
    minFacts: 1,
    requiredFactKeys: ['minimized_reproduces_failure'],
    description: 'Minimizer reproduced real failure',
  },
  HEARTBEAT_OWNERSHIP: {
    id: 'HEARTBEAT_OWNERSHIP',
    minFacts: 1,
    requiredFactKeys: ['ownership_enforced'],
    description: 'Heartbeat ownership enforced',
  },
  STAGE1_8_REGRESSION: {
    id: 'STAGE1_8_REGRESSION',
    minFacts: 1,
    requiredFactKeys: ['regression_exit_code'],
    description: 'Stage 1–8 regression actually ran',
  },
  RESOURCE_BOUNDS: {
    id: 'RESOURCE_BOUNDS',
    minFacts: 1,
    requiredFactKeys: ['bounds_checked'],
    description: 'Resource bounds checked',
  },
  LEGITIMATE_PASS_DEMO: {
    id: 'LEGITIMATE_PASS_DEMO',
    minFacts: 1,
    requiredFactKeys: ['demo_assertion'],
    requiredKinds: ['ASSERTION_RESULT'],
    description: 'Demonstrates that genuine PASS is still possible',
  },
};

export class CertificationKernel {
  private records: ExecutionRecord[] = [];
  private gates: Map<string, GateResult> = new Map();
  private runId: string;
  private startedAt: string;
  private environment: Record<string, string>;

  constructor(runId?: string) {
    this.runId = runId ?? `stage9-${Date.now()}`;
    this.startedAt = new Date().toISOString();
    this.environment = {
      node: typeof process !== 'undefined' ? process.version : 'unknown',
      platform: typeof process !== 'undefined' ? process.platform : 'unknown',
    };
  }

  public getRunId(): string {
    return this.runId;
  }

  public begin(
    category: string,
    opts?: {
      gate?: string;
      seed?: number;
      mutationId?: string;
      crashWindow?: string;
      raceId?: string;
      sequenceId?: string;
      contractId?: string;
    }
  ): string {
    const id = `${category}-${this.records.length + 1}-${Date.now()}`;
    this.records.push({
      id,
      category,
      gate: opts?.gate,
      startTime: new Date().toISOString(),
      status: 'RUNNING',
      seed: opts?.seed,
      mutationId: opts?.mutationId,
      crashWindow: opts?.crashWindow,
      raceId: opts?.raceId,
      sequenceId: opts?.sequenceId,
      contractId: opts?.contractId ?? opts?.gate,
      facts: [],
    });
    return id;
  }

  /**
   * Complete a record.
   * PASS is granted only when:
   *  1. status requested is PASS
   *  2. structured facts satisfy the gate contract (if any)
   *  3. facts are non-empty and not merely free-form notes
   * Free-form notes alone never produce PASS.
   */
  public complete(
    id: string,
    requestedStatus: GateStatus,
    detail: {
      expected?: string;
      notes?: string;
      error?: string;
      facts?: StructuredEvidence[];
    } = {}
  ): GateStatus {
    const rec = this.records.find((r) => r.id === id);
    if (!rec) {
      throw new Error(`CertificationKernel: unknown record id ${id}`);
    }
    if (rec.status !== 'RUNNING') {
      throw new Error(`CertificationKernel: record ${id} already completed as ${rec.status}`);
    }

    const facts = detail.facts ?? [];
    rec.facts = facts;
    rec.expected = detail.expected;
    rec.notes = detail.notes;
    rec.error = detail.error;
    rec.endTime = new Date().toISOString();

    let finalStatus: GateStatus = requestedStatus;

    if (requestedStatus === 'PASS') {
      const contract = rec.contractId ? GATE_CONTRACTS[rec.contractId] : undefined;
      const validation = this.validateFactsAgainstContract(facts, contract);
      if (!validation.ok) {
        finalStatus = 'NOT_VERIFIED';
        rec.notes = `${detail.notes ?? ''} [REJECTED: ${validation.reason}]`.trim();
      }
    }

    // Non-PASS statuses are accepted as-is (FAIL, SKIPPED, etc.)
    rec.status = finalStatus;
    return finalStatus;
  }

  private validateFactsAgainstContract(
    facts: StructuredEvidence[],
    contract?: GateContract
  ): { ok: boolean; reason: string } {
    if (facts.length === 0) {
      return { ok: false, reason: 'PASS requires structured facts; none provided' };
    }
    // Reject the classic self-reported pattern: only a stringy "detected=true" style fact
    const onlySelfReport =
      facts.length === 1 &&
      facts[0].kind === 'OTHER' &&
      (String(facts[0].value).toLowerCase() === 'detected=true' ||
        String(facts[0].value).toLowerCase() === 'true' ||
        facts[0].key === 'detected');
    if (onlySelfReport) {
      return {
        ok: false,
        reason: 'Self-reported detected=true / free-form claim is not structured evidence',
      };
    }
    if (!contract) {
      // No contract: require at least one ASSERTION_RESULT or STATE_SNAPSHOT
      const hasStrong = facts.some(
        (f) => f.kind === 'ASSERTION_RESULT' || f.kind === 'STATE_SNAPSHOT'
      );
      if (!hasStrong) {
        return {
          ok: false,
          reason: 'Without a gate contract, PASS requires ASSERTION_RESULT or STATE_SNAPSHOT fact',
        };
      }
      return { ok: true, reason: 'ok' };
    }
    if (facts.length < contract.minFacts) {
      return {
        ok: false,
        reason: `Contract ${contract.id} requires minFacts=${contract.minFacts}, got ${facts.length}`,
      };
    }
    if (contract.requiredKinds && contract.requiredKinds.length > 0) {
      const kinds = new Set(facts.map((f) => f.kind));
      const missing = contract.requiredKinds.filter((k) => !kinds.has(k));
      if (missing.length > 0) {
        return {
          ok: false,
          reason: `Contract ${contract.id} missing required kinds: ${missing.join(',')}`,
        };
      }
    }
    if (contract.requiredFactKeys && contract.requiredFactKeys.length > 0) {
      const keys = new Set(facts.map((f) => f.key));
      const missing = contract.requiredFactKeys.filter((k) => !keys.has(k));
      if (missing.length > 0) {
        return {
          ok: false,
          reason: `Contract ${contract.id} missing required fact keys: ${missing.join(',')}`,
        };
      }
    }
    return { ok: true, reason: 'ok' };
  }

  /** Derive a gate only from existing records. Empty → NOT_EXECUTED. */
  public deriveGate(gate: string, requiredCategories: string[]): GateResult {
    const related = this.records.filter(
      (r) => r.gate === gate || requiredCategories.includes(r.category)
    );
    let status: GateStatus = 'NOT_EXECUTED';
    let detail = 'No execution records for this gate';
    const recordIds = related.map((r) => r.id);

    if (related.length === 0) {
      status = 'NOT_EXECUTED';
      detail = 'No execution records';
    } else if (related.some((r) => r.status === 'RUNNING')) {
      status = 'NOT_VERIFIED';
      detail = 'Some records still RUNNING';
    } else if (related.some((r) => r.status === 'FAIL' || r.status === 'ERROR')) {
      status = 'FAIL';
      detail = 'One or more related records FAILED/ERROR';
    } else if (related.some((r) => r.status === 'ENVIRONMENT_FAILURE')) {
      status = 'ENVIRONMENT_FAILURE';
      detail = 'Environment failure in related records';
    } else if (related.some((r) => r.status === 'NOT_EXECUTED' || r.status === 'SKIPPED')) {
      status = 'NOT_VERIFIED';
      detail = 'Some required records NOT_EXECUTED/SKIPPED';
    } else if (related.every((r) => r.status === 'PASS')) {
      status = 'PASS';
      detail = `All ${related.length} related records PASS`;
    } else {
      status = 'NOT_VERIFIED';
      detail = 'Mixed or non-PASS statuses among records';
    }

    // PASS with zero recordIds is impossible here; extra guard
    if (status === 'PASS' && recordIds.length === 0) {
      status = 'NOT_VERIFIED';
      detail = 'PASS claimed with empty recordIds';
    }

    const result: GateResult = { gate, status, detail, recordIds };
    this.gates.set(gate, result);
    return result;
  }

  /** Injection of PASS is always rejected. Non-PASS may be recorded for meta-tests. */
  public attemptInjectGate(
    gate: string,
    status: GateStatus,
    detail: string
  ): { accepted: boolean; reason: string } {
    if (status === 'PASS') {
      return {
        accepted: false,
        reason: 'PASS may only be derived from execution records via deriveGate; injection rejected',
      };
    }
    this.gates.set(gate, {
      gate,
      status,
      detail: `injected:${detail}`,
      recordIds: [],
    });
    return { accepted: true, reason: 'Non-PASS injection accepted for meta-test only' };
  }

  public certify(requiredGates: string[]): {
    status: 'VERIFIED' | 'NOT_VERIFIED';
    gates: GateResult[];
    reason: string;
  } {
    const results: GateResult[] = [];
    for (const g of requiredGates) {
      const existing = this.gates.get(g);
      if (!existing) {
        results.push({
          gate: g,
          status: 'NOT_EXECUTED',
          detail: 'Gate never derived',
          recordIds: [],
        });
      } else {
        results.push(existing);
      }
    }
    const allPass =
      results.every((r) => r.status === 'PASS') && results.length === requiredGates.length;
    const anyEmptyPass = results.some((r) => r.status === 'PASS' && r.recordIds.length === 0);
    if (allPass && !anyEmptyPass) {
      return {
        status: 'VERIFIED',
        gates: results,
        reason: 'All required gates PASS with execution records',
      };
    }
    const failed = results
      .filter((r) => r.status !== 'PASS')
      .map((r) => `${r.gate}:${r.status}`);
    return {
      status: 'NOT_VERIFIED',
      gates: results,
      reason: anyEmptyPass
        ? 'PASS claimed with empty recordIds'
        : `Missing or non-PASS gates: ${failed.join(', ')}`,
    };
  }

  public toManifest(): object {
    return {
      run_id: this.runId,
      started_at: this.startedAt,
      finished_at: new Date().toISOString(),
      environment: this.environment,
      records: this.records,
      gates: Array.from(this.gates.values()),
      certification: this.certify(Array.from(this.gates.keys())),
    };
  }

  public getRecords(): readonly ExecutionRecord[] {
    return this.records;
  }

  public getGates(): readonly GateResult[] {
    return Array.from(this.gates.values());
  }
}
