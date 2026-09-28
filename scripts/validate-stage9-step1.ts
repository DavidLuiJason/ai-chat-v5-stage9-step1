/**
 * @file scripts/validate-stage9-step1.ts
 * STEP 1 SELF-CERTIFICATION — Certification Kernel + Manifest + Meta-Validation
 *
 * No database / pglite required. Pure in-process tests of the certification judge.
 *
 * Step 1 is COMPLETE only when these tests pass.
 * Stage 9 remains IN_PROGRESS.
 */

import { writeFileSync } from 'node:fs';
import {
  CertificationKernel,
  GATE_CONTRACTS,
  type StructuredEvidence,
} from '../src/stage9/certificationKernel.ts';

let failures = 0;

function check(cond: boolean, name: string, detail?: string): void {
  if (!cond) {
    console.error(`  [FAIL] ${name}: ${detail ?? 'failed'}`);
    failures += 1;
  } else {
    console.log(`  [PASS] ${name}: ${detail ?? 'ok'}`);
  }
}

async function runStep1(): Promise<void> {
  console.log('===============================================================');
  console.log('STAGE 9 — STEP 1: CERTIFICATION KERNEL SELF-CERTIFICATION');
  console.log('===============================================================');

  // -------------------------------------------------------------------------
  // 1. Legitimate PASS is still possible
  // -------------------------------------------------------------------------
  console.log('\n--- 1. Legitimate PASS path ---');
  {
    const k = new CertificationKernel('legitimate');
    const id = k.begin('DEMO', { gate: 'LEGITIMATE_PASS_DEMO', contractId: 'LEGITIMATE_PASS_DEMO' });
    const facts: StructuredEvidence[] = [
      { kind: 'ASSERTION_RESULT', key: 'demo_assertion', value: true, source: 'runtime' },
    ];
    const status = k.complete(id, 'PASS', { facts, expected: 'true', notes: 'real assertion' });
    check(status === 'PASS', 'Legitimate PASS granted', `status=${status}`);
    const gate = k.deriveGate('LEGITIMATE_PASS_DEMO', ['DEMO']);
    check(gate.status === 'PASS', 'Legitimate gate derived PASS', gate.detail);
  }

  // -------------------------------------------------------------------------
  // 2. TEST A — NO EXECUTION
  // -------------------------------------------------------------------------
  console.log('\n--- 2. Meta A: No execution ---');
  {
    const k = new CertificationKernel('meta-a');
    const gate = k.deriveGate('CERTIFICATION_META', ['NONEXISTENT']);
    check(gate.status === 'NOT_EXECUTED', 'A: empty records → NOT_EXECUTED', gate.status);
    const cert = k.certify(['CERTIFICATION_META']);
    check(cert.status === 'NOT_VERIFIED', 'A: certify empty → NOT_VERIFIED', cert.reason);
  }

  // -------------------------------------------------------------------------
  // 3. TEST B — FORCED PASS injection
  // -------------------------------------------------------------------------
  console.log('\n--- 3. Meta B: Forced PASS injection ---');
  {
    const k = new CertificationKernel('meta-b');
    const inj = k.attemptInjectGate('FAKE_GATE', 'PASS', 'forced');
    check(inj.accepted === false, 'B: inject PASS rejected', inj.reason);
  }

  // -------------------------------------------------------------------------
  // 4. TEST C — FAKE OBSERVATION (detected=true without structured facts)
  // -------------------------------------------------------------------------
  console.log('\n--- 4. Meta C: Fake observation detected=true ---');
  {
    const k = new CertificationKernel('meta-c');
    const id = k.begin('FAKE', { gate: 'MUTATION_TESTS', contractId: 'MUTATION_TESTS' });
    // Caller tries the classic self-report
    const status = k.complete(id, 'PASS', {
      notes: 'detected=true',
      facts: [{ kind: 'OTHER', key: 'detected', value: 'detected=true' }],
    });
    check(status === 'NOT_VERIFIED', 'C: self-reported detected=true rejected', `status=${status}`);
  }

  // -------------------------------------------------------------------------
  // 5. TEST D — FAKE EVIDENCE REFERENCE (empty facts / wrong keys)
  // -------------------------------------------------------------------------
  console.log('\n--- 5. Meta D: Fake evidence / missing required keys ---');
  {
    const k = new CertificationKernel('meta-d');
    const id = k.begin('FAKE_EV', { gate: 'MUTATION_TESTS', contractId: 'MUTATION_TESTS' });
    const status = k.complete(id, 'PASS', {
      facts: [{ kind: 'ASSERTION_RESULT', key: 'wrong_key', value: true }],
    });
    check(
      status === 'NOT_VERIFIED',
      'D: missing required fact key detector_observed_failure → NOT_VERIFIED',
      `status=${status}`
    );
  }

  // -------------------------------------------------------------------------
  // 6. TEST E — SWALLOWED ERROR then PASS
  // -------------------------------------------------------------------------
  console.log('\n--- 6. Meta E: Swallowed error then PASS ---');
  {
    const k = new CertificationKernel('meta-e');
    const id = k.begin('SWALLOW', { gate: 'CERTIFICATION_META', contractId: 'CERTIFICATION_META' });
    // Simulate: error occurred but caller still asks for PASS with no proper facts
    const status = k.complete(id, 'PASS', {
      error: 'internal assertion failed',
      notes: 'swallowed',
      facts: [],
    });
    check(status === 'NOT_VERIFIED', 'E: empty facts after error → NOT_VERIFIED', `status=${status}`);
  }

  // -------------------------------------------------------------------------
  // 7. TEST F — SKIPPED then try derive as PASS
  // -------------------------------------------------------------------------
  console.log('\n--- 7. Meta F: Skipped cannot become PASS ---');
  {
    const k = new CertificationKernel('meta-f');
    const id = k.begin('SKIP', { gate: 'META_SKIP' });
    k.complete(id, 'SKIPPED', { notes: 'intentionally skipped' });
    const gate = k.deriveGate('META_SKIP', ['SKIP']);
    check(gate.status !== 'PASS', 'F: SKIPPED gate not PASS', `status=${gate.status}`);
  }

  // -------------------------------------------------------------------------
  // 8. TEST G — ENVIRONMENT_FAILURE
  // -------------------------------------------------------------------------
  console.log('\n--- 8. Meta G: Environment failure preserved ---');
  {
    const k = new CertificationKernel('meta-g');
    const id = k.begin('ENV', { gate: 'META_ENV' });
    k.complete(id, 'ENVIRONMENT_FAILURE', {
      error: 'pglite unavailable',
      facts: [{ kind: 'ENVIRONMENT', key: 'pglite', value: 'unavailable' }],
    });
    const gate = k.deriveGate('META_ENV', ['ENV']);
    check(
      gate.status === 'ENVIRONMENT_FAILURE',
      'G: ENVIRONMENT_FAILURE preserved',
      gate.status
    );
  }

  // -------------------------------------------------------------------------
  // 9. TEST H — EMPTY MANIFEST certify
  // -------------------------------------------------------------------------
  console.log('\n--- 9. Meta H: Empty manifest ---');
  {
    const k = new CertificationKernel('meta-h');
    const cert = k.certify(['CERTIFICATION_KERNEL', 'CERTIFICATION_META']);
    check(cert.status === 'NOT_VERIFIED', 'H: empty certify → NOT_VERIFIED', cert.reason);
  }

  // -------------------------------------------------------------------------
  // 10. TEST I — Fabricated gate (never derived)
  // -------------------------------------------------------------------------
  console.log('\n--- 10. Meta I: Fabricated / never-derived gate ---');
  {
    const k = new CertificationKernel('meta-i');
    const cert = k.certify(['FABRICATED_GATE']);
    check(
      cert.status === 'NOT_VERIFIED' &&
        cert.gates.some((g) => g.gate === 'FABRICATED_GATE' && g.status === 'NOT_EXECUTED'),
      'I: fabricated gate → NOT_EXECUTED/NOT_VERIFIED',
      cert.reason
    );
  }

  // -------------------------------------------------------------------------
  // 11. TEST J — Fabricated aggregate (required gates missing)
  // -------------------------------------------------------------------------
  console.log('\n--- 11. Meta J: Aggregate cannot bypass missing gates ---');
  {
    const k = new CertificationKernel('meta-j');
    // Only satisfy one gate
    const id = k.begin('DEMO', { gate: 'LEGITIMATE_PASS_DEMO', contractId: 'LEGITIMATE_PASS_DEMO' });
    k.complete(id, 'PASS', {
      facts: [{ kind: 'ASSERTION_RESULT', key: 'demo_assertion', value: true }],
    });
    k.deriveGate('LEGITIMATE_PASS_DEMO', ['DEMO']);
    const cert = k.certify(['LEGITIMATE_PASS_DEMO', 'STAGE1_8_REGRESSION', 'MUTATION_TESTS']);
    check(
      cert.status === 'NOT_VERIFIED',
      'J: aggregate with missing gates → NOT_VERIFIED',
      cert.reason
    );
  }

  // -------------------------------------------------------------------------
  // 12. TEST K — Tracker must not be COMPLETE (structural check of source)
  // -------------------------------------------------------------------------
  console.log('\n--- 12. Meta K: Tracker Stage 9 is IN_PROGRESS ---');
  {
    // Read tracker source — do not rely on runtime DB
    const fs = await import('node:fs');
    const trackerSrc = fs.readFileSync(
      new URL('../src/tracker/stageTracker.ts', import.meta.url),
      'utf8'
    );
    // Find Stage 9 block
    const stage9Block = trackerSrc.match(
      /stage_number:\s*9[\s\S]*?status:\s*'([^']+)'/
    );
    const status = stage9Block?.[1] ?? 'UNKNOWN';
    check(
      status === 'IN_PROGRESS',
      'K: Stage 9 tracker status is IN_PROGRESS',
      `status=${status}`
    );
    check(
      !trackerSrc.includes("stage_number: 9,\n    stage_name: 'Property Tests & Fault Injection',\n    status: 'COMPLETE'"),
      'K: no COMPLETE hard-code for Stage 9 adjacent to name',
      'ok'
    );
  }

  // -------------------------------------------------------------------------
  // 13. PASS without any facts at all
  // -------------------------------------------------------------------------
  console.log('\n--- 13. PASS with zero facts rejected ---');
  {
    const k = new CertificationKernel('zero-facts');
    const id = k.begin('Z', { gate: 'CERTIFICATION_KERNEL', contractId: 'CERTIFICATION_KERNEL' });
    const status = k.complete(id, 'PASS', {});
    check(status === 'NOT_VERIFIED', 'Zero facts → NOT_VERIFIED', `status=${status}`);
  }

  // -------------------------------------------------------------------------
  // 14. Manifest integrity
  // -------------------------------------------------------------------------
  console.log('\n--- 14. Manifest derived from records ---');
  {
    const k = new CertificationKernel('manifest');
    const id = k.begin('DEMO', { gate: 'LEGITIMATE_PASS_DEMO', contractId: 'LEGITIMATE_PASS_DEMO' });
    k.complete(id, 'PASS', {
      facts: [{ kind: 'ASSERTION_RESULT', key: 'demo_assertion', value: true, source: 'runtime' }],
    });
    k.deriveGate('LEGITIMATE_PASS_DEMO', ['DEMO']);
    const manifest = k.toManifest() as any;
    check(typeof manifest.run_id === 'string', 'Manifest has run_id');
    check(Array.isArray(manifest.records) && manifest.records.length === 1, 'Manifest has 1 record');
    check(
      manifest.records[0].facts?.[0]?.key === 'demo_assertion',
      'Manifest preserves structured facts'
    );
    check(
      manifest.gates.some((g: any) => g.gate === 'LEGITIMATE_PASS_DEMO' && g.status === 'PASS'),
      'Manifest gate derived PASS'
    );
    // Write artifact
    writeFileSync('stage9-step1-manifest.json', JSON.stringify(manifest, null, 2));
    console.log('  [INFO] Wrote stage9-step1-manifest.json');
  }

  // -------------------------------------------------------------------------
  // 15. Gate contracts exist for future steps
  // -------------------------------------------------------------------------
  console.log('\n--- 15. Future gate contracts registered ---');
  {
    const needed = [
      'MUTATION_TESTS',
      'DIFFERENTIAL',
      'RANDOMIZED',
      'CRASH',
      'CONCURRENCY',
      'MINIMIZATION',
      'HEARTBEAT_OWNERSHIP',
      'STAGE1_8_REGRESSION',
      'RESOURCE_BOUNDS',
    ];
    for (const g of needed) {
      check(!!GATE_CONTRACTS[g], `Contract registered: ${g}`);
    }
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log('\n===============================================================');
  if (failures === 0) {
    console.log('STEP 1 IMPLEMENTATION COMPLETE');
    console.log('All meta-attacks rejected; legitimate PASS still possible; tracker IN_PROGRESS.');
    console.log('STAGE 9 remains IN_PROGRESS.');
    console.log('===============================================================');
    process.exit(0);
  } else {
    console.log(`STEP 1 INCOMPLETE: ${failures} failure(s)`);
    console.log('===============================================================');
    process.exit(1);
  }
}

runStep1().catch((err) => {
  console.error('Step 1 failed:', err);
  process.exit(1);
});
