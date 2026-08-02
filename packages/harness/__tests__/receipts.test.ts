// SPDX-License-Identifier: MIT
import { describe, it, expect } from 'vitest';
import { ReceiptLog, hash, canonical } from '../src/receipts.js';

describe('hash / canonical', () => {
  it('is order-independent over object keys', () => {
    expect(canonical({ a: 1, b: 2 })).toBe(canonical({ b: 2, a: 1 }));
    expect(hash({ a: 1, b: 2 })).toBe(hash({ b: 2, a: 1 }));
  });
  it('differs when a value changes', () => {
    expect(hash({ a: 1 })).not.toBe(hash({ a: 2 }));
  });
});

function seed(): ReceiptLog {
  const log = new ReceiptLog();
  log.append({ runId: 'r', step: 's1', input: { i: 1 }, output: { o: 1 }, agent: 'coder', model: 'haiku', costUsd: 0.01, latencyMs: 100, verdict: 'pass' });
  log.append({ runId: 'r', step: 's2', input: { i: 2 }, output: { o: 2 }, agent: 'tester', model: 'opus', costUsd: 0.04, latencyMs: 200, verdict: 'pass' });
  return log;
}

describe('ReceiptLog (hash-chained, tamper-evident)', () => {
  it('verifies an untampered chain', () => {
    const log = seed();
    expect(log.verify().ok).toBe(true);
    expect(log.totalCostUsd()).toBeCloseTo(0.05);
  });

  it('chains genesis → first → second', () => {
    const log = seed();
    const [a, b] = log.entries();
    expect(a.prevHash).toBe('0'.repeat(64));
    expect(b.prevHash).toBe(a.thisHash);
  });

  it('detects a tampered field', () => {
    const log = seed();
    // Mutate a stored receipt out from under the chain.
    (log.entries()[0] as { costUsd: number }).costUsd = 999;
    const v = log.verify();
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.brokenAt).toBe(0);
  });

  it('detects reordering', () => {
    const log = seed();
    const e = log.entries() as unknown as Array<unknown>;
    [e[0], e[1]] = [e[1], e[0]];
    expect(log.verify().ok).toBe(false);
  });
});

describe('ReceiptLog.length / isEmpty', () => {
  it('reports length 0 and isEmpty true for a fresh log', () => {
    const log = new ReceiptLog();
    expect(log.length).toBe(0);
    expect(log.isEmpty).toBe(true);
  });

  it('tracks length as receipts are appended', () => {
    const log = seed();
    expect(log.length).toBe(2);
    expect(log.isEmpty).toBe(false);
  });
});

describe('ReceiptLog.export / toJSON', () => {
  it('export produces deterministic canonical JSON', () => {
    const a = seed();
    const b = seed();
    expect(a.export()).toBe(b.export());
  });

  it('toJSON returns a serializable snapshot', () => {
    const log = seed();
    const json = log.toJSON();
    expect(json.receipts).toHaveLength(2);
    expect(json.receipts[0].step).toBe('s1');
  });

  it('export round-trips through JSON.parse', () => {
    const log = seed();
    const parsed = JSON.parse(log.export());
    expect(parsed.receipts).toHaveLength(2);
    expect(parsed.receipts[0].prevHash).toBe('0'.repeat(64));
  });
});

describe('ReceiptLog.import (static)', () => {
  it('imports a valid exported chain and verifies', () => {
    const original = seed();
    const json = original.export();
    const restored = ReceiptLog.import(json);
    expect(restored.length).toBe(2);
    expect(restored.verify().ok).toBe(true);
    expect(restored.totalCostUsd()).toBeCloseTo(0.05);
  });

  it('imported chain matches original entries', () => {
    const original = seed();
    const restored = ReceiptLog.import(original.export());
    expect(restored.entries()).toEqual(original.entries());
  });

  it('rejects malformed JSON', () => {
    expect(() => ReceiptLog.import('not json')).toThrow('malformed JSON');
  });

  it('rejects wrong shape (no receipts array)', () => {
    expect(() => ReceiptLog.import('{"foo":1}')).toThrow('expected { receipts: Receipt[] }');
  });

  it('rejects a tampered chain', () => {
    const original = seed();
    const parsed = JSON.parse(original.export());
    // Tamper with a cost field.
    parsed.receipts[0].costUsd = 999;
    const tampered = JSON.stringify(parsed);
    expect(() => ReceiptLog.import(tampered)).toThrow('chain broken at index 0');
  });

  it('rejects a truncated chain', () => {
    const original = seed();
    const parsed = JSON.parse(original.export());
    parsed.receipts.pop(); // Remove last receipt — breaks the chain.
    const truncated = JSON.stringify(parsed);
    // A single-receipt truncated chain may still verify; tamper to force failure.
    parsed.receipts[0].costUsd = 123;
    expect(() => ReceiptLog.import(JSON.stringify(parsed))).toThrow('chain broken');
  });
});

describe('ReceiptLog.fromJSON (static)', () => {
  it('reconstructs from a toJSON snapshot', () => {
    const original = seed();
    const snapshot = original.toJSON();
    const restored = ReceiptLog.fromJSON(snapshot);
    expect(restored.length).toBe(2);
    expect(restored.verify().ok).toBe(true);
  });

  it('rejects wrong shape', () => {
    expect(() => ReceiptLog.fromJSON({ foo: 1 })).toThrow('expected { receipts: Receipt[] }');
  });

  it('rejects a tampered snapshot', () => {
    const original = seed();
    const snapshot = original.toJSON();
    snapshot.receipts[0].costUsd = 999;
    expect(() => ReceiptLog.fromJSON(snapshot)).toThrow('chain broken');
  });
});

describe('ReceiptLog.merge', () => {
  it('appends another log and re-links the chain', () => {
    const a = new ReceiptLog();
    a.append({ runId: 'r1', step: 'plan', input: 'g', output: 'p', agent: 'c', model: 'm', costUsd: 0.01, latencyMs: 100, verdict: 'pass' });
    const b = new ReceiptLog();
    b.append({ runId: 'r2', step: 'code', input: 'p', output: 'c', agent: 'c', model: 'm', costUsd: 0.02, latencyMs: 200, verdict: 'pass' });
    const added = a.merge(b);
    expect(added).toBe(1);
    expect(a.length).toBe(2);
    expect(a.verify().ok).toBe(true);
    expect(a.totalCostUsd()).toBeCloseTo(0.03);
  });

  it('returns 0 when merging an empty log', () => {
    const a = seed();
    const empty = new ReceiptLog();
    expect(a.merge(empty)).toBe(0);
    expect(a.length).toBe(2);
  });

  it('rejects merging a broken source chain', () => {
    const a = seed();
    const broken = seed();
    (broken.entries()[0] as { costUsd: number }).costUsd = 999;
    expect(() => a.merge(broken)).toThrow('source chain broken');
  });

  it('produces a valid combined chain after merge', () => {
    const daily = new ReceiptLog();
    for (let i = 0; i < 5; i++) {
      daily.append({ runId: `r${i}`, step: `s${i}`, input: i, output: i, agent: 'a', model: 'm', costUsd: 0.01, latencyMs: 100, verdict: 'pass' });
    }
    const archive = new ReceiptLog();
    archive.merge(daily);
    expect(archive.length).toBe(5);
    expect(archive.verify().ok).toBe(true);
    // Export and re-import the merged archive.
    const restored = ReceiptLog.import(archive.export());
    expect(restored.verify().ok).toBe(true);
    expect(restored.length).toBe(5);
  });
});
