// SPDX-License-Identifier: MIT
//
// Hash-chained receipts (ADR-047 audit layer; the ADR-011 witness substrate made
// first-class in the harness). Every step emits a receipt whose `thisHash` chains
// over the previous receipt's hash, so any tampering or reordering is detectable
// by replaying the chain — `verify()` recomputes every link.

import { createHash } from 'node:crypto';

/** SHA-256 hex of a value's canonical JSON form (stable key order). */
export function hash(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

/** Deterministic JSON: object keys sorted recursively so hashes are stable. */
export function canonical(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

/** A single receipt — the ADR-047 receipt format plus the chaining hashes. */
export interface Receipt {
  runId: string;
  step: string;
  inputHash: string;
  outputHash: string;
  agent: string;
  model: string;
  costUsd: number;
  latencyMs: number;
  verdict: 'pass' | 'fail' | 'gated';
  /** Hash of the previous receipt (genesis = 64 zeros). */
  prevHash: string;
  /** Hash over all of the above; the next receipt chains on this. */
  thisHash: string;
}

const GENESIS = '0'.repeat(64);

/** Fields a caller supplies; the log fills in the hashes. */
export type ReceiptDraft = Omit<Receipt, 'inputHash' | 'outputHash' | 'prevHash' | 'thisHash'> & {
  input: unknown;
  output: unknown;
};

/**
 * An append-only, hash-chained receipt log. Tamper-evident: mutate any field of
 * any receipt and `verify()` reports the first broken link.
 */
export class ReceiptLog {
  private readonly receipts: Receipt[] = [];

  /** Append a receipt, chaining it onto the tail. Returns the stored receipt. */
  append(draft: ReceiptDraft): Receipt {
    const prevHash = this.receipts.length ? this.receipts[this.receipts.length - 1].thisHash : GENESIS;
    const body = {
      runId: draft.runId,
      step: draft.step,
      inputHash: hash(draft.input),
      outputHash: hash(draft.output),
      agent: draft.agent,
      model: draft.model,
      costUsd: draft.costUsd,
      latencyMs: draft.latencyMs,
      verdict: draft.verdict,
      prevHash,
    };
    const receipt: Receipt = { ...body, thisHash: hash(body) };
    this.receipts.push(receipt);
    return receipt;
  }

  /** Every receipt, in order. */
  entries(): readonly Receipt[] {
    return this.receipts;
  }

  /** Total recorded spend. */
  totalCostUsd(): number {
    return this.receipts.reduce((s, r) => s + r.costUsd, 0);
  }

  /**
   * Replay the chain. Returns `{ ok: true }` if every link recomputes and the
   * genesis links to zeros; otherwise the 0-based index of the first bad receipt.
   */
  verify(): { ok: true } | { ok: false; brokenAt: number; reason: string } {
    let prevHash = GENESIS;
    for (let i = 0; i < this.receipts.length; i++) {
      const r = this.receipts[i];
      if (r.prevHash !== prevHash) {
        return { ok: false, brokenAt: i, reason: 'prevHash does not chain' };
      }
      const { thisHash, ...body } = r;
      if (hash(body) !== thisHash) {
        return { ok: false, brokenAt: i, reason: 'thisHash does not match body' };
      }
      prevHash = thisHash;
    }
    return { ok: true };
  }

  /**
   * Number of receipts in the chain.
   */
  get length(): number {
    return this.receipts.length;
  }

  /**
   * True if the log has no receipts.
   */
  get isEmpty(): boolean {
    return this.receipts.length === 0;
  }

  /**
   * Serialize the receipt chain to a deterministic JSON string for export.
   * Uses canonical (sorted-key) encoding so two identical chains produce
   * identical bytes — safe for signing, comparison, and audit archival.
   */
  export(): string {
    return canonical({ receipts: this.receipts });
  }

  /**
   * Serialize to a plain object for JSON storage or cross-system transport.
   * The shape is `{ receipts: Receipt[] }` — reversible via `fromJSON()`.
   */
  toJSON(): { receipts: Receipt[] } {
    return { receipts: [...this.receipts] };
  }

  /**
   * Import a receipt chain from an exported JSON string. Validates the chain
   * before accepting — a tampered or truncated chain is rejected with a
   * descriptive error pointing at the first broken link.
   *
   * @throws If the JSON is malformed, has the wrong shape, or the chain fails verification.
   */
  static import(json: string): ReceiptLog {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Error('ReceiptLog.import: malformed JSON');
    }
    if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as Record<string, unknown>).receipts)) {
      throw new Error('ReceiptLog.import: expected { receipts: Receipt[] }');
    }
    const log = new ReceiptLog();
    for (const r of (parsed as { receipts: Receipt[] }).receipts) {
      log.receipts.push(r);
    }
    const result = log.verify();
    if (!result.ok) {
      throw new Error(`ReceiptLog.import: chain broken at index ${result.brokenAt}: ${result.reason}`);
    }
    return log;
  }

  /**
   * Reconstruct a ReceiptLog from a plain object (the shape produced by `toJSON()`
   * or `export()`). Validates the chain before accepting.
   *
   * @throws If the shape is wrong or the chain fails verification.
   */
  static fromJSON(obj: unknown): ReceiptLog {
    if (!obj || typeof obj !== 'object' || !Array.isArray((obj as Record<string, unknown>).receipts)) {
      throw new Error('ReceiptLog.fromJSON: expected { receipts: Receipt[] }');
    }
    const log = new ReceiptLog();
    for (const r of (obj as { receipts: Receipt[] }).receipts) {
      log.receipts.push(r);
    }
    const result = log.verify();
    if (!result.ok) {
      throw new Error(`ReceiptLog.fromJSON: chain broken at index ${result.brokenAt}: ${result.reason}`);
    }
    return log;
  }

  /**
   * Merge another ReceiptLog's chain into this one. The imported chain is
   * appended after the current tail, with hashes re-linked so the combined
   * chain remains valid and verifiable. Returns the number of receipts added.
   *
   * This enables cross-run receipt aggregation — e.g., merging daily audit
   * logs into a monthly compliance archive without breaking the hash chain.
   *
   * @throws If the source chain fails its own verification.
   */
  merge(source: ReceiptLog): number {
    if (source.isEmpty) return 0;
    const sourceVerify = source.verify();
    if (!sourceVerify.ok) {
      throw new Error(`ReceiptLog.merge: source chain broken at index ${sourceVerify.brokenAt}: ${sourceVerify.reason}`);
    }
    const startCount = this.receipts.length;
    for (const r of source.receipts) {
      this.receipts.push(r);
    }
    for (let i = startCount; i < this.receipts.length; i++) {
      const prevHash = i > 0 ? this.receipts[i - 1].thisHash : GENESIS;
      const { thisHash, ...body } = this.receipts[i];
      const newBody = { ...body, prevHash };
      this.receipts[i] = { ...newBody, thisHash: hash(newBody) } as Receipt;
    }
    return this.receipts.length - startCount;
  }
}
