"""Unit test cho agent.ledger — Bước 3d, tamper-evident hash chain."""
from __future__ import annotations

import json

from agent import ledger


def _entry(tool: str, decision: str) -> dict:
    return {
        "ts": "2026-08-24T00:00:00Z",
        "agent_id": "lab24-agent",
        "run_id": "run-a",
        "tool": tool,
        "args_hash": "deadbeef",
        "classification": "internal",
        "decision": decision,
        "reason": f"{tool} {decision} for test",
    }


def test_append_chains_hashes(clean_ledger):
    r1 = ledger.append(_entry("search_docs", "allow"), clean_ledger)
    r2 = ledger.append(_entry("read_customer", "allow"), clean_ledger)
    assert r2["prev_hash"] == r1["hash"]
    assert r1["hash"] != r2["hash"]
    assert ledger.verify(clean_ledger) is True


def test_verify_detects_tampering(clean_ledger):
    ledger.append(_entry("search_docs", "allow"), clean_ledger)
    ledger.append(_entry("http_post", "deny"), clean_ledger)

    lines = clean_ledger.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["tool"] = "TAMPERED"
    lines[0] = json.dumps(tampered, ensure_ascii=False)
    clean_ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert ledger.verify(clean_ledger) is False


def test_every_entry_needs_a_non_empty_reason(clean_ledger):
    bad_entry = _entry("http_post", "deny")
    bad_entry["reason"] = ""
    ledger.append(bad_entry, clean_ledger)
    assert ledger.verify(clean_ledger) is False


def test_verify_detects_tail_truncation(clean_ledger):
    ledger.append(_entry("search_docs", "allow"), clean_ledger)
    ledger.append(_entry("read_customer", "allow"), clean_ledger)

    lines = clean_ledger.read_text(encoding="utf-8").splitlines()
    clean_ledger.write_text(lines[0] + "\n", encoding="utf-8")

    assert ledger.verify(clean_ledger) is False
