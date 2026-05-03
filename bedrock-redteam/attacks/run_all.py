#!/usr/bin/env python3
"""Run all red-team attacks (01–04) in sequence and produce a scorecard.

Executes each attack as a subprocess so that each one gets a clean process
and its own evidence directory, exactly as if run individually.  After all
attacks complete, the script reads back every evidence JSON produced during
this run, builds a Markdown summary table, writes it to
evidence/{timestamp}/summary.md, and prints it to the terminal.

Usage:
    python -m attacks.run_all

Requires:
    Same env vars as the individual attacks (AWS_PROFILE, API_ENDPOINT, etc.)
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = PROJECT_ROOT / "evidence"

PROFILE = os.environ.get("AWS_PROFILE", "redteam")

# Ordered list of attack modules to run
ATTACKS: list[dict] = [
    {
        "module": "attacks.attack_01_direct_injection",
        "name": "Attack 01 — Direct Injection",
        "evidence_file": "attack_01.json",
    },
    {
        "module": "attacks.attack_02_obfuscated",
        "name": "Attack 02 — Obfuscated Injection",
        "evidence_file": "attack_02.json",
    },
    {
        "module": "attacks.attack_03_cross_tool",
        "name": "Attack 03 — Cross-Tool (LLM06)",
        "evidence_file": "attack_03.json",
    },
    {
        "module": "attacks.attack_04_output_handling",
        "name": "Attack 04 — Output Handling (LLM02)",
        "evidence_file": "attack_04.json",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_evidence_dirs_since(start_ts: float) -> list[pathlib.Path]:
    """Return evidence subdirectories created at or after *start_ts* (epoch)."""
    dirs = []
    if not EVIDENCE_ROOT.is_dir():
        return dirs
    for child in sorted(EVIDENCE_ROOT.iterdir()):
        if child.is_dir() and child.name not in ("screenshots", "smoke"):
            # Use directory mtime as a proxy; also accept if name >= our run ts
            if child.stat().st_mtime >= start_ts - 5:  # 5s grace
                dirs.append(child)
    return dirs


def _load_evidence(evidence_dirs: list[pathlib.Path], filename: str) -> dict | None:
    """Search evidence dirs (newest first) for *filename* and return parsed JSON."""
    for d in reversed(evidence_dirs):
        candidate = d / filename
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                pass
    return None


def _outcome_icon(outcome: str) -> str:
    return {
        "BLOCKED": "🛡️",
        "RESISTED": "✅",
        "PARTIAL": "⚠️",
        "COMPROMISED": "❌",
    }.get(outcome, "❓")


# ---------------------------------------------------------------------------
# Row builders — extract table rows from each attack's evidence JSON
# ---------------------------------------------------------------------------

def _rows_from_attack_01(ev: dict) -> list[dict]:
    """Single-variant attack."""
    sc = ev.get("scoring", {})
    return [{
        "attack": "01 — Direct Injection",
        "variant": "—",
        "outcome": sc.get("outcome", "UNKNOWN"),
        "guardrail": "Yes" if sc.get("guardrail_blocked") else "No",
        "finding": sc.get("detail", ""),
    }]


def _rows_from_attack_02(ev: dict) -> list[dict]:
    """Multi-variant attack."""
    rows = []
    for v in ev.get("variants", []):
        sc = v.get("scoring", {})
        rows.append({
            "attack": "02 — Obfuscated Injection",
            "variant": v.get("variant_id", "?"),
            "outcome": sc.get("outcome", "UNKNOWN"),
            "guardrail": "Yes" if sc.get("guardrail_blocked") else "No",
            "finding": sc.get("detail", ""),
        })
    return rows


def _rows_from_attack_03(ev: dict) -> list[dict]:
    sc = ev.get("scoring", {})
    finding = sc.get("detail", "")
    if sc.get("order_lookup_called"):
        finding += f" (order_id={ev.get('injected_order_id', '?')})"
    return [{
        "attack": "03 — Cross-Tool (LLM06)",
        "variant": "—",
        "outcome": sc.get("outcome", "UNKNOWN"),
        "guardrail": "Yes" if sc.get("guardrail_blocked") else "No",
        "finding": finding,
    }]


def _rows_from_attack_04(ev: dict) -> list[dict]:
    sc = ev.get("scoring", {})
    passed = sc.get("payloads_passed", 0)
    total = sc.get("payloads_total", 0)
    finding = sc.get("detail", "")
    if not finding:
        finding = f"{passed}/{total} payloads passed through"
    return [{
        "attack": "04 — Output Handling (LLM02)",
        "variant": "—",
        "outcome": sc.get("outcome", "UNKNOWN"),
        "guardrail": "Yes" if sc.get("guardrail_blocked") else "No",
        "finding": finding,
    }]


ROW_BUILDERS = {
    "attack_01.json": _rows_from_attack_01,
    "attack_02.json": _rows_from_attack_02,
    "attack_03.json": _rows_from_attack_03,
    "attack_04.json": _rows_from_attack_04,
}


# ---------------------------------------------------------------------------
# Markdown summary builder
# ---------------------------------------------------------------------------

def build_summary_md(
    rows: list[dict],
    run_ts: str,
    attack_results: list[dict],
) -> str:
    """Build the full Markdown scorecard."""
    lines: list[str] = []
    lines.append("# Red-Team Scorecard")
    lines.append("")
    lines.append(f"**Run timestamp:** {run_ts}")
    lines.append("")

    # ── Aggregate stats ───────────────────────────────────────────────
    outcomes = [r["outcome"] for r in rows]
    lines.append("## Aggregate Results")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total checks | {len(rows)} |")
    for label in ("BLOCKED", "RESISTED", "PARTIAL", "COMPROMISED", "UNKNOWN"):
        c = outcomes.count(label)
        if c > 0:
            lines.append(f"| {_outcome_icon(label)} {label} | {c} |")
    lines.append("")

    # ── Detailed table ────────────────────────────────────────────────
    lines.append("## Detailed Results")
    lines.append("")
    lines.append("| # | Attack | Variant | Outcome | Guardrail | Finding |")
    lines.append("|---|--------|---------|---------|-----------|---------|")
    for i, r in enumerate(rows, 1):
        icon = _outcome_icon(r["outcome"])
        # Escape pipes in finding text
        finding = r["finding"].replace("|", "\\|")
        lines.append(
            f"| {i} "
            f"| {r['attack']} "
            f"| {r['variant']} "
            f"| {icon} {r['outcome']} "
            f"| {r['guardrail']} "
            f"| {finding} |"
        )
    lines.append("")

    # ── Per-attack execution metadata ─────────────────────────────────
    lines.append("## Execution Details")
    lines.append("")
    for ar in attack_results:
        status = "✅ passed" if ar["exit_code"] == 0 else "❌ failed"
        lines.append(f"### {ar['name']}")
        lines.append("")
        lines.append(f"- **Module:** `{ar['module']}`")
        lines.append(f"- **Exit code:** {ar['exit_code']} ({status})")
        lines.append(f"- **Duration:** {ar['duration_seconds']:.1f}s")
        if ar.get("evidence_path"):
            lines.append(f"- **Evidence:** `{ar['evidence_path']}`")
        lines.append("")

    # ── Footer ────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append("*Generated by `attacks.run_all`*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    summary_dir = EVIDENCE_ROOT / run_ts
    run_start = time.time()

    print("=" * 70)
    print("RED-TEAM FULL SUITE — Attacks 01–04")
    print(f"  Timestamp : {run_ts}")
    print(f"  Summary   : {summary_dir / 'summary.md'}")
    print(f"  Attacks   : {len(ATTACKS)}")
    print("=" * 70)
    print()

    attack_results: list[dict] = []

    for i, attack in enumerate(ATTACKS, 1):
        print(f"{'─' * 70}")
        print(f"  [{i}/{len(ATTACKS)}] Running {attack['name']}...")
        print(f"{'─' * 70}")

        t0 = time.time()
        try:
            result = subprocess.run(
                [sys.executable, "-m", attack["module"]],
                cwd=str(PROJECT_ROOT),
                timeout=300,
            )
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            print(f"  ⚠️  TIMEOUT after 300s")
            exit_code = -1
        except Exception as exc:
            print(f"  ⚠️  ERROR: {exc}")
            exit_code = -2

        duration = time.time() - t0

        attack_results.append({
            "name": attack["name"],
            "module": attack["module"],
            "evidence_file": attack["evidence_file"],
            "exit_code": exit_code,
            "duration_seconds": round(duration, 1),
            "evidence_path": None,  # filled in below
        })

        status_icon = "✅" if exit_code == 0 else "❌"
        print(f"\n  {status_icon} {attack['name']} finished (exit={exit_code}, {duration:.1f}s)\n")

    # ── Collect evidence ──────────────────────────────────────────────
    print("=" * 70)
    print("Collecting evidence and building scorecard...")
    print("=" * 70)

    evidence_dirs = _find_evidence_dirs_since(run_start)
    all_rows: list[dict] = []

    for ar in attack_results:
        ev = _load_evidence(evidence_dirs, ar["evidence_file"])
        if ev is None:
            all_rows.append({
                "attack": ar["name"],
                "variant": "—",
                "outcome": "UNKNOWN",
                "guardrail": "—",
                "finding": f"Evidence file {ar['evidence_file']} not found.",
            })
            continue

        # Record the evidence path for the execution details section
        for d in reversed(evidence_dirs):
            if (d / ar["evidence_file"]).exists():
                ar["evidence_path"] = str(d / ar["evidence_file"])
                break

        builder = ROW_BUILDERS.get(ar["evidence_file"])
        if builder:
            all_rows.extend(builder(ev))
        else:
            all_rows.append({
                "attack": ar["name"],
                "variant": "—",
                "outcome": "UNKNOWN",
                "guardrail": "—",
                "finding": "No row builder for this evidence file.",
            })

    # ── Build and write summary ───────────────────────────────────────
    summary_md = build_summary_md(all_rows, run_ts, attack_results)

    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_path = summary_dir / "summary.md"
    summary_path.write_text(summary_md, encoding="utf-8")

    # Also write a machine-readable JSON version
    summary_json_path = summary_dir / "summary.json"
    summary_json_path.write_text(
        json.dumps(
            {
                "run_timestamp": run_ts,
                "total_duration_seconds": round(time.time() - run_start, 1),
                "attacks": attack_results,
                "rows": all_rows,
                "aggregate": {
                    "total": len(all_rows),
                    "blocked": sum(1 for r in all_rows if r["outcome"] == "BLOCKED"),
                    "resisted": sum(1 for r in all_rows if r["outcome"] == "RESISTED"),
                    "partial": sum(1 for r in all_rows if r["outcome"] == "PARTIAL"),
                    "compromised": sum(1 for r in all_rows if r["outcome"] == "COMPROMISED"),
                    "unknown": sum(1 for r in all_rows if r["outcome"] == "UNKNOWN"),
                },
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    # ── Print summary to terminal ─────────────────────────────────────
    print()
    print(summary_md)

    # ── Final status ──────────────────────────────────────────────────
    compromised = sum(1 for r in all_rows if r["outcome"] == "COMPROMISED")
    print(f"Evidence written to: {summary_path}")
    print(f"JSON written to:     {summary_json_path}")

    if compromised > 0:
        print(f"\n⚠️  {compromised} check(s) resulted in COMPROMISED — review findings.")
        return 1
    else:
        print(f"\n✅ All {len(all_rows)} checks passed (no COMPROMISED outcomes).")
        return 0


if __name__ == "__main__":
    sys.exit(main())
