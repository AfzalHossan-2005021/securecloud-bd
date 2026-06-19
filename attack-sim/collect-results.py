#!/usr/bin/env python3
"""
collect-results.py — Aggregate attack simulation results into a JSON report.

Parses every ``results/0*.txt`` file written by the scenario scripts,
extracts structured metadata from the header block (KEY: VALUE lines above
the ``---`` separator), derives detection statistics, and writes a
machine-readable JSON report with:

  summary.scenarios_run             Total files processed
  summary.detection_rate_pct        Fraction of scenarios flagged DETECTED
  summary.mean_time_to_detect_s     Average MTTD across detected scenarios
  summary.network_policy_blocks     Steps with BLOCKED result
  summary.falco_total_alerts        Aggregate Falco alert count
  summary.true_positives            Scenarios correctly DETECTED
  summary.false_negatives           Scenarios that were UNDETECTED (missed)

  scenarios.<id>                    Per-scenario metrics

  kill_chain                        Dedicated section for scenario 05

Usage
-----
    python3 attack-sim/collect-results.py \\
        --results-dir attack-sim/results \\
        --output      attack-sim/report-$(date +%Y%m%d).json \\
        [--pretty]

The exit code is non-zero when any scenario reports UNDETECTED.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    """Parsed metadata from one results/*.txt file."""

    file_path: str
    scenario_id: str = ""
    scenario_name: str = ""
    mitre_id: str = ""
    start_time: str = ""
    end_time: str = ""
    category: str = ""
    severity: str = ""
    detection_status: str = ""    # DETECTED | UNDETECTED | N/A
    falco_alert_count: int = 0
    mttd_seconds: float = 0.0
    target_ip: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    # Derived
    @property
    def detected(self) -> bool:
        return self.detection_status == "DETECTED"

    @property
    def duration_seconds(self) -> float:
        try:
            t0 = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
            return (t1 - t0).total_seconds()
        except (ValueError, AttributeError):
            return 0.0


@dataclass
class KillChainStep:
    step_num: int
    name: str
    status: str
    detected: str
    time: str
    detail: str


@dataclass
class KillChainResult:
    """Parsed kill-chain data from scenario 05."""

    steps: list[KillChainStep] = field(default_factory=list)
    steps_controlled: int = 0
    kill_chain_broken_at: str = ""
    total_falco_alerts: int = 0
    scenario_duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_header(lines: list[str]) -> dict[str, str]:
    """
    Parse KEY: VALUE lines from the metadata header block.

    Everything above the first ``---`` line is treated as the header.
    Lines that don't match ``KEY: VALUE`` (e.g. the ``SECURECLOUD_RESULT_V1``
    sentinel) are silently ignored.
    """
    meta: dict[str, str] = {}
    for line in lines:
        if line.strip() == "---":
            break
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta


def _int(meta: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(meta.get(key, default))
    except (ValueError, TypeError):
        return default


def _float(meta: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        return float(meta.get(key, default))
    except (ValueError, TypeError):
        return default


def _parse_kill_chain(meta: dict[str, str]) -> KillChainResult:
    """Extract per-step kill-chain fields from the metadata dict."""
    steps: list[KillChainStep] = []
    for i in range(1, 6):
        name = meta.get(f"KC_STEP_{i}_NAME", "")
        if not name:
            continue
        steps.append(KillChainStep(
            step_num=i,
            name=name,
            status=meta.get(f"KC_STEP_{i}_STATUS", ""),
            detected=meta.get(f"KC_STEP_{i}_DETECTED", ""),
            time=meta.get(f"KC_STEP_{i}_TIME", ""),
            detail=meta.get(f"KC_STEP_{i}_DETAIL", ""),
        ))
    return KillChainResult(
        steps=steps,
        steps_controlled=_int(meta, "STEPS_CONTROLLED"),
        kill_chain_broken_at=meta.get("KILL_CHAIN_BROKEN_AT", ""),
        total_falco_alerts=_int(meta, "TOTAL_FALCO_ALERTS"),
        scenario_duration_seconds=_float(meta, "SCENARIO_DURATION_SECONDS"),
    )


def parse_result_file(path: Path) -> ScenarioResult:
    """Parse a single scenario results file."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ScenarioResult(file_path=str(path), scenario_id="ERROR",
                               extra={"parse_error": str(exc)})

    lines = content.splitlines()
    meta  = _parse_header(lines)

    # Gather all extra keys (step results, kill-chain fields, etc.)
    reserved = {
        "SECURECLOUD_RESULT_V1", "SCENARIO_ID", "SCENARIO_NAME", "MITRE_ID",
        "START_TIME", "END_TIME", "CATEGORY", "SEVERITY",
        "DETECTION_STATUS", "FALCO_ALERT_COUNT", "MTTD_SECONDS", "TARGET_IP",
    }
    extra = {k: v for k, v in meta.items() if k not in reserved}

    return ScenarioResult(
        file_path=str(path),
        scenario_id=meta.get("SCENARIO_ID", path.stem),
        scenario_name=meta.get("SCENARIO_NAME", ""),
        mitre_id=meta.get("MITRE_ID", meta.get("MITRE_CHAIN", "")),
        start_time=meta.get("START_TIME", ""),
        end_time=meta.get("END_TIME", ""),
        category=meta.get("CATEGORY", ""),
        severity=meta.get("SEVERITY", ""),
        detection_status=meta.get("DETECTION_STATUS", "UNKNOWN"),
        falco_alert_count=_int(meta, "FALCO_ALERT_COUNT"),
        mttd_seconds=_float(meta, "MTTD_SECONDS"),
        target_ip=meta.get("TARGET_IP", ""),
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Summary calculation
# ---------------------------------------------------------------------------

@dataclass
class ReportSummary:
    scenarios_run: int          = 0
    true_positives: int         = 0
    false_negatives: int        = 0
    detection_rate_pct: float   = 0.0
    mean_time_to_detect_s: float = 0.0
    p50_mttd_s: float           = 0.0
    p95_mttd_s: float           = 0.0
    network_policy_blocks: int  = 0
    falco_total_alerts: int     = 0
    scenarios_by_severity: dict[str, int] = field(default_factory=dict)
    mitre_techniques: list[str] = field(default_factory=list)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def compute_summary(results: list[ScenarioResult]) -> ReportSummary:
    if not results:
        return ReportSummary()

    detected    = [r for r in results if r.detected]
    undetected  = [r for r in results if not r.detected and r.detection_status != "N/A"]
    mttd_values = [r.mttd_seconds for r in detected if r.mttd_seconds > 0]

    # Count BLOCKED steps across lateral-movement and kill-chain scenarios
    np_blocks = 0
    for r in results:
        for key, val in r.extra.items():
            if "STATUS" in key and val in ("BLOCKED", "RBAC_BLOCKED"):
                np_blocks += 1

    sev_counts: dict[str, int] = {}
    for r in results:
        sev_counts[r.severity or "UNKNOWN"] = sev_counts.get(r.severity or "UNKNOWN", 0) + 1

    mitre = sorted({r.mitre_id for r in results if r.mitre_id})

    return ReportSummary(
        scenarios_run=len(results),
        true_positives=len(detected),
        false_negatives=len(undetected),
        detection_rate_pct=round(len(detected) / len(results) * 100, 1) if results else 0.0,
        mean_time_to_detect_s=round(sum(mttd_values) / len(mttd_values), 1) if mttd_values else 0.0,
        p50_mttd_s=round(_percentile(mttd_values, 50), 1),
        p95_mttd_s=round(_percentile(mttd_values, 95), 1),
        network_policy_blocks=np_blocks,
        falco_total_alerts=sum(r.falco_alert_count for r in results),
        scenarios_by_severity=sev_counts,
        mitre_techniques=mitre,
    )


# ---------------------------------------------------------------------------
# Report construction
# ---------------------------------------------------------------------------

def _scenario_to_dict(r: ScenarioResult) -> dict[str, Any]:
    d: dict[str, Any] = {
        "file": r.file_path,
        "name": r.scenario_name,
        "mitre": r.mitre_id,
        "category": r.category,
        "severity": r.severity,
        "start_time": r.start_time,
        "end_time": r.end_time,
        "duration_seconds": round(r.duration_seconds, 1),
        "detection_status": r.detection_status,
        "detected": r.detected,
        "falco_alert_count": r.falco_alert_count,
        "mttd_seconds": r.mttd_seconds,
        "target_ip": r.target_ip,
    }
    # Inline useful extra fields
    for k, v in r.extra.items():
        if any(kw in k for kw in (
            "STEP_", "KC_STEP_", "BASELINE", "PACKETS", "OPEN_PORTS",
            "CREDENTIAL", "KILL_CHAIN", "STEPS_",
        )):
            d[k.lower()] = v
    return d


def build_report(
    results: list[ScenarioResult],
    kill_chain: KillChainResult | None,
) -> dict[str, Any]:
    summary = compute_summary(results)

    report: dict[str, Any] = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "generator": "attack-sim/collect-results.py",
        "summary": asdict(summary),
        "scenarios": {r.scenario_id: _scenario_to_dict(r) for r in results},
    }

    if kill_chain:
        report["kill_chain"] = {
            "steps_controlled": kill_chain.steps_controlled,
            "kill_chain_broken_at": kill_chain.kill_chain_broken_at,
            "total_falco_alerts": kill_chain.total_falco_alerts,
            "duration_seconds": kill_chain.scenario_duration_seconds,
            "steps": [asdict(s) for s in kill_chain.steps],
        }

    return report


# ---------------------------------------------------------------------------
# Formatted console summary
# ---------------------------------------------------------------------------

def print_summary(report: dict[str, Any]) -> None:
    s = report["summary"]
    print()
    print("━" * 62)
    print("  SecureCloud-BD — Attack Simulation Report")
    print("━" * 62)
    print(f"  Report generated : {report['report_generated'][:19]}Z")
    print(f"  Scenarios run    : {s['scenarios_run']}")
    print(f"  True positives   : {s['true_positives']}")
    print(f"  False negatives  : {s['false_negatives']}")
    print(f"  Detection rate   : {s['detection_rate_pct']:.1f}%")
    print(f"  Mean MTTD        : {s['mean_time_to_detect_s']:.1f} s")
    print(f"  P50 MTTD         : {s['p50_mttd_s']:.1f} s")
    print(f"  P95 MTTD         : {s['p95_mttd_s']:.1f} s")
    print(f"  NetworkPolicy blocks : {s['network_policy_blocks']}")
    print(f"  Falco alerts (total) : {s['falco_total_alerts']}")
    print()

    # Per-scenario table
    print(f"  {'Scenario':<30}  {'Status':<10}  {'MTTD(s)':<8}  {'Falco'}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*8}  {'-----'}")
    for sid, sc in report["scenarios"].items():
        status = sc["detection_status"]
        icon   = "✓" if sc["detected"] else "✗"
        mttd   = f"{sc['mttd_seconds']:.0f}" if sc["mttd_seconds"] else "—"
        falco  = str(sc["falco_alert_count"])
        print(f"  {sc['name']:<30}  {icon} {status:<9}  {mttd:<8}  {falco}")

    if kc := report.get("kill_chain"):
        print()
        print("  Kill-chain (05-bkash-scenario)")
        print(f"    Steps controlled  : {kc['steps_controlled']} / 4")
        print(f"    Chain broken at   : {kc['kill_chain_broken_at'] or '—'}")
        for step in kc.get("steps", []):
            status  = step.get("status", "?")
            detect  = step.get("detected", "")
            icon    = "✓" if status in ("BLOCKED", "RBAC_BLOCKED") or detect == "DETECTED" else "✗"
            print(f"    Step {step['step_num']}: {step['name'][:40]:<40} {icon} {status}")

    print("━" * 62)
    print()

    if s["false_negatives"] > 0:
        print(f"  ⚠ {s['false_negatives']} scenario(s) were UNDETECTED.")
        print("    Review: siem/falco/falco-values.yaml (customRules section)")
        print("    and:    infra/istio/ (NetworkPolicy / AuthorizationPolicy)")
        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Aggregate SecureCloud-BD attack simulation results.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--results-dir",
        type=Path,
        default=Path("attack-sim/results"),
        help="Directory containing scenario result .txt files.",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for the JSON report (default: results-dir/report-TIMESTAMP.json).",
    )
    p.add_argument(
        "--pretty",
        action="store_true",
        help="Indent the JSON output for human readability.",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    results_dir: Path = args.results_dir
    if not results_dir.is_dir():
        print(f"ERROR: results directory not found: {results_dir}", file=sys.stderr)
        sys.exit(2)

    # Find all scenario result files
    result_files = sorted(results_dir.glob("0*.txt"))
    if not result_files:
        print(f"No result files found in {results_dir}", file=sys.stderr)
        print("Run scenario scripts first: bash attack-sim/scenarios/01-port-scan.sh")
        sys.exit(2)

    print(f"Parsing {len(result_files)} result file(s) from {results_dir}…")
    results: list[ScenarioResult] = [parse_result_file(f) for f in result_files]

    # Parse kill-chain data from the bkash scenario (most recent file)
    kill_chain: KillChainResult | None = None
    bkash_files = sorted(results_dir.glob("05-bkash-scenario-*.txt"))
    if bkash_files:
        bkash_meta = _parse_header(bkash_files[-1].read_text(encoding="utf-8").splitlines())
        kill_chain = _parse_kill_chain(bkash_meta)

    report = build_report(results, kill_chain)

    # Output path
    if args.output:
        out_path = args.output
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        out_path = results_dir / f"report-{ts}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if args.pretty else None
    out_path.write_text(
        json.dumps(report, indent=indent, default=str),
        encoding="utf-8",
    )
    print(f"Report written → {out_path}")

    # Human-readable summary to stdout
    print_summary(report)

    # Exit non-zero if any scenario missed detection
    if report["summary"]["false_negatives"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
