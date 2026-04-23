"""Tests for ``splitEvaluations.audit_rules_hash``.

Three small synthetic ``results.json`` fixtures pin the audit logic:

1. A "healthy" sweep where every refine action mutates the YAML and at
   least one CVE's findings_hash changes across k → no-op rate is 0,
   no k-invariant CVEs.
2. A "B2 broken" sweep where every refine action leaves the YAML
   identical → no-op rate is 100%, CVE is flagged k-invariant.
3. A back-compat sweep with no ``rules_yaml_changed`` key (only the
   pre/post hashes) → auditor falls back to the hash comparison.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from splitEvaluations.audit_rules_hash import (
    audit_results_json,
    build_summary_rows,
    compute_findings_invariance,
    compute_no_op_rate,
)


def _iter(k: int, *, hash_pre: str, hash_post: str, yaml_changed: bool,
          findings_hash: str, action: str = "refine",
          target_rule_id: str = "r1") -> dict:
    return {
        "metrics": {
            "rules_hash_pre": hash_pre,
            "rules_hash_post": hash_post,
            "rules_yaml_bytes_pre": 100,
            "rules_yaml_bytes_post": 110 if yaml_changed else 100,
            "rules_yaml_changed": yaml_changed,
            "findings_hash": findings_hash,
        },
        "refinement_actions": [{"action": action, "target_rule_id": target_rule_id}],
    }


def _cve(cve_id: str, arms: dict) -> dict:
    return {"cve_id": cve_id, "arms": arms}


class TestRulesHashAudit:
    def test_healthy_sweep_reports_zero_no_op_rate(self, tmp_path: Path) -> None:
        data = [
            _cve("CVE-A", {
                "semgrep_0": _iter(0, hash_pre="h0", hash_post="h1",
                                   yaml_changed=True, findings_hash="fA0"),
                "semgrep_1": _iter(1, hash_pre="h1", hash_post="h2",
                                   yaml_changed=True, findings_hash="fA1"),
            }),
            _cve("CVE-B", {
                "semgrep_0": _iter(0, hash_pre="g0", hash_post="g1",
                                   yaml_changed=True, findings_hash="fB0"),
                "semgrep_1": _iter(1, hash_pre="g1", hash_post="g2",
                                   yaml_changed=True, findings_hash="fB1"),
            }),
        ]
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data))

        summary = audit_results_json(p)
        assert summary["refine_actions_total"] == 4
        assert summary["refine_actions_no_op"] == 0
        assert summary["refine_no_op_rate"] == pytest.approx(0.0)
        assert summary["cves_with_k_invariant_findings"] == 0

    def test_broken_sweep_reports_100pct_no_op_and_flags_invariance(
        self, tmp_path: Path,
    ) -> None:
        data = [
            _cve("CVE-X", {
                "semgrep_0": _iter(0, hash_pre="h", hash_post="h",
                                   yaml_changed=False, findings_hash="f0"),
                "semgrep_1": _iter(1, hash_pre="h", hash_post="h",
                                   yaml_changed=False, findings_hash="f0"),
                "semgrep_2": _iter(2, hash_pre="h", hash_post="h",
                                   yaml_changed=False, findings_hash="f0"),
            }),
        ]
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data))

        summary = audit_results_json(p)
        assert summary["refine_actions_total"] == 3
        assert summary["refine_actions_no_op"] == 3
        assert summary["refine_no_op_rate"] == pytest.approx(1.0)
        assert summary["cves_with_k_invariant_findings"] == 1
        assert summary["findings_invariance_frac"] == pytest.approx(1.0)

    def test_backcompat_falls_back_to_hash_only(self, tmp_path: Path) -> None:
        # Simulate an older results.json with no ``rules_yaml_changed`` or
        # byte-size columns — only the pre/post hashes.  The auditor must
        # still classify "hash-changed" rows as non-no-op.
        data = [{
            "cve_id": "CVE-OLD",
            "arms": {
                "semgrep_0": {
                    "metrics": {
                        "rules_hash_pre": "aaa", "rules_hash_post": "bbb",
                        "findings_hash": "fOLD0",
                    },
                    "refinement_actions": [{"action": "refine", "target_rule_id": "r"}],
                },
                "semgrep_1": {
                    "metrics": {
                        "rules_hash_pre": "bbb", "rules_hash_post": "bbb",
                        "findings_hash": "fOLD0",
                    },
                    "refinement_actions": [{"action": "refine", "target_rule_id": "r"}],
                },
            },
        }]
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data))

        summary = audit_results_json(p)
        assert summary["refine_actions_total"] == 2
        # semgrep_0 is hash-changed (non-no-op), semgrep_1 is identical (no-op).
        assert summary["refine_actions_no_op"] == 1
        assert summary["refine_no_op_rate"] == pytest.approx(0.5)

    def test_csv_is_written_and_has_expected_schema(self, tmp_path: Path) -> None:
        data = [_cve("CVE-A", {
            "semgrep_0": _iter(0, hash_pre="h", hash_post="h",
                               yaml_changed=False, findings_hash="fA0"),
        })]
        p = tmp_path / "results.json"
        p.write_text(json.dumps(data))

        summary = audit_results_json(p)
        csv_path = Path(summary["csv_path"])
        assert csv_path.exists()
        header = csv_path.read_text().splitlines()[0]
        for col in (
            "cve_id", "arm", "k", "action", "target_rule_id",
            "rules_hash_pre", "rules_hash_post",
            "rules_yaml_bytes_pre", "rules_yaml_bytes_post",
            "rules_yaml_changed",
            "findings_hash", "findings_changed_vs_k0",
        ):
            assert col in header

    def test_ignores_patched_and_joern_entries(self, tmp_path: Path) -> None:
        data = [{
            "cve_id": "CVE-MIX",
            "arms": {
                "semgrep_0": _iter(0, hash_pre="h", hash_post="j",
                                   yaml_changed=True, findings_hash="f0"),
                "semgrep_1_patched": {"metrics": {}},  # must be ignored
                "joern_0": {"metrics": {}},             # must be ignored
            },
        }]
        rows = build_summary_rows(data)
        assert [r["k"] for r in rows] == [0]
        total, no_op, rate = compute_no_op_rate(rows)
        assert total == 1 and no_op == 0 and rate == 0.0
        n_cves, n_inv, frac = compute_findings_invariance(rows)
        assert n_cves == 1 and n_inv == 0
