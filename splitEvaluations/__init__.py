"""Split-by-arm evaluation harnesses (Semgrep-only and Joern-only sweeps).

Each arm runs in its own sequential sweep so we can (a) give Joern a
larger per-CVE budget without quadrupling the wall time of the Semgrep
arm and (b) audit Semgrep's rule-mutation path independently via
``audit_rules_hash.py``.
"""
