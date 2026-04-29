"""Fixed development set for CWE-78 readiness experiments.

This module is intentionally not a benchmark definition.  The CVE list is a
small, dev-only loop for making Joern/Semgrep operational before spending on
frontier models or reporting heldout accuracy.
"""

from __future__ import annotations

DEV_LOOP_CVES: tuple[str, ...] = (
    "CVE-2025-1753",
    "CVE-2021-43857",
    "CVE-2021-21386",
    "CVE-2024-13129",
    "CVE-2017-16667",
    "CVE-2024-22423",
    "CVE-2026-34955",
    "CVE-2026-34935",
    "CVE-2026-33718",
    "CVE-2024-52803",
    "CVE-2024-53305",
    "CVE-2025-47782",
    "CVE-2022-24065",
    "CVE-2026-33310",
    "CVE-2026-32608",
)

GPT54_MINI_DIAGNOSTIC_CVES: tuple[str, ...] = (
    "CVE-2021-43857",
    "CVE-2024-13129",
    "CVE-2024-52803",
    "CVE-2026-34955",
    "CVE-2026-34935",
    "CVE-2026-33718",
    "CVE-2025-47782",
    "CVE-2017-16667",
    "CVE-2021-21386",
    "CVE-2022-24065",
)

GPT54_JOERN_DIAGNOSTIC_CVES: tuple[str, ...] = (
    "CVE-2021-21386",
    "CVE-2024-13129",
    "CVE-2017-16667",
    "CVE-2024-22423",
    "CVE-2022-24065",
    "CVE-2026-33310",
    "CVE-2026-32608",
    "CVE-2025-47782",
    "CVE-2024-52803",
    "CVE-2026-33718",
)

PATCH_RULE_DEV_CVES: tuple[str, ...] = (
    "CVE-2021-43857",
    "CVE-2024-13129",
    "CVE-2024-52803",
    "CVE-2021-21386",
    "CVE-2022-24065",
)

PATCH_RULE_EVAL_CVES: tuple[str, ...] = (
    "CVE-2020-15271",
    "CVE-2021-38305",
    "CVE-2024-22423",
    "CVE-2026-33310",
    "CVE-2026-32608",
    "CVE-2026-33718",
    "CVE-2025-47782",
    "CVE-2024-53305",
    "CVE-2026-34955",
    "CVE-2026-34935",
    "CVE-2023-24816",
    "CVE-2022-39327",
    "CVE-2023-34540",
    "CVE-2020-7698",
    "CVE-2021-3148",
    "CVE-2017-16667",
    "CVE-2018-6353",
    "CVE-2021-23422",
    "CVE-2024-51378",
    "CVE-2024-47821",
)

KNOWN_JOERN_TIMEOUT_CVES: tuple[str, ...] = (
    "CVE-2020-11981",
    "CVE-2020-11978",
    "CVE-2021-41228",
    "CVE-2019-14904",
    "CVE-2025-54941",
    "CVE-2022-40127",
    "CVE-2022-38649",
    "CVE-2022-41131",
    "CVE-2022-40189",
    "CVE-2022-40954",
    "CVE-2020-1734",
    "CVE-2021-3583",
    "CVE-2017-17835",
    "CVE-2023-22884",
    "CVE-2022-46421",
)

JOERN_DIAGNOSTIC_30_CVES: tuple[str, ...] = (
    *GPT54_JOERN_DIAGNOSTIC_CVES,
    "CVE-2020-15271",
    "CVE-2021-38305",
    "CVE-2024-53305",
    "CVE-2026-34955",
    "CVE-2026-34935",
    "CVE-2023-24816",
    "CVE-2022-39327",
    "CVE-2023-34540",
    "CVE-2020-7698",
    "CVE-2021-3148",
    "CVE-2018-6353",
    "CVE-2021-23422",
    "CVE-2024-51378",
    "CVE-2024-47821",
    "CVE-2025-1753",
    "CVE-2021-43857",
    "CVE-2021-39160",
    "CVE-2021-39159",
    "CVE-2021-22557",
    "CVE-2026-25130",
)

assert len(JOERN_DIAGNOSTIC_30_CVES) == 30
assert len(set(JOERN_DIAGNOSTIC_30_CVES)) == len(JOERN_DIAGNOSTIC_30_CVES)
assert not (set(JOERN_DIAGNOSTIC_30_CVES) & set(KNOWN_JOERN_TIMEOUT_CVES))

SEMGREP_DEV_TIMEOUT_S = 300
JOERN_DEV_TIMEOUT_S = 900
JOERN_DEV_MAX_K = 1
SEMGREP_DEV_MAX_K = 3
