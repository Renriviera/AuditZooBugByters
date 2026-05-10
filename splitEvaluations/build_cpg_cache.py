#!/usr/bin/env python3
"""Pre-warm the Joern CPG cache for every CVE in the dataset.

For each CVE we:

1. Look up the deterministic cache slot from
   :func:`auditzoo.agents.cwe78_study.cpg_cache.cpg_cache_location`
   (key = ``sha256(repo_url, commit, language, joern_version, cache_version)``).
2. Skip if the project subdirectory already exists (cache hit).
3. Otherwise clone the vulnerable commit, spin up a fresh Joern JVM
   pointed at the cache slot as its workspace, run ``importCode`` once,
   disconnect, kill the JVM, and write a breadcrumb.

Subsequent ``run_joern_sweep`` invocations that pass
``--cpg-cache-dir <same-root>`` then hit the cache and skip the
expensive importCode step entirely.

Why bypass :class:`Pipeline` ?  The pipeline pulls in the LLM client,
the triage agent, and the refinement loop — none of which are needed to
build a CPG.  Going straight to :class:`JoernBackend` keeps the
pre-warm strictly an I/O + Joern problem (no API keys, no LLM cost).

Memory envelope: the JVM heap is bounded by ``AUDITZOO_JOERN_HEAP``
(default 8 GB in the wrapper) regardless of how many CPGs we cache —
they're flushed to disk between CVEs.  Disk usage is the sum of all
cached CPGs (typically 1–500 MB each, so ~5–30 GB for the full 105-CVE
set; well under the 106 GB free on the runpod).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from auditzoo.agents.cwe78_study.cpg_cache import (
    cpg_cache_location,
    is_cache_hit,
    write_cache_metadata,
)
from auditzoo.backends.base import JoernConfig
from auditzoo.backends.joern.backend import JoernBackend
from scripts.run_evaluation import (
    _cleanup_stray_joern,
    _is_port_in_use,
    clone_and_checkout,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Path to the CVE metadata.json (e.g. benchmark/python/cwe78_cves/metadata.json).",
    )
    ap.add_argument(
        "--cache-dir",
        type=Path,
        required=True,
        help="Stable workspace root for the CPG cache "
        "(matches --cpg-cache-dir on subsequent sweeps).",
    )
    ap.add_argument(
        "--clone-dir",
        type=Path,
        default=Path("/tmp/auditzoo_cpg_cache_build"),
        help="Scratch dir for shallow clones (rmtree'd between CVEs).",
    )
    ap.add_argument("--joern-port", type=int, default=12345)
    ap.add_argument(
        "--per-cve-timeout",
        type=float,
        default=900.0,
        help="Wall-clock budget per CVE for clone + importCode "
        "(0 disables).  Joern OOMs / hangs are caught here.",
    )
    ap.add_argument(
        "--port-wait-s",
        type=float,
        default=30.0,
        help="Seconds to wait for the Joern port to drain between CVEs.",
    )
    ap.add_argument(
        "--include-patched",
        action="store_true",
        default=False,
        help="Also build the CPG for the patched commit of each CVE.  "
        "Doubles wall-clock and disk usage; only needed when the sweep "
        "will run with --run-patched.",
    )
    ap.add_argument(
        "--only-cves",
        nargs="+",
        default=[],
        help="If non-empty, restrict to these CVE IDs.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="If >0, cap the number of CVEs after filtering.",
    )
    ap.add_argument(
        "--summary-out",
        type=Path,
        default=None,
        help="Where to write the per-CVE build summary JSON.  Defaults "
        "to <cache-dir>/build_summary.json.",
    )
    return ap.parse_args()


async def _build_one_cpg(
    *,
    cve_id: str,
    repo_url: str,
    commit: str,
    repo_dest: Path,
    cache_root: Path,
    joern_port: int,
    port_wait_s: float,
    label: str,
) -> dict[str, Any]:
    """Clone *repo_url@commit* and trigger Joern ``importCode`` once.

    Returns a per-CVE summary record.  ``label`` is appended to the log
    line so we can tell vulnerable vs. patched runs apart.
    """
    loc = cpg_cache_location(cache_root, repo_url=repo_url, commit=commit)
    record: dict[str, Any] = {
        "cve_id": cve_id,
        "label": label,
        "cache_key": loc.cache_key,
        "cache_dir": str(loc.workspace_dir),
        "repo_url": repo_url,
        "commit": commit,
    }

    if is_cache_hit(loc):
        logger.info("[%s|%s] cache HIT key=%s — skipping", cve_id, label, loc.cache_key)
        record["status"] = "hit"
        return record

    if not repo_url or not commit:
        record["status"] = "no_metadata"
        return record

    if not clone_and_checkout(repo_url, commit, repo_dest):
        record["status"] = "clone_failed"
        return record

    if _is_port_in_use(joern_port):
        logger.warning("[%s|%s] port %d busy; reaping", cve_id, label, joern_port)
        _cleanup_stray_joern(joern_port, wait_s=port_wait_s)

    loc.workspace_dir.mkdir(parents=True, exist_ok=True)
    # NOTE: ``language="python"`` is Joern's *binary/bytecode* frontend
    # and silently parses zero ``.py`` files; the source frontend is
    # ``pythonsrc``.  We use ``"auto"`` to match Pipeline._run_joern_arm
    # so Joern's auto-detection picks ``pythonsrc`` for any directory
    # containing ``.py`` files.  Explicitly forcing ``"python"`` here was
    # the cause of the 13-CVE empty-cache run on 20260508_05.
    cfg = JoernConfig(
        source_path=str(repo_dest),
        language="auto",
        analysis_path=str(loc.workspace_dir),
        project_name=loc.project_name,
        host="localhost",
        port=joern_port,
    )

    backend = JoernBackend(cfg)
    t0 = time.perf_counter()
    try:
        await backend.connect()
        await backend.disconnect()
        elapsed = time.perf_counter() - t0
        size_b = sum(
            (Path(root) / f).stat().st_size
            for root, _, files in os.walk(loc.workspace_dir)
            for f in files
            if (Path(root) / f).is_file()
        )
        record.update(
            {
                "status": "built",
                "build_elapsed_s": elapsed,
                "cache_bytes": size_b,
            }
        )
        write_cache_metadata(
            loc,
            cve_id=cve_id,
            label=label,
            build_elapsed_s=elapsed,
            cache_bytes=size_b,
        )
        logger.info(
            "[%s|%s] BUILT key=%s in %.1fs (%.1f MB)",
            cve_id,
            label,
            loc.cache_key,
            elapsed,
            size_b / (1024 * 1024),
        )
    except Exception as exc:  # noqa: BLE001 — isolate per-CVE failure
        elapsed = time.perf_counter() - t0
        record.update(
            {
                "status": "error",
                "build_elapsed_s": elapsed,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        logger.exception(
            "[%s|%s] FAILED key=%s after %.1fs", cve_id, label, loc.cache_key, elapsed
        )
    return record


async def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for noisy in ("autogen_core", "autogen_core.events", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    args.clone_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.summary_out or (args.cache_dir / "build_summary.json")

    dataset = json.loads(args.dataset.read_text())
    if args.only_cves:
        keep = set(args.only_cves)
        dataset = [c for c in dataset if c.get("cve_id") in keep]
    if args.limit and args.limit > 0:
        dataset = dataset[: args.limit]

    logger.info(
        "Building CPG cache: %d CVEs, cache=%s, port=%d, include_patched=%s",
        len(dataset),
        args.cache_dir,
        args.joern_port,
        args.include_patched,
    )

    # Reap any lingering JVM from a previous (perhaps killed) run so the
    # very first CVE has a clean Joern listener slot.
    if _is_port_in_use(args.joern_port):
        logger.warning(
            "Port %d already bound at start; reaping stray JVMs", args.joern_port
        )
        _cleanup_stray_joern(args.joern_port, wait_s=args.port_wait_s)

    summary: list[dict[str, Any]] = []
    started_at = datetime.now().isoformat()

    for idx, cve in enumerate(dataset):
        cve_id = str(cve.get("cve_id", "unknown"))
        repo_url = str(cve.get("repo_url", ""))
        vuln_commit = str(cve.get("vulnerable_commit", ""))
        patch_commit = str(cve.get("patch_commit", ""))
        repo_dest = args.clone_dir / cve_id

        targets: list[tuple[str, str]] = [("vulnerable", vuln_commit)]
        if args.include_patched and patch_commit:
            targets.append(("patched", patch_commit))

        for label, commit in targets:
            logger.info(
                "[%d/%d] %s (%s)", idx + 1, len(dataset), cve_id, label
            )
            try:
                if args.per_cve_timeout and args.per_cve_timeout > 0:
                    record = await asyncio.wait_for(
                        _build_one_cpg(
                            cve_id=cve_id,
                            repo_url=repo_url,
                            commit=commit,
                            repo_dest=repo_dest,
                            cache_root=args.cache_dir,
                            joern_port=args.joern_port,
                            port_wait_s=args.port_wait_s,
                            label=label,
                        ),
                        timeout=args.per_cve_timeout,
                    )
                else:
                    record = await _build_one_cpg(
                        cve_id=cve_id,
                        repo_url=repo_url,
                        commit=commit,
                        repo_dest=repo_dest,
                        cache_root=args.cache_dir,
                        joern_port=args.joern_port,
                        port_wait_s=args.port_wait_s,
                        label=label,
                    )
            except asyncio.TimeoutError:
                logger.warning(
                    "[%s|%s] timeout after %.0fs; reaping JVM",
                    cve_id,
                    label,
                    args.per_cve_timeout,
                )
                _cleanup_stray_joern(args.joern_port, wait_s=args.port_wait_s)
                record = {
                    "cve_id": cve_id,
                    "label": label,
                    "status": "timeout",
                    "per_cve_timeout_s": args.per_cve_timeout,
                }
            summary.append(record)
            shutil.rmtree(repo_dest, ignore_errors=True)
            # Belt-and-braces port cleanup: the JoernBackend.disconnect()
            # path occasionally leaves a TIME_WAIT listener that the next
            # CVE's connect() trips on.
            if _is_port_in_use(args.joern_port):
                _cleanup_stray_joern(args.joern_port, wait_s=args.port_wait_s)

            # Persist progress incrementally so a kill-9 still leaves us
            # with a recoverable summary.
            summary_payload = {
                "started_at": started_at,
                "updated_at": datetime.now().isoformat(),
                "cache_dir": str(args.cache_dir),
                "n_records": len(summary),
                "records": summary,
            }
            summary_path.write_text(json.dumps(summary_payload, indent=2))

    n_built = sum(1 for r in summary if r.get("status") == "built")
    n_hit = sum(1 for r in summary if r.get("status") == "hit")
    n_failed = sum(
        1 for r in summary if r.get("status") not in ("built", "hit")
    )
    total_bytes = sum(int(r.get("cache_bytes", 0) or 0) for r in summary)
    logger.info(
        "CPG cache build done: built=%d hit=%d failed=%d size=%.1f MB summary=%s",
        n_built,
        n_hit,
        n_failed,
        total_bytes / (1024 * 1024),
        summary_path,
    )


if __name__ == "__main__":
    asyncio.run(main())
