# CWE-78 Evaluation: Pipeline + Joern Backend Fixes

This document records three pipeline reliability fixes made to the Joern arm
and the evaluation harness while stabilising the full 105-CVE CWE-78 sweep.
The fork builds on the upstream
[`coms4995-ai4sec/AuditZoo`](https://github.com/coms4995-ai4sec/AuditZoo)
framework; all changes here are local to this fork.

All three problems were uncovered while running the main comparison driver
`scripts/run_evaluation.py` against `benchmark/python/cwe78_cves/metadata.json`
(105 CVEs × 2 arms × 4 k-levels × vulnerable + patched commits) backed by a
local vLLM server for LLM triage/refinement.

---

## Problem 1 — Whole-sweep crash on non-UTF-8 Python sources

### Symptom

After ~1 h 17 m on the full run (29 / 105 CVEs in), the evaluation script
died mid-sweep with an unhandled exception:

```
File "/workspace/AuditZooBugByters/scripts/run_evaluation.py", line 166, in count_loc
  total += sum(1 for line in pyfile.read_text().splitlines() if line.strip())
File ".../codecs.py", line 322, in decode
  (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xb1 in position 23: invalid start byte
```

Processing `CVE-2023-34540` (langchain) had pulled in a `.py` file containing
non-UTF-8 bytes, `Path.read_text()` uses the default UTF-8 decoder, and the
resulting exception took down `asyncio.run(main())`. All 23 CVEs processed so
far had already been persisted to `results.json` incrementally, but the
remaining 76 were lost.

### Root cause

`count_loc` in `scripts/run_evaluation.py` naïvely decoded every `*.py` file
as UTF-8. Real-world repos contain legacy Python 2 files with latin-1 text
(docstrings, comments, example strings), binary-ish fixtures accidentally
named `.py`, etc.

### Fix

Count lines in **byte mode** so decoding never runs:

```163:173:scripts/run_evaluation.py
    total = 0
    for pyfile in repo_path.rglob("*.py"):
        try:
            # Read as bytes so non-UTF-8 source files (e.g. latin-1 / mojibake in
            # older Python 2 code) don't abort the whole evaluation sweep.
            with pyfile.open("rb") as fh:
                for raw in fh:
                    if raw.strip():
                        total += 1
        except OSError:
            pass
    return total
```

This is equivalent to the previous semantics (non-blank line count) but is
encoding-agnostic.

---

## Problem 2 — Any per-CVE exception aborts the whole sweep

### Symptom

Even after fixing `count_loc`, any single CVE raising anything uncaught
(e.g. a transient network failure during `git clone`, an OOM inside Joern,
a pathological Semgrep rule hang) would take the whole 12-hour sweep with it.
The log already tracks LLM / backend / timeout conditions explicitly, but
there was no outer "containment belt" around the per-CVE body of
`run_main_comparison`.

### Root cause

`run_main_comparison` in `scripts/run_evaluation.py` had a flat `for`-loop
body; any unhandled exception propagated up out of the async driver and
terminated the sweep. The only failure modes recorded in `results.json`
were `clone failed`, `timeout`, and `explicit skip` — novel failures simply
crashed.

### Fix

Wrap the entire per-CVE body in a try / except / finally with three
distinct branches:

- `KeyboardInterrupt` / `asyncio.CancelledError`: flush partial results
  and re-raise so operators can still cleanly stop the sweep.
- `Exception`: log with full traceback, record an `{"skipped": "error"}`
  row with the exception type + message, clean up any stray Joern, and
  continue with the next CVE.
- `finally`: always remove the repo clone.

```355:380:scripts/run_evaluation.py
        except (KeyboardInterrupt, asyncio.CancelledError):
            # Honour user/system cancellation: flush partial results and re-raise
            # so callers can shut the whole sweep down cleanly.
            _save_json(all_results, output_dir / "results.json")
            shutil.rmtree(repo_dest, ignore_errors=True)
            raise
        except Exception as exc:  # noqa: BLE001 — isolate per-CVE failures
            logger.exception("  %s: unhandled error, skipping CVE: %s", cve_id, exc)
            all_results.append({
                "cve_id": cve_id,
                "repo_url": cve.get("repo_url"),
                "skipped": "error",
                "error": f"{type(exc).__name__}: {exc}",
            })
            _save_json(all_results, output_dir / "results.json")
            _cleanup_stray_joern()
        finally:
            shutil.rmtree(repo_dest, ignore_errors=True)
```

Subsequent 12 h 20 m run processed all 105 CVEs with zero sweep-level
crashes; no CVE hit the new `{"skipped": "error"}` path, confirming the
net (and the UTF-8 fix) covered the previously-fatal cases.

---

## Problem 3 — Joern arm flooded with "Recursion limit exceeded" compiler errors

This was the headline problem: the Joern arm contributed **zero true
positives across all 40 evaluated CVEs**, with 185 `BackendResponseError`
and 122 `Recursion limit exceeded` entries in the run log.

### Symptom

Representative traceback (`/workspace/logs/eval_full_resume.log`,
lines ~60–130):

```text
auditzoo.core.ir.backend_api.BackendResponseError:
Failed to parse Joern JSON response: -- [E008] Not Found Error: -----
1 |cpg.method.id(107374185269L).call.map { call => Map("callees" -> call.callee.l, "callsite" -> call) }.toJson
  |^^^^^^^^^^
  |value method is not a member of io.shiftleft.codepropertygraph.generated.Cpg.
  |Extension methods were tried, but the search failed with:
  |    Recursion limit exceeded.
  |    Maybe there is an illegal cyclic reference?
  |    If that's not the case, you could also try to increase the stacksize using the -Xss JVM option.
  |    For the unprocessed stack trace, compile with -Xno-enrich-error-messages.
  |    A recurring operation is (inner to outer):
  |      find-member JoernConsole#ItExtend
  |      find-member Joern.ItExtend
1 error found
```

The same two query shapes accounted for virtually all of the failures:

1. `cpg.method.id(<ID>L).call.map { call => … }.toJson`
   (the IR call-graph preload path, from
   `auditzoo.core.ir.view.IRView.preload_from_backend`)
2. `cpg.tag.filter(_.name.startsWith("unitfact:")).toJson` and
   `cpg.tag.id(<ID>L).filter(...)` (the fact-tag preload path)

Joern's own diagnostic literally tells us what to do:

> *try to increase the stacksize using the `-Xss` JVM option*

### Root cause

The Joern REPL is a Scala 3 compile-then-run loop. Every `cpg.<member>`
reference (`cpg.method`, `cpg.tag`, `cpg.call`, …) forces the Scala 3
compiler to perform an extension-method / implicit search. For non-trivial
CPGs the candidate tree is deep; on the default JVM stack (≈1 MB on Linux
x86_64) the compiler's own internal recursion limit fires before the
search completes, and it writes the `[E008] Not Found Error` banner to
stdout instead of returning a result.

This is not a semantic issue with any particular query — the CPG is loaded
fine, the queries are valid, and the same queries work once the compiler's
extension-cache has been primed. It is purely a **compile-time resource
issue inside the REPL's JVM**.

Two contributors made the failure rate especially high in our sweep:

- Upstream
  [`JoernClient._start_joern_server`](https://github.com/coms4995-ai4sec/AuditZoo/blob/main/auditzoo/backends/joern/client.py)
  passes the parent process environment straight through to the Joern
  subprocess with no JVM tuning. There is no `-Xss` bump anywhere in the
  control path.
- The very first real query against any freshly-loaded CPG is usually a
  deep one (the per-method `call.map { … callees … }` preload from
  `view.IRView.preload_from_backend`), which is exactly the worst time to
  be compiling extension methods with a cold cache.

### Fix

Three layers, each fully addressable on its own but complementary:

#### (a) JVM stack bump via `JAVA_OPTS` (primary cure)

Joern's launcher (`joern-cli/bin/repl-bridge`) respects `JAVA_OPTS`
(verified by reading lines 260–266 of that script in the installed
distribution). `JoernClient` now composes a `JAVA_OPTS` env value for the
subprocess containing `-Xss<size>` (default `16m`) plus any
`jvm_extra_opts` the caller supplies, without disturbing any pre-existing
`JAVA_OPTS` in the parent environment.

```294:313:auditzoo/backends/joern/client.py
    def _build_server_env(self) -> dict[str, str]:
        """Build the subprocess env for the Joern REPL server.

        Adds ``-Xss<size>`` (and any ``jvm_extra_opts``) to ``JAVA_OPTS`` so
        the Scala 3 compiler has enough stack to resolve deep extension-method
        search trees without tripping "Recursion limit exceeded".
        """
        env = os.environ.copy()
        extra: list[str] = []
        if self.jvm_stack_size:
            extra.append(f"-Xss{self.jvm_stack_size}")
        extra.extend(self.jvm_extra_opts)
        if extra:
            existing = env.get("JAVA_OPTS", "").strip()
            env["JAVA_OPTS"] = (existing + " " + " ".join(extra)).strip()
            logger.debug(
                "Joern JVM JAVA_OPTS set to: %s", env["JAVA_OPTS"],
            )
        return env
```

The knobs are exposed all the way through the config graph:

```13:27:auditzoo/backends/base.py
class JoernConfig(BackendConfig):
    """Configuration for Joern backend."""

    joern_path: str  # Path to Joern installation
    force_create_cpg: bool = False
    host: str = "localhost"
    port: int = 8080
    # JVM tuning for the Joern REPL subprocess.  The Scala 3 compiler that
    # powers the Joern REPL walks a deep extension-method search tree when
    # resolving things like ``cpg.method`` / ``cpg.tag``; on the default 1 MB
    # thread stack this intermittently trips "Recursion limit exceeded"
    # (see https://github.com/scala/scala3/issues/ and Joern issue trackers).
    # Bumping -Xss to 16m has been the recommended mitigation for years.
    jvm_stack_size: str = "16m"
    jvm_extra_opts: list[str] | None = None
```

With env-var overrides (`AUDITZOO_JOERN_XSS`, `AUDITZOO_JOERN_JAVA_OPTS`)
so ops can tune without code changes.

#### (b) Extension-method warm-up in `JoernClient.connect`

After the project is imported and control flow / call graph have been run,
we now force a cheap touch on each `Cpg` extension the later pipeline
actually uses. This primes the Scala 3 compiler's implicit-search cache
while the stack is still shallow, so deeper queries don't pay the
full-search cost under load:

```264:287:auditzoo/backends/joern/client.py
    async def _warm_up_extensions(self) -> None:
        """Touch the common ``Cpg`` extension entry points once.

        The Joern REPL is a Scala 3 compile-then-run loop.  Each fresh
        ``cpg.<member>`` reference forces an extension-method search whose
        intermediate results get cached.  Touching the members we actually
        use early (when the compiler's search depth is small) makes later
        queries either succeed outright or at least be retry-eligible.
        """
        warm_ups = [
            "cpg.method.size",       # used by get_code_units / callees
            "cpg.call.size",         # taint-reachability entry point
            "cpg.file.size",         # used by file-level lookups
            "cpg.tag.size",          # used by get_unit_tags
            "cpg.fieldAccess.size",  # used by source matching
        ]
        for q in warm_ups:
            try:
                await self.query(q)
            except (BackendQueryError, BackendConnectionError) as exc:
                logger.warning(
                    "Joern warm-up query %r failed (continuing): %s", q, exc,
                )
```

This corresponds to the **"wait-for-CPG-ready"** half of the original
diagnosis: once all five warm-ups return normal domain results, we know
the compiler is in a good state and the CPG is fully loaded.

#### (c) One-shot retry on transient compile-error payloads

A safety net for any remaining recursion-limit hits: the Joern REPL
reports compile errors as *successful* RPC responses whose stdout is the
`[E008] Not Found Error` banner (that is why they manifest as
`BackendResponseError` at parse time, not `BackendQueryError` at RPC
time). We now detect that payload shape before parsing and retry once:

```_RECURSION_LIMIT_RE and retry loop in auditzoo/backends/joern/client.py::query```

- Detector matches `Recursion limit exceeded` and the
  `Extension methods were tried, but the search failed with` banner.
- If the payload looks transient we sleep `query_retry_sleep_s` (default
  0.5 s) and retry once.
- If retries are exhausted we return the compiler payload verbatim so the
  upstream `parse_joern_response` still raises `BackendResponseError`
  with the full diagnostic — we never silently swallow real compile
  failures.

### Compared to upstream

In [`coms4995-ai4sec/AuditZoo@main`](https://github.com/coms4995-ai4sec/AuditZoo/tree/main/auditzoo/backends/joern)
the Joern client:

- spawns the JVM with `env=os.environ.copy()` and no JVM tuning;
- has no warm-up phase (`connect()` returns as soon as `importCode` has
  run);
- has no retry wrapper around `query()` — a single transient compile
  error fails the whole iteration.

The fork adds all three pieces without changing the public `JoernClient`
or `JoernBackend` interface: new parameters are keyword-only and all
default to safe values so existing callers continue to work.

### Tests

`tests/test_joern_client_retry.py` adds 10 unit tests that pin the new
behaviour without requiring a running Joern server:

- transient-error detector matches recursion-limit + extension-search
  banner payloads and ignores normal payloads;
- `query()` retries once on transient payloads and succeeds if the retry
  returns a normal result;
- `query()` returns the last (still-bad) payload if retries are
  exhausted, preserving the historical upstream behaviour of letting the
  parser raise;
- `query()` does not retry on normal payloads;
- `query()` still raises `BackendQueryError` on hard RPC failures;
- `_build_server_env` injects `-Xss` and any extras, preserves any
  pre-existing `JAVA_OPTS`, and omits `-Xss` cleanly when disabled.

Total suite: **20 / 20 passing** (10 pre-existing + 10 new).

### End-to-end validation

`scripts/validate_joern_recursion_fix.py` clones `CVE-2023-34540`
(langchain, the exact CVE that first tripped the bug in production),
brings up a Joern backend with the fix applied, and replays the same
query shapes that failed before.

```
probe cpg.method.size           0.06s  →  val res9: Int = 21961
probe cpg.tag.size              0.05s  →  val res10: Int = 18882
probe cpg.call.size             0.05s  →  val res11: Int = 179755
probe cpg.fieldAccess.size      0.07s  →  val res12: Int = 34792
probe cpg.method.id(...).call   0.35s  →  val res14: String = "[]"
probe cpg.tag.filter(...)       0.09s  →  val res15: String = "[]"
RESULT: PASS
```

Before / after on the exact reproducer:

| Query | Upstream behaviour | With this fork |
|---|---|---|
| `cpg.method.size` (warm-up) | compiler can't resolve `cpg.method` | `21 961` in 0.06 s |
| `cpg.call.size` | — | `179 755` in 0.05 s |
| `cpg.tag.size` | — | `18 882` in 0.05 s |
| `cpg.fieldAccess.size` | — | `34 792` in 0.07 s |
| `cpg.method.id(<ID>L).call.map{…}.toJson` | `BackendResponseError: Recursion limit exceeded` | `"[]"` in 0.35 s |
| `cpg.tag.filter(_.name.startsWith("unitfact:")).toJson` | `BackendResponseError: Recursion limit exceeded` | `"[]"` in 0.09 s |
| CPG build (`create_backend → connect`) | crashed after ~222 s | completes in 38.6 s |
| Retries needed | N/A (fatal) | 0 (warm-up alone sufficed) |

The retry wrapper stayed unused on this test — meaning the stack bump
plus warm-up are together sufficient for this repo, and the retry path
is insurance for rarer cases.

---

## Operator knobs (environment variables)

| Variable | Default | Effect |
|---|---|---|
| `AUDITZOO_JOERN_XSS` | `16m` | Value passed as `-Xss<size>` to the Joern JVM. Empty string disables the injection entirely. |
| `AUDITZOO_JOERN_JAVA_OPTS` | `""` | Extra space-separated JVM flags appended to `JAVA_OPTS` after `-Xss`. |
| `AUDITZOO_SKIP_PRELOAD_CALLS` | `"1"` when the eval harness selects the Joern arm (use `--ir-preload` or set the variable explicitly to override) | Skip the O(n_methods) IR call-graph preload. Safe for the CWE-78 `JoernArm` since it queries the backend directly. |
| `AUDITZOO_SKIP_PRELOAD_FACTS` | `"1"` when the eval harness selects the Joern arm (use `--ir-preload` or set the variable explicitly to override) | Skip the per-unit facts preload. |

---

## Files changed in this fork

Pipeline harness (crash containment):

- `scripts/run_evaluation.py` — UTF-8-tolerant `count_loc`, per-CVE
  try/except/finally isolation, error-row persistence.

Joern backend (recursion-limit mitigation):

- `auditzoo/backends/base.py` — `JoernConfig.jvm_stack_size`,
  `JoernConfig.jvm_extra_opts` with env-var overrides.
- `auditzoo/backends/joern/backend.py` — propagate JVM config into
  `JoernClient`.
- `auditzoo/backends/joern/client.py` — `_build_server_env`,
  `_warm_up_extensions`, transient-compile-error detector and one-shot
  retry in `query()`.

Tests + validation:

- `tests/test_joern_client_retry.py` — 10 new unit tests.
- `scripts/validate_joern_recursion_fix.py` — end-to-end validator
  reproducing the exact langchain / CVE-2023-34540 failure mode.

---

## Recommended next sweep

1. Confirm port 12345 is free and vLLM is healthy.
2. Re-run `scripts/run_evaluation.py` with the default dataset and arms
   `semgrep joern`. The Joern arm should now produce non-zero candidate
   counts on large repos.
3. If specific large repos still time out on the 900 s per-CVE budget,
   set `AUDITZOO_SKIP_PRELOAD_CALLS=1` to defer the call-graph preload —
   the CWE-78 `JoernArm` queries the backend directly and does not
   consult the IR call-graph cache, so this is a safe speed-up for this
   study.
4. If a future Joern / Scala 3 upgrade changes the REPL diagnostic text,
   extend `_looks_like_transient_compile_error` in
   `auditzoo/backends/joern/client.py` accordingly (the detector is
   string-based on purpose — Scala compiler output is not structured).

---

## CPG cache and phase timings (`joernTimeoutDebug` branch)

When per-CVE Joern runs exceed the wall-clock budget (the default is
`--per-cve-timeout 900.0`, and even 1800s was insufficient on the largest
repos), the dominant cost is always CPG construction. The
`joernTimeoutDebug` branch adds three pieces of instrumentation so ops
can (a) diagnose which sub-phase is the culprit and (b) avoid paying that
cost twice for the same checkout.

### 1. Per-phase CPG build timing + RSS

`JoernClient.connect` now records every sub-phase into
`client.last_connect_timings` (floats, seconds) and `client.last_connect_rss`
(ints, bytes) and the pipeline surfaces both under
`metrics.cpg_phase_s` / `metrics.cpg_rss_bytes` on the Joern arm's k=0
iteration. The keys are:

- `switch_workspace_s`, `project_exists_check_s`, `import_code_s`
- `overlay_<name>_s` for every entry in `run_overlays` (default
  `["controlflow", "callgraph"]`)
- `warmup_s`, `total_connect_s`
- `cache_hit: bool`
- `overlays: list[str]` — the exact list of overlays run

RSS samples are taken at phase boundaries and a running `peak_bytes` is
kept. Look for the single INFO line emitted per arm iteration:

```
[CVE-XXXX-YYYY | joern k=0] cpg_phases import=42.10s overlays={'controlflow': 318.4, 'callgraph': 12.9} warmup=1.2s total=375.6s cache_hit=False rss_peak=7482.3MiB
```

If `import_code_s` dominates, focus on shrinking the input tree (drop
vendored deps, pin `language` instead of `auto`). If
`overlay_controlflow_s` dominates on a Python repo, that's the type
recovery pass — consider dropping it via `AUDITZOO_JOERN_OVERLAYS=callgraph`
for taint-reachability queries that don't need types.

Failed connects (timeout or exception before `__aenter__` returns) now
also surface whatever partial `cpg_phase_s` was recorded; this is
exactly what you want when diagnosing the 1800s timeouts — the
phase-in-flight is visible on the `cpg_build_failed` iteration.

### 2. Configurable overlay passes

`JoernBackend.connect` now forwards a `run_overlays` list through to the
client. The default preserves existing behaviour. Overlay names are
validated against
`{"controlflow", "callgraph", "dataflow", "typerelations"}`; anything
else raises `BackendConnectionError` so typos don't silently skip work.

Env override: `AUDITZOO_JOERN_OVERLAYS` accepts comma- or
whitespace-separated names. An explicit empty string means "no overlays".

### 3. CPG cache keyed on `<cve_id>_<git_sha[:12]>`

`run_evaluation.py` now captures `git rev-parse HEAD` from the freshly
checked-out repo and threads it through `Pipeline.run(..., git_sha=)`.
The Joern arm builds `JoernConfig.cpg_cache_key = make_cpg_cache_key(
cve_id, git_sha)` which points Joern's workspace at the shared cache dir
so the existing `workspace.projects.exists(...)` branch in `JoernClient`
skips both `importCode` and every overlay pass on re-run.

Cache correctness:

- A sidecar `<cache>/<project>/_auditzoo_meta.json` records the
  `run_overlays` that were used. A mismatch forces a rebuild.
- An advisory `fcntl.flock` on `<cache>/<project>.lock` serialises
  concurrent workers importing the same SHA so two JVMs never race on
  the same CPG directory.
- `--cpg-cache-max-gb` prunes oldest-by-mtime project entries at startup
  until the tree is under the configured budget.

### New operator knobs

| Variable / flag | Default | Effect |
|---|---|---|
| `AUDITZOO_JOERN_OVERLAYS` | unset | Comma/space-separated overlay list. Empty = no overlays. |
| `AUDITZOO_CPG_CACHE_DIR` | `~/.cache/auditzoo/joern_cpgs` | Shared Joern workspace for cached CPGs. |
| `AUDITZOO_JOERN_GC_LOG` | unset | If set to a directory, wires `-Xlog:gc*,safepoint:file=<dir>/joern-gc-%t.log` into `JAVA_OPTS` so timed-out builds can be confirmed as heap thrash. |
| `--cpg-cache-dir` | env / default | Per-run override for the cache dir. |
| `--no-cpg-cache` | off | Disable the cache entirely (clean baseline / ablation). |
| `--cpg-cache-max-gb` | `50.0` | Best-effort size budget for the cache, pruned at startup. `0` disables pruning. |

### Recommended triage order when a CVE still times out

1. Read `metrics.cpg_phase_s` on the failing iteration. Whichever
   `overlay_<name>_s` is closest to the budget is your culprit.
2. Check `metrics.cpg_rss_bytes.peak_bytes`. If it's close to your
   `-Xmx`, raise heap via
   `AUDITZOO_JOERN_JAVA_OPTS="-Xmx32g -XX:+UseG1GC"`.
3. Enable `AUDITZOO_JOERN_GC_LOG=/tmp/joern-gc` and re-run the same CVE.
   A GC% > ~30% confirms heap thrash, not a hung pass.
4. If the import itself is slow, prune input (exclude vendored deps) and
   pin `language` instead of `auto`.
5. Only after (1)–(4) does a larger machine help, and even then the
   missing resource is RAM, not CPU.

### Lazy `pre_define.sc` load (follow-up fix)

The first 10-CVE smoke on this branch showed a large "hidden" gap
between `cpg_build_s` (measured by the pipeline around
`AnalysisRuntime.__aenter__`) and `client.last_connect_timings["total_connect_s"]`
(measured inside `JoernClient.connect`). One suspected contributor was
`_load_pre_defined_scripts` — a single `query_raw(pre_define.sc)`
fired at the end of `JoernBackend.connect` — because the cwe78_study
pipeline **never calls the one helper it defines**
(`minimalCoveringNodeInfo`, reached only from
`get_code_unit_by_location` → `IrStorageAgent._handle_fetch_unit`).

`JoernBackend.connect` / `reload` no longer ship the script eagerly.
Instead:

- `JoernBackend.__init__` seeds `self._pre_define_loaded = False` and a
  per-instance `asyncio.Lock`.
- `get_code_unit_by_location` calls `await
  self._ensure_pre_defined_loaded()` before referencing
  `minimalCoveringNodeInfo`. The guard is double-checked under the lock
  so concurrent first-time callers trigger exactly one compile.
- `connect`, `disconnect`, and `reload` all reset
  `self._pre_define_loaded = False`, because each of them produces a
  fresh JVM session in which the helper is no longer defined.

Tests in `tests/test_joern_pre_define_lazy.py` lock down: no eager
load from `connect`/`reload`, lazy load on first demand, idempotence,
concurrent serialisation, and flag reset on `disconnect`/`reload`.

**Impact correction (post-second smoke).** This fix alone did *not*
close the hidden-phase gap: on the first CVE of the follow-up smoke
the gap was still ~42 s, essentially unchanged. The real dominant
cost is documented in the next section. The lazy load still matters
for correctness (callers that *do* use `fetch_unit` now pay for
`pre_define.sc` exactly once, on first demand) and it stays on the
critical path, it just is not the headline win.

### IRView preload is the real hidden phase

`AnalysisRuntime.initialize` calls `IRView.create(backend)` which in
turn calls `IRView.preload_from_backend`. That method runs four
backend-round-trip chunks before control returns to the pipeline:

1. `get_all_units_by_kind(Function, fetch_backend=True)`
2. `get_all_units_by_kind(File, fetch_backend=True)`
3. `get_all_relations_by_kind(Calls, fetch_backend=True)` — **O(n_methods)**,
   the dominant cost on any non-trivial repo
4. `load_facts()` — per-unit facts preload

Step (3) alone is what scales with repo size: the second smoke
measured the gap at `~44 s` on a 1 k-LoC repo (lookatme) and `~450 s`
on the 25 kLoC bikeshed outlier. The CWE-78 Joern arm queries the
backend directly via `JoernArm.scan` and never reads
`IRView.get_all_relations_by_kind(Calls)` or per-unit facts, so
skipping both preloads is functionally safe — a property the existing
`AUDITZOO_SKIP_PRELOAD_CALLS` / `AUDITZOO_SKIP_PRELOAD_FACTS`
docstrings on `IRView.preload_from_backend` already spell out.

#### What the harness now does

`scripts/run_evaluation.py` now applies both skip knobs by default
whenever the Joern arm is selected:

```python
if "joern" in args.arms and not args.ir_preload:
    for key in ("AUDITZOO_SKIP_PRELOAD_CALLS", "AUDITZOO_SKIP_PRELOAD_FACTS"):
        os.environ.setdefault(key, "1")
```

`os.environ.setdefault` means an operator's explicit
`AUDITZOO_SKIP_PRELOAD_* = 0` (or any other value) still wins, and the
new `--ir-preload` CLI flag re-enables the preload for the rare case
where a downstream consumer of the `IRView` is added and needs it.
The eval log prints which mode was selected.

#### Measured before / after (same 10 CVEs, fresh CPG cache, `--per-cve-timeout 600` for A/B, otherwise identical)

| Metric (avg over CVEs that finished in both runs) | Baseline | With preload-skip | Δ |
|---|---:|---:|---:|
| `cpg_build_s` | 142.0 s | 20.7 s | **−6.8×** |
| hidden = `cpg_build_s − total_connect_s` | 120.3 s | 1.0 s | **−99%** |
| `rss_peak` (per-CPG) | `1.5 MiB` (bug) | ~0.9–9.0 GiB (real) | fixed |
| CVEs hitting the 600 s CPG budget | 4 / 10 | 1 / 10 (LLM triage, not CPG) | **−75%** |

The `rss_peak` delta is orthogonal: the old `1.5 MiB` reading was a
PID-tree sampling bug in `_sample_rss` (the `joern` launcher is a
shell wrapper, so `psutil.Process(pid).memory_info().rss` never saw
the JVM). It is now fixed to walk the process tree.

#### Operator knobs added in this step

| Variable / flag | Default | Effect |
|---|---|---|
| `--ir-preload` | off | Re-enable `IRView.preload_from_backend` for the Joern arm. Default-off because the CWE-78 pipeline does not consume the preloaded structures. |
| `AUDITZOO_SKIP_PRELOAD_CALLS` | `1` when `--arms joern` and not `--ir-preload`, else `""` | Already-existing upstream knob; the harness now sets it via `os.environ.setdefault`. |
| `AUDITZOO_SKIP_PRELOAD_FACTS` | `1` when `--arms joern` and not `--ir-preload`, else `""` | Already-existing upstream knob; same plumbing. |

Default `--per-cve-timeout` stays at **900 s** — that is the budget
the second smoke was sized against (largest CPG build + triage came in
at ~85 s; triage outliers can still hit a few hundred seconds, which
is why the budget is not shrunk further).
