"""Catalog sanitization helpers for Joern source/sink/sanitizer entries.

The Joern arm builds a regex of the form ``(?s)^(<sink_1>|<sink_2>|...)\\(.*``
to filter ``call.code`` for sinks (and an analogous regex for sources).
LLM-generated catalog entries occasionally contain regex metacharacters
(``(``, ``[``, ``$``, etc.) or Python comment fragments (``# notes``),
which break pattern compilation and produce::

    PatternSyntaxException: Unclosed group near index 217

at Joern query time and zero findings for the rest of the run.

This module enforces a single normalization contract for catalog entries:

* Strip whitespace and any trailing comment after ``#``.
* Strip any trailing ``(`` / parameter list (``"os.system(cmd"``).
* Reject anything that is not a *dotted Python identifier*
  (``[A-Za-z_][\\w]*(\\.[A-Za-z_][\\w]*)*``).
* Deduplicate while preserving order.

The same cleaner is used at *seed parse* time (so we drop garbage as
early as possible and the audit fingerprint reflects what the analysis
actually used) and inside :class:`JoernArm` (defence-in-depth: even a
manually-injected catalog from ``PipelineConfig`` is sanitised before
entering the regex builder).
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# A single "Python module path" segment must look like an identifier
# (letters, digits, underscore, not starting with a digit).  Joern's
# Python frontend stores both unqualified call names ("system") and
# attribute-access reads ("request.args"), so we accept any number of
# dot-separated segments.
_DOTTED_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*$")


def clean_catalog_entry(raw: str) -> str | None:
    """Normalise *raw* to a dotted-identifier string or return ``None``.

    The returned value (when non-``None``) is guaranteed to:

    * match :data:`_DOTTED_IDENT_RE`;
    * contain no regex metacharacters; and therefore
    * be safe to ``re.escape`` and join into a Joern ``code`` filter.
    """
    if not isinstance(raw, str):
        return None

    # Drop trailing line/block comments and surrounding whitespace.
    # ``parse_joern_seed_catalog`` previously accepted entries like
    # ``"subprocess.run  # OS_COMMAND"`` which then exploded the regex.
    candidate = raw.split("#", 1)[0].strip()

    # Strip parameter-list noise: an LLM that thought it was writing
    # Python source may emit ``"os.system(cmd"`` or ``"shlex.quote("``.
    # Keep only the receiver up to the first paren / square bracket /
    # comma / whitespace.
    for terminator in ("(", "[", "<", ",", " ", "\t"):
        if terminator in candidate:
            candidate = candidate.split(terminator, 1)[0]

    candidate = candidate.strip().strip(".")
    if not candidate:
        return None

    if not _DOTTED_IDENT_RE.match(candidate):
        return None

    return candidate


def sanitize_catalog(
    entries: list[str] | None,
    *,
    label: str = "catalog",
) -> tuple[list[str], list[str]]:
    """Normalise a catalog list, returning ``(kept, dropped)``.

    Order is preserved and duplicates are removed.  ``dropped`` contains
    the *original* strings (not the cleaned form) so callers can log
    actionable diagnostics.
    """
    kept: list[str] = []
    dropped: list[str] = []
    seen: set[str] = set()

    for entry in entries or []:
        cleaned = clean_catalog_entry(entry) if isinstance(entry, str) else None
        if cleaned is None:
            dropped.append(str(entry))
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        kept.append(cleaned)

    if dropped:
        logger.warning(
            "Dropped %d invalid %s entr%s: %s",
            len(dropped),
            label,
            "y" if len(dropped) == 1 else "ies",
            dropped[:5] + (["..."] if len(dropped) > 5 else []),
        )

    return kept, dropped
