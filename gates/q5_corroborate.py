"""GA7 Q5 - OSINT Corroboration Engine.

Pure-stdlib evidence engine.  `handle(body)` takes the already-parsed JSON
request body and returns the response dict:

    {"verdict": "supported" | "contradicted" | "unverified" | "invalid",
     "confidence": "high" | "medium" | "low",
     "corroboratingSources": ["s1", "s2"]}

Design rules:
  * NEVER read the wall clock.  Every freshness decision comes from the
    caller-supplied `asOf`; there is no datetime.now / utcnow / time.time in
    this module.  That keeps the endpoint deterministic and replayable.
  * NEVER raise.  Hostile / malformed payloads produce the "invalid" response
    so the mounting web layer can never turn a bad request into a 500.

The assigned subject for this deployment is "gbcrga.example".  No decision
rule keys off the subject, so this module deliberately does NOT filter on it -
a claim about any subject is evaluated with the same rules.
"""

from datetime import datetime, timezone

__all__ = ["handle", "evaluate", "SOURCE_TYPES"]

# The only source types that carry evidentiary weight.  Anything else means
# the whole source record is ignored.
SOURCE_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

_INVALID = {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}
_UNVERIFIED = {"verdict": "unverified", "confidence": "low", "corroboratingSources": []}


def _parse_ts(value):
    """Parse an ISO-8601 timestamp string, or return None.

    Accepts a trailing "Z" (Python < 3.11 cannot, so it is rewritten to
    "+00:00" first) and explicit offsets such as "+05:30".  A naive timestamp
    (no offset at all) is assumed to be UTC: mixing naive and aware datetimes
    would otherwise raise on subtraction, and rejecting them outright would be
    harsher than the spec asks for.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _is_number(value):
    """True for int/float but NOT for bool (bool is a subclass of int)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _valid_sources(raw):
    """Keep only well-formed source records.

    A source counts only when it is a dict, its id / origin / value /
    observedAt are all strings, and its type is one of SOURCE_TYPES.
    Everything else is ignored ENTIRELY - it neither supports nor
    contradicts.  `authoritative` is optional and defaults to False; only a
    literal True marks a source as authoritative.
    """
    kept = []
    if not isinstance(raw, list):
        return kept
    for item in raw:
        if not isinstance(item, dict):
            continue
        if not all(isinstance(item.get(key), str) for key in ("id", "origin", "value", "observedAt")):
            continue
        if item.get("type") not in SOURCE_TYPES:
            continue
        kept.append(item)
    return kept


def _is_fresh(source, as_of, staleness_days):
    """True when asOf - observedAt <= stalenessDays.

    Judgement call: an `observedAt` that is a string but not parseable as
    ISO-8601 fails the spirit of the "valid source" test, so it is treated as
    not fresh - i.e. the record is ignored rather than trusted.

    A source observed AFTER `asOf` yields a negative delta, and "<=" holds, so
    future observations are considered fresh.  That is deliberate: a clock
    skew of a few seconds should not silently discard live evidence.
    """
    observed = _parse_ts(source.get("observedAt"))
    if observed is None:
        return False
    return (as_of - observed).total_seconds() / 86400.0 <= staleness_days


def evaluate(body):
    """Apply the decision rules in their required order."""
    # -- Rule 1: structural validation -----------------------------------
    if not isinstance(body, dict):
        return _INVALID

    claim = body.get("claim")
    claim_value = claim.get("value") if isinstance(claim, dict) else None
    if not isinstance(claim_value, str):
        return _INVALID

    as_of = _parse_ts(body.get("asOf"))
    if as_of is None:
        return _INVALID

    staleness_days = body.get("stalenessDays")
    if not _is_number(staleness_days):
        return _INVALID

    if not isinstance(body.get("sources"), list):
        return _INVALID

    # Malformed records drop out before any verdict logic runs.
    sources = _valid_sources(body.get("sources"))
    fresh = [s for s in sources if _is_fresh(s, as_of, staleness_days)]

    # -- Rule 2: authoritative contradiction ------------------------------
    # Only FRESH + authoritative + differing value contradicts.  A stale
    # authoritative disagreement is already gone (it never entered `fresh`),
    # and a non-authoritative disagreement is simply not counted at all.
    # Origin de-duplication does NOT apply here: every contradicting id is
    # reported.  Value comparison is exact string equality - IPs, hashes and
    # CT-log identifiers are case-sensitive in practice, so no normalisation.
    contradicting = sorted(
        s["id"] for s in fresh if s.get("authoritative") is True and s["value"] != claim_value
    )
    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contradicting,
        }

    # -- Rule 3: independent corroboration --------------------------------
    # Keep fresh agreeing sources, then collapse each origin to ONE
    # representative: the record with the lexicographically smallest id.
    # Same origin == mirrors of one another, so they count once.
    representatives = {}
    for source in fresh:
        if source["value"] != claim_value:
            continue
        origin = source["origin"]
        current = representatives.get(origin)
        if current is None or source["id"] < current["id"]:
            representatives[origin] = source

    if len(representatives) >= 2:
        chosen = list(representatives.values())
        types = {s["type"] for s in chosen}
        return {
            "verdict": "supported",
            "confidence": "high" if len(types) >= 2 else "medium",
            "corroboratingSources": sorted(s["id"] for s in chosen),
        }

    # -- Rule 4: everything else ------------------------------------------
    # No sources, one independent source, mirrors of a single origin, or
    # agreement that is entirely stale.
    return _UNVERIFIED


def handle(body):
    """Entry point mounted at POST /corroborate."""
    try:
        result = evaluate(body)
    except Exception:  # pragma: no cover - evaluate is written not to raise
        result = _INVALID
    # Copy so a caller mutating the response cannot poison the constants.
    return {
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "corroboratingSources": list(result["corroboratingSources"]),
    }
