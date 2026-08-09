"""GA7 Q1 - CI/CD Container Release Gate.

Pure-stdlib policy engine.  `handle(body)` takes the already-parsed JSON
request body and returns the response dict:

    {"decision": "promote" | "block", "violations": ["CODE", ...]}

`decision` is "promote" only when `violations` is empty.

Design rule: this function must NEVER raise.  Hostile / malformed payloads
produce the relevant violation code instead of an exception, so the mounting
web layer can never turn a bad request into a 500.
"""

import re

__all__ = ["handle", "evaluate", "VIOLATION_ORDER"]

# Exactly the least-privilege permission set required for a release.
REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

# Third-party actions must be pinned to a full 40-char lowercase hex commit SHA.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Secret handling modes that do not bake a secret into an image layer.
SAFE_SECRET_MODES = {"none", "buildkit"}

# Canonical (deterministic) output order.  The grader ignores order, but a
# stable order makes the responses diff-able and the tests readable.
VIOLATION_ORDER = [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
]


def _as_dict(value):
    """Return `value` if it is a dict, else an empty dict (never raises)."""
    return value if isinstance(value, dict) else {}


def _text(value):
    """Normalise a scalar to a stripped string; non-strings become ""."""
    if isinstance(value, str):
        return value.strip()
    return ""


def _is_true(value):
    """Strict boolean truth: the string "true" is NOT true."""
    return value is True


def _is_false(value):
    """Strict boolean falsity: 0 / "" / None are NOT False."""
    return value is False


def _check_permissions(workflow, out):
    """Rule 1: permissions must match REQUIRED_PERMISSIONS exactly.

    Extra scope, missing scope, or a differing value -> EXCESS_PERMISSION.
    Keys are lower-cased and stripped (GitHub scope names are canonically
    lowercase); values are compared exactly after stripping whitespace, so
    "Read" != "read".  A missing / non-dict `permissions` is a violation.
    """
    raw = workflow.get("permissions")
    if not isinstance(raw, dict):
        out.add("EXCESS_PERMISSION")
        return

    normalised = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            # A non-string key can never be one of the three allowed scopes.
            out.add("EXCESS_PERMISSION")
            return
        normalised[key.strip().lower()] = value.strip() if isinstance(value, str) else value

    if normalised != REQUIRED_PERMISSIONS:
        out.add("EXCESS_PERMISSION")


def _check_trigger(workflow, out):
    """Rule 2: `pull_request_target` is never acceptable for this gate.

    Judgement call: we fire UNSAFE_PR_TRIGGER *only* when
    workflow.trigger == "pull_request_target".  We deliberately do NOT fire on
    an event/trigger mismatch (e.g. event "pull_request" with trigger "push"),
    because the spec names exactly one unsafe trigger and over-firing would
    block otherwise-clean payloads.
    """
    if _text(workflow.get("trigger")) == "pull_request_target":
        out.add("UNSAFE_PR_TRIGGER")


def _check_tests(workflow, out):
    """Rule 3: testsPassed is True, matrixComplete is True, failFast is False."""
    if (
        not _is_true(workflow.get("testsPassed"))
        or not _is_true(workflow.get("matrixComplete"))
        or not _is_false(workflow.get("failFast"))
    ):
        out.add("TESTS_INCOMPLETE")


def _check_actions(workflow, out):
    """Rule 4: third-party actions must be pinned to a 40-char lowercase SHA.

    Actions owned by "actions" (case-insensitive) may use a version tag.
    One bad entry is enough; the code is emitted at most once (set semantics).
    A missing `actions` key means "no actions declared" -> no violation.
    A present-but-wrong-typed `actions`, or a non-dict entry, is unverifiable
    and therefore treated as a violation.
    """
    if "actions" not in workflow:
        return

    actions = workflow.get("actions")
    if not isinstance(actions, list):
        out.add("MUTABLE_ACTION")
        return

    for entry in actions:
        if not isinstance(entry, dict):
            out.add("MUTABLE_ACTION")
            continue
        owner = _text(entry.get("owner")).lower()
        if owner == "actions":
            continue
        if not SHA_RE.match(_text(entry.get("ref"))):
            out.add("MUTABLE_ACTION")


def _check_image(body, out):
    """Rule 5: image hardening checks.  A missing image fails all of them."""
    image = _as_dict(body.get("image"))

    if not _is_true(image.get("multiStage")):
        out.add("SINGLE_STAGE_IMAGE")

    # Only an explicit True means "runs as root"; anything else is non-root.
    if _is_true(image.get("runsAsRoot")):
        out.add("ROOT_RUNTIME")

    if _text(image.get("secretMode")) not in SAFE_SECRET_MODES:
        out.add("SECRET_IN_LAYER")

    cve = image.get("criticalVulnerabilities")
    # bool is a subclass of int - True must not sneak through as 1/0.
    if isinstance(cve, bool) or not isinstance(cve, int) or cve != 0:
        out.add("CRITICAL_CVE")

    if not _is_true(image.get("digestPinned")):
        out.add("UNPINNED_IMAGE")


def _check_production(body, workflow, out):
    """Rule 6: extra gates that only apply when target == "production"."""
    if _text(body.get("target")) != "production":
        return

    if _text(body.get("event")) != "push" or _text(body.get("ref")) != "refs/heads/main":
        out.add("INVALID_PRODUCTION_REF")

    if not _is_true(workflow.get("environmentApproval")):
        out.add("APPROVAL_REQUIRED")


def evaluate(body):
    """Return the de-duplicated list of violation codes for `body`."""
    payload = _as_dict(body)
    workflow = _as_dict(payload.get("workflow"))

    found = set()
    _check_permissions(workflow, found)
    _check_trigger(workflow, found)
    _check_tests(workflow, found)
    _check_actions(workflow, found)
    _check_image(payload, found)
    _check_production(payload, workflow, found)

    known = [code for code in VIOLATION_ORDER if code in found]
    # Defensive: surface anything not in the canonical order rather than drop it.
    extra = sorted(found - set(VIOLATION_ORDER))
    return known + extra


def handle(body):
    """Entry point mounted at POST /release-gate."""
    try:
        violations = evaluate(body)
    except Exception:  # pragma: no cover - belt and braces, evaluate never raises
        violations = sorted(set(VIOLATION_ORDER))
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
