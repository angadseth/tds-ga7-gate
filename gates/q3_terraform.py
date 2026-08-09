"""TDS GA7 Q3 - Terraform Plan Policy Gate.

Pure stdlib. Mounted at POST /terraform/plan.

Rules are evaluated in the fixed order below and the FIRST failure wins:
  1 INVALID_PLAN         - shape/type validation
  2 ENVIRONMENT_MISMATCH - environment != prod workspace
  3 STATE_UNSAFE         - bad backend or unlocked state
  4 UNPINNED_PROVIDER    - provider version not exactly/pessimistically pinned
  5 MISSING_LABELS       - required labels absent or wrong value
  6 PLAINTEXT_SECRET     - secret is not null and not a secret:// reference
  7 DELETE_NOT_APPROVED  - destructive delete without destroyApproved
  8 FORCE_DESTROY        - production storage_bucket with forceDestroy
"""

import re
import variant

PROD_ENVIRONMENT = "prod-loqe15"

REQUIRED_LABELS = {
    "owner": "student-l75qy",
    "environment": "production",
    "cost_center": "cc-pomc",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
DESTRUCTIVE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

SECRET_PREFIX = "secret://"

# Optional "=" (with optional space) followed by a full semver X.Y.Z.
_EXACT_RE = re.compile(r"^=?\s*\d+\.\d+\.\d+$")
# "~>" (optional space) followed by X.Y or X.Y.Z.
_PESSIMISTIC_RE = re.compile(r"^~>\s*\d+\.\d+(\.\d+)?$")

_APPROVE = {"decision": "approve", "reason": "APPROVE"}


def _reject(reason):
    return {"decision": "reject", "reason": reason}


def _is_bool(value):
    return isinstance(value, bool)


def _is_str(value):
    # bool is not an int here, but guard strings only; keeps intent explicit.
    return isinstance(value, str)


def _valid_shape(body):
    """Rule 1: every documented key must be present with the documented type."""
    if not isinstance(body, dict):
        return False

    if not _is_str(body.get("environment")):
        return False

    state = body.get("state")
    if not isinstance(state, dict):
        return False
    if not _is_str(state.get("backend")) or not _is_bool(state.get("locked")):
        return False

    if not _is_str(body.get("providerVersion")):
        return False
    if not _is_bool(body.get("destroyApproved")):
        return False

    resource = body.get("resource")
    if not isinstance(resource, dict):
        return False
    if not _is_str(resource.get("address")):
        return False
    if not _is_str(resource.get("type")):
        return False
    action = resource.get("action")
    if not _is_str(action) or action not in ALLOWED_ACTIONS:
        return False

    labels = resource.get("labels")
    if not isinstance(labels, dict):
        return False
    for key, value in labels.items():
        if not _is_str(key) or not _is_str(value):
            return False

    # Judgement call: secret is explicitly nullable, so an absent key is
    # treated as null rather than as a missing required key.
    secret = resource.get("secret", None)
    if secret is not None and not _is_str(secret):
        return False

    if not _is_bool(resource.get("forceDestroy")):
        return False

    return True


def _provider_pinned(raw):
    """Rule 4: exact ("6.2.1" / "= 6.2.1") or pessimistic ("~> 6.0") only."""
    version = raw.strip()
    if not version:
        return False
    if "latest" in version.lower():
        return False
    # Checked before the operator blocklist below, since "~>" contains ">".
    if _PESSIMISTIC_RE.match(version):
        return True
    # Ranges, wildcards and comma-joined constraints are never a pin.
    for bad in (">=", "<=", ">", "<", "!=", "*", ","):
        if bad in version:
            return False
    return bool(_EXACT_RE.match(version))


def handle(body):
    try:
        # Rule 1 - shape/type validation.
        if not _valid_shape(body):
            return _reject("INVALID_PLAN")

        resource = body["resource"]

        # Rule 2 - production workspace only.
        if body["environment"] != variant.get("environment", PROD_ENVIRONMENT):
            return _reject("ENVIRONMENT_MISMATCH")

        # Rule 3 - remote, locked state.
        state = body["state"]
        if state["backend"] not in ALLOWED_BACKENDS or state["locked"] is not True:
            return _reject("STATE_UNSAFE")

        # Rule 4 - pinned provider.
        if not _provider_pinned(body["providerVersion"]):
            return _reject("UNPINNED_PROVIDER")

        # Rule 5 - required labels.
        # Judgement call: the spec says all three assigned labels must be
        # PRESENT with exact values; it never forbids additional labels, so
        # extra labels are accepted rather than treated as a violation.
        labels = resource["labels"]
        for key, value in variant.get("labels", REQUIRED_LABELS).items():
            if labels.get(key) != value:
                return _reject("MISSING_LABELS")

        # Rule 6 - secrets by reference only.
        secret = resource.get("secret")
        if secret is not None:
            if not secret.startswith(SECRET_PREFIX):
                return _reject("PLAINTEXT_SECRET")
            if not secret[len(SECRET_PREFIX):].strip():
                return _reject("PLAINTEXT_SECRET")

        # Rule 7 - destructive deletes need approval.
        if resource["action"] == "delete" and resource["type"] in DESTRUCTIVE_TYPES:
            if body["destroyApproved"] is not True:
                return _reject("DELETE_NOT_APPROVED")

        # Rule 8 - production buckets may never force-destroy.
        # Environment was already pinned to the production workspace by rule 2,
        # so anything reaching here is production.
        if resource["type"] == "storage_bucket" and resource["forceDestroy"] is True:
            return _reject("FORCE_DESTROY")

        return dict(_APPROVE)
    except Exception:
        return _reject("INVALID_PLAN")
