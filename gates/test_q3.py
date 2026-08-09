"""Plain-assert tests for q3_terraform.handle. Run: python test_q3.py"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from q3_terraform import handle  # noqa: E402

BASE = {
    "environment": "prod-loqe15",
    "state": {"backend": "gcs", "locked": True},
    "providerVersion": "~> 6.0",
    "destroyApproved": False,
    "resource": {
        "address": "google_storage_bucket.data",
        "type": "storage_bucket",
        "action": "create",
        "labels": {
            "owner": "student-l75qy",
            "environment": "production",
            "cost_center": "cc-pomc",
        },
        "secret": None,
        "forceDestroy": False,
    },
}


def plan(**overrides):
    body = copy.deepcopy(BASE)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(body.get(key), dict):
            body[key].update(value)
        else:
            body[key] = value
    return body


def check(body, reason, label):
    got = handle(body)
    expected_decision = "approve" if reason == "APPROVE" else "reject"
    assert got == {"decision": expected_decision, "reason": reason}, (
        "%s: expected %s/%s, got %r" % (label, expected_decision, reason, got)
    )


# --- happy paths -----------------------------------------------------------
check(plan(), "APPROVE", "valid create")
check(plan(resource={"action": "update"}), "APPROVE", "valid update")
check(
    plan(resource={"action": "delete"}, destroyApproved=True),
    "APPROVE",
    "approved delete",
)
check(
    plan(resource={"type": "compute_instance", "action": "delete"}),
    "APPROVE",
    "delete of non-destructive type needs no approval",
)
check(
    plan(resource={"secret": "secret://db/password"}),
    "APPROVE",
    "secret reference",
)

# --- rule 1: INVALID_PLAN --------------------------------------------------
check(None, "INVALID_PLAN", "body is None")
check("not-a-dict", "INVALID_PLAN", "body is a string")
check([], "INVALID_PLAN", "body is a list")
check({}, "INVALID_PLAN", "body is empty")
check(plan(environment=123), "INVALID_PLAN", "environment not a string")
check(plan(state="gcs"), "INVALID_PLAN", "state not a dict")
check(plan(state={"locked": "true"}), "INVALID_PLAN", "locked not a boolean")
check(plan(state={"backend": None}), "INVALID_PLAN", "backend not a string")
check(plan(providerVersion=6.21), "INVALID_PLAN", "providerVersion not a string")
check(plan(destroyApproved="yes"), "INVALID_PLAN", "destroyApproved not a boolean")
check(plan(resource=None), "INVALID_PLAN", "resource not a dict")
check(plan(resource={"address": 7}), "INVALID_PLAN", "address not a string")
check(plan(resource={"type": None}), "INVALID_PLAN", "type not a string")
check(plan(resource={"action": "destroy"}), "INVALID_PLAN", "action not in enum")
check(plan(resource={"labels": []}), "INVALID_PLAN", "labels not a dict")
check(
    plan(resource={"labels": dict(BASE["resource"]["labels"], owner=1)}),
    "INVALID_PLAN",
    "label value not a string",
)
check(plan(resource={"secret": 42}), "INVALID_PLAN", "secret neither null nor string")
check(plan(resource={"forceDestroy": "false"}), "INVALID_PLAN", "forceDestroy not bool")

_missing = plan()
del _missing["state"]
check(_missing, "INVALID_PLAN", "missing state key")

_missing = plan()
del _missing["resource"]["forceDestroy"]
check(_missing, "INVALID_PLAN", "missing forceDestroy key")

# Type validation runs before everything, even a wrong environment.
check(
    plan(environment=None, state={"backend": "ftp"}),
    "INVALID_PLAN",
    "bad type beats bad environment",
)

# --- rule 2: ENVIRONMENT_MISMATCH -----------------------------------------
check(plan(environment="dev-loqe15"), "ENVIRONMENT_MISMATCH", "wrong environment")
check(plan(environment="PROD-LOQE15"), "ENVIRONMENT_MISMATCH", "case-sensitive match")
check(plan(environment=""), "ENVIRONMENT_MISMATCH", "empty environment")
check(
    plan(environment="staging", state={"backend": "ftp", "locked": False}),
    "ENVIRONMENT_MISMATCH",
    "environment beats state",
)

# --- rule 3: STATE_UNSAFE --------------------------------------------------
for backend in ("gcs", "s3", "azurerm", "remote"):
    check(plan(state={"backend": backend}), "APPROVE", "backend %s allowed" % backend)
check(plan(state={"backend": "local"}), "STATE_UNSAFE", "local backend")
check(plan(state={"backend": ""}), "STATE_UNSAFE", "empty backend")
check(plan(state={"backend": "GCS"}), "STATE_UNSAFE", "backend is case-sensitive")
check(plan(state={"locked": False}), "STATE_UNSAFE", "state not locked")
check(
    plan(state={"backend": "local"}, providerVersion="latest"),
    "STATE_UNSAFE",
    "state beats provider",
)

# --- rule 4: UNPINNED_PROVIDER --------------------------------------------
for version in ("6.2.1", "= 6.2.1", "=6.2.1", "~> 6.0", "~>6.0.1", "  6.2.1  "):
    check(plan(providerVersion=version), "APPROVE", "pinned %r" % version)
for version in (
    ">= 6.0",
    "6.*",
    "latest",
    "LATEST",
    "> 6.0",
    "",
    "   ",
    "< 7.0",
    "!= 6.1.0",
    "6",
    "6.0",
    ">= 6.0, < 7.0",
    "~> 6",
):
    check(plan(providerVersion=version), "UNPINNED_PROVIDER", "unpinned %r" % version)
check(
    plan(providerVersion="latest", resource={"labels": {"owner": "someone-else"}}),
    "UNPINNED_PROVIDER",
    "provider beats labels",
)

# --- rule 5: MISSING_LABELS ------------------------------------------------
check(
    plan(resource={"labels": dict(BASE["resource"]["labels"], team="data-eng")}),
    "APPROVE",
    "extra labels are allowed",
)
for dropped in ("owner", "environment", "cost_center"):
    labels = dict(BASE["resource"]["labels"])
    del labels[dropped]
    check(
        plan(resource={"labels": labels}),
        "MISSING_LABELS",
        "missing label %s" % dropped,
    )
check(
    plan(resource={"labels": dict(BASE["resource"]["labels"], owner="student-xxxxx")}),
    "MISSING_LABELS",
    "wrong owner value",
)
check(
    plan(resource={"labels": dict(BASE["resource"]["labels"], environment="prod")}),
    "MISSING_LABELS",
    "wrong environment label value",
)
_renamed = dict(BASE["resource"]["labels"])
_renamed["costCenter"] = _renamed.pop("cost_center")
check(plan(resource={"labels": _renamed}), "MISSING_LABELS", "renamed label key")
check(plan(resource={"labels": {}}), "MISSING_LABELS", "no labels at all")
check(
    plan(resource={"labels": {}, "secret": "hunter2"}),
    "MISSING_LABELS",
    "labels beat secret",
)

# --- rule 6: PLAINTEXT_SECRET ---------------------------------------------
check(plan(resource={"secret": None}), "APPROVE", "null secret")
check(plan(resource={"secret": "secret://foo"}), "APPROVE", "secret://foo")
check(plan(resource={"secret": "hunter2"}), "PLAINTEXT_SECRET", "plaintext secret")
check(plan(resource={"secret": "secret://"}), "PLAINTEXT_SECRET", "empty reference")
check(plan(resource={"secret": ""}), "PLAINTEXT_SECRET", "empty string secret")
check(
    plan(resource={"secret": "SECRET://foo"}),
    "PLAINTEXT_SECRET",
    "prefix is case-sensitive",
)
check(
    plan(resource={"secret": "hunter2", "action": "delete"}),
    "PLAINTEXT_SECRET",
    "secret beats delete approval",
)

# --- rule 7: DELETE_NOT_APPROVED ------------------------------------------
for rtype in ("storage_bucket", "sql_database", "persistent_disk"):
    check(
        plan(resource={"type": rtype, "action": "delete"}),
        "DELETE_NOT_APPROVED",
        "unapproved delete of %s" % rtype,
    )
    check(
        plan(resource={"type": rtype, "action": "delete"}, destroyApproved=True),
        "APPROVE",
        "approved delete of %s" % rtype,
    )
check(
    plan(resource={"action": "delete", "forceDestroy": True}),
    "DELETE_NOT_APPROVED",
    "delete approval beats forceDestroy",
)

# --- rule 8: FORCE_DESTROY -------------------------------------------------
check(plan(resource={"forceDestroy": True}), "FORCE_DESTROY", "bucket force destroy")
check(
    plan(resource={"forceDestroy": True, "action": "update"}),
    "FORCE_DESTROY",
    "force destroy on update",
)
check(
    plan(
        resource={"type": "compute_instance", "forceDestroy": True},
    ),
    "APPROVE",
    "forceDestroy only matters for storage_bucket",
)
check(
    plan(resource={"forceDestroy": True, "action": "delete"}, destroyApproved=True),
    "FORCE_DESTROY",
    "approved bucket delete still blocked by forceDestroy",
)

print("all tests passed")
