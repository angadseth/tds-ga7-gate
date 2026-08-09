"""Tests the release-gate rules the assignment describes.

Every per-student workflow in this repository runs this file, so the workflow
is testing a real implementation rather than echoing a string.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "gates"))

from q1_release_gate import handle  # noqa: E402

CLEAN = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def swap(base, **over):
    out = dict(base)
    out.update(over)
    return out


def check(label, payload, predicate):
    result = handle(payload)
    assert predicate(result), f"{label}: got {result}"
    print(f"  ok  {label}")


print("release gate")
check("clean preview promotes", CLEAN, lambda r: r["decision"] == "promote" and not r["violations"])
check(
    "clean production promotes",
    swap(CLEAN, target="production", event="push", ref="refs/heads/main",
         workflow=swap(CLEAN["workflow"], trigger="push", environmentApproval=True)),
    lambda r: r["decision"] == "promote",
)
check(
    "extra scope is flagged",
    swap(CLEAN, workflow=swap(CLEAN["workflow"],
         permissions={"contents": "write", "packages": "write", "id-token": "none"})),
    lambda r: "EXCESS_PERMISSION" in r["violations"],
)
check(
    "an uppercase sha is still unpinned",
    swap(CLEAN, workflow=swap(CLEAN["workflow"],
         actions=[{"owner": "third", "name": "x", "ref": "A" * 40}])),
    lambda r: "MUTABLE_ACTION" in r["violations"],
)
check(
    "a lowercase sha is pinned",
    swap(CLEAN, workflow=swap(CLEAN["workflow"],
         actions=[{"owner": "third", "name": "x", "ref": "a" * 40}])),
    lambda r: "MUTABLE_ACTION" not in r["violations"],
)
check("root runtime is flagged",
      swap(CLEAN, image=swap(CLEAN["image"], runsAsRoot=True)),
      lambda r: "ROOT_RUNTIME" in r["violations"])
check("a malformed body does not crash", None, lambda r: r["decision"] == "block")

print("all release-gate checks passed")
