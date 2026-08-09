"""Tests for q1_release_gate.handle - plain asserts, pytest-compatible.

Run directly:   python test_q1.py
Or with pytest: pytest test_q1.py
"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from q1_release_gate import handle  # noqa: E402

SHA = "a" * 40
SHA2 = "0123456789abcdef0123456789abcdef01234567"


def clean_preview():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/x",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "docker", "name": "build-push-action", "ref": SHA2},
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def clean_production():
    body = clean_preview()
    body["target"] = "production"
    body["event"] = "push"
    body["ref"] = "refs/heads/main"
    body["workflow"]["trigger"] = "push"
    body["workflow"]["environmentApproval"] = True
    return body


def mutate(base, path, value):
    """Return a deep copy of `base` with the dotted `path` set to `value`."""
    body = copy.deepcopy(base)
    node = body
    parts = path.split(".")
    for key in parts[:-1]:
        node = node[key]
    node[parts[-1]] = value
    return body


def drop(base, path):
    body = copy.deepcopy(base)
    node = body
    parts = path.split(".")
    for key in parts[:-1]:
        node = node[key]
    node.pop(parts[-1], None)
    return body


def codes(body):
    result = handle(body)
    assert set(result) == {"decision", "violations"}, result
    assert result["decision"] in ("promote", "block"), result
    assert isinstance(result["violations"], list), result
    assert len(result["violations"]) == len(set(result["violations"])), "duplicate codes"
    assert result["decision"] == ("promote" if not result["violations"] else "block")
    return set(result["violations"])


# --------------------------------------------------------------------------
# clean payloads
# --------------------------------------------------------------------------

def test_clean_preview_promotes():
    assert handle(clean_preview()) == {"decision": "promote", "violations": []}


def test_clean_production_promotes():
    assert handle(clean_production()) == {"decision": "promote", "violations": []}


def test_preview_ignores_production_only_rules():
    # A preview on a non-main ref with no approval is still fine.
    body = mutate(clean_preview(), "ref", "refs/heads/anything")
    assert codes(body) == set()


# --------------------------------------------------------------------------
# rule 1 - EXCESS_PERMISSION
# --------------------------------------------------------------------------

def test_permission_extra_scope():
    body = clean_preview()
    body["workflow"]["permissions"]["issues"] = "write"
    assert codes(body) == {"EXCESS_PERMISSION"}


def test_permission_missing_scope():
    assert codes(drop(clean_preview(), "workflow.permissions.id-token")) == {"EXCESS_PERMISSION"}


def test_permission_wrong_value():
    body = mutate(clean_preview(), "workflow.permissions.contents", "write")
    assert codes(body) == {"EXCESS_PERMISSION"}


def test_permission_value_case_is_strict():
    body = mutate(clean_preview(), "workflow.permissions.contents", "Read")
    assert codes(body) == {"EXCESS_PERMISSION"}


def test_permission_whitespace_tolerated():
    body = mutate(clean_preview(), "workflow.permissions.contents", "  read  ")
    assert codes(body) == set()


def test_permission_key_whitespace_and_case_tolerated():
    body = clean_preview()
    body["workflow"]["permissions"] = {"Contents": "read", " packages ": "write", "id-token": "none"}
    assert codes(body) == set()


def test_permissions_missing_entirely():
    assert codes(drop(clean_preview(), "workflow.permissions")) == {"EXCESS_PERMISSION"}


def test_permissions_wrong_type():
    assert codes(mutate(clean_preview(), "workflow.permissions", "read-all")) == {"EXCESS_PERMISSION"}
    assert codes(mutate(clean_preview(), "workflow.permissions", None)) == {"EXCESS_PERMISSION"}
    assert codes(mutate(clean_preview(), "workflow.permissions", [])) == {"EXCESS_PERMISSION"}


def test_permission_underscore_spelling_is_a_violation():
    body = clean_preview()
    body["workflow"]["permissions"] = {"contents": "read", "packages": "write", "id_token": "none"}
    assert codes(body) == {"EXCESS_PERMISSION"}


# --------------------------------------------------------------------------
# rule 2 - UNSAFE_PR_TRIGGER
# --------------------------------------------------------------------------

def test_pull_request_target_blocks():
    assert codes(mutate(clean_preview(), "workflow.trigger", "pull_request_target")) == {
        "UNSAFE_PR_TRIGGER"
    }


def test_push_trigger_on_pr_event_does_not_fire():
    # Deliberate non-firing: only pull_request_target is unsafe.
    assert codes(mutate(clean_preview(), "workflow.trigger", "push")) == set()


def test_missing_trigger_does_not_fire():
    assert codes(drop(clean_preview(), "workflow.trigger")) == set()


# --------------------------------------------------------------------------
# rule 3 - TESTS_INCOMPLETE
# --------------------------------------------------------------------------

def test_tests_failed():
    assert codes(mutate(clean_preview(), "workflow.testsPassed", False)) == {"TESTS_INCOMPLETE"}


def test_matrix_incomplete():
    assert codes(mutate(clean_preview(), "workflow.matrixComplete", False)) == {"TESTS_INCOMPLETE"}


def test_fail_fast_true():
    assert codes(mutate(clean_preview(), "workflow.failFast", True)) == {"TESTS_INCOMPLETE"}


def test_tests_string_true_is_not_true():
    assert codes(mutate(clean_preview(), "workflow.testsPassed", "true")) == {"TESTS_INCOMPLETE"}


def test_tests_fields_missing():
    assert codes(drop(clean_preview(), "workflow.testsPassed")) == {"TESTS_INCOMPLETE"}
    assert codes(drop(clean_preview(), "workflow.failFast")) == {"TESTS_INCOMPLETE"}


def test_all_three_test_fields_bad_still_one_code():
    body = clean_preview()
    body["workflow"].update({"testsPassed": False, "matrixComplete": False, "failFast": True})
    result = handle(body)
    assert result["violations"] == ["TESTS_INCOMPLETE"]


# --------------------------------------------------------------------------
# rule 4 - MUTABLE_ACTION
# --------------------------------------------------------------------------

def test_third_party_tag_is_mutable():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": "v5"}])
    assert codes(body) == {"MUTABLE_ACTION"}


def test_third_party_sha_ok():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": SHA}])
    assert codes(body) == set()


def test_uppercase_sha_rejected():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": SHA.upper()}])
    assert codes(body) == {"MUTABLE_ACTION"}


def test_short_sha_rejected():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": "a" * 39}])
    assert codes(body) == {"MUTABLE_ACTION"}
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": "a" * 41}])
    assert codes(body) == {"MUTABLE_ACTION"}


def test_non_hex_40_chars_rejected():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b", "ref": "g" * 40}])
    assert codes(body) == {"MUTABLE_ACTION"}


def test_actions_owner_case_insensitive():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "ACTIONS", "name": "checkout", "ref": "v4"}])
    assert codes(body) == set()


def test_multiple_bad_actions_emit_one_code():
    body = mutate(
        clean_preview(),
        "workflow.actions",
        [
            {"owner": "docker", "name": "a", "ref": "v1"},
            {"owner": "aquasecurity", "name": "trivy", "ref": "master"},
        ],
    )
    assert handle(body)["violations"] == ["MUTABLE_ACTION"]


def test_empty_actions_ok():
    assert codes(mutate(clean_preview(), "workflow.actions", [])) == set()


def test_missing_actions_key_ok():
    assert codes(drop(clean_preview(), "workflow.actions")) == set()


def test_actions_wrong_type_blocks():
    assert codes(mutate(clean_preview(), "workflow.actions", "checkout@v4")) == {"MUTABLE_ACTION"}
    assert codes(mutate(clean_preview(), "workflow.actions", [None, "x"])) == {"MUTABLE_ACTION"}


def test_action_missing_ref():
    body = mutate(clean_preview(), "workflow.actions", [{"owner": "docker", "name": "b"}])
    assert codes(body) == {"MUTABLE_ACTION"}


# --------------------------------------------------------------------------
# rule 5 - image
# --------------------------------------------------------------------------

def test_single_stage():
    assert codes(mutate(clean_preview(), "image.multiStage", False)) == {"SINGLE_STAGE_IMAGE"}


def test_root_runtime():
    assert codes(mutate(clean_preview(), "image.runsAsRoot", True)) == {"ROOT_RUNTIME"}


def test_secret_mode_buildkit_ok():
    assert codes(mutate(clean_preview(), "image.secretMode", "buildkit")) == set()


def test_secret_mode_arg_and_copy():
    assert codes(mutate(clean_preview(), "image.secretMode", "arg")) == {"SECRET_IN_LAYER"}
    assert codes(mutate(clean_preview(), "image.secretMode", "copy")) == {"SECRET_IN_LAYER"}
    assert codes(mutate(clean_preview(), "image.secretMode", "env")) == {"SECRET_IN_LAYER"}
    assert codes(mutate(clean_preview(), "image.secretMode", None)) == {"SECRET_IN_LAYER"}


def test_critical_cve():
    assert codes(mutate(clean_preview(), "image.criticalVulnerabilities", 1)) == {"CRITICAL_CVE"}
    assert codes(mutate(clean_preview(), "image.criticalVulnerabilities", 12)) == {"CRITICAL_CVE"}
    assert codes(mutate(clean_preview(), "image.criticalVulnerabilities", -1)) == {"CRITICAL_CVE"}
    assert codes(mutate(clean_preview(), "image.criticalVulnerabilities", "0")) == {"CRITICAL_CVE"}
    assert codes(mutate(clean_preview(), "image.criticalVulnerabilities", False)) == {"CRITICAL_CVE"}
    assert codes(drop(clean_preview(), "image.criticalVulnerabilities")) == {"CRITICAL_CVE"}


def test_unpinned_image():
    assert codes(mutate(clean_preview(), "image.digestPinned", False)) == {"UNPINNED_IMAGE"}
    assert codes(mutate(clean_preview(), "image.digestPinned", "true")) == {"UNPINNED_IMAGE"}


def test_image_missing_entirely():
    assert codes(drop(clean_preview(), "image")) == {
        "SINGLE_STAGE_IMAGE",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }


# --------------------------------------------------------------------------
# rule 6 - production
# --------------------------------------------------------------------------

def test_production_wrong_event():
    assert codes(mutate(clean_production(), "event", "pull_request")) == {"INVALID_PRODUCTION_REF"}


def test_production_wrong_ref():
    assert codes(mutate(clean_production(), "ref", "refs/heads/develop")) == {"INVALID_PRODUCTION_REF"}
    assert codes(mutate(clean_production(), "ref", "refs/tags/v1.0.0")) == {"INVALID_PRODUCTION_REF"}


def test_production_missing_approval():
    assert codes(drop(clean_production(), "workflow.environmentApproval")) == {"APPROVAL_REQUIRED"}
    assert codes(mutate(clean_production(), "workflow.environmentApproval", False)) == {
        "APPROVAL_REQUIRED"
    }
    assert codes(mutate(clean_production(), "workflow.environmentApproval", "true")) == {
        "APPROVAL_REQUIRED"
    }


def test_production_both_extra_rules():
    body = mutate(clean_production(), "ref", "refs/heads/hotfix")
    body = mutate(body, "workflow.environmentApproval", False)
    assert codes(body) == {"INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"}


def test_production_target_case_sensitive_label():
    # "Production" is not the documented literal -> treated as a preview target.
    body = mutate(clean_production(), "target", "Production")
    body = drop(body, "workflow.environmentApproval")
    assert codes(body) == set()


# --------------------------------------------------------------------------
# combinations
# --------------------------------------------------------------------------

def test_multi_failure_payload():
    body = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/feature/rush",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {"contents": "write", "packages": "write", "id-token": "write"},
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [{"owner": "evilcorp", "name": "deploy", "ref": "latest"}],
            "environmentApproval": False,
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "arg",
            "criticalVulnerabilities": 7,
            "digestPinned": False,
        },
    }
    assert codes(body) == {
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
    }


def test_two_failures_only():
    body = mutate(clean_preview(), "image.runsAsRoot", True)
    body = mutate(body, "workflow.failFast", True)
    assert codes(body) == {"ROOT_RUNTIME", "TESTS_INCOMPLETE"}


# --------------------------------------------------------------------------
# malformed input - must never raise
# --------------------------------------------------------------------------

def test_empty_body():
    result = handle({})
    assert result["decision"] == "block"
    assert set(result["violations"]) == {
        "EXCESS_PERMISSION",
        "TESTS_INCOMPLETE",
        "SINGLE_STAGE_IMAGE",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }


def test_non_dict_bodies_do_not_raise():
    for bad in [None, [], "", "workflow", 0, 3.14, True, [1, 2, 3], {"workflow": 5, "image": "x"}]:
        result = handle(bad)
        assert result["decision"] == "block"
        assert "EXCESS_PERMISSION" in result["violations"]


def test_workflow_missing_entirely():
    body = {"target": "preview", "event": "push", "image": clean_preview()["image"]}
    assert codes(body) == {"EXCESS_PERMISSION", "TESTS_INCOMPLETE"}


def test_deeply_wrong_types_do_not_raise():
    body = {
        "target": 5,
        "event": ["push"],
        "ref": {"a": 1},
        "workflow": {
            "trigger": 12,
            "permissions": {"contents": 1, "packages": None, "id-token": []},
            "testsPassed": "yes",
            "matrixComplete": 1,
            "failFast": 0,
            "actions": [{"owner": 3, "ref": 4}],
        },
        "image": {
            "multiStage": "yes",
            "runsAsRoot": "no",
            "secretMode": 9,
            "criticalVulnerabilities": None,
            "digestPinned": 1,
        },
    }
    assert codes(body) == {
        "EXCESS_PERMISSION",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }


def test_non_string_permission_key():
    body = clean_preview()
    body["workflow"]["permissions"] = {1: "read", "packages": "write", "id-token": "none"}
    assert codes(body) == {"EXCESS_PERMISSION"}


def test_handle_does_not_mutate_input():
    body = clean_preview()
    before = copy.deepcopy(body)
    handle(body)
    assert body == before


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS  " + name)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL  {}: {!r}".format(name, exc))
    print("\n{}/{} passed".format(len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)
