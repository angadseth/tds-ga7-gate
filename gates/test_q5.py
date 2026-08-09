"""Tests for GA7 Q5 - OSINT Corroboration Engine.

Plain asserts, no framework.  Run with:  python test_q5.py

Every timestamp is derived from a FIXED base via timedelta, so the suite is
deterministic and, like the module under test, never reads the wall clock.
"""

from datetime import datetime, timedelta, timezone

from q5_corroborate import handle

AS_OF = "2026-08-01T00:00:00Z"
_BASE = datetime(2026, 8, 1, tzinfo=timezone.utc)


def ago(**kwargs):
    """An ISO-8601 "Z" timestamp `kwargs` before asOf."""
    return (_BASE - timedelta(**kwargs)).strftime("%Y-%m-%dT%H:%M:%SZ")


def src(sid, origin, value, stype="dns", observed=None, authoritative=None, **extra):
    source = {
        "id": sid,
        "type": stype,
        "origin": origin,
        "observedAt": observed if observed is not None else ago(days=2),
        "value": value,
    }
    if authoritative is not None:
        source["authoritative"] = authoritative
    source.update(extra)
    return source


def body(sources, value="203.0.113.20", as_of=AS_OF, staleness=180, claim=None):
    payload = {
        "claim": {"subject": "gbcrga.example", "predicate": "resolves_to", "value": value}
        if claim is None
        else claim,
        "asOf": as_of,
        "stalenessDays": staleness,
        "sources": sources,
    }
    return payload


def check(result, verdict, confidence, ids):
    assert result == {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": ids,
    }, result


# --- the example request from the spec: one fresh matching source -----------
def test_example_single_source():
    request = {
        "claim": {"subject": "gbcrga.example", "predicate": "resolves_to", "value": "203.0.113.20"},
        "asOf": "2026-08-01T00:00:00Z",
        "stalenessDays": 180,
        "sources": [
            {
                "id": "s1",
                "type": "dns",
                "origin": "resolver-a",
                "observedAt": "2026-07-30T00:00:00Z",
                "value": "203.0.113.20",
                "authoritative": False,
            }
        ],
    }
    check(handle(request), "unverified", "low", [])


# --- rule 3: supported ------------------------------------------------------
def test_two_origins_two_types_is_high():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "ct-shard-1", "203.0.113.20", "ct_log"),
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


def test_two_origins_same_type_is_medium():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "resolver-b", "203.0.113.20", "dns"),
            ]
        )
    )
    check(result, "supported", "medium", ["s1", "s2"])


def test_mirrors_of_one_origin_are_unverified():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "resolver-a", "203.0.113.20", "ct_log"),
            ]
        )
    )
    check(result, "unverified", "low", [])


def test_representative_is_lexicographically_smallest_id():
    result = handle(
        body(
            [
                src("s3", "resolver-a", "203.0.113.20", "dns"),
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "resolver-a", "203.0.113.20", "dns"),
                src("s9", "resolver-b", "203.0.113.20", "dns"),
            ]
        )
    )
    check(result, "supported", "medium", ["s1", "s9"])


# --- rule 2: contradiction --------------------------------------------------
def test_fresh_authoritative_disagreement_contradicts():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "registry-x", "198.51.100.7", "registry", authoritative=True),
            ]
        )
    )
    check(result, "contradicted", "low", ["s2"])


def test_multiple_contradictions_sorted_regardless_of_origin():
    result = handle(
        body(
            [
                src("s9", "registry-x", "198.51.100.7", "registry", authoritative=True),
                src("s2", "registry-x", "198.51.100.8", "registry", authoritative=True),
                src("s5", "registry-y", "198.51.100.9", "registry", authoritative=True),
            ]
        )
    )
    check(result, "contradicted", "low", ["s2", "s5", "s9"])


def test_stale_authoritative_disagreement_does_not_contradict():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "ct-shard-1", "203.0.113.20", "ct_log"),
                src(
                    "s3",
                    "registry-x",
                    "198.51.100.7",
                    "registry",
                    observed=ago(days=400),
                    authoritative=True,
                ),
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


def test_fresh_non_authoritative_disagreement_is_ignored():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "ct-shard-1", "203.0.113.20", "ct_log"),
                src("s3", "scanner-z", "198.51.100.7", "scan", authoritative=False),
                src("s4", "archive-q", "198.51.100.8", "archive"),  # authoritative missing
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


# --- source validity --------------------------------------------------------
def test_invalid_sources_are_ignored_entirely():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "whois-x", "203.0.113.20", "whois"),  # bad type
                {**src("s3", "resolver-c", "203.0.113.20"), "id": 3},  # non-string id
                {**src("s4", "resolver-d", "203.0.113.20"), "origin": None},
                {**src("s5", "resolver-e", "203.0.113.20"), "value": 20},
                {**src("s6", "resolver-f", "203.0.113.20"), "observedAt": 1234},
                "not-a-dict",
                None,
            ]
        )
    )
    # Only s1 survives -> a single independent source.
    check(result, "unverified", "low", [])


def test_invalid_authoritative_source_cannot_contradict():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "ct-shard-1", "203.0.113.20", "ct_log"),
                src("s3", "registry-x", "198.51.100.7", "whois", authoritative=True),
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


def test_unparseable_observed_at_is_ignored():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns"),
                src("s2", "resolver-b", "203.0.113.20", "dns", observed="not-a-date"),
            ]
        )
    )
    check(result, "unverified", "low", [])


def test_offset_timestamps_are_parsed():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns", observed="2026-07-30T05:30:00+05:30"),
                src("s2", "resolver-b", "203.0.113.20", "ct_log", observed="2026-07-29T00:00:00Z"),
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


# --- staleness --------------------------------------------------------------
def test_entirely_stale_agreement_is_unverified():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns", observed=ago(days=200)),
                src("s2", "ct-shard-1", "203.0.113.20", "ct_log", observed=ago(days=365)),
            ]
        )
    )
    check(result, "unverified", "low", [])


def test_boundary_exactly_staleness_days_is_fresh():
    exact = ago(days=180)
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns", observed=exact),
                src("s2", "resolver-b", "203.0.113.20", "dns", observed=exact),
            ]
        )
    )
    check(result, "supported", "medium", ["s1", "s2"])


def test_boundary_one_second_older_is_stale():
    stale = ago(days=180, seconds=1)
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns", observed=stale),
                src("s2", "resolver-b", "203.0.113.20", "dns", observed=ago(days=180)),
            ]
        )
    )
    # Only s2 stays fresh -> a single independent source.
    check(result, "unverified", "low", [])


def test_observation_after_as_of_counts_as_fresh():
    future = (_BASE + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = handle(
        body(
            [
                src("s1", "resolver-a", "203.0.113.20", "dns", observed=future),
                src("s2", "resolver-b", "203.0.113.20", "ct_log"),
            ]
        )
    )
    check(result, "supported", "high", ["s1", "s2"])


# --- rule 1: malformed bodies ----------------------------------------------
def test_malformed_bodies_are_invalid():
    bad = [
        "not-a-dict",
        None,
        [],
        42,
        {"asOf": AS_OF, "stalenessDays": 180, "sources": []},  # claim missing
        {"claim": "nope", "asOf": AS_OF, "stalenessDays": 180, "sources": []},
        body([], claim={"value": 20}),  # claim.value an int
        body([], claim={"subject": "gbcrga.example"}),  # claim.value missing
        body([], as_of="garbage"),
        {"claim": {"value": "x"}, "stalenessDays": 180, "sources": []},  # asOf missing
        body([], as_of=None),
        body([], staleness="180"),
        body([], staleness=True),  # bool is not a number
        body([], staleness=None),
        {"claim": {"value": "x"}, "asOf": AS_OF, "stalenessDays": 180, "sources": {}},
        {"claim": {"value": "x"}, "asOf": AS_OF, "stalenessDays": 180},  # sources missing
    ]
    for payload in bad:
        check(handle(payload), "invalid", "low", [])


def test_valid_empty_sources_is_unverified():
    check(handle(body([])), "unverified", "low", [])
    check(handle(body([], staleness=0.5)), "unverified", "low", [])


def test_case_sensitive_value_comparison():
    result = handle(
        body(
            [
                src("s1", "resolver-a", "AA:BB", "dns"),
                src("s2", "resolver-b", "aa:bb", "dns"),
            ],
            value="AA:BB",
        )
    )
    # s2 does not match (no case normalisation) -> single independent source.
    check(result, "unverified", "low", [])


def test_response_shape_is_a_fresh_object():
    first = handle(body([]))
    first["corroboratingSources"].append("poison")
    second = handle(body([]))
    assert second["corroboratingSources"] == [], second


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  -", name)
    print(f"\n{len(tests)} tests passed")
