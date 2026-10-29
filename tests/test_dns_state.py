import copy
import pytest
from dns_state import InvalidState, canonical, expected_snapshot, plan, snapshot, survey_records


def record(host="one", **kwargs):
    return {
        "host": host,
        "domain": "automation.test",
        "ip": ["192.0.2.1"],
        "aliases": [],
        "descr": "",
        **kwargs,
    }


def test_subset_and_full_declarations_have_identical_effect():
    existing = [record("existing")]
    single = plan([record("new")], existing)
    full = plan(existing + [record("new")], existing)
    assert single == full
    assert expected_snapshot(existing, single)[
        ("existing", "automation.test")
    ] == canonical(existing[0])


def test_order_case_and_address_spelling_are_semantic_noops():
    existing = [
        record(
            ip=["2001:db8::1", "192.0.2.1"],
            aliases=[{"host": "a", "domain": "automation.test", "descr": ""}],
        )
    ]
    desired = [
        record(
            "ONE",
            domain="AUTOMATION.TEST.",
            ip=["192.0.2.1", "2001:db8:0::1"],
            aliases=[{"host": "A", "domain": "AUTOMATION.TEST."}],
        )
    ]
    assert plan(desired, existing) == []


def test_update_is_single_operation_and_does_not_mutate_input():
    existing = [record()]
    before = copy.deepcopy(existing)
    ops = plan([record(ip=["192.0.2.2"])], existing)
    assert len(ops) == 1 and ops[0]["before"] and ops[0]["after"]
    assert existing == before


def test_deletion_needs_only_identity_and_is_idempotent():
    desired = [{"host": "one", "domain": "automation.test", "state": "absent"}]
    assert plan(desired, [record()])[0]["after"] is None
    assert plan(desired, []) == []


@pytest.mark.parametrize(
    "desired",
    [
        [record(ip=[])],
        [record(ip=["invalid"])],
        [record(domain="")],
        [record(), record()],
        [record(state="remove")],
        [record(extra="typo")],
        [record(aliases=[{"host": "one", "domain": "automation.test"}])],
        [
            record(aliases=[{"host": "other", "domain": "automation.test"}]),
            record("other"),
        ],
    ],
)
def test_invalid_input_is_rejected_before_any_operation(desired):
    with pytest.raises(InvalidState):
        plan(desired, [])


def test_ambiguous_existing_matches_are_rejected():
    with pytest.raises(InvalidState):
        plan([record()], [record(), record(ip=["192.0.2.2"])])


def test_omitted_records_never_become_deletions():
    assert plan([], [record()]) == []
    assert snapshot([record()])


def test_survey_creates_new_record_and_full_declaration_replaces_contents():
    desired = survey_records({"host": "new", "domain": "automation.test", "type": "AAAA",
                              "address": "2001:db8::2", "descr": "new"}, [])
    assert desired[0]["ip"] == ["2001:db8::2"] and desired[0]["descr"] == "new"
    existing = [record(ip=["192.0.2.1", "2001:db8::1"], aliases=[
        {"host": "old-alias", "domain": "automation.test"},
    ], descr="old")]
    op = plan([record(ip=["192.0.2.2"])], existing)[0]
    assert op["after"]["ip"] == ["192.0.2.2"]
    assert op["after"]["aliases"] == [] and op["after"]["descr"] == ""


@pytest.mark.parametrize("changes", [
    {"type": "TXT"}, {"address": "bad"}, {"domain": ""}, {"host": "bad host"},
])
def test_invalid_survey_is_rejected(changes):
    survey = {"host": "new", "domain": "automation.test", "type": "A", "address": "192.0.2.1", **changes}
    with pytest.raises(InvalidState):
        survey_records(survey, [])


def test_survey_delete_type_preserves_other_family_and_metadata():
    existing = [record(ip=["192.0.2.1", "2001:db8::1"], descr="keep", aliases=[
        {"host": "alias", "domain": "automation.test", "descr": "keep"},
    ])]
    survey = {"action": "delete_type", "host": "one", "domain": "automation.test", "type": "A"}
    desired = survey_records(survey, existing)
    assert desired[0]["ip"] == ["2001:db8::1"]
    assert desired[0]["aliases"] == existing[0]["aliases"] and desired[0]["descr"] == "keep"
    assert plan(survey_records(survey, desired), desired) == []
    deleted = survey_records({**survey, "type": "AAAA"}, desired)
    assert deleted == [{"host": "one", "domain": "automation.test", "state": "absent"}]


@pytest.mark.parametrize("action", ["delete_host", "delete_type"])
def test_survey_delete_missing_record_is_noop_and_requires_no_address(action):
    survey = {"action": action, "host": "one", "domain": "automation.test", "type": "A", "address": "ignored"}
    assert plan(survey_records(survey, []), []) == []


def test_survey_delete_host_ignores_address_and_type_but_requires_identity():
    survey = {"action": "delete_host", "host": "one", "domain": "automation.test", "type": "ignored", "address": "ignored"}
    assert plan(survey_records(survey, [record()]), [record()])[0]["after"] is None
    with pytest.raises(InvalidState):
        survey_records({**survey, "domain": ""}, [record()])
    with pytest.raises(InvalidState):
        survey_records({**survey, "action": "unknown"}, [record()])
