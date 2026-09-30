from importlib.resources import files

from k8s_baseline_audit.analyze.checks import all_checks
from k8s_baseline_audit.mapping.schema import load_mapping

FORBIDDEN_WORDS = ("erfüllt", "fulfilled", "compliant", "konform")


def _expected():
    ids_file = files("k8s_baseline_audit.mappings").joinpath("sources/kompendium-2023-ids.txt")
    text = ids_file.read_text()
    rows = [line.split("\t") for line in text.splitlines() if line.strip()]
    return {rid: level for rid, level in rows}


def test_every_source_requirement_is_mapped_exactly_once():
    m = load_mapping()
    expected = _expected()
    assert expected, "ids file is empty"
    assert {r.id for r in m.requirements} == set(expected)
    for r in m.requirements:
        assert r.level.value == expected[r.id], r.id


def test_both_modules_present():
    m = load_mapping()
    assert {r.module for r in m.requirements} == {"APP.4.4", "SYS.1.6"}
    assert m.modules == ["APP.4.4", "SYS.1.6"]


def test_every_referenced_check_exists():
    known = {c.id for c in all_checks()}
    m = load_mapping()
    for r in m.requirements:
        assert set(r.checks) <= known, (r.id, set(r.checks) - known)


def test_every_builtin_check_is_mapped_or_explicitly_unmapped():
    m = load_mapping()
    mapped = {c for r in m.requirements for c in r.checks}
    unmapped = {u.check_id for u in m.unmapped_checks}
    assert not mapped & unmapped
    missing = {c.id for c in all_checks()} - mapped - unmapped
    assert not missing, f"checks neither mapped nor listed in unmapped_checks: {sorted(missing)}"


def test_texts_are_bilingual_sourced_and_never_claim_fulfilment():
    m = load_mapping()
    for r in m.requirements:
        for loc in [r.title, r.summary, *r.questions]:
            assert loc.de.strip() and loc.en.strip(), r.id
            for word in FORBIDDEN_WORDS:
                assert word not in (loc.de + loc.en).lower(), (r.id, word)
        assert r.source.url.startswith("https://www.bsi.bund.de/"), r.id
        assert r.source.edition, r.id
