import pytest
import yaml
from pydantic import ValidationError

from k8s_baseline_audit.mapping.schema import load_mapping_file, requirement_sort_key

SRC = {
    "document": "APP.4.4 Kubernetes",
    "edition": "2023",
    "url": "https://www.bsi.bund.de/x.pdf",
    "page": 3,
}


def _req(rid, coverage_type="automatic", checks=("workload.privileged",), questions=()):
    return {
        "id": rid,
        "module": rid.rsplit(".A", 1)[0],
        "level": "basic",
        "title": {"de": "Titel", "en": "Title"},
        "summary": {"de": "Kurz", "en": "Short"},
        "source": SRC,
        "coverage_type": coverage_type,
        "checks": list(checks),
        "questions": [{"de": q, "en": q} for q in questions],
    }


def _write(tmp_path, requirements, unmapped=()):
    doc = {
        "name": "test",
        "framework": "BSI IT-Grundschutz-Kompendium",
        "edition": "2023",
        "modules": ["APP.4.4", "SYS.1.6"],
        "requirements": requirements,
        "unmapped_checks": list(unmapped),
    }
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True))
    return path


def test_loads_and_indexes(tmp_path):
    m = load_mapping_file(
        _write(
            tmp_path,
            [
                _req("APP.4.4.A10"),
                _req(
                    "APP.4.4.A2",
                    checks=("workload.privileged", "workload.host_path"),
                ),
                _req(
                    "SYS.1.6.A1",
                    "organizational",
                    checks=(),
                    questions=("Gibt es ein Konzept?",),
                ),
            ],
        )
    )
    assert m.get("APP.4.4.A2").checks == ["workload.privileged", "workload.host_path"]
    assert m.requirements_for_check("workload.privileged") == ["APP.4.4.A2", "APP.4.4.A10"]
    assert m.requirements_for_check("nope") == []


def test_sort_key_is_numeric():
    ids = ["APP.4.4.A10", "SYS.1.6.A1", "APP.4.4.A2"]
    assert sorted(ids, key=requirement_sort_key) == ["APP.4.4.A2", "APP.4.4.A10", "SYS.1.6.A1"]


@pytest.mark.parametrize(
    "bad",
    [
        [_req("APP.4.4.A1"), _req("APP.4.4.A1")],  # duplicate id
        [_req("APP.9.9.A1")],  # module not listed / id pattern
        [_req("APP.4.4.A1", "automatic", checks=())],  # automatic needs checks
        [_req("APP.4.4.A1", "manual", checks=(), questions=())],  # manual needs questions
    ],
)
def test_invalid_mappings_are_rejected(tmp_path, bad):
    with pytest.raises(ValidationError):
        load_mapping_file(_write(tmp_path, bad))


def test_unmapped_check_needs_bilingual_reason(tmp_path):
    m = load_mapping_file(
        _write(
            tmp_path,
            [_req("APP.4.4.A1")],
            unmapped=[{"check_id": "x", "reason": {"de": "d", "en": "e"}}],
        )
    )
    assert m.unmapped_checks[0].check_id == "x"


def test_unknown_packaged_mapping():
    from k8s_baseline_audit.mapping.schema import load_mapping

    with pytest.raises(FileNotFoundError, match="unknown mapping"):
        load_mapping("does-not-exist")
