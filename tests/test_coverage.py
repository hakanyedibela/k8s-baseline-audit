import yaml

from k8s_baseline_audit.analyze.coverage import compute_coverage
from k8s_baseline_audit.analyze.pipeline import CheckRun
from k8s_baseline_audit.mapping.schema import load_mapping_file
from k8s_baseline_audit.models import (
    CoverageStatus,
    Finding,
    Localized,
    ResourceRef,
    Severity,
    Source,
)

SRC = {"document": "d", "edition": "2023", "url": "https://www.bsi.bund.de/x", "page": 1}
L = {"de": "x", "en": "x"}


def req(n, ctype, checks=()):
    return {
        "id": f"APP.4.4.A{n}",
        "module": "APP.4.4",
        "level": "basic",
        "title": L,
        "summary": L,
        "source": SRC,
        "coverage_type": ctype,
        "checks": list(checks),
        "questions": [L],
    }


def mapping(tmp_path):
    doc = {
        "name": "t",
        "framework": "f",
        "edition": "2023",
        "modules": ["APP.4.4"],
        "requirements": [
            req(1, "organizational"),
            req(2, "manual"),
            req(3, "automatic", ["a"]),
            req(4, "automatic", ["b"]),
            req(5, "automatic", ["c", "a"]),
            req(6, "partial", ["a"]),
            req(7, "automatic", ["m"]),
            req(8, "automatic", ["c", "hit"]),
        ],
    }
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(doc))
    return load_mapping_file(p)


def finding(fid, reqs):
    ref = ResourceRef(kind="Pod", name="p", namespace="n")
    lz = Localized(de="x", en="x")
    return Finding(
        id=fid,
        check_id="hit",
        title=lz,
        severity=Severity.HIGH,
        resources=[ref],
        evidence=[],
        sources=[Source.BUILTIN],
        requirements=reqs,
        remediation=lz,
    )


def test_statuses(tmp_path):
    runs = [
        CheckRun("a", "ran"),
        CheckRun("b", "ran"),
        CheckRun("c", "not_run", "pods: forbidden"),
        CheckRun("m", "manual", "static pod not visible"),
        CheckRun("hit", "ran"),
    ]
    cov = {
        c.requirement_id: c
        for c in compute_coverage(mapping(tmp_path), [finding("f1", ["APP.4.4.A8"])], runs)
    }
    assert cov["APP.4.4.A1"].status == CoverageStatus.ORGANIZATIONAL
    assert cov["APP.4.4.A2"].status == CoverageStatus.MANUAL
    assert cov["APP.4.4.A3"].status == CoverageStatus.NO_DEVIATION
    assert cov["APP.4.4.A5"].status == CoverageStatus.NOT_CHECKED
    assert cov["APP.4.4.A5"].reasons == ["c: pods: forbidden"]
    assert cov["APP.4.4.A6"].status == CoverageStatus.PARTIAL
    assert cov["APP.4.4.A7"].status == CoverageStatus.MANUAL
    assert cov["APP.4.4.A7"].reasons == ["m: static pod not visible"]
    assert cov["APP.4.4.A8"].status == CoverageStatus.DEVIATION
    assert cov["APP.4.4.A8"].finding_ids == ["f1"]
    assert cov["APP.4.4.A8"].reasons == ["c: pods: forbidden"]


def test_unknown_check_is_not_checked(tmp_path):
    cov = compute_coverage(mapping(tmp_path), [], [])
    by_id = {c.requirement_id: c for c in cov}
    assert by_id["APP.4.4.A3"].status == CoverageStatus.NOT_CHECKED
    assert by_id["APP.4.4.A3"].reasons == ["a: check did not run"]
    assert [c.requirement_id for c in cov] == [f"APP.4.4.A{n}" for n in range(1, 9)]
