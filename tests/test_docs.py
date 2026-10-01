"""Documentation claims that must stay in sync with the code."""

from pathlib import Path

import yaml

from k8s_baseline_audit.collect.collector import ALL_KINDS
from k8s_baseline_audit.collect.scanners import kubescape_argv, trivy_argv

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
SKILL = (ROOT / "skill" / "k8s-baseline-audit" / "SKILL.md").read_text(encoding="utf-8")
RBAC = ROOT / "examples" / "rbac" / "readonly-clusterrole.yaml"


def test_readonly_wording_names_the_real_scanner_flags():
    ks = kubescape_argv(Path("x"), None)
    tv = trivy_argv(Path("x"), None)
    assert {"--keep-local", "--host-scan=false"} <= set(ks)
    assert {"--disable-node-collector", "--disable-telemetry"} <= set(tv)
    for text in (README, SKILL):
        assert "`kubescape scan --keep-local --host-scan=false`" in text
        assert "`trivy k8s --disable-node-collector --disable-telemetry`" in text
        assert "read-only identity" in text
        assert "examples/rbac/readonly-clusterrole.yaml" in text


def test_rbac_example_grants_only_reads_on_collected_kinds():
    roles = list(yaml.safe_load_all(RBAC.read_text(encoding="utf-8")))
    base, secret = roles
    kinds = set()
    for rule in base["rules"]:
        assert set(rule["verbs"]) == {"get", "list", "watch"}
        kinds.update(rule["resources"])
    assert kinds == set(ALL_KINDS) - {"secrets"}
    assert secret["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]
    assert "values included" in RBAC.read_text(encoding="utf-8")


def test_readme_documents_residuals_and_checkout_requirement():
    assert "## Known limitations" in README
    assert "mode 0700" in README and "power" in README
    assert "`scripts/install-skill.sh` are not part of the package" in README
    assert (
        "Prüfgrundlage für Zertifizierungen nach ISO 27001 auf der Basis von IT-Grundschutz "
        "nach dem IT-Grundschutz-Kompendium" in README
    )
