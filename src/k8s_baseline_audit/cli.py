"""k8s-baseline-audit command-line interface."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError

from . import __version__
from .analyze.checks.base import AnalyzerConfig
from .analyze.pipeline import analyze as run_analysis
from .analyze.pipeline import write_analysis
from .analyze.scanners import ScannerFormatError
from .bundle import BundleFormatError, BundleIntegrityError, load_bundle
from .collect.collector import CollectOptions
from .collect.collector import collect as collect_bundle
from .collect.runner import KubectlRunner
from .collect.scanners import ScannerPlan, node_slug, run_scanners
from .mapping.schema import load_mapping
from .models import Severity
from .report.render import Narrative, NarrativeError, load_report_input, render_reports

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Read-only Kubernetes security audit mapped to BSI IT-Grundschutz APP.4.4 and SYS.1.6.",
)


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(EXIT_ERROR)


def _internal(exc: BaseException) -> typer.Exit:
    return _fail(f"internal error: {type(exc).__name__}: {exc}")


def _make_runner(context: str | None) -> KubectlRunner:
    return KubectlRunner(context=context)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"k8s-baseline-audit {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True)
    ] = False,
) -> None:
    """Collect, analyze and report."""


def _parse_kube_bench(values: list[str]) -> tuple[tuple[str, Path], ...]:
    parsed = []
    for value in values:
        node, sep, path = value.partition("=")
        if not sep or not node or not path:
            raise _fail(f"--kube-bench-result expects NODE=FILE, got {value!r}")
        if not Path(path).is_file():
            raise _fail(f"kube-bench result file not found: {path}")
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            doc = None
        if not isinstance(doc, dict):
            raise _fail(f"kube-bench result is not valid JSON: {path}")
        parsed.append((node, Path(path)))
    slugs = [node_slug(node) for node, _ in parsed]
    for slug in slugs:
        if slugs.count(slug) > 1:
            raise _fail(f"duplicate kube-bench node name: {slug}")
    return tuple(parsed)


@app.command()
def collect(
    out: Annotated[Path, typer.Option("--out", help="Parent directory for the bundle")] = Path("."),
    context: Annotated[str | None, typer.Option("--context", help="kubectl context")] = None,
    no_scanners: Annotated[
        bool, typer.Option("--no-scanners", help="Skip kubescape and trivy")
    ] = False,
    kube_bench_result: Annotated[
        list[str], typer.Option("--kube-bench-result", help="NODE=FILE, repeatable")
    ] = [],  # noqa: B006
) -> None:
    """Collect cluster state read-only into an evidence bundle."""
    plan = ScannerPlan(
        kubescape=not no_scanners,
        trivy=not no_scanners,
        kube_bench_results=_parse_kube_bench(kube_bench_result),
    )
    try:
        with tempfile.TemporaryDirectory() as tmp:
            scans = run_scanners(plan, context, Path(tmp))
        options = CollectOptions(
            tool_version=__version__,
            now=datetime.now(UTC),
            extra_files=scans.files,
            scanner_status=scans.status,
            extra_commands=scans.commands,
        )
        out.mkdir(parents=True, exist_ok=True)
        path = collect_bundle(_make_runner(context), out, options)
        bundle = load_bundle(path)
        collected_errors = bundle.errors
        collected = [r for r in bundle.files_under("resources/") if r != "resources/version.json"]
    except (BundleFormatError, BundleIntegrityError, ValueError, OSError) as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _internal(exc) from exc
    for err in collected_errors:
        typer.echo(f"warning: {err['resource']}: {err['reason']}", err=True)
    if not collected:
        typer.echo(str(path))
        raise _fail("no resources collected; check kubeconfig, context and permissions")
    typer.echo(str(path))


def _as_of(manifest: dict) -> date:
    created = manifest.get("created_at") or ""
    try:
        return date.fromisoformat(created[:10])
    except ValueError:
        return datetime.now(UTC).date()


@app.command()
def analyze(
    bundle_dir: Annotated[Path, typer.Argument(help="Bundle directory")],
    out: Annotated[
        Path, typer.Option("--out", help="Output directory for findings.json and coverage.json")
    ],
    mapping: Annotated[str, typer.Option("--mapping")] = "kompendium-2023",
    registry_allowlist: Annotated[
        list[str], typer.Option("--registry-allowlist", help="Repeatable")
    ] = [],  # noqa: B006
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Analyze a bundle deterministically."""
    try:
        bundle = load_bundle(bundle_dir)
        m = load_mapping(mapping)
        config = AnalyzerConfig(
            as_of=_as_of(bundle.manifest), registry_allowlist=tuple(sorted(registry_allowlist))
        )
        result = run_analysis(bundle, m, config, tool_version=__version__)
        findings_path, coverage_path = write_analysis(result, out)
    except (
        BundleFormatError,
        BundleIntegrityError,
        ScannerFormatError,
        FileNotFoundError,
        ValidationError,
        yaml.YAMLError,
        ValueError,
        OSError,
    ) as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _internal(exc) from exc
    typer.echo(str(findings_path))
    typer.echo(str(coverage_path))
    worst = any(f.severity.at_or_above(fail_on) for f in result.findings)
    raise typer.Exit(EXIT_FINDINGS if worst else EXIT_OK)


@app.command()
def report(
    analysis_dir: Annotated[
        Path, typer.Argument(help="Directory with findings.json and coverage.json")
    ],
    bundle_dir: Annotated[Path, typer.Option("--bundle")],
    out: Annotated[Path, typer.Option("--out")],
    narrative_de: Annotated[Path | None, typer.Option("--narrative-de")] = None,
    narrative_en: Annotated[Path | None, typer.Option("--narrative-en")] = None,
) -> None:
    """Render report.de.md and report.en.md."""
    if (narrative_de is None) != (narrative_en is None):
        raise _fail("pass both --narrative-de and --narrative-en, or neither")
    try:
        narratives = None
        if narrative_de and narrative_en:
            narratives = {
                "de": Narrative.model_validate_json(narrative_de.read_text(encoding="utf-8")),
                "en": Narrative.model_validate_json(narrative_en.read_text(encoding="utf-8")),
            }
        inp = load_report_input(analysis_dir, load_bundle(bundle_dir))
        paths = render_reports(inp, narratives, out)
    except (
        BundleFormatError,
        BundleIntegrityError,
        NarrativeError,
        ScannerFormatError,
        FileNotFoundError,
        ValidationError,
        yaml.YAMLError,
        KeyError,
        ValueError,
        OSError,
    ) as exc:
        raise _fail(str(exc)) from exc
    except Exception as exc:
        raise _internal(exc) from exc
    for path in paths.values():
        typer.echo(str(path))
