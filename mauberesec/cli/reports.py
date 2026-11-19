"""CLI: reports, history, and assessment inspection (v0.11)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ..paths import database_path
from ..reports.generator import report_schema, write_report
from ..storage.db import Database

report_app = typer.Typer(help="Reports, assessment history, and inspection (v0.11).")


@report_app.command("generate")
def generate(
    assessment_id: Annotated[str, typer.Argument(help="Assessment ID (see 'mauberesec history').")],
    out: Annotated[
        str | None, typer.Option("--out", help="Output directory (default ./reports).")
    ] = None,
    print_md: Annotated[
        bool, typer.Option("--print", help="Also print the Markdown report to stdout.")
    ] = False,
) -> None:
    """Generate Markdown + JSON reports for an assessment (redacted)."""
    db = Database(database_path())
    assessment = db.get_assessment(assessment_id)
    if assessment is None:
        typer.echo(f"Assessment '{assessment_id}' not found. Run 'mauberesec history'.", err=True)
        db.close()
        raise typer.Exit(code=2)
    out_dir = Path(out) if out else Path.cwd() / "reports"
    bundle = write_report(db, assessment, out_dir)
    db.close()

    typer.echo(
        f"Report written: {bundle.markdown_path}\n"
        f"                {bundle.json_path}\n"
        f"findings={len(bundle.findings)} partial={bundle.partial} "
        f"tools={','.join(bundle.tools_used) or 'none'}"
    )
    if print_md:
        typer.echo(bundle.markdown_path.read_text())


@report_app.command("schema")
def schema() -> None:
    """Print the JSON Schema used for report documents."""
    typer.echo(json.dumps(report_schema(), indent=2))


@report_app.command("list")
def list_assessments(
    limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 20,
) -> None:
    """Alias for 'mauberesec history'."""
    history(limit=limit, json_output=False)


@report_app.command("show")
def show(
    assessment_id: Annotated[str, typer.Argument(help="Assessment ID.")],
) -> None:
    """Show a stored assessment with its findings (redacted)."""
    db = Database(database_path())
    assessment = db.get_assessment(assessment_id)
    if assessment is None:
        typer.echo(f"Assessment '{assessment_id}' not found.", err=True)
        db.close()
        raise typer.Exit(code=2)
    findings = db.list_findings(assessment_id)
    typer.echo(
        f"{assessment.id}  mode={assessment.mode.value}  status={assessment.status}\n"
        f"scope={[f'{t.kind.value}:{t.value}' for t in assessment.scope.targets]}\n"
        f"created={assessment.created_at.isoformat()}"
    )
    for finding in findings:
        typer.echo(
            f"  [{finding.severity.value}/{finding.confidence.value}/"
            f"{finding.verification.value}] {finding.title}"
        )
    db.close()


@report_app.command("history")
def history(
    limit: Annotated[int, typer.Option("--limit", min=1, max=200)] = 20,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON.")
    ] = False,
) -> None:
    """List recent assessments (newest first)."""
    db = Database(database_path())
    assessments = sorted(db.list_assessments(), key=lambda a: a.created_at, reverse=True)[:limit]
    if json_output:
        import json as _json

        typer.echo(
            _json.dumps(
                [
                    {
                        "id": a.id,
                        "created_at": a.created_at.isoformat(),
                        "mode": a.mode.value,
                        "status": a.status,
                        "findings": len(db.list_findings(a.id)),
                        "targets": [f"{t.kind.value}:{t.value}" for t in a.scope.targets],
                    }
                    for a in assessments
                ],
                indent=2,
            )
        )
        db.close()
        return
    if not assessments:
        typer.echo(
            "No assessments recorded yet. Start with: mauberesec scan|audit|apk analyze|agent run"
        )
    for assessment in assessments:
        counts = len(db.list_findings(assessment.id))
        typer.echo(
            f"{assessment.created_at.isoformat()}  {assessment.id}  "
            f"mode={assessment.mode.value}  status={assessment.status}  findings={counts}"
        )
    db.close()
