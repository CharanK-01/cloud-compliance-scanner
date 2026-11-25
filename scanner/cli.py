"""CLI interface for Cloud Security Compliance Scanner."""

import sys
import time
from pathlib import Path
from typing import List, Optional
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from scanner.models import Finding
from scanner.registry import CHECKS, get_check, list_checks, load_all_checks
from scanner.reports.exporters import export_csv, export_json
from scanner.reports.html_report import generate_html_report
from scanner.scoring import build_scan_summary
from scanner.session import create_session, init_scan_context

app = typer.Typer(
    name="scanner",
    help="AWS Cloud Security Compliance Scanner mapped to ISO 27001:2022 Annex A",
    add_completion=False,
)
console = Console()


SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


@app.command("version")
def version():
    """Display the scanner version."""
    console.print("[bold cyan]Cloud Security Compliance Scanner[/bold cyan] v1.0.0")


@app.command("list-checks")
def list_available_checks():
    """List all registered checks and their ISO 27001 mappings."""
    load_all_checks()
    from scanner.session import load_controls_mapping
    controls = load_controls_mapping()

    table = Table(title="Registered Compliance Checks (ISO 27001:2022)", box=box.ROUNDED)
    table.add_column("Check ID", style="bold cyan")
    table.add_column("Service", style="green")
    table.add_column("Title")
    table.add_column("ISO Controls", style="yellow")
    table.add_column("Risk Score", justify="right")

    for cid in list_checks():
        meta = controls.get(cid)
        if meta:
            table.add_row(cid, meta.service, meta.title, ", ".join(meta.iso_controls), str(meta.risk_score))
        else:
            table.add_row(cid, "unknown", cid, "", "")

    console.print(table)


@app.command("scan")
def scan(
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="AWS CLI named profile to use"),
    regions: Optional[str] = typer.Option(None, "--regions", "-r", help="Comma-separated AWS regions to scan"),
    services: Optional[str] = typer.Option(None, "--services", "-s", help="Comma-separated AWS services to scan (e.g. iam,s3,ec2,logging,kms,rds)"),
    format: str = typer.Option("html,json,csv", "--format", "-f", help="Comma-separated output formats: html, json, csv"),
    output: Path = typer.Option(Path("./reports"), "--output", "-o", help="Output directory for reports"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit with code 1 if failures found at or above severity: critical, high, medium, low"),
):
    """Run read-only compliance checks against AWS infrastructure."""
    console.print(
        Panel.fit(
            "[bold cyan]AWS Cloud Security Compliance Scanner[/bold cyan]\n"
            "[dim]ISO 27001:2022 Annex A Alignment & Risk Scoring Engine[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # 1. Load registered check plugins
    load_all_checks()
    all_check_ids = list_checks()

    # 2. Parse arguments
    region_list = [r.strip() for r in regions.split(",")] if regions else None
    service_list = [s.strip().lower() for s in services.split(",")] if services else None
    formats = [fmt.strip().lower() for fmt in format.split(",")]

    # 3. Initialize session and context
    with console.status("[bold green]Connecting to AWS and discovering scope...", spinner="dots"):
        try:
            boto_session = create_session(profile_name=profile)
            ctx = init_scan_context(session=boto_session, regions=region_list)
        except Exception as e:
            console.print(f"[bold red]Initialization Error:[/bold red] {e}")
            raise typer.Exit(code=2)

    console.print(f"• AWS Account: [bold yellow]{ctx.account_id}[/bold yellow]")
    console.print(f"• Target Regions: [cyan]{', '.join(ctx.regions)}[/cyan]")

    # 4. Filter checks by service if requested
    selected_checks = []
    for cid in all_check_ids:
        meta = ctx.controls.get(cid)
        svc = meta.service.lower() if meta else "unknown"
        if service_list and svc not in service_list:
            continue
        selected_checks.append(cid)

    console.print(f"• Scheduled Checks: [bold green]{len(selected_checks)}[/bold green] evaluation modules\n")

    # 5. Execute checks
    all_findings: List[Finding] = []
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running compliance checks...", total=len(selected_checks))

        for cid in selected_checks:
            fn = get_check(cid)
            progress.update(task, description=f"[cyan]Evaluating [bold]{cid}[/bold]...")
            try:
                findings = fn(ctx)
                all_findings.extend(findings)
            except Exception as e:
                # Catch-all to guarantee scan completion even on unexpected check failure
                meta = ctx.controls.get(cid)
                title = meta.title if meta else cid
                svc = meta.service if meta else "unknown"
                all_findings.append(
                    Finding(
                        check_id=cid,
                        title=title,
                        service=svc,
                        region="global",
                        resource_id=f"{svc}:{cid}",
                        status="ERROR",
                        severity="Medium",
                        risk_score=9,
                        iso_controls=meta.iso_controls if meta else [],
                        evidence={"exception": str(e)},
                        remediation="Investigate scanner permissions or service endpoint availability.",
                    )
                )
            progress.advance(task)

    duration = time.time() - start_time

    # 6. Aggregate metrics and scoring
    summary = build_scan_summary(
        account_id=ctx.account_id,
        regions=ctx.regions,
        duration_seconds=duration,
        findings=all_findings,
        attempted_checks_count=len(selected_checks),
    )

    # 7. Print Console Results Summary
    summary_table = Table(title="Audit Executive Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    score_color = "green" if summary.overall_posture_score >= 80 else ("yellow" if summary.overall_posture_score >= 60 else "red")
    summary_table.add_row("Overall Posture Score", f"[{score_color}][bold]{summary.overall_posture_score}%[/bold][/{score_color}]")
    summary_table.add_row("Audit Coverage", f"[green]{summary.coverage_rate}%[/green]")
    summary_table.add_row("Total Evaluations", str(summary.total_findings))
    summary_table.add_row("Passed Findings", f"[green]{summary.passed_count}[/green]")
    summary_table.add_row("Failed Findings", f"[red]{summary.failed_count}[/red]")
    summary_table.add_row("Errors / Gaps", f"[magenta]{summary.error_count}[/magenta]")
    summary_table.add_row("Critical Risks", f"[bold red]{summary.severity_counts.get('Critical', 0)}[/bold red]")
    summary_table.add_row("High Risks", f"[red]{summary.severity_counts.get('High', 0)}[/red]")
    summary_table.add_row("Medium Risks", f"[yellow]{summary.severity_counts.get('Medium', 0)}[/yellow]")
    summary_table.add_row("Low Risks", f"[green]{summary.severity_counts.get('Low', 0)}[/green]")
    console.print(summary_table)

    # Top Risks Table
    if summary.top_risks:
        top_table = Table(title="Top Priority Risks Requiring Remediation", box=box.SIMPLE_HEAD)
        top_table.add_column("Check ID", style="bold cyan")
        top_table.add_column("Resource", style="dim", overflow="ellipsis", max_width=45)
        top_table.add_column("Severity", justify="center")
        top_table.add_column("Score", justify="right")
        top_table.add_column("ISO Controls")

        for r in summary.top_risks:
            sev_col = "red" if r.severity in ("Critical", "High") else "yellow"
            top_table.add_row(
                r.check_id,
                r.resource_id,
                f"[{sev_col}]{r.severity}[/{sev_col}]",
                str(r.risk_score),
                ", ".join(r.iso_controls),
            )
        console.print(top_table)

    # 8. Export Reports
    output.mkdir(parents=True, exist_ok=True)
    generated_files = []
    json_hash = ""

    if "json" in formats or "html" in formats:
        json_path = output / "compliance_report.json"
        _, json_hash = export_json(summary, json_path)
        if "json" in formats:
            generated_files.append(f"JSON: {json_path} (SHA-256: {json_hash[:12]}...)")

    if "csv" in formats:
        csv_path = output / "compliance_findings.csv"
        export_csv(summary, csv_path)
        generated_files.append(f"CSV:  {csv_path}")

    if "html" in formats:
        html_path = output / "compliance_report.html"
        generate_html_report(summary, html_path, json_sha256=json_hash)
        generated_files.append(f"HTML: {html_path}")

    console.print("\n[bold]Generated Audit Artifacts:[/bold]")
    for gf in generated_files:
        console.print(f"  ✓ {gf}")

    # 9. CI / CD Quality Gate (--fail-on)
    if fail_on:
        threshold = fail_on.strip().lower()
        if threshold in SEVERITY_WEIGHTS:
            min_weight = SEVERITY_WEIGHTS[threshold]
            violating_findings = [
                f for f in summary.findings
                if f.status == "FAIL" and SEVERITY_WEIGHTS.get(f.severity.lower(), 0) >= min_weight
            ]
            if violating_findings:
                console.print(
                    f"\n[bold red]CI Failure:[/bold red] Found {len(violating_findings)} failure(s) at or above '{threshold}' severity threshold."
                )
                raise typer.Exit(code=1)

    console.print("\n[bold green]Scan completed successfully.[/bold green]\n")


def main():
    app()


if __name__ == "__main__":
    main()
