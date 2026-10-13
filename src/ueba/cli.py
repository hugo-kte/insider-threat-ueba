"""UEBA command-line interface."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

app = typer.Typer(
    help="Insider-threat UEBA on the CERT r4.2 dataset.", no_args_is_help=True, add_completion=False
)
console = Console()
# inputs are checked before any work starts: a wrong path is a one-line error, not a traceback
ExistingFile = Annotated[Path, typer.Option(exists=True, dir_okay=False)]
ExistingDir = Annotated[Path, typer.Option(exists=True, file_okay=False)]


@app.callback()
def main(verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False)],
    )


@app.command()
def extract(
    archive: ExistingFile = Path("data/raw/r4.2.tar.bz2"),
    answers: ExistingFile = Path("data/raw/answers.tar.bz2"),
    out_dir: Path = Path("data/extracted"),
    answers_dir: Path = Path("data/answers"),
) -> None:
    """Stream the archive once: keep only the columns the features use, aggregate the web log."""
    import tarfile

    from ueba.extract import extract as _extract

    with tarfile.open(answers) as tar:  # seconds: a bad answer archive fails before the long pass
        tar.extractall(answers_dir, filter="data")
    _extract(archive, out_dir)
    console.print(f"Extracted to {out_dir} and {answers_dir}")


@app.command()
def evaluate(
    extracted: ExistingDir = Path("data/extracted"),
    answers: ExistingDir = Path("data/answers/answers"),
    out_dir: Path = Path("reports"),
    warmup_days: Annotated[int, typer.Option(min=1)] = 60,
) -> None:
    """Build features, score every detector, evaluate against the answers, write reports/."""
    from ueba.pipeline import run

    m = run(extracted, answers, out_dir, warmup_days)
    scenarios = ("scenario_1", "scenario_2", "scenario_3")
    table = Table(title="Insiders caught with 10 reviews/day | user-level ROC-AUC")
    for col in ("detector", "scenario 1", "scenario 2", "scenario 3", "total", "AUC"):
        table.add_column(col)
    for det, r in m["detectors"].items():
        d = r["daily_budget"]["10"]
        table.add_row(
            det,
            *(f"{d[s]['caught']}/{d[s]['insiders']}" if s in d else "-" for s in scenarios),
            f"{d['caught_total']}/{d['insiders_total']}",
            f"{r['user_level']['roc_auc']:.3f}",
        )
    d = m["random_baseline"]["daily_budget"]["10"]
    table.add_row(
        "random (expected)",
        *(f"{d[s]['expected_caught']:.1f}" if s in d else "-" for s in scenarios),
        f"{d['expected_caught_total']:.1f}",
        "0.500",
        style="dim",
    )
    console.print(table)
    console.print(f"Report: [bold]{out_dir / 'REPORT.md'}[/bold]")


if __name__ == "__main__":
    app()
