"""Ground truth from the CERT answer files: insiders and their malicious user-days."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from ueba import TIMESTAMP


def insiders(answers: Path, release: str = "4.2") -> pd.DataFrame:
    df = pd.read_csv(answers / "insiders.csv", dtype={"dataset": str})
    df = df[df["dataset"] == release].copy()
    for col in ("start", "end"):
        df[col] = pd.to_datetime(df[col], format=TIMESTAMP).astype("datetime64[ns]")
    return df[["user", "scenario", "start", "end"]].reset_index(drop=True)


def malicious_days(answers: Path, release: str = "4.2") -> pd.DataFrame:
    """(user, day, scenario) for every day with at least one red-team event.

    Detail files are not proper CSV (rows of different lengths), so they are parsed line by line:
    ``type,id,date,user,pc,...``. Release 4.2 keeps them in one directory per scenario.
    """
    rows = []
    for path in sorted(answers.glob(f"r{release}-*/*.csv")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(",", 4)
            if len(parts) < 4:
                continue
            rows.append((parts[3], parts[2]))
    df = pd.DataFrame(rows, columns=["user", "date"])
    df["day"] = pd.to_datetime(df["date"], format=TIMESTAMP).dt.normalize().astype("datetime64[ns]")
    df = df[["user", "day"]].drop_duplicates()
    df["scenario"] = df["user"].map(insiders(answers, release).set_index("user")["scenario"])
    df = df.dropna(subset=["scenario"]).astype({"scenario": int})
    return df.sort_values(["day", "user"]).reset_index(drop=True)
