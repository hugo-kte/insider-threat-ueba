"""End-to-end run: features (cached) -> detector scores -> evaluation -> report."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from ueba import features, groundtruth
from ueba.detectors import DETECTORS, score_all
from ueba.evaluate import (
    artifact_audit,
    base_rates,
    daily_budget,
    evaluate,
    random_baseline,
    review_cards,
    user_level,
)

log = logging.getLogger(__name__)


def load_features(extracted: Path, warmup_days: int) -> pd.DataFrame:
    """Feature table, cached next to the extracted logs.

    The cache is named after the warm-up length and the version of the feature code, so a change
    to either builds a new table instead of silently reusing a stale one.
    """
    cache = extracted / f"features_warmup{warmup_days}_{features.CODE_VERSION}.parquet"
    if cache.exists():
        df = pd.read_parquet(cache)
    else:
        df = features.build(extracted, warmup_days)
        df.to_parquet(cache, index=False)
    return df.astype({"day": "datetime64[ns]"})


def leak_ablation(
    df: pd.DataFrame, warmup_end: pd.Timestamp, insiders: set[str], bad: pd.DataFrame
) -> dict[str, Any]:
    """What the detectors would score if the simulator's web request count were a feature."""
    leaky = score_all(df, warmup_end, features=features.FEATURES)
    leaky = leaky[leaky["day"] >= warmup_end].reset_index(drop=True)
    return {
        det: {
            "user_level": user_level(leaky, det, insiders),
            "daily_budget": {"10": daily_budget(leaky, det, bad, 10)},
        }
        for det in ("self", "peer", "iforest", "ensemble")
    }


def run(
    extracted: Path = Path("data/extracted"),
    answers: Path = Path("data/answers/answers"),
    out_dir: Path = Path("reports"),
    warmup_days: int = 60,
) -> dict[str, Any]:
    df = load_features(extracted, warmup_days)
    warmup_end = df["day"].min() + pd.Timedelta(days=warmup_days)
    scores = score_all(df, warmup_end)
    scores = scores[scores["day"] >= warmup_end].reset_index(drop=True)

    insiders = groundtruth.insiders(answers)
    bad = groundtruth.malicious_days(answers)
    bad = bad[bad["day"] >= warmup_end]
    who = set(insiders["user"])
    log.info("%d scored user-days after the warm-up, %d malicious", len(scores), len(bad))

    metrics = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "warmup_days": warmup_days,
        "period": [str(scores["day"].min().date()), str(scores["day"].max().date())],
        "base_rates": base_rates(scores, who, bad),
        "random_baseline": random_baseline(scores, who, bad),
        "detectors": evaluate(scores, who, bad, DETECTORS, incidents=insiders),
        "review_cards": review_cards(df, scores, bad, insiders),
        "artifact_audit": artifact_audit(df, warmup_end, who),
        "with_web_request_count": leak_ablation(df, warmup_end, who, bad),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    from ueba import plots, report

    figures = out_dir / "figures"
    plots.daily_budget(metrics, figures / "daily_budget.png")
    plots.top_k_curve(scores, who, figures / "insiders_top_k.png")
    plots.timeline(scores, bad, insiders, figures / "insider_timeline.png")
    (out_dir / "REPORT.md").write_text(report.render(metrics), encoding="utf-8")
    return metrics
