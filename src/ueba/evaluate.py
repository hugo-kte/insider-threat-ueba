"""Evaluation framed as an analyst's day, not as a leaderboard.

* **User level**: rank the employees by their highest daily score; how many insiders are among
  the top 10, 25, 50, 100? (ROC-AUC for completeness.)
* **Daily budget**: every day the analyst reviews the ``budget`` highest-scoring users (never a
  user whose score is 0: nothing fired). An insider counts as caught on the first day they appear
  in that list on one of their malicious days. Reported per scenario, with the delay from the
  insider's first malicious day.
* **User-day level**: average precision of the user-day ranking (malicious days are rare).

Each metric comes with what a random ranking would achieve with the same budget. Tied scores are
ordered at random (fixed seed), never by user ID.
"""

from __future__ import annotations

from string import ascii_uppercase
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ueba.detectors import explain
from ueba.features import FEATURE_LABELS, FEATURES

TOP_K = (10, 25, 50, 100)
SEED = 0


def users_by_worst_day(scores: pd.DataFrame, detector: str) -> pd.Series:
    """Each user's highest daily score, most suspicious first."""
    worst = scores.groupby("user")[detector].max().sample(frac=1, random_state=SEED)
    return worst.sort_values(ascending=False, kind="stable")


def daily_rank(scores: pd.DataFrame, detector: str) -> pd.Series:
    """Rank among the day's active users, 1 = most suspicious."""
    shuffled = scores[["day", detector]].sample(frac=1, random_state=SEED)
    rank = shuffled.groupby("day")[detector].rank(ascending=False, method="first")
    return rank.reindex(scores.index)


def user_level(scores: pd.DataFrame, detector: str, insiders: set[str]) -> dict[str, Any]:
    per_user = users_by_worst_day(scores, detector)
    y = per_user.index.isin(insiders)
    return {
        "roc_auc": float(roc_auc_score(y, per_user.to_numpy())),
        **{f"insiders_in_top_{k}": int(y[:k].sum()) for k in TOP_K},
    }


def _per_scenario(bad_days: pd.DataFrame) -> pd.Series:
    return bad_days.groupby("user")["scenario"].first().astype(int)


def daily_budget(
    scores: pd.DataFrame,
    detector: str,
    bad_days: pd.DataFrame,
    budget: int,
    incidents: pd.DataFrame | None = None,
) -> dict[str, Any]:
    flagged = (daily_rank(scores, detector) <= budget) & (scores[detector] > 0)
    reviewed = scores.loc[flagged, ["user", "day"]]
    hits = reviewed.merge(bad_days, on=["user", "day"])
    first_bad = bad_days.groupby("user")["day"].min()
    caught = hits.groupby("user")["day"].min()
    scen = _per_scenario(bad_days)
    out: dict[str, Any] = {"budget_per_day": budget}
    for s in sorted(scen.unique()):
        users = scen[scen == s].index
        found = caught.reindex(users).dropna()
        delays = (found - first_bad.reindex(found.index)).dt.days
        out[f"scenario_{s}"] = {
            "insiders": len(users),
            "caught": len(found),
            "median_delay_days": float(delays.median()) if len(delays) else None,
        }
    out["caught_total"] = int(caught.size)
    out["insiders_total"] = int(scen.size)
    out["reviews_total"] = len(reviewed)
    out["reviews_on_malicious_days"] = len(hits)
    if incidents is not None:
        out["reviewed_during_incident_total"] = _reviewed_during_incident(reviewed, incidents)
    return out


def _reviewed_during_incident(reviewed: pd.DataFrame, incidents: pd.DataFrame) -> int:
    """Insiders reviewed on any day from their incident's start to its end, whether or not that
    day has a labelled event: a lenient catch (the analyst looked while it was going on)."""
    w = reviewed.merge(incidents[["user", "start", "end"]], on="user")
    during = (w["day"] >= w["start"].dt.normalize()) & (w["day"] <= w["end"])
    return int(w.loc[during, "user"].nunique())


def random_daily_budget(scores: pd.DataFrame, bad_days: pd.DataFrame, budget: int) -> dict:
    """Expected catches if the analyst picked ``budget`` of the day's active users at random."""
    active = scores.groupby("day").size()
    seen = bad_days.merge(scores[["user", "day"]], on=["user", "day"])
    p_review = np.minimum(1.0, budget / seen["day"].map(active).to_numpy())
    p_caught = 1 - pd.Series(1 - p_review).groupby(seen["user"].to_numpy()).prod()
    scen = _per_scenario(bad_days)
    p_caught = p_caught.reindex(scen.index, fill_value=0.0)
    out: dict[str, Any] = {"budget_per_day": budget}
    for s in sorted(scen.unique()):
        users = scen[scen == s].index
        out[f"scenario_{s}"] = {
            "insiders": len(users),
            "expected_caught": round(float(p_caught[users].sum()), 2),
        }
    out["expected_caught_total"] = round(float(p_caught.sum()), 2)
    out["insiders_total"] = int(scen.size)
    return out


def day_level(scores: pd.DataFrame, detector: str, bad_days: pd.DataFrame) -> dict[str, float]:
    y = _is_malicious(scores, bad_days)
    s = scores[detector].to_numpy()
    return {
        "average_precision": float(average_precision_score(y, s)),
        "roc_auc": float(roc_auc_score(y, s)),
    }


def _is_malicious(scores: pd.DataFrame, bad_days: pd.DataFrame) -> np.ndarray:
    keys = pd.MultiIndex.from_frame(bad_days[["user", "day"]])
    return pd.MultiIndex.from_frame(scores[["user", "day"]]).isin(keys)


def evaluate(
    scores: pd.DataFrame,
    insiders: set[str],
    bad_days: pd.DataFrame,
    detectors: list[str],
    budgets: tuple[int, ...] = (5, 10),
    incidents: pd.DataFrame | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for det in detectors:
        out[det] = {
            "user_level": user_level(scores, det, insiders),
            "day_level": day_level(scores, det, bad_days),
            "daily_budget": {
                str(b): daily_budget(scores, det, bad_days, b, incidents) for b in budgets
            },
        }
    return out


def random_baseline(
    scores: pd.DataFrame,
    insiders: set[str],
    bad_days: pd.DataFrame,
    budgets: tuple[int, ...] = (5, 10),
) -> dict[str, Any]:
    n_users = scores["user"].nunique()
    n_insiders = len(insiders & set(scores["user"]))
    return {
        "user_level": {
            "roc_auc": 0.5,
            **{
                f"insiders_in_top_{k}": round(min(k, n_users) * n_insiders / n_users, 2)
                for k in TOP_K
            },
        },
        "day_level": {"average_precision": float(_is_malicious(scores, bad_days).mean())},
        "daily_budget": {str(b): random_daily_budget(scores, bad_days, b) for b in budgets},
    }


def example_insiders(insiders: pd.DataFrame) -> pd.DataFrame:
    """The first insider of each scenario in the answer key (not cherry-picked), pseudonymised.

    These are the insiders of the review cards and the timeline figure. The answer key's terms of
    use allow reports but not redistribution, so the outputs name them "A", "B", ... and count
    days from their first malicious day: no user ID or date from the answer key is published.
    """
    first = insiders.sort_values("scenario", kind="stable").drop_duplicates("scenario")
    return first.assign(pseudonym=list(ascii_uppercase[: len(first)])).reset_index(drop=True)


def review_cards(
    df: pd.DataFrame, scores: pd.DataFrame, bad_days: pd.DataFrame, insiders: pd.DataFrame
) -> list[dict[str, Any]]:
    """Review card of each example insider on their best-ranked malicious day for the ensemble."""
    ranked = scores.assign(rank=daily_rank(scores, "ensemble"))
    cards = []
    for who in example_insiders(insiders).itertuples():
        mine = bad_days.loc[bad_days["user"] == who.user, ["user", "day"]]
        days = ranked.merge(mine)
        if days.empty:
            continue
        best = days.loc[days["rank"].idxmin()]
        card = explain(df, who.user, best["day"])
        cards.append(
            {
                "scenario": int(who.scenario),
                "insider": who.pseudonym,
                "days_after_first_malicious_day": (best["day"] - mine["day"].min()).days,
                "ensemble_rank": int(best["rank"]),
                "top_features": [
                    {"feature": FEATURE_LABELS[name], **{k: float(v) for k, v in row.items()}}
                    for name, row in card.iterrows()
                ],
            }
        )
    return cards


def artifact_audit(
    df: pd.DataFrame, warmup_end: pd.Timestamp, insiders: set[str]
) -> dict[str, Any]:
    """Why the web request count is not a feature.

    Label-free: during the warm-up, how many users make exactly the same number of requests on
    every day they browse (and, for contrast, how many users are flat on each feature). The
    answer key is only used to document who has a count that ever changes.
    """
    warm = df[df["day"] < warmup_end]
    browsing = df[df["n_http"] > 0]
    warm_browsing = browsing[browsing["day"] < warmup_end]
    same_every_day = warm_browsing.groupby("user")["n_http"].nunique() == 1
    distinct = browsing.groupby("user")["n_http"].nunique()
    changes = distinct.index[distinct > 1]
    flat = (warm.groupby("user")[FEATURES].std().fillna(0.0) == 0).mean()
    scored = df[df["day"] >= warmup_end]
    return {
        "scored_user_days_with_a_never_visited_domain": round(
            float((scored["n_http_new_domains"] > 0).mean()), 4
        ),
        "web_request_count": {
            "users": int(distinct.size),
            "same_count_every_browsing_day_during_warmup": int(same_every_day.sum()),
            "mean_requests_per_browsing_day_during_warmup": round(
                float(warm_browsing["n_http"].mean()), 1
            ),
            "users_whose_count_ever_changes": len(changes),
            "insiders_among_them": int(changes.isin(insiders).sum()),
            "insiders_total": len(insiders),
        },
        "share_of_users_flat_during_warmup": {f: round(float(flat[f]), 3) for f in FEATURES},
    }


def base_rates(scores: pd.DataFrame, insiders: set[str], bad_days: pd.DataFrame) -> dict:
    malicious = _is_malicious(scores, bad_days)
    return {
        "users": int(scores["user"].nunique()),
        "roles": int(scores["role"].nunique()),
        "insiders": len(insiders & set(scores["user"])),
        "days": int(scores["day"].nunique()),
        "user_days": len(scores),
        "malicious_user_days_in_answer_key": len(bad_days),
        "malicious_user_days": int(malicious.sum()),  # those with logged activity, i.e. scorable
        "share_malicious": float(malicious.mean()),
    }
