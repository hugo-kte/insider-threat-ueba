"""Behaviour detectors over the user-day table.

Every score for a day only uses what is known at the end of that day:

* ``rules``: an expert rule (after-hours activity, removable media, other users' machines), the
  usual SIEM baseline.
* ``self``: robust deviation from the user's own previous active days (trailing window, today
  excluded).
* ``peer``: robust deviation from colleagues with the same role on the same day.
* ``iforest``: Isolation Forest fitted on the warm-up period only, on log counts and self
  deviations.
* ``ensemble``: mean of the self, peer and iforest scores, each first converted to its percentile
  among the warm-up user-days. The calibration is frozen after the warm-up, so no later score can
  move an earlier one (unlike ranks computed over the whole period).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view
from sklearn.ensemble import IsolationForest

from ueba.features import MODEL_FEATURES

DETECTORS = ["rules", "self", "peer", "iforest", "ensemble"]

WINDOW, MIN_HISTORY = 30, 10  # own-history baseline: previous active days considered / needed
EPS = 1.0  # count data: +1 in the denominator stops a flat history (IQR = 0) from exploding
IQR_PER_SIGMA = 1.349  # interquartile range of a normal distribution, in standard deviations
QUARTILES = (0.25, 0.5, 0.75)


def robust_z(x: np.ndarray, q1: np.ndarray, median: np.ndarray, q3: np.ndarray) -> np.ndarray:
    """(x - median) / (IQR as a standard deviation + EPS): one past spike barely moves it."""
    return (x - median) / ((q3 - q1) / IQR_PER_SIGMA + EPS)


def trailing_quartiles(x: np.ndarray, window: int, min_history: int) -> np.ndarray:
    """Quartiles of the ``window`` rows before each row of ``x`` (n, F), the row itself excluded.

    Returns an array (3, n, F), NaN for rows with fewer than ``min_history`` previous rows.
    """
    if not 1 <= min_history <= window:
        raise ValueError(f"need 1 <= min_history <= window, got {min_history} and {window}")
    n = len(x)
    out = np.full((len(QUARTILES), *x.shape), np.nan)
    for i in range(min_history, min(window, n)):  # history still shorter than the window
        out[:, i] = np.quantile(x[:i], QUARTILES, axis=0)
    if n > window:
        past = sliding_window_view(x[:-1], window, axis=0)  # past[j]: rows j .. j + window - 1
        out[:, window:] = np.quantile(past, QUARTILES, axis=-1)
    return out


def self_z(
    df: pd.DataFrame,
    features: list[str] = MODEL_FEATURES,
    window: int = WINDOW,
    min_history: int = MIN_HISTORY,
) -> pd.DataFrame:
    """Robust z-score of each feature against the user's previous ``window`` active days.

    Rows with less than ``min_history`` days of history get 0 (no opinion yet).
    """
    x = df[features].to_numpy(np.float64)
    day = df["day"].to_numpy()
    z = np.zeros_like(x)
    for rows in df.groupby("user", sort=False).indices.values():
        rows = rows[np.argsort(day[rows], kind="stable")]
        q1, median, q3 = trailing_quartiles(x[rows], window, min_history)
        z[rows] = robust_z(x[rows], q1, median, q3)
    return pd.DataFrame(np.nan_to_num(z), index=df.index, columns=features)


def peer_z(df: pd.DataFrame, features: list[str] = MODEL_FEATURES) -> pd.DataFrame:
    """Robust z-score of each feature against colleagues with the same role on the same day."""
    grouped = df.groupby(["day", "role"], sort=False)[features]
    q1, median, q3 = (grouped.transform("quantile", q=q).to_numpy(np.float64) for q in QUARTILES)
    z = robust_z(df[features].to_numpy(np.float64), q1, median, q3)
    return pd.DataFrame(z, index=df.index, columns=features)


def top_k_sum(z: pd.DataFrame, k: int = 3) -> pd.Series:
    """Sum of the k largest positive deviations: several mild signals beat one spike."""
    arr = np.clip(z.to_numpy(dtype=np.float64), 0, None)
    arr.sort(axis=1)
    return pd.Series(arr[:, -k:].sum(axis=1), index=z.index)


def rules_score(df: pd.DataFrame) -> pd.Series:
    return (
        2.0 * df["n_usb_after_hours"]
        + df["n_file_after_hours"]
        + 0.5 * df["n_logon_after_hours"]
        + 0.5 * df["n_logon_other_pc"]
    )


def warmup_percentile(score: pd.Series, warm: np.ndarray) -> pd.Series:
    """Percentile of each score among the warm-up scores (mid-rank for ties)."""
    ref = np.sort(score.to_numpy()[warm])
    s = score.to_numpy()
    below, at_or_below = np.searchsorted(ref, s, "left"), np.searchsorted(ref, s, "right")
    return pd.Series((below + at_or_below) / (2 * len(ref)), index=score.index)


def explain(
    df: pd.DataFrame,
    user: str,
    day: pd.Timestamp,
    features: list[str] = MODEL_FEATURES,
    top: int = 3,
) -> pd.DataFrame:
    """The analyst's review card: features furthest from the user's own past and from peers.

    Same statistics as the two baselines (previous ``WINDOW`` active days; same role, same day).
    """
    mine = df[df["user"] == user].sort_values("day")
    today = mine[mine["day"] == day].iloc[0]
    x = today[features].to_numpy(np.float64)
    past = mine.loc[mine["day"] < day, features].tail(WINDOW).to_numpy(np.float64)
    peers = df.loc[(df["day"] == day) & (df["role"] == today["role"]), features]
    own = np.quantile(past, QUARTILES, axis=0) if len(past) else np.full((3, len(x)), np.nan)
    peer = np.quantile(peers.to_numpy(np.float64), QUARTILES, axis=0)
    card = pd.DataFrame(
        {
            "value": x,
            "own_median": own[1],
            "peer_median": peer[1],
            "own_z": robust_z(x, *own),
            "peer_z": robust_z(x, *peer),
        },
        index=pd.Index(features, name="feature"),
    )
    return card.loc[card[["own_z", "peer_z"]].max(axis=1).nlargest(top).index]


def score_all(
    df: pd.DataFrame,
    warmup_end: pd.Timestamp,
    features: list[str] = MODEL_FEATURES,
    seed: int = 0,
    n_jobs: int = 4,
) -> pd.DataFrame:
    """One column per detector. Rows before ``warmup_end`` only serve as history and training."""
    out = df[["user", "day", "role"]].copy()
    sz = self_z(df, features)
    out["rules"] = rules_score(df)
    out["self"] = top_k_sum(sz)
    out["peer"] = top_k_sum(peer_z(df, features))
    X = np.hstack(
        [np.log1p(df[features].to_numpy(dtype=np.float64)), np.clip(sz.to_numpy(), -10, 10)]
    )
    warm = (df["day"] < warmup_end).to_numpy()
    forest = IsolationForest(
        n_estimators=300, max_samples=min(4096, int(warm.sum())), random_state=seed, n_jobs=n_jobs
    )
    forest.fit(X[warm])
    out["iforest"] = -forest.score_samples(X)
    calibrated = [warmup_percentile(out[det], warm) for det in ("self", "peer", "iforest")]
    out["ensemble"] = sum(calibrated) / len(calibrated)
    return out
