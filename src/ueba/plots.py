"""Report figures (matplotlib, Agg), same visual spec as the rest of the portfolio."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FixedLocator, NullLocator, PercentFormatter

from ueba.detectors import DETECTORS
from ueba.evaluate import daily_rank, example_insiders, users_by_worst_day

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
LABELS = {
    "rules": "Expert rules",
    "self": "Own-history baseline",
    "peer": "Peer-group baseline",
    "iforest": "Isolation Forest",
    "ensemble": "Ensemble",
}
COLORS = dict(zip(DETECTORS, SERIES, strict=True))
DASHED = (0, (3, 2))
SCENARIOS = {
    1: "Scenario 1\nnew after-hours activity,\nremovable drive, leak",
    2: "Scenario 2\njob hunting, data theft\nbefore leaving",
    3: "Scenario 3\nadmin sabotage\nwith a keylogger",
}

plt.rcParams.update(
    {
        "font.family": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK2,
        "ytick.labelcolor": INK2,
        "legend.frameon": False,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    }
)


def _style(ax: plt.Axes) -> None:
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _label(ax: plt.Axes, text: str, offset: float, **style: Any) -> None:
    """Left-aligned text ``offset`` points above the axes."""
    ax.annotate(
        text,
        xy=(0, 1),
        xycoords="axes fraction",
        xytext=(0, offset),
        textcoords="offset points",
        va="bottom",
        **style,
    )


def _titles(ax: plt.Axes, title: str, subtitle: str, offset: float = 8) -> None:
    _label(ax, subtitle, offset, fontsize=9.5, color=INK2)
    _label(ax, title, offset + 18, fontsize=13, fontweight="bold", color=INK)


def _days(delta: Any) -> Any:
    """Timedelta(s) as a number of days."""
    return delta / pd.Timedelta(days=1)


def _save(fig: plt.Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path


def daily_budget(metrics: dict[str, Any], path: Path, budget: str = "10") -> Path:
    """Share of insiders caught per scenario with ``budget`` reviews per day, vs. random reviews."""
    random = metrics["random_baseline"]["daily_budget"][budget]
    scenarios = [s for s in SCENARIOS if f"scenario_{s}" in random]
    fig, ax = plt.subplots(figsize=(7.6, 4.4), dpi=100)
    _style(ax)
    ax.grid(axis="x", visible=False)
    width, gap = 0.15, 0.01
    handles = []
    for k, det in enumerate(DETECTORS):
        res = metrics["detectors"][det]["daily_budget"][budget]
        shares = [
            res[f"scenario_{s}"]["caught"] / res[f"scenario_{s}"]["insiders"] for s in scenarios
        ]
        xs = np.arange(len(scenarios)) + (k - 2) * (width + gap)
        handles.append(ax.bar(xs, shares, width, color=COLORS[det], lw=0, label=LABELS[det]))
    half = 2.5 * width + 2 * gap
    for i, s in enumerate(scenarios):
        r = random[f"scenario_{s}"]
        ax.hlines(r["expected_caught"] / r["insiders"], i - half, i + half, color=INK, ls=DASHED)
    handles += ax.plot([], [], color=INK, ls=DASHED, label="Random reviews (expected)")
    ax.set_xticks(np.arange(len(scenarios)), [SCENARIOS[s] for s in scenarios])
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylabel("Insiders caught")
    ax.legend(
        handles=handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.25),
        ncol=3,
        fontsize=9,
        labelcolor=INK2,
    )
    b = metrics["base_rates"]
    _titles(
        ax,
        f"Insiders caught with {budget} reviews per day",
        f"CERT r4.2: {b['users']:,} employees, {b['insiders']} insiders; "
        "caught = among the day's top users on a malicious day",
    )
    return _save(fig, path)


def top_k_curve(scores: pd.DataFrame, insiders: set[str], path: Path, k_max: int = 200) -> Path:
    """Insiders found when employees are reviewed in order of their highest daily score."""
    fig, ax = plt.subplots(figsize=(7.6, 4.4), dpi=100)
    _style(ax)
    n_users = scores["user"].nunique()
    n_insiders = len(insiders & set(scores["user"]))
    k = np.arange(1, min(k_max, n_users) + 1)
    for det in DETECTORS:
        found = np.cumsum(users_by_worst_day(scores, det).index.isin(insiders))
        ax.step(k, found[: len(k)], where="post", color=COLORS[det], lw=1.8, label=LABELS[det])
    ax.plot(k, k * n_insiders / n_users, color=INK, lw=1.4, ls=DASHED, label="Random order")
    ax.set_xlim(0, k[-1])
    ax.set_ylim(0, n_insiders)
    ax.set_xlabel("Employees reviewed, most suspicious first")
    ax.set_ylabel(f"Insiders found (of {n_insiders})")
    ax.legend(loc="upper left", fontsize=9, labelcolor=INK2)
    _titles(
        ax,
        "Who should be investigated?",
        f"{n_users:,} employees ranked by their most anomalous day in the scored period",
    )
    return _save(fig, path)


def timeline(
    scores: pd.DataFrame,
    bad: pd.DataFrame,
    insiders: pd.DataFrame,
    path: Path,
    detector: str = "ensemble",
    budget: int = 10,
    window: tuple[int, int] = (-90, 60),
) -> Path:
    """Daily rank of each example insider (pseudonymised, first of each scenario in the answer
    key, not cherry-picked) in a fixed window of days around their first malicious day.

    No user ID or calendar date is shown, and the fixed window keeps the date from being read
    off where a line starts (the beginning of the scored period).
    """
    examples = example_insiders(insiders)
    fig, axes = plt.subplots(
        len(examples), 1, figsize=(7.6, 2.0 * len(examples) + 0.6), dpi=100, sharex=True
    )
    axes = np.atleast_1d(axes)
    fig.subplots_adjust(hspace=0.42)
    ranked = scores.assign(rank=daily_rank(scores, detector))
    bottom = max(int(ranked["rank"].max()), 1000) * 1.2
    for ax, who in zip(axes, examples.itertuples(), strict=True):
        _style(ax)
        mine = ranked[ranked["user"] == who.user].sort_values("day")
        bad_days = bad.loc[bad["user"] == who.user, "day"]
        first = bad_days.min()
        x, malicious = _days(mine["day"] - first), mine["day"].isin(bad_days)
        start, end = _days(who.start.normalize() - first), _days(who.end - first)
        ax.axvspan(start, end, color=SERIES[1], alpha=0.10, lw=0)
        ax.plot(x, mine["rank"], color=SERIES[0], lw=0.9, alpha=0.85)
        ax.scatter(
            x[malicious],
            mine["rank"][malicious],
            s=30,
            color=SERIES[1],
            ec=SURFACE,
            lw=1.2,
            zorder=5,
        )
        ax.axhline(budget, color=INK, lw=1.0, ls=DASHED)
        ax.set_yscale("log")
        ax.set_ylim(bottom, 0.8)
        ticks = [1, 10, 100, 1000]
        ax.yaxis.set_major_locator(FixedLocator(ticks))
        ax.yaxis.set_minor_locator(NullLocator())
        ax.set_yticklabels([f"#{t}" for t in ticks])
        _label(ax, f"Scenario {who.scenario} · insider {who.pseudonym}", 5, fontsize=9.5, color=INK)
    axes[-1].set_xlim(*window)
    axes[-1].set_xlabel("Days from the insider's first malicious day")
    axes[0].text(
        1.0,
        budget,
        f"  top {budget}",
        transform=axes[0].get_yaxis_transform(),
        fontsize=8.5,
        color=INK,
        va="center",
    )
    axes[len(axes) // 2].set_ylabel("Daily rank among active employees")
    _titles(
        axes[0],
        "What the analyst sees: one insider per scenario",
        f"{LABELS[detector]} rank each day (log scale); dots: malicious days; shaded: incident",
        offset=26,
    )
    return _save(fig, path)
