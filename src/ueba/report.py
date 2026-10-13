"""Markdown evaluation report."""

from __future__ import annotations

from typing import Any

from ueba.evaluate import TOP_K
from ueba.plots import LABELS

SCENARIO_KEYS = ("scenario_1", "scenario_2", "scenario_3")


def _fmt(x: float) -> str:
    if x != x:  # NaN: no history to compare with
        return "–"
    return f"{x:g}" if x == int(x) else f"{x:.1f}"


def render(m: dict[str, Any]) -> str:
    b, rnd = m["base_rates"], m["random_baseline"]
    lines = [
        "# UEBA evaluation report (CERT r4.2)",
        "",
        f"_Generated {m['generated_at']}. Scored period {m['period'][0]} to {m['period'][1]}, "
        f"after a {m['warmup_days']}-day warm-up used only as history and training data._",
        "",
        f"{b['users']:,} users ({b['insiders']} insiders), {b['days']} days, "
        f"{b['user_days']:,} active user-days, of which {b['malicious_user_days']:,} malicious "
        f"({100 * b['share_malicious']:.2f}%).",
        "",
        f"## Who should be investigated? (user level, {b['insiders']} insiders among "
        f"{b['users']:,} employees)",
        "",
        "Employees ranked by their highest daily score: insiders among the first k.",
        "",
        "| Detector | ROC-AUC | " + " | ".join(f"Top {k}" for k in TOP_K) + " |",
        "|---|---:|" + "---:|" * len(TOP_K),
    ]
    for det, r in m["detectors"].items():
        u = r["user_level"]
        cells = " | ".join(str(u[f"insiders_in_top_{k}"]) for k in TOP_K)
        lines.append(f"| {LABELS[det]} | {u['roc_auc']:.3f} | {cells} |")
    ru = rnd["user_level"]
    cells = " | ".join(_fmt(ru[f"insiders_in_top_{k}"]) for k in TOP_K)
    lines += [
        f"| _Random order (expected)_ | 0.500 | {cells} |",
        "",
        "## An analyst's day: insiders caught with a fixed number of reviews per day",
        "",
        "Every day the analyst reviews the top-scoring users; an insider is caught when reviewed "
        "on one of their malicious days. Delay: days from the insider's first malicious day. "
        "During incident (lenient): reviewed on any day between the incident's start and end.",
        "",
        "| Detector | Reviews/day | Scenario 1 | Scenario 2 | Scenario 3 | Total "
        "| Median delay S1/S2/S3 (days) | During incident |",
        "|---|---:|---:|---:|---:|---:|---|---:|",
    ]
    for det, r in m["detectors"].items():
        for budget, d in r["daily_budget"].items():
            scen = [d.get(s) for s in SCENARIO_KEYS]
            cells = ["–" if x is None else f"{x['caught']}/{x['insiders']}" for x in scen]
            delays = "/".join(
                "–" if x is None or x["median_delay_days"] is None else _fmt(x["median_delay_days"])
                for x in scen
            )
            during = d.get("reviewed_during_incident_total")
            lines.append(
                f"| {LABELS[det]} | {budget} | "
                + " | ".join(cells)
                + f" | {d['caught_total']}/{d['insiders_total']} | {delays} | "
                + ("–" if during is None else f"{during}/{d['insiders_total']}")
                + " |"
            )
    for budget, d in rnd["daily_budget"].items():
        scen = [d.get(s) for s in SCENARIO_KEYS]
        cells = ["–" if x is None else f"{x['expected_caught']:.1f}" for x in scen]
        lines.append(
            f"| _Random reviews (expected)_ | {budget} | "
            + " | ".join(cells)
            + f" | {d['expected_caught_total']:.1f} | | |"
        )
    lines += [
        "",
        "![Insiders caught](figures/daily_budget.png)",
        "",
        "![Insiders in the top k](figures/insiders_top_k.png)",
        "",
        "## User-day ranking",
        "",
        "| Detector | Average precision | ROC-AUC |",
        "|---|---:|---:|",
    ]
    for det, r in m["detectors"].items():
        d = r["day_level"]
        lines.append(f"| {LABELS[det]} | {d['average_precision']:.3f} | {d['roc_auc']:.3f} |")
    lines += [
        f"| _Random order (expected)_ | {rnd['day_level']['average_precision']:.4f} | 0.500 |",
        "",
        "## What the analyst sees",
        "",
        "The first insider of each scenario in the answer key, on their best-ranked malicious "
        "day: the three features furthest from their own past and from their peers. The answer "
        "key may be reported on but not redistributed, so insiders are pseudonymised and days "
        "counted from their first malicious day.",
        "",
        "| Scenario | Insider | Days after first malicious day | Ensemble rank "
        "| Top deviations: value (own median / peer median) |",
        "|---:|---|---:|---:|---|",
    ]
    for c in m.get("review_cards", []):
        devs = "; ".join(
            f"{f['feature']} {_fmt(f['value'])} "
            f"({_fmt(f['own_median'])} / {_fmt(f['peer_median'])})"
            for f in c["top_features"]
        )
        lines.append(
            f"| {c['scenario']} | {c['insider']} | {c['days_after_first_malicious_day']} "
            f"| #{c['ensemble_rank']} | {devs} |"
        )
    lines += [
        "",
        "_Daily counts derived from the CERT r4.2 test data files: Copyright © 2011 ExactData, "
        "LLC, All Rights Reserved._",
        "",
        "![Insider timeline](figures/insider_timeline.png)",
    ]
    if "artifact_audit" in m:
        lines += _leak_section(m)
    return "\n".join(lines) + "\n"


def _leak_section(m: dict[str, Any]) -> list[str]:
    web = m["artifact_audit"]["web_request_count"]
    lines = [
        "",
        "## A leak in the dataset: the daily web request count",
        "",
        f"During the warm-up, {web['same_count_every_browsing_day_during_warmup']:,} of "
        f"{web['users']:,} users make exactly the same number of web requests on every day they "
        f"browse ({web['mean_requests_per_browsing_day_during_warmup']:g} on average). Over the "
        f"whole period the count changes for only {web['users_whose_count_ever_changes']} users, "
        f"including {web['insiders_among_them']} of the {web['insiders_total']} insiders: "
        "injected red-team web events are the main thing that moves it. The count is therefore "
        "excluded from every detector. For the record, this is what it would do:",
        "",
        "| Detector | Insiders caught, 10 reviews/day | ROC-AUC (user level) |",
        "|---|---:|---:|",
    ]
    for det, leaky in m.get("with_web_request_count", {}).items():
        clean = m["detectors"][det]
        d, c = leaky["daily_budget"]["10"], clean["daily_budget"]["10"]
        lines.append(
            f"| {LABELS[det]} | {c['caught_total']}/{c['insiders_total']} -> "
            f"{d['caught_total']}/{d['insiders_total']} | "
            f"{clean['user_level']['roc_auc']:.3f} -> {leaky['user_level']['roc_auc']:.3f} |"
        )
    chance = m["random_baseline"]["daily_budget"]["10"]["expected_caught_total"]
    lines.append(f"| _Random reviews (expected)_ | {chance:.1f} | 0.500 |")
    return lines
