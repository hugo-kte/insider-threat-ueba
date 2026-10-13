"""End-to-end tests on a miniature archive in the CERT r4.2 layout (no download needed)."""

from __future__ import annotations

import bz2
import io
import json
import random
import shutil
import tarfile
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from typer.testing import CliRunner

from ueba import features, groundtruth
from ueba.cli import app
from ueba.detectors import (
    DETECTORS,
    explain,
    peer_z,
    score_all,
    self_z,
    top_k_sum,
    trailing_quartiles,
    warmup_percentile,
)
from ueba.evaluate import artifact_audit, daily_budget, random_daily_budget, user_level
from ueba.extract import COLUMNS, aggregate_http, extract
from ueba.pipeline import load_features

START = datetime(2010, 1, 4)
USERS = [f"USR{i:04d}" for i in range(12)]
INSIDER = "USR0007"
THEFT_DAYS = range(70, 76)


def fmt(ts: datetime) -> str:
    return ts.strftime("%m/%d/%Y %H:%M:%S")


def make_logs(days: int = 90, seed: int = 0) -> dict[str, str]:
    rng = random.Random(seed)
    logon, device, file, email, http = (
        ["id,date,user,pc,activity"],
        ["id,date,user,pc,activity"],
        ["id,date,user,pc,filename,content"],
        ["id,date,user,pc,to,cc,bcc,from,size,attachments,content"],
        ["id,date,user,pc,url,content"],
    )
    n = 0
    for d in range(days):
        day = START + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for u, user in enumerate(USERS):
            pc = f"PC-{u:04d}"
            theft = user == INSIDER and d in THEFT_DAYS
            hour = 22 if theft else rng.randint(8, 9)
            n += 1
            logon.append(f"{{L{n}}},{fmt(day.replace(hour=hour))},{user},{pc},Logon")
            if theft:
                device.append(f"{{D{n}}},{fmt(day.replace(hour=22, minute=5))},{user},{pc},Connect")
                for k in range(5):
                    ts = fmt(day.replace(hour=22, minute=10 + k))
                    file.append(f"{{F{n}{k}}},{ts},{user},{pc},doc{k}.zip,x")
            email.append(
                f"{{E{n}}},{fmt(day.replace(hour=11))},{user},{pc},a@dtaa.com,,,{user}@dtaa.com,1000,0,hi"
            )
            http.append(
                f"{{H{n}}},{fmt(day.replace(hour=12))},{user},{pc},http://news.example.com/{d},x"
            )
    ldap = [
        "employee_name,user_id,email,role,business_unit,functional_unit,department,team,supervisor"
    ]
    ldap += [f"Name {u},{u},{u}@dtaa.com,Engineer,1,1,Dev,1,Boss" for u in USERS]
    return {
        "r4.2/logon.csv": "\n".join(logon),
        "r4.2/device.csv": "\n".join(device),
        "r4.2/file.csv": "\n".join(file),
        "r4.2/email.csv": "\n".join(email),
        "r4.2/http.csv": "\n".join(http),
        "r4.2/LDAP/2010-01.csv": "\n".join(ldap),
    }


def make_archive(tmp: Path) -> Path:
    """Tar compressed as two concatenated bzip2 streams, like the real (pbzip2) archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, text in make_logs().items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    path = tmp / "r4.2.tar.bz2"
    path.write_bytes(bz2.compress(raw[: len(raw) // 2]) + bz2.compress(raw[len(raw) // 2 :]))
    return path


def make_answers(tmp: Path) -> Path:
    root = tmp / "answers"
    (root / "r4.2-2").mkdir(parents=True)
    first, last = START + timedelta(days=THEFT_DAYS[0]), START + timedelta(days=THEFT_DAYS[-1])
    (root / "insiders.csv").write_text(
        "dataset,scenario,details,user,start,end\n"
        f"4.2,2,r4.2-2-{INSIDER}.csv,{INSIDER},{fmt(first)},{fmt(last.replace(hour=23))}\n"
    )
    rows = [
        f"device,{{X{d}}},{fmt((START + timedelta(days=d)).replace(hour=22))},{INSIDER},PC-0007,Connect"  # noqa: E501
        for d in THEFT_DAYS
        if (START + timedelta(days=d)).weekday() < 5
    ]
    (root / "r4.2-2" / f"r4.2-2-{INSIDER}.csv").write_text("\n".join(rows))
    return root


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> tuple[Path, Path]:
    tmp = tmp_path_factory.mktemp("cert")
    extract(make_archive(tmp), tmp / "extracted")
    return tmp / "extracted", make_answers(tmp)


def test_extract_keeps_only_what_the_features_read(workspace):
    extracted, _ = workspace
    assert not list(extracted.rglob("*.csv"))  # no raw log reaches the disk
    for log in ("logon", "device", "file", "email"):
        kept = pd.read_parquet(extracted / f"{log}.parquet").columns.tolist()
        assert kept == COLUMNS[f"{log}.csv"].names and "content" not in kept
    ldap = pd.read_parquet(extracted / "LDAP" / "2010-01.parquet")
    assert ldap.columns.tolist() == ["user_id", "role", "department"]  # no names or addresses
    n_emails = len(make_logs()["r4.2/email.csv"].splitlines()) - 1  # header
    assert len(pd.read_parquet(extracted / "email.parquet")) == n_emails  # every row is kept
    http = pd.read_parquet(extracted / "http_daily.parquet")
    assert http["n_http"].sum() > 0 and http["n_http_new_domains"].max() == 1  # one domain each


def test_new_domains_are_counted_once_per_user():
    csv = "id,date,user,pc,url,content\n" + "\n".join(
        f"{{H{i}}},01/0{1 + i // 2}/2010 10:00:00,U1,PC,http://site{i % 2}.example.com/p,x"
        for i in range(4)
    )
    agg = aggregate_http(io.BytesIO(csv.encode()))
    assert agg["n_http"].tolist() == [2, 2] and agg["n_http_new_domains"].tolist() == [2, 0]


def test_features(workspace):
    extracted, _ = workspace
    df = features.build(extracted, warmup_days=30)
    row = df[(df["user"] == INSIDER) & (df["day"] == pd.Timestamp(START + timedelta(days=70)))]
    assert row.iloc[0]["n_usb_after_hours"] == 1 and row.iloc[0]["n_file_after_hours"] == 5
    assert set(features.FEATURES) <= set(df.columns) and (df["role"] == "Engineer").all()
    assert df[df["user"] != INSIDER]["n_usb"].sum() == 0


def test_baselines_only_look_at_the_past():
    df = pd.DataFrame(
        {
            "user": ["a"] * 15,
            "day": pd.date_range("2010-01-01", periods=15),
            "role": "x",
            **{f: 1.0 for f in features.FEATURES},
        }
    )
    df.loc[14, "n_usb"] = 50.0
    z = self_z(df, window=10, min_history=5)
    assert z.loc[:13, "n_usb"].abs().max() == 0  # the spike does not leak backwards
    assert z.loc[14, "n_usb"] > 40
    assert top_k_sum(
        pd.DataFrame({"a": [1.0, -5], "b": [2.0, 3], "c": [4.0, 0]}), k=2
    ).tolist() == [6.0, 3.0]
    peers = peer_z(pd.concat([df.iloc[[14]], df.iloc[[14]].assign(user="b", n_usb=1.0)]))
    assert peers["n_usb"].iloc[0] > 0 > peers["n_usb"].iloc[1]


def test_ground_truth(workspace):
    _, answers = workspace
    ins = groundtruth.insiders(answers)
    bad = groundtruth.malicious_days(answers)
    assert ins["user"].tolist() == [INSIDER] and (bad["user"] == INSIDER).all()
    assert bad["scenario"].unique().tolist() == [2]


def test_trailing_quartiles_match_a_naive_loop():
    x = np.random.default_rng(0).poisson(3, size=(40, 3)).astype(float)
    got = trailing_quartiles(x, window=10, min_history=4)
    for i in range(len(x)):
        past = x[max(0, i - 10) : i]
        want = np.quantile(past, (0.25, 0.5, 0.75), axis=0) if i >= 4 else np.full((3, 3), np.nan)
        np.testing.assert_allclose(got[:, i], want, equal_nan=True)


def noisy_user_days(n_users: int = 24, n_days: int = 70, seed: int = 0) -> pd.DataFrame:
    """User-day table in which every feature varies, on days when 80% of the users are active."""
    rng = np.random.default_rng(seed)
    days = pd.date_range("2010-01-04", periods=n_days)
    df = pd.DataFrame(
        [(f"U{u:02d}", f"role{u % 3}", day) for day in days for u in range(n_users)],
        columns=["user", "role", "day"],
    )
    df = df[rng.random(len(df)) < 0.8].reset_index(drop=True)
    rates = rng.uniform(0.1, 5.0, size=len(features.FEATURES))
    df[features.FEATURES] = rng.poisson(rates, size=(len(df), len(rates))).astype(float)
    return df


def test_scores_ignore_the_future():
    """Cutting the data after day t must not change any score up to t: no look-ahead anywhere.

    Every feature is noisy, so a window reaching forward, peer statistics pooled across days, a
    forest fitted beyond the warm-up or a calibration over the whole period would all move a score.
    """
    df = noisy_user_days()
    warmup_end = df["day"].min() + pd.Timedelta(days=30)
    full = score_all(df, warmup_end, n_jobs=1)
    for cutoff in warmup_end + pd.to_timedelta([0, 11, 38], unit="D"):
        past = score_all(df[df["day"] <= cutoff].reset_index(drop=True), warmup_end, n_jobs=1)
        pd.testing.assert_frame_equal(full[full["day"] <= cutoff].reset_index(drop=True), past)


def test_detectors_find_the_insider(workspace):
    extracted, answers = workspace
    df = features.build(extracted, warmup_days=30)
    scores = score_all(df, df["day"].min() + pd.Timedelta(days=30))
    bad = groundtruth.malicious_days(answers)
    # Not the Isolation Forest: nobody touched a USB drive during this toy warm-up, and a tree
    # cannot split on a feature that was constant in its training data.
    for det in ("rules", "self", "peer", "ensemble"):
        assert scores.groupby("user")[det].max().idxmax() == INSIDER, det
        assert user_level(scores, det, {INSIDER})["roc_auc"] == 1.0, det
    result = daily_budget(scores, "rules", bad, budget=1)
    assert result["scenario_2"]["caught"] == 1 and result["scenario_2"]["median_delay_days"] == 0


def test_feature_cache_is_rebuilt_when_the_feature_code_changes(workspace, tmp_path, monkeypatch):
    extracted = shutil.copytree(workspace[0], tmp_path / "extracted")
    fresh = load_features(extracted, warmup_days=30)
    cache = extracted / f"features_warmup30_{features.CODE_VERSION}.parquet"
    fresh.head(3).to_parquet(cache, index=False)  # a stale table under the current code's name
    assert len(load_features(extracted, warmup_days=30)) == 3  # same code: the cache is reused
    monkeypatch.setattr(features, "CODE_VERSION", "edited")
    assert len(load_features(extracted, warmup_days=30)) == len(fresh)  # new code: rebuilt


def test_review_card_names_what_changed(workspace):
    extracted, _ = workspace
    df = features.build(extracted, warmup_days=30)
    card = explain(df, INSIDER, pd.Timestamp(START + timedelta(days=THEFT_DAYS[0])))
    assert card.index[:2].tolist() == ["n_file", "n_file_after_hours"]
    assert card.loc["n_file", ["value", "own_median", "peer_median"]].tolist() == [5, 0, 0]


def test_artifact_audit_spots_a_flat_web_request_count(workspace):
    extracted, _ = workspace
    df = features.build(extracted, warmup_days=30)
    warmup_end = df["day"].min() + pd.Timedelta(days=30)
    later = df["day"] >= warmup_end + pd.Timedelta(days=10)
    df.loc[(df["user"] == INSIDER) & later, "n_http"] += 3  # injected events
    web = artifact_audit(df, warmup_end, {INSIDER})["web_request_count"]
    assert web["same_count_every_browsing_day_during_warmup"] == len(USERS)
    assert web["users_whose_count_ever_changes"] == 1 and web["insiders_among_them"] == 1


def test_daily_budget_never_reviews_a_user_with_nothing_flagged():
    day = pd.Timestamp("2010-06-01")
    scores = pd.DataFrame({"user": ["A", "B", "C"], "day": day, "rules": [0.0, 0.0, 2.0]})
    bad = pd.DataFrame({"user": ["A"], "day": [day], "scenario": [1]})
    result = daily_budget(scores, "rules", bad, budget=3)
    assert result["reviews_total"] == 1 and result["caught_total"] == 0


def test_a_review_during_the_incident_is_only_a_lenient_catch():
    days = pd.to_datetime(["2010-06-01", "2010-06-02", "2010-06-03"])
    scores = pd.DataFrame({"user": "A", "day": days, "rules": [0.0, 5.0, 0.0]})
    bad = pd.DataFrame({"user": ["A"], "day": [days[2]], "scenario": [1]})  # labelled: day 3
    incident = pd.DataFrame({"user": ["A"], "start": [days[0]], "end": [days[2]]})
    result = daily_budget(scores, "rules", bad, budget=1, incidents=incident)
    assert result["caught_total"] == 0 and result["reviewed_during_incident_total"] == 1


def test_random_baseline_is_the_chance_of_being_drawn():
    days = pd.to_datetime(["2010-06-01", "2010-06-02"])
    scores = pd.DataFrame(
        {"user": [f"U{i}" for i in range(4)] * 2, "day": np.repeat(days, 4), "x": 0.0}
    )
    bad = pd.DataFrame({"user": ["U0", "U0"], "day": days, "scenario": [1, 1]})
    expected = random_daily_budget(scores, bad, budget=1)["scenario_1"]["expected_caught"]
    assert expected == pytest.approx(1 - 0.75**2, abs=0.01)  # missed on both days: (3/4)^2


def test_warmup_percentile_is_frozen_after_the_warmup():
    score = pd.Series([1.0, 2.0, 3.0, 4.0, 0.5, 2.0, 99.0])
    warm = np.array([True, True, True, True, False, False, False])
    assert warmup_percentile(score, warm).tolist() == [0.125, 0.375, 0.625, 0.875, 0.0, 0.375, 1.0]


def test_cli_evaluate_writes_reports(workspace, tmp_path):
    extracted, answers = workspace
    out = tmp_path / "reports"
    args = ["--extracted", extracted, "--answers", answers, "--out-dir", out, "--warmup-days", 30]
    result = CliRunner().invoke(app, ["evaluate", *map(str, args)])
    assert result.exit_code == 0, result.output
    metrics, report = (out / "metrics.json").read_text(), (out / "REPORT.md").read_text()
    m = json.loads(metrics)
    assert set(m["detectors"]) == set(DETECTORS) and m["base_rates"]["users"] == 12
    assert np.isfinite(m["detectors"]["ensemble"]["user_level"]["roc_auc"])
    assert "| 2 | A | 0 |" in report  # review card: pseudonym, day counted from the first bad day
    # the answer key may be reported on, not redistributed: no insider ID or bad day is published
    first_bad_day = START + timedelta(days=THEFT_DAYS[0])
    assert INSIDER not in metrics + report
    assert first_bad_day.strftime("%Y-%m-%d") not in metrics + report
    for fig in ("daily_budget", "insiders_top_k", "insider_timeline"):
        assert (out / "figures" / f"{fig}.png").exists()


def test_cli_checks_its_inputs_before_starting(tmp_path):
    result = CliRunner().invoke(app, ["evaluate", "--extracted", str(tmp_path / "missing")])
    assert result.exit_code == 2  # usage error, before any work
