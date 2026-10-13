"""User-day behaviour features from the CERT r4.2 logs.

One row per (user, day) with counts an analyst would recognise: logons outside office hours,
removable-media use, files written to removable media, external e-mail, web activity and new
domains. Psychometric scores shipped with the dataset are deliberately not used: monitoring
people's personality traits is neither proportionate nor necessary to detect data theft.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd

from ueba import TIMESTAMP

log = logging.getLogger(__name__)

OFFICE_START, OFFICE_END = 7, 19  # hours; activity outside is "after hours"
INTERNAL_DOMAIN = "dtaa.com"

FEATURE_LABELS = {
    "n_logon": "logons",
    "n_logon_after_hours": "after-hours logons",
    "n_logon_weekend": "weekend logons",
    "n_pc": "distinct PCs",
    "n_logon_other_pc": "logons to an unusual PC",
    "n_usb": "removable-drive connections",
    "n_usb_after_hours": "after-hours drive connections",
    "n_file": "files copied",
    "n_file_exe": ".exe files copied",
    "n_file_after_hours": "after-hours file copies",
    "n_email": "e-mails sent",
    "n_email_external": "e-mails with an external recipient",
    "n_attachments": "attachments",
    "email_kb": "e-mail volume (KB)",
    "n_http": "web requests",
    "n_http_new_domains": "never-visited web domains",
}
FEATURES = list(FEATURE_LABELS)
# r4.2's web generator emits the same number of requests per user and browsing day (all users are
# exactly flat during the warm-up); later the count moves almost only where the red team injected
# events. It measures the simulator, not behaviour: kept for the audit, never given to a detector.
SIMULATOR_ARTIFACTS = ("n_http",)
MODEL_FEATURES = [f for f in FEATURES if f not in SIMULATOR_ARTIFACTS]
# Hash of this file, part of the feature cache's name: editing the feature code rebuilds the table.
CODE_VERSION = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]


def _read(path: Path, columns: list[str]) -> pd.DataFrame:
    df = pd.read_parquet(path, columns=columns)
    df["ts"] = pd.to_datetime(df["date"], format=TIMESTAMP)
    df["day"] = df["ts"].dt.normalize().astype("datetime64[ns]")
    df["after_hours"] = (df["ts"].dt.hour < OFFICE_START) | (df["ts"].dt.hour >= OFFICE_END)
    return df.drop(columns="date")


def logon_features(path: Path, warmup_days: int) -> pd.DataFrame:
    df = _read(path, ["date", "user", "pc", "activity"])
    df = df[df["activity"] == "Logon"]
    start = df["day"].min()
    warm = df[df["day"] < start + pd.Timedelta(days=warmup_days)]
    primary = df["user"].map(warm.groupby("user")["pc"].agg(lambda s: s.value_counts().index[0]))
    df["other_pc"] = primary.notna() & (df["pc"] != primary)  # no warm-up logon: no reference
    df["weekend"] = df["day"].dt.dayofweek >= 5
    return df.groupby(["user", "day"]).agg(
        n_logon=("pc", "size"),
        n_logon_after_hours=("after_hours", "sum"),
        n_logon_weekend=("weekend", "sum"),
        n_pc=("pc", "nunique"),
        n_logon_other_pc=("other_pc", "sum"),
    )


def device_features(path: Path) -> pd.DataFrame:
    df = _read(path, ["date", "user", "activity"])
    df = df[df["activity"] == "Connect"]
    return df.groupby(["user", "day"]).agg(
        n_usb=("activity", "size"), n_usb_after_hours=("after_hours", "sum")
    )


def file_features(path: Path) -> pd.DataFrame:
    df = _read(path, ["date", "user", "filename"])
    df["exe"] = df["filename"].str.lower().str.endswith(".exe")
    return df.groupby(["user", "day"]).agg(
        n_file=("filename", "size"),
        n_file_exe=("exe", "sum"),
        n_file_after_hours=("after_hours", "sum"),
    )


def email_features(path: Path) -> pd.DataFrame:
    df = _read(path, ["date", "user", "to", "cc", "bcc", "size", "attachments"])
    recipients = df["to"].fillna("") + ";" + df["cc"].fillna("") + ";" + df["bcc"].fillna("")
    # an address whose domain is not exactly the company's (vectorised: 2.6M e-mails in r4.2)
    df["external"] = recipients.str.contains(rf"@(?!{re.escape(INTERNAL_DOMAIN)}(?:;|$))")
    df["kb"] = df["size"] / 1024
    return df.groupby(["user", "day"]).agg(
        n_email=("size", "size"),
        n_email_external=("external", "sum"),
        n_attachments=("attachments", "sum"),
        email_kb=("kb", "sum"),
    )


def ldap_roles(ldap_dir: Path) -> pd.DataFrame:
    """Role and department from the first monthly directory snapshot (peer groups)."""
    first = sorted(ldap_dir.glob("*.parquet"))[0]
    df = pd.read_parquet(first)
    return df.rename(columns={"user_id": "user"}).set_index("user")[["role", "department"]]


def build(extracted: Path, warmup_days: int = 60) -> pd.DataFrame:
    parts = [
        logon_features(extracted / "logon.parquet", warmup_days),
        device_features(extracted / "device.parquet"),
        file_features(extracted / "file.parquet"),
        email_features(extracted / "email.parquet"),
        pd.read_parquet(extracted / "http_daily.parquet")
        .astype({"day": "datetime64[ns]"})
        .set_index(["user", "day"]),
    ]
    df = pd.concat(parts, axis=1).fillna(0)[FEATURES].astype(np.float32).reset_index()
    roles = ldap_roles(extracted / "LDAP")
    df = df.join(roles, on="user")
    df[["role", "department"]] = df[["role", "department"]].fillna("unknown")
    log.info("features: %d user-days, %d users", len(df), df["user"].nunique())
    return df.sort_values(["day", "user"]).reset_index(drop=True)
