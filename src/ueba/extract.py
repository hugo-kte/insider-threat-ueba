"""One pass over the CERT r4.2 archive.

The archive is 4.8 GB of bzip2; ``http.csv`` alone is 14.5 GB once decompressed. Instead of
unpacking everything, the archive is streamed once and only what the features read reaches the
disk: the logon, device, file and e-mail logs and the LDAP snapshots are cut down to the columns
in ``COLUMNS`` and ``LDAP_COLUMNS`` and written as Parquet (no e-mail or file contents, no names
or addresses from the directory), and the web log is aggregated on the fly into per user-day
counts (requests, never-seen-before domains), so no URL is stored.

The archive is multi-stream bzip2 (as written by pbzip2): tarfile's own streaming mode ``r|bz2``
raises ``EOFError`` at the end of the first stream, so the archive is decompressed with
``bz2.open``, which reads every stream, and handed to tarfile as a plain tar stream.
"""

from __future__ import annotations

import bz2
import io
import logging
import tarfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ueba import TIMESTAMP

log = logging.getLogger(__name__)

TEXT, COUNT = pa.string(), pa.int64()
# The only columns kept from each log, i.e. what features.py reads: record IDs, file and e-mail
# contents, e-mail "from" fields and the PCs of device, file and e-mail events never reach the disk.
COLUMNS = {
    "logon.csv": pa.schema([("date", TEXT), ("user", TEXT), ("pc", TEXT), ("activity", TEXT)]),
    "device.csv": pa.schema([("date", TEXT), ("user", TEXT), ("activity", TEXT)]),
    "file.csv": pa.schema([("date", TEXT), ("user", TEXT), ("filename", TEXT)]),
    "email.csv": pa.schema(
        [
            ("date", TEXT),
            ("user", TEXT),
            ("to", TEXT),
            ("cc", TEXT),
            ("bcc", TEXT),
            ("size", COUNT),
            ("attachments", COUNT),
        ]
    ),
}
# Monthly directory snapshots: peer groups need the role; names, e-mail addresses, teams and
# supervisors are dropped.
LDAP_COLUMNS = pa.schema([("user_id", TEXT), ("role", TEXT), ("department", TEXT)])


class _RawStream(io.RawIOBase):
    """Read-only adapter: tarfile's streaming members lack ``seekable()``, which pandas needs."""

    def __init__(self, fileobj: io.BufferedIOBase) -> None:
        self._f = fileobj

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        data = self._f.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _domain(url: str) -> str:
    host = urlsplit(url if "//" in url else "//" + url).hostname or ""
    return host.removeprefix("www.")


def aggregate_http(stream: io.BufferedIOBase, chunk_rows: int = 2_000_000) -> pd.DataFrame:
    """Per user-day web activity: request count and domains the user never visited before."""
    seen: dict[str, set[str]] = defaultdict(set)
    rows: list[pd.DataFrame] = []
    n_rows = 0
    reader = pd.read_csv(stream, usecols=["date", "user", "url"], chunksize=chunk_rows)
    for chunk in reader:
        chunk["day"] = pd.to_datetime(chunk["date"], format=TIMESTAMP).dt.normalize()
        chunk["domain"] = chunk["url"].map(_domain)
        chunk = chunk.sort_values("day", kind="stable")
        new = []
        for user, domain in zip(chunk["user"], chunk["domain"], strict=True):
            known = seen[user]
            new.append(domain not in known)
            known.add(domain)
        chunk["new_domain"] = new
        rows.append(
            chunk.groupby(["user", "day"]).agg(
                n_http=("url", "size"), n_http_new_domains=("new_domain", "sum")
            )
        )
        n_rows += len(chunk)
        log.info("http: %d rows processed", n_rows)
    agg = pd.concat(rows).groupby(level=["user", "day"]).sum().reset_index()
    return agg


def project_csv(
    stream: io.BufferedIOBase, schema: pa.Schema, dest: Path, chunk_rows: int = 500_000
) -> int:
    """Write only the ``schema`` columns of a CSV stream to a Parquet file, chunk by chunk."""
    dtypes = {f.name: "int64" if pa.types.is_integer(f.type) else str for f in schema}
    rows = 0
    with pq.ParquetWriter(dest, schema) as writer:
        for chunk in pd.read_csv(stream, usecols=schema.names, dtype=dtypes, chunksize=chunk_rows):
            table = pa.Table.from_pandas(chunk[schema.names], schema=schema, preserve_index=False)
            writer.write_table(table)
            rows += len(chunk)
    return rows


def extract(archive: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "LDAP").mkdir(exist_ok=True)
    with bz2.open(archive) as raw, tarfile.open(fileobj=raw, mode="r|") as tar:
        for member in tar:
            name = Path(member.name).name
            if not member.isfile():
                continue
            src = tar.extractfile(member)
            if src is None:
                continue
            stream = io.BufferedReader(_RawStream(src), buffer_size=1 << 22)
            parquet = Path(name).with_suffix(".parquet").name
            if name in COLUMNS:
                rows = project_csv(stream, COLUMNS[name], out_dir / parquet)
                kept = ", ".join(COLUMNS[name].names)
                log.info("%s (%.0f MB): %d rows, kept %s", name, member.size / 1e6, rows, kept)
            elif "LDAP" in Path(member.name).parts[:-1]:
                project_csv(stream, LDAP_COLUMNS, out_dir / "LDAP" / parquet)
            elif name == "http.csv":
                aggregate_http(stream).to_parquet(out_dir / "http_daily.parquet", index=False)
                log.info("aggregated http.csv (%.0f MB) to http_daily.parquet", member.size / 1e6)
