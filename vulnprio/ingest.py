"""Streaming, offline readers for the four supported input formats."""

from __future__ import annotations

import csv
import gzip
import json
import math
import os
import re
from datetime import date
from typing import Iterator

from .models import CVE_RE, CveRecord, EpssSnapshot, Finding, KevEntry, VulnprioError

CHUNK_SIZE = 1 << 20


def open_text(path: str):
    """Open plain or gzip text, accepting an optional UTF-8 BOM."""
    if os.fspath(path).lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return open(path, "r", encoding="utf-8-sig", newline="")


def parse_cwe_list(text: str) -> tuple[str, ...]:
    return tuple(sorted(set(re.findall(r"CWE-\d+", text)), key=lambda c: (int(c[4:]), c)))


def iter_nvd_items(path: str) -> Iterator[object]:
    """Decode individual array values, retaining only unconsumed input."""
    key = '"vulnerabilities"'
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False

    with open_text(path) as fh:
        def fill():
            nonlocal buffer, eof
            chunk = fh.read(CHUNK_SIZE)
            if chunk == "":
                eof = True
            buffer += chunk

        def skip_space():
            nonlocal buffer
            while True:
                buffer = buffer.lstrip()
                if buffer or eof:
                    return
                fill()

        while True:
            index = buffer.find(key)
            if index >= 0:
                buffer = buffer[index + len(key):]
                break
            if eof:
                raise VulnprioError(f"not an NVD CVE 2.0 feed: {path}")
            buffer = buffer[-(len(key) - 1):]
            fill()
        for expected in (":", "["):
            skip_space()
            if not buffer or buffer[0] != expected:
                raise VulnprioError(f"not an NVD CVE 2.0 feed: {path}")
            buffer = buffer[1:]

        first = True
        while True:
            skip_space()
            if first and buffer.startswith("]"):
                return
            first = False
            while True:
                try:
                    value, end = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    if eof:
                        raise VulnprioError(f"truncated or invalid NVD feed: {path}") from None
                    fill()
                    continue
                # Numbers may end at a chunk boundary, including midway through
                # an exponent or fraction that raw_decode has not consumed.
                partial_number = (
                    isinstance(value, (int, float)) and not isinstance(value, bool)
                    and end < len(buffer) and buffer[end] in ".eE"
                )
                if not eof and (end == len(buffer) or partial_number):
                    fill()
                    continue
                break
            yield value
            buffer = buffer[end:]
            skip_space()
            if buffer.startswith("]"):
                return
            if not buffer.startswith(","):
                raise VulnprioError(f"truncated or invalid NVD feed: {path}")
            buffer = buffer[1:]


def parse_nvd_item(item: object) -> CveRecord | None:
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        return None
    cve = item["cve"]
    cve_id, published = cve.get("id"), cve.get("published")
    if not isinstance(cve_id, str) or not CVE_RE.match(cve_id) or not isinstance(published, str):
        return None
    try:
        published = date.fromisoformat(published[:10])
    except ValueError:
        return None
    status = cve.get("vulnStatus")
    status = status if isinstance(status, str) else ""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
    score = version = source = None
    for key, candidate_version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        candidates = [entry for entry in entries if isinstance(entry, dict)
                      and isinstance(entry.get("cvssData"), dict)
                      and isinstance(entry["cvssData"].get("baseScore"), (int, float))
                      and not isinstance(entry["cvssData"]["baseScore"], bool)]
        if candidates:
            chosen = next((entry for entry in candidates if entry.get("type") == "Primary"), candidates[0])
            score, version = float(chosen["cvssData"]["baseScore"]), candidate_version
            source = chosen.get("type") if isinstance(chosen.get("type"), str) else None
            break
    values = []
    weaknesses = cve.get("weaknesses")
    for weakness in weaknesses if isinstance(weaknesses, list) else []:
        descriptions = weakness.get("description") if isinstance(weakness, dict) else None
        for description in descriptions if isinstance(descriptions, list) else []:
            if isinstance(description, dict) and isinstance(description.get("value"), str):
                values.append(description["value"])
    return CveRecord(cve_id, published, status, score, version, source, parse_cwe_list(" ".join(values)))


def parse_kev_csv(path: str) -> tuple[list[KevEntry], int]:
    entries = {}
    skipped = 0
    with open_text(path) as fh:
        reader = csv.DictReader(fh)
        for name in ("cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"):
            if name not in (reader.fieldnames or []):
                raise VulnprioError(f"KEV file is missing column '{name}': {path}")
        for row in reader:
            cve_id = (row.get("cveID") or "").strip().upper()
            try:
                added = date.fromisoformat((row.get("dateAdded") or "").strip())
            except ValueError:
                skipped += 1
                continue
            if not CVE_RE.match(cve_id):
                skipped += 1
                continue
            entry = KevEntry(cve_id, (row.get("vendorProject") or "").strip(),
                             (row.get("product") or "").strip(), added,
                             (row.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
                             parse_cwe_list(row.get("cwes") or ""))
            if cve_id not in entries or added < entries[cve_id].date_added:
                entries[cve_id] = entry
    return sorted(entries.values(), key=lambda e: (e.date_added, e.cve_id)), skipped


def _probability(value: str) -> float | None:
    try:
        result = float(value)
    except (ValueError, TypeError):
        return None
    return result if math.isfinite(result) and 0 <= result <= 1 else None


def parse_epss_csv(path: str, snapshot_date: date | None = None) -> EpssSnapshot:
    model_version = metadata_date = None
    scores, percentiles = {}, {}
    skipped = 0
    with open_text(path) as fh:
        header = fh.readline()
        if header.startswith("#"):
            metadata = {}
            for part in header[1:].split(","):
                if ":" in part:
                    key, value = part.split(":", 1)
                    metadata[key.strip()] = value.strip()
            model_version = metadata.get("model_version")
            try:
                metadata_date = date.fromisoformat(metadata.get("score_date", "")[:10])
            except ValueError:
                pass
            header = fh.readline()
        if not header:
            raise VulnprioError(f"EPSS file is empty: {path}")
        names = [name.strip() for name in next(csv.reader([header]))]
        for name in ("cve", "epss"):
            if name not in names:
                raise VulnprioError(f"EPSS file is missing column '{name}': {path}")
        cve_col, epss_col = names.index("cve"), names.index("epss")
        percentile_col = names.index("percentile") if "percentile" in names else None
        for row in csv.reader(fh):
            if not row or all(not value.strip() for value in row):
                continue
            if len(row) <= max(cve_col, epss_col):
                skipped += 1
                continue
            cve = row[cve_col].strip().upper()
            score = _probability(row[epss_col])
            if not CVE_RE.match(cve) or score is None:
                skipped += 1
                continue
            if cve in scores:
                continue
            scores[cve] = score
            if percentile_col is not None and percentile_col < len(row):
                percentile = _probability(row[percentile_col])
                if percentile is not None:
                    percentiles[cve] = percentile
    resolved_date = snapshot_date or metadata_date
    if resolved_date is None:
        for match in re.finditer(r"\d{4}-\d{2}-\d{2}", os.path.basename(path)):
            try:
                resolved_date = date.fromisoformat(match.group())
                break
            except ValueError:
                pass
    if resolved_date is None:
        raise VulnprioError(f"cannot determine EPSS snapshot date: {path}")
    return EpssSnapshot(resolved_date, model_version, scores, percentiles, skipped)


def parse_findings_csv(path: str) -> tuple[list[Finding], int]:
    findings, seen = [], set()
    skipped = 0
    with open_text(path) as fh:
        reader = csv.DictReader(fh)
        for name in ("asset_id", "cve_id"):
            if name not in (reader.fieldnames or []):
                raise VulnprioError(f"findings file is missing column '{name}': {path}")
        for row in reader:
            asset, cve = (row.get("asset_id") or "").strip(), (row.get("cve_id") or "").strip().upper()
            if not asset or not CVE_RE.match(cve) or (asset, cve) in seen:
                skipped += 1
                continue
            criticality = (row.get("asset_criticality") or "").strip().lower()
            if criticality not in {"high", "medium", "low"}:
                criticality = "medium"
            internet = (row.get("internet_facing") or "").strip().lower() in {"true", "yes", "y", "1"}
            seen.add((asset, cve))
            findings.append(Finding(asset, cve, criticality, internet))
    return findings, skipped
