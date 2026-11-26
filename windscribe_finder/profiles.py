"""Persistent per-(ISP, anti-censorship mode) JSON profile store."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from windscribe_finder.models import AttemptResult, ProfileEntry

SCHEMA_VERSION = 1
DEFAULT_ISP = "default"
DEFAULT_MODE = "default"


def default_profile_path() -> Path:
    """Return the default on-disk location for the Windscribe Finder profile JSON."""
    return Path.home() / ".windscribe_finder" / "profiles.json"


def _normalize_label(value: str | None, fallback: str) -> str:
    cleaned = (value or "").strip()
    return cleaned if cleaned else fallback


def _profile_key(isp: str, mode: str) -> str:
    return json.dumps([isp, mode], ensure_ascii=False)


def _entry_key(location: str, protocol: str, port: str | None) -> tuple[str, str, str | None]:
    return (location, protocol.strip().lower(), port.strip() if isinstance(port, str) and port.strip() else None)


def _entry_to_dict(entry: ProfileEntry) -> dict[str, Any]:
    return {
        "location": entry.location,
        "protocol": entry.protocol,
        "port": entry.port,
        "success_count": entry.success_count,
        "failure_count": entry.failure_count,
        "last_latency_ms": entry.last_latency_ms,
        "last_verified_at": entry.last_verified_at,
    }


def _entry_from_dict(raw: dict[str, Any]) -> ProfileEntry:
    port_raw = raw.get("port")
    port = str(port_raw).strip() if port_raw is not None and str(port_raw).strip() else None
    latency_raw = raw.get("last_latency_ms")
    latency = float(latency_raw) if latency_raw is not None else None
    verified_raw = raw.get("last_verified_at")
    verified = str(verified_raw) if verified_raw is not None else None
    return ProfileEntry(
        location=str(raw["location"]),
        protocol=str(raw["protocol"]).strip().lower(),
        port=port,
        success_count=int(raw.get("success_count", 0)),
        failure_count=int(raw.get("failure_count", 0)),
        last_latency_ms=latency,
        last_verified_at=verified,
    )


def _parse_iso_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _entry_rank_key(entry: ProfileEntry, reference_time: datetime) -> tuple[Any, ...]:
    has_success_rank = 0 if entry.success_count > 0 else 1
    total = entry.success_count + entry.failure_count
    failure_rate = (entry.failure_count / total) if total > 0 else 1.0
    base_latency = entry.last_latency_ms if entry.last_latency_ms is not None else 10_000.0

    verified_at = _parse_iso_utc(entry.last_verified_at)
    if verified_at is None:
        age_days = 90.0
    else:
        age_days = max(0.0, (reference_time - verified_at).total_seconds() / 86_400.0)

    failure_penalty = failure_rate * 2_000.0
    staleness_penalty = min(age_days, 90.0) * 5.0
    effective_score = base_latency + failure_penalty + staleness_penalty

    return (
        has_success_rank,
        effective_score,
        -entry.success_count,
        entry.failure_count,
        base_latency,
        entry.location,
        entry.protocol,
        entry.port or "",
    )


def rank_profile_entries(
    entries: list[ProfileEntry] | tuple[ProfileEntry, ...],
    *,
    now: datetime | None = None,
) -> list[ProfileEntry]:
    """Order profile entries by reliability, freshness, and lowest latency."""
    reference_time = (now if now is not None else datetime.now(timezone.utc)).astimezone(timezone.utc)
    return sorted(entries, key=lambda entry: _entry_rank_key(entry, reference_time))


class ProfileStore:
    """JSON-backed profile store with atomic writes per (isp, anti_censorship_mode)."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else default_profile_path()
        self._profiles: dict[tuple[str, str], dict[tuple[str, str, str | None], ProfileEntry]] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        self._profiles.clear()
        if not self._path.is_file():
            return
        raw_text = self._path.read_text(encoding="utf-8")
        if not raw_text.strip():
            return
        data = json.loads(raw_text)
        profiles_raw = data.get("profiles", {})
        if not isinstance(profiles_raw, dict):
            return
        for key_str, profile_obj in profiles_raw.items():
            if not isinstance(profile_obj, dict):
                continue
            isp = _normalize_label(profile_obj.get("isp"), DEFAULT_ISP)
            mode = _normalize_label(profile_obj.get("anti_censorship_mode"), DEFAULT_MODE)
            entries_map: dict[tuple[str, str, str | None], ProfileEntry] = {}
            for raw_entry in profile_obj.get("entries", []):
                if not isinstance(raw_entry, dict) or "location" not in raw_entry or "protocol" not in raw_entry:
                    continue
                entry = _entry_from_dict(raw_entry)
                entries_map[_entry_key(entry.location, entry.protocol, entry.port)] = entry
            self._profiles[(isp, mode)] = entries_map

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        serialized_profiles: dict[str, Any] = {}
        for (isp, mode), entries_map in sorted(self._profiles.items()):
            serialized_profiles[_profile_key(isp, mode)] = {
                "isp": isp,
                "anti_censorship_mode": mode,
                "entries": [_entry_to_dict(e) for e in entries_map.values()],
            }
        payload = {
            "version": SCHEMA_VERSION,
            "profiles": serialized_profiles,
        }
        encoded = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self._path.name}.",
            suffix=".tmp",
            dir=str(self._path.parent),
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._path)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def list_profiles(self) -> list[tuple[str, str]]:
        """Return all saved (isp, anti_censorship_mode) profile keys."""
        return sorted(self._profiles.keys())

    def get_entries(
        self,
        isp: str | None = None,
        anti_censorship_mode: str | None = None,
        *,
        now: datetime | None = None,
    ) -> list[ProfileEntry]:
        """Return saved entries for (isp, anti_censorship_mode) ordered by priority."""
        norm_isp = _normalize_label(isp, DEFAULT_ISP)
        norm_mode = _normalize_label(anti_censorship_mode, DEFAULT_MODE)
        entries_map = self._profiles.get((norm_isp, norm_mode))
        if not entries_map:
            return []
        return rank_profile_entries(list(entries_map.values()), now=now)

    def record_attempt(
        self,
        isp: str | None,
        anti_censorship_mode: str | None,
        attempt: AttemptResult,
        *,
        now: datetime | None = None,
    ) -> ProfileEntry | None:
        """Record an attempt outcome for (isp, anti_censorship_mode) and persist atomically.

        Healthy attempts create or update an entry. Failed attempts only update entries
        that already exist in the profile so never-working combos do not pollute saved data.
        """
        norm_isp = _normalize_label(isp, DEFAULT_ISP)
        norm_mode = _normalize_label(anti_censorship_mode, DEFAULT_MODE)
        key = _entry_key(attempt.location, attempt.protocol, attempt.port)

        entries_map = self._profiles.get((norm_isp, norm_mode))
        existing = entries_map.get(key) if entries_map is not None else None

        if not attempt.healthy:
            if existing is None:
                return None
            updated = ProfileEntry(
                location=existing.location,
                protocol=existing.protocol,
                port=existing.port,
                success_count=existing.success_count,
                failure_count=existing.failure_count + 1,
                last_latency_ms=existing.last_latency_ms,
                last_verified_at=existing.last_verified_at,
            )
            assert entries_map is not None
            entries_map[key] = updated
            self._save()
            return updated

        timestamp = (now if now is not None else datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        if entries_map is None:
            entries_map = {}
            self._profiles[(norm_isp, norm_mode)] = entries_map

        updated = ProfileEntry(
            location=attempt.location,
            protocol=attempt.protocol.strip().lower(),
            port=key[2],
            success_count=(existing.success_count if existing else 0) + 1,
            failure_count=existing.failure_count if existing else 0,
            last_latency_ms=attempt.avg_latency_ms,
            last_verified_at=timestamp,
        )
        entries_map[key] = updated
        self._save()
        return updated
