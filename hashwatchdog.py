#!/usr/bin/env python3
"""HashWatchDog: cross-filesystem duplicate-file scanner.

HashWatchDog runs on Linux (including live Linux environments) and scans one or
more mounted directory trees as a single global namespace. Windows filesystems
must be mounted by Linux first.

The SQLite database is the canonical scan record. CSV reports are generated only
when a scan completes successfully, then atomically moved into place.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import errno
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

PROGRAM_NAME = "hashwatchdog"
VERSION = "3.0.0"
SCHEMA_VERSION = 3
DEFAULT_CHUNK_MIB = 8
DEFAULT_PROGRESS_SECONDS = 5.0
DEFAULT_FILE_PROGRESS_SECONDS = 10.0
DEFAULT_QUEUE_MULTIPLIER = 4
COMMIT_SECONDS = 30.0
DEFAULT_PATH_WARNING_CHARS = 200
DEFAULT_OFFICE_PATH_LIMIT = 240
DEFAULT_HARD_PATH_LIMIT = 259
DEFAULT_FILENAME_LIMIT = 100
DEFAULT_DIRECTORY_NAME_LIMIT = 100
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ScanInterrupted(RuntimeError):
    """Raised when SIGTERM requests a cooperative stop."""


@dataclass(slots=True, frozen=True)
class RootInfo:
    root_id: int
    path: str
    path_display: str
    path_raw: bytes
    device: int
    mount_point: str
    filesystem_type: str
    mount_source: str
    filesystem_uuid: str


@dataclass(slots=True, frozen=True)
class FileTask:
    root: RootInfo
    path: str
    path_display: str
    path_raw: bytes
    size_bytes: int
    allocated_bytes: int | None
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int
    nlink: int
    generation: int


@dataclass(slots=True)
class HashResult:
    task: FileTask
    digest: str
    sample_digest: str
    status: str
    error: str
    bytes_read: int
    elapsed_seconds: float
    final_size_bytes: int | None
    final_allocated_bytes: int | None
    final_mtime_ns: int | None
    final_ctime_ns: int | None
    final_device: int | None
    final_inode: int | None
    management_class: str
    classification_confidence: str
    classification_reason: str
    cleanup_risk: str


@dataclass(slots=True)
class ActiveFile:
    path_display: str
    size_bytes: int
    bytes_read: int
    started: float
    attempt: int


@dataclass(slots=True)
class Counters:
    discovered: int = 0
    examined: int = 0
    hashed: int = 0
    reused: int = 0
    errors: int = 0
    changed: int = 0
    cancelled: int = 0
    empty: int = 0


@dataclass(slots=True, frozen=True)
class PathAuditPolicy:
    warning_path_chars: int
    office_path_limit: int
    hard_path_limit: int
    filename_limit: int
    directory_name_limit: int
    windows_prefix_length: int


@dataclass(slots=True)
class PathAuditCounters:
    examined: int = 0
    files: int = 0
    directories: int = 0
    findings: int = 0
    warnings: int = 0
    high: int = 0
    critical: int = 0


class ProgressTracker:
    """Thread-safe aggregate and active-file progress state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[int, ActiveFile] = {}
        self._logical_bytes_read = 0
        self._started = time.monotonic()

    def start_file(self, path_display: str, size_bytes: int, attempt: int) -> int:
        key = threading.get_ident()
        with self._lock:
            self._active[key] = ActiveFile(
                path_display=path_display,
                size_bytes=size_bytes,
                bytes_read=0,
                started=time.monotonic(),
                attempt=attempt,
            )
        return key

    def add_bytes(self, key: int, count: int) -> None:
        with self._lock:
            self._logical_bytes_read += count
            active = self._active.get(key)
            if active is not None:
                active.bytes_read += count

    def finish_file(self, key: int) -> None:
        with self._lock:
            self._active.pop(key, None)

    def snapshot(self) -> tuple[int, float, list[ActiveFile]]:
        with self._lock:
            return (
                self._logical_bytes_read,
                max(time.monotonic() - self._started, 0.001),
                [
                    ActiveFile(
                        path_display=item.path_display,
                        size_bytes=item.size_bytes,
                        bytes_read=item.bytes_read,
                        started=item.started,
                        attempt=item.attempt,
                    )
                    for item in self._active.values()
                ],
            )


class ProgressReporter(threading.Thread):
    def __init__(
        self,
        tracker: ProgressTracker,
        counters: Counters,
        counters_lock: threading.Lock,
        logger: logging.Logger,
        stop_event: threading.Event,
        progress_seconds: float,
        file_progress_seconds: float,
        detail: str,
    ) -> None:
        super().__init__(name="progress-reporter", daemon=True)
        self.tracker = tracker
        self.counters = counters
        self.counters_lock = counters_lock
        self.logger = logger
        self.stop_event = stop_event
        self.progress_seconds = progress_seconds
        self.file_progress_seconds = file_progress_seconds
        self.detail = detail

    def run(self) -> None:
        next_general = time.monotonic() + self.progress_seconds
        next_file = time.monotonic() + self.file_progress_seconds
        while not self.stop_event.wait(0.25):
            now = time.monotonic()
            if now >= next_general:
                logical_read, elapsed, active = self.tracker.snapshot()
                with self.counters_lock:
                    examined = self.counters.examined
                    discovered = self.counters.discovered
                    reused = self.counters.reused
                self.logger.info(
                    "Progress: %d files completed | %d discovered | %d reused | %s hashed | %s/s | %d active",
                    examined,
                    discovered,
                    reused,
                    human_bytes(logical_read),
                    human_bytes(logical_read / elapsed),
                    len(active),
                )
                next_general = now + self.progress_seconds

            if self.file_progress_seconds > 0 and now >= next_file:
                logical_read, _elapsed, active = self.tracker.snapshot()
                if active:
                    active.sort(key=lambda item: item.bytes_read, reverse=True)
                    limit = len(active) if self.detail == "trace" else 1
                    for item in active[:limit]:
                        file_elapsed = max(now - item.started, 0.001)
                        percent = (
                            (item.bytes_read / item.size_bytes) * 100.0
                            if item.size_bytes > 0
                            else 100.0
                        )
                        self.logger.info(
                            "Current file: %s | file progress: %s / %s (%.1f%%) | total hashed: %s | current-file rate: %s/s | attempt %d",
                            item.path_display,
                            human_bytes(item.bytes_read),
                            human_bytes(item.size_bytes),
                            percent,
                            human_bytes(logical_read),
                            human_bytes(item.bytes_read / file_elapsed),
                            item.attempt,
                        )
                next_file = now + self.file_progress_seconds


_THREAD_LOCAL = threading.local()


def worker_buffer(size: int) -> bytearray:
    buffer = getattr(_THREAD_LOCAL, "buffer", None)
    if buffer is None or len(buffer) != size:
        buffer = bytearray(size)
        _THREAD_LOCAL.buffer = buffer
    return buffer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description=(
            "Hash regular files beneath one or more mounted roots and identify "
            "duplicates globally across all roots."
        ),
    )
    parser.add_argument(
        "--root",
        dest="roots",
        action="append",
        required=True,
        metavar="PATH",
        help="Root directory to scan. Repeat to compare multiple filesystems.",
    )
    parser.add_argument(
        "--output-dir",
        default="hashwatchdog-results",
        metavar="DIR",
        help="Directory for reports, log, and SQLite database (default: %(default)s).",
    )
    parser.add_argument(
        "--algorithm",
        choices=("sha256", "blake2b", "blake3"),
        default="sha256",
        help="Hash algorithm. BLAKE3 requires the optional blake3 package.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Concurrent hash workers (default: %(default)s).",
    )
    parser.add_argument(
        "--chunk-size-mib",
        type=int,
        default=DEFAULT_CHUNK_MIB,
        metavar="MIB",
        help="Reusable per-worker read buffer size (default: %(default)s MiB).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATH",
        help="Path to exclude. Repeat for additional paths.",
    )
    parser.add_argument(
        "--one-file-system",
        action="store_true",
        help="Do not cross mount boundaries beneath each selected root.",
    )
    parser.add_argument(
        "--empty-files",
        choices=("ignore", "count", "report"),
        default="count",
        help=(
            "Empty-file policy: ignore/count exclude them from duplicate groups; "
            "report includes them (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--progress-seconds",
        type=float,
        default=DEFAULT_PROGRESS_SECONDS,
        metavar="SECONDS",
        help="General progress interval (default: %(default)s).",
    )
    parser.add_argument(
        "--file-progress-seconds",
        type=float,
        default=DEFAULT_FILE_PROGRESS_SECONDS,
        metavar="SECONDS",
        help="Active-file progress interval; 0 disables it (default: %(default)s).",
    )
    parser.add_argument(
        "--log-detail",
        choices=("summary", "verbose", "trace"),
        default="summary",
        help=(
            "summary logs operations and final totals; verbose adds duplicate-group "
            "summaries; trace also logs every duplicate path (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--print-hashes",
        action="store_true",
        help="Print each successful hash. This can slow scans with many small files.",
    )
    parser.add_argument(
        "--retry-changed",
        type=int,
        default=1,
        metavar="N",
        help="Retries when a file changes while hashing (default: %(default)s).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume a compatible interrupted scan from hash_index.sqlite3.partial.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help=(
            "Generate reports from an existing partial or completed SQLite database "
            "without walking or hashing the filesystem."
        ),
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help=(
            "Reuse hashes from the latest completed database when path and strong "
            "filesystem metadata are unchanged."
        ),
    )
    parser.add_argument(
        "--cache-policy",
        choices=("metadata", "sampled", "strict"),
        default="sampled",
        help=(
            "Incremental reuse policy. strict rehashes all files; sampled verifies "
            "three small regions; metadata trusts identity metadata (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--no-managed-classification",
        action="store_true",
        help="Disable managed-path and cleanup-risk classification heuristics.",
    )
    path_group = parser.add_argument_group(
        "Office and OneDrive path-length auditing"
    )
    path_group.add_argument(
        "--audit-paths",
        action="store_true",
        help=(
            "Audit files and directories for Office/OneDrive path-length risks "
            "while performing the normal duplicate scan."
        ),
    )
    path_group.add_argument(
        "--path-audit-only",
        action="store_true",
        help=(
            "Audit path lengths without reading or hashing file contents. "
            "Implies --audit-paths."
        ),
    )
    path_group.add_argument(
        "--path-warning-chars",
        type=int,
        default=DEFAULT_PATH_WARNING_CHARS,
        metavar="N",
        help=(
            "Projected Windows path length that becomes a warning "
            "(default: %(default)s UTF-16 characters)."
        ),
    )
    path_group.add_argument(
        "--office-path-limit",
        type=int,
        default=DEFAULT_OFFICE_PATH_LIMIT,
        metavar="N",
        help=(
            "Projected Windows path length that becomes high risk "
            "(default: %(default)s UTF-16 characters)."
        ),
    )
    path_group.add_argument(
        "--hard-path-limit",
        type=int,
        default=DEFAULT_HARD_PATH_LIMIT,
        metavar="N",
        help=(
            "Maximum Office path length; paths longer than this are critical "
            "(default: %(default)s UTF-16 characters)."
        ),
    )
    path_group.add_argument(
        "--filename-limit",
        type=int,
        default=DEFAULT_FILENAME_LIMIT,
        metavar="N",
        help=(
            "Organization policy limit for an individual filename "
            "(default: %(default)s UTF-16 characters)."
        ),
    )
    path_group.add_argument(
        "--directory-name-limit",
        type=int,
        default=DEFAULT_DIRECTORY_NAME_LIMIT,
        metavar="N",
        help=(
            "Organization policy limit for an individual directory name "
            "(default: %(default)s UTF-16 characters)."
        ),
    )
    path_group.add_argument(
        "--windows-prefix-length",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Characters occupied by the Windows sync root, including its trailing "
            "backslash. When nonzero, projected length is this value plus the "
            "root-relative path; 0 audits the scanned path as-is (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--ignore-empty",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-print-duplicates",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def safe_display(value: str) -> str:
    """Return UTF-8/terminal-safe text while preserving exact bytes elsewhere."""
    encoded = value.encode("utf-8", "backslashreplace").decode("utf-8")
    pieces: list[str] = []
    for char in encoded:
        code = ord(char)
        if char == "\n":
            pieces.append("\\n")
        elif char == "\r":
            pieces.append("\\r")
        elif char == "\t":
            pieces.append("\\t")
        elif code < 32 or code == 127:
            pieces.append(f"\\x{code:02x}")
        else:
            pieces.append(char)
    return "".join(pieces)


def raw_path(value: str) -> bytes:
    return os.fsencode(value)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_timestamp(ns: int | None) -> str:
    if ns is None:
        return ""
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()


def human_bytes(value: float | int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PiB"


def utf16_char_count(value: str) -> int:
    """Count Windows UTF-16 code units rather than Python Unicode code points."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


class PathAuditor:
    """Persist path-policy violations encountered by the filesystem walker."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        generation: int,
        policy: PathAuditPolicy,
        logger: logging.Logger,
        progress_seconds: float,
    ) -> None:
        self.connection = connection
        self.scan_id = scan_id
        self.generation = generation
        self.policy = policy
        self.logger = logger
        self.progress_seconds = progress_seconds
        self.counters = PathAuditCounters()
        self._last_progress = time.monotonic()

    def record(self, root: RootInfo, path: str, item_type: str) -> None:
        try:
            relative_native = os.path.relpath(path, root.path)
        except ValueError:
            relative_native = path
        if relative_native == ".":
            relative_native = ""

        relative_windows = relative_native.replace(os.sep, "\\")
        scanned_windows = path.replace(os.sep, "\\")
        actual_path_chars = utf16_char_count(scanned_windows)
        relative_path_chars = utf16_char_count(relative_windows)
        projected_path_chars = (
            self.policy.windows_prefix_length + relative_path_chars
            if self.policy.windows_prefix_length > 0
            else actual_path_chars
        )

        components = [piece for piece in relative_native.split(os.sep) if piece]
        name = components[-1] if components else os.path.basename(path)
        name_chars = utf16_char_count(name)
        directory_components = components if item_type == "directory" else components[:-1]
        directory_lengths = [utf16_char_count(piece) for piece in directory_components]
        longest_directory_chars = max(directory_lengths, default=0)
        longest_directory_name = ""
        if directory_lengths:
            longest_index = max(range(len(directory_lengths)), key=directory_lengths.__getitem__)
            longest_directory_name = directory_components[longest_index]

        issues: list[str] = []
        severity = "none"
        if projected_path_chars > self.policy.hard_path_limit:
            issues.append("hard_path_limit_exceeded")
            severity = "critical"
        elif projected_path_chars >= self.policy.office_path_limit:
            issues.append("office_path_risk")
            severity = "high"
        elif projected_path_chars >= self.policy.warning_path_chars:
            issues.append("path_length_warning")
            severity = "warning"

        if item_type == "file" and name_chars > self.policy.filename_limit:
            issues.append("filename_limit_exceeded")
            if severity == "none":
                severity = "warning"
        if longest_directory_chars > self.policy.directory_name_limit:
            issues.append("directory_name_limit_exceeded")
            if severity == "none":
                severity = "warning"

        if name_chars > 255 or longest_directory_chars > 255:
            issues.append("filesystem_component_limit_exceeded")
            severity = "critical"

        path_bytes = sqlite3.Binary(raw_path(path))
        if not issues:
            self.connection.execute(
                "DELETE FROM path_issues WHERE scan_id=? AND path_raw=?",
                (self.scan_id, path_bytes),
            )
        else:
            if projected_path_chars >= self.policy.warning_path_chars:
                shorten_by = projected_path_chars - self.policy.warning_path_chars + 1
                recommendation = (
                    f"Shorten the filename or folder hierarchy by at least "
                    f"{shorten_by} UTF-16 character(s) to return below the warning threshold."
                )
            elif "filename_limit_exceeded" in issues:
                shorten_by = name_chars - self.policy.filename_limit
                recommendation = (
                    f"Shorten the filename by at least {shorten_by} UTF-16 character(s)."
                )
            else:
                shorten_by = longest_directory_chars - self.policy.directory_name_limit
                recommendation = (
                    f"Shorten the longest directory name by at least "
                    f"{shorten_by} UTF-16 character(s)."
                )

            self.connection.execute(
                """
                INSERT INTO path_issues(
                    scan_id, root_id, path_display, path_raw, item_type,
                    relative_path_display, actual_path_chars, relative_path_chars,
                    projected_path_chars, name_chars, longest_directory_name,
                    longest_directory_chars, warning_path_chars, office_path_limit,
                    hard_path_limit, filename_limit, directory_name_limit,
                    windows_prefix_length, severity, issue_codes, recommendation,
                    seen_generation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, path_raw) DO UPDATE SET
                    root_id=excluded.root_id,
                    path_display=excluded.path_display,
                    item_type=excluded.item_type,
                    relative_path_display=excluded.relative_path_display,
                    actual_path_chars=excluded.actual_path_chars,
                    relative_path_chars=excluded.relative_path_chars,
                    projected_path_chars=excluded.projected_path_chars,
                    name_chars=excluded.name_chars,
                    longest_directory_name=excluded.longest_directory_name,
                    longest_directory_chars=excluded.longest_directory_chars,
                    warning_path_chars=excluded.warning_path_chars,
                    office_path_limit=excluded.office_path_limit,
                    hard_path_limit=excluded.hard_path_limit,
                    filename_limit=excluded.filename_limit,
                    directory_name_limit=excluded.directory_name_limit,
                    windows_prefix_length=excluded.windows_prefix_length,
                    severity=excluded.severity,
                    issue_codes=excluded.issue_codes,
                    recommendation=excluded.recommendation,
                    seen_generation=excluded.seen_generation
                """,
                (
                    self.scan_id,
                    root.root_id,
                    safe_display(path),
                    path_bytes,
                    item_type,
                    safe_display(relative_windows),
                    actual_path_chars,
                    relative_path_chars,
                    projected_path_chars,
                    name_chars,
                    safe_display(longest_directory_name),
                    longest_directory_chars,
                    self.policy.warning_path_chars,
                    self.policy.office_path_limit,
                    self.policy.hard_path_limit,
                    self.policy.filename_limit,
                    self.policy.directory_name_limit,
                    self.policy.windows_prefix_length,
                    severity,
                    ";".join(issues),
                    recommendation,
                    self.generation,
                ),
            )

        self.counters.examined += 1
        if item_type == "file":
            self.counters.files += 1
        else:
            self.counters.directories += 1
        if issues:
            self.counters.findings += 1
            if severity == "critical":
                self.counters.critical += 1
            elif severity == "high":
                self.counters.high += 1
            else:
                self.counters.warnings += 1

        now = time.monotonic()
        if now - self._last_progress >= self.progress_seconds:
            self.logger.info(
                "Path audit progress: %d items | %d findings | %d critical | %d high | %d warnings",
                self.counters.examined,
                self.counters.findings,
                self.counters.critical,
                self.counters.high,
                self.counters.warnings,
            )
            self._last_progress = now

    def finish(self) -> PathAuditCounters:
        self.connection.execute(
            "DELETE FROM path_issues WHERE scan_id=? AND seen_generation<>?",
            (self.scan_id, self.generation),
        )
        self.connection.execute(
            """
            UPDATE scans SET
                path_audit_examined=?,
                path_audit_files=?,
                path_audit_directories=?,
                path_audit_findings=?,
                path_audit_warnings=?,
                path_audit_high=?,
                path_audit_critical=?
            WHERE scan_id=?
            """,
            (
                self.counters.examined,
                self.counters.files,
                self.counters.directories,
                self.counters.findings,
                self.counters.warnings,
                self.counters.high,
                self.counters.critical,
                self.scan_id,
            ),
        )
        self.connection.commit()
        return self.counters


def allocated_bytes_from_stat(info: os.stat_result) -> int | None:
    blocks = getattr(info, "st_blocks", None)
    if blocks is None:
        return None
    return int(blocks) * 512


def normalize_existing_directory(raw_value: str) -> str:
    expanded = os.path.expanduser(raw_value)
    resolved = os.path.realpath(os.path.abspath(expanded))
    if not os.path.exists(resolved):
        raise ValueError(f"Path does not exist: {raw_value}")
    if not os.path.isdir(resolved):
        raise ValueError(f"Path is not a directory: {raw_value}")
    return resolved


def is_same_or_child(path: str, parent: str) -> bool:
    try:
        return os.path.commonpath((path, parent)) == parent
    except ValueError:
        return False


def validate_roots(raw_roots: Sequence[str]) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for raw_root in raw_roots:
        root = normalize_existing_directory(raw_root)
        if root not in seen:
            roots.append(root)
            seen.add(root)
    return roots


def nested_root_excludes(roots: Sequence[RootInfo]) -> dict[int, tuple[str, ...]]:
    """Partition overlapping roots so each pathname is yielded exactly once.

    For example, with roots '/' and '/mnt/windows', the parent-root walk skips
    '/mnt/windows' while the child-root walk scans it normally. This supports the
    common --one-file-system multi-volume pattern without false duplicates.
    """
    result: dict[int, tuple[str, ...]] = {}
    for parent in roots:
        children = [
            child.path
            for child in roots
            if child.root_id != parent.root_id and is_same_or_child(child.path, parent.path)
        ]
        result[parent.root_id] = tuple(sorted(children, key=len))
    return result


def automatic_excludes(roots: Sequence[str]) -> list[str]:
    if os.path.realpath(os.sep) not in roots:
        return []
    return ["/proc", "/sys", "/dev", "/run"]


def make_hasher(algorithm: str) -> Callable[[], object]:
    if algorithm == "sha256":
        return hashlib.sha256
    if algorithm == "blake2b":
        return lambda: hashlib.blake2b(digest_size=32)
    if algorithm == "blake3":
        try:
            from blake3 import blake3  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "BLAKE3 was selected but the optional package is missing. "
                "Install it with: python3 -m pip install blake3"
            ) from exc
        return blake3
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def read_mountinfo() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.rstrip("\n").split()
                try:
                    separator = fields.index("-")
                except ValueError:
                    continue
                if len(fields) < 10 or separator + 2 >= len(fields):
                    continue
                entries.append(
                    {
                        "major_minor": fields[2],
                        "mount_point": fields[4].replace("\\040", " "),
                        "filesystem_type": fields[separator + 1],
                        "mount_source": fields[separator + 2].replace("\\040", " "),
                    }
                )
    except OSError:
        pass
    return entries


def device_uuid_map() -> dict[str, str]:
    result: dict[str, str] = {}
    base = Path("/dev/disk/by-uuid")
    try:
        for entry in base.iterdir():
            try:
                target = os.path.realpath(entry)
                result[target] = entry.name
            except OSError:
                continue
    except OSError:
        pass
    return result


def mount_details(path: str, info: os.stat_result) -> tuple[str, str, str, str]:
    major_minor = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    candidates = [
        entry
        for entry in read_mountinfo()
        if entry["major_minor"] == major_minor and is_same_or_child(path, entry["mount_point"])
    ]
    if candidates:
        selected = max(candidates, key=lambda entry: len(entry["mount_point"]))
        source = selected["mount_source"]
        fs_uuid = device_uuid_map().get(os.path.realpath(source), "")
        return (
            selected["mount_point"],
            selected["filesystem_type"],
            source,
            fs_uuid,
        )
    return (path, "unknown", "unknown", "")


def configure_logging(log_path: Path, detail: str) -> logging.Logger:
    logger = logging.getLogger(PROGRAM_NAME)
    logger.setLevel(logging.DEBUG if detail == "trace" else logging.INFO)
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    file_handler = logging.FileHandler(
        log_path, mode="a", encoding="utf-8", errors="backslashreplace"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    try:
        os.chmod(log_path, 0o600)
    except OSError:
        pass
    return logger


@contextlib.contextmanager
def restrictive_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def secure_output_directory(path: Path) -> None:
    with restrictive_umask():
        path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def create_schema(connection: sqlite3.Connection) -> None:
    existing_columns = {row[1] for row in connection.execute("PRAGMA table_info(files)")}
    if existing_columns and "scan_id" not in existing_columns:
        raise RuntimeError(
            "This is a legacy HashWatchDog database and cannot be reused incrementally. "
            "Run without --incremental, or move the old database to an archive directory."
        )
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA temp_store=MEMORY")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            started_utc TEXT NOT NULL,
            ended_utc TEXT,
            hostname TEXT NOT NULL,
            platform TEXT NOT NULL,
            python_version TEXT NOT NULL,
            program_version TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            config_fingerprint TEXT NOT NULL,
            invocation_json TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 1,
            interrupted_reason TEXT NOT NULL DEFAULT '',
            path_audit_enabled INTEGER NOT NULL DEFAULT 0,
            path_audit_only INTEGER NOT NULL DEFAULT 0,
            path_warning_chars INTEGER NOT NULL DEFAULT 200,
            office_path_limit INTEGER NOT NULL DEFAULT 240,
            hard_path_limit INTEGER NOT NULL DEFAULT 259,
            filename_limit INTEGER NOT NULL DEFAULT 100,
            directory_name_limit INTEGER NOT NULL DEFAULT 100,
            windows_prefix_length INTEGER NOT NULL DEFAULT 0,
            path_audit_examined INTEGER NOT NULL DEFAULT 0,
            path_audit_files INTEGER NOT NULL DEFAULT 0,
            path_audit_directories INTEGER NOT NULL DEFAULT 0,
            path_audit_findings INTEGER NOT NULL DEFAULT 0,
            path_audit_warnings INTEGER NOT NULL DEFAULT 0,
            path_audit_high INTEGER NOT NULL DEFAULT 0,
            path_audit_critical INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS roots (
            id INTEGER PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL,
            path_display TEXT NOT NULL,
            path_raw BLOB NOT NULL,
            device INTEGER NOT NULL,
            mount_point TEXT NOT NULL,
            filesystem_type TEXT NOT NULL,
            mount_source TEXT NOT NULL,
            filesystem_uuid TEXT NOT NULL,
            UNIQUE(scan_id, path_raw)
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            root_id INTEGER NOT NULL REFERENCES roots(id) ON DELETE CASCADE,
            path_display TEXT NOT NULL,
            path_raw BLOB NOT NULL,
            size_bytes INTEGER,
            allocated_bytes INTEGER,
            mtime_ns INTEGER,
            ctime_ns INTEGER,
            device INTEGER,
            inode INTEGER,
            digest TEXT NOT NULL,
            sample_digest TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT NOT NULL,
            bytes_read INTEGER NOT NULL,
            elapsed_seconds REAL NOT NULL,
            management_class TEXT NOT NULL,
            classification_confidence TEXT NOT NULL,
            classification_reason TEXT NOT NULL,
            cleanup_risk TEXT NOT NULL,
            seen_generation INTEGER NOT NULL,
            reused_from_file_id INTEGER,
            UNIQUE(scan_id, path_raw)
        );

        CREATE TABLE IF NOT EXISTS path_issues (
            id INTEGER PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            root_id INTEGER NOT NULL REFERENCES roots(id) ON DELETE CASCADE,
            path_display TEXT NOT NULL,
            path_raw BLOB NOT NULL,
            item_type TEXT NOT NULL,
            relative_path_display TEXT NOT NULL,
            actual_path_chars INTEGER NOT NULL,
            relative_path_chars INTEGER NOT NULL,
            projected_path_chars INTEGER NOT NULL,
            name_chars INTEGER NOT NULL,
            longest_directory_name TEXT NOT NULL,
            longest_directory_chars INTEGER NOT NULL,
            warning_path_chars INTEGER NOT NULL,
            office_path_limit INTEGER NOT NULL,
            hard_path_limit INTEGER NOT NULL,
            filename_limit INTEGER NOT NULL,
            directory_name_limit INTEGER NOT NULL,
            windows_prefix_length INTEGER NOT NULL,
            severity TEXT NOT NULL,
            issue_codes TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            seen_generation INTEGER NOT NULL,
            UNIQUE(scan_id, path_raw)
        );

        CREATE INDEX IF NOT EXISTS idx_files_scan_digest_size
            ON files(scan_id, status, digest, size_bytes);
        CREATE INDEX IF NOT EXISTS idx_files_scan_device_inode
            ON files(scan_id, device, inode);
        CREATE INDEX IF NOT EXISTS idx_files_scan_path_display
            ON files(scan_id, path_display);
        CREATE INDEX IF NOT EXISTS idx_files_reuse_lookup
            ON files(path_raw, algorithm, size_bytes, mtime_ns, ctime_ns, device, inode, status);
        CREATE INDEX IF NOT EXISTS idx_path_issues_scan_severity
            ON path_issues(scan_id, severity, projected_path_chars);
        CREATE INDEX IF NOT EXISTS idx_path_issues_scan_path
            ON path_issues(scan_id, path_display);
        CREATE INDEX IF NOT EXISTS idx_scans_state_started
            ON scans(state, started_utc);
        """
    )
    current_columns = {row[1] for row in connection.execute("PRAGMA table_info(files)")}
    if "sample_digest" not in current_columns:
        connection.execute("ALTER TABLE files ADD COLUMN sample_digest TEXT NOT NULL DEFAULT ''")
    scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
    scan_column_migrations = {
        "path_audit_enabled": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_only": "INTEGER NOT NULL DEFAULT 0",
        "path_warning_chars": "INTEGER NOT NULL DEFAULT 200",
        "office_path_limit": "INTEGER NOT NULL DEFAULT 240",
        "hard_path_limit": "INTEGER NOT NULL DEFAULT 259",
        "filename_limit": "INTEGER NOT NULL DEFAULT 100",
        "directory_name_limit": "INTEGER NOT NULL DEFAULT 100",
        "windows_prefix_length": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_examined": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_files": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_directories": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_findings": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_warnings": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_high": "INTEGER NOT NULL DEFAULT 0",
        "path_audit_critical": "INTEGER NOT NULL DEFAULT 0",
    }
    for column, declaration in scan_column_migrations.items():
        if column not in scan_columns:
            connection.execute(f"ALTER TABLE scans ADD COLUMN {column} {declaration}")
    connection.execute(
        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()


def open_database(path: Path) -> sqlite3.Connection:
    with restrictive_umask():
        connection = sqlite3.connect(path, timeout=60.0)
    connection.row_factory = sqlite3.Row
    create_schema(connection)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


def sqlite_backup(source: Path, destination: Path) -> None:
    with sqlite3.connect(source) as source_conn:
        with restrictive_umask():
            destination_conn = sqlite3.connect(destination)
        try:
            source_conn.backup(destination_conn)
            destination_conn.commit()
        finally:
            destination_conn.close()


def configuration_payload(args: argparse.Namespace, roots: Sequence[str], excludes: Sequence[str]) -> dict[str, object]:
    return {
        "roots": [safe_display(root) for root in roots],
        "roots_raw_hex": [raw_path(root).hex() for root in roots],
        "excludes_raw_hex": sorted(raw_path(path).hex() for path in excludes),
        "algorithm": args.algorithm,
        "one_file_system": bool(args.one_file_system),
        "empty_files": args.empty_files,
        "chunk_size_mib": int(args.chunk_size_mib),
        "managed_classification": not bool(args.no_managed_classification),
        "path_audit_enabled": bool(args.audit_paths),
        "path_audit_only": bool(args.path_audit_only),
        "path_warning_chars": int(args.path_warning_chars),
        "office_path_limit": int(args.office_path_limit),
        "hard_path_limit": int(args.hard_path_limit),
        "filename_limit": int(args.filename_limit),
        "directory_name_limit": int(args.directory_name_limit),
        "windows_prefix_length": int(args.windows_prefix_length),
    }


def legacy_configuration_payload(
    args: argparse.Namespace,
    roots: Sequence[str],
    excludes: Sequence[str],
) -> dict[str, object]:
    """Build the v2 fingerprint payload for resuming pre-path-audit scans."""
    return {
        "roots": [safe_display(root) for root in roots],
        "roots_raw_hex": [raw_path(root).hex() for root in roots],
        "excludes_raw_hex": sorted(raw_path(path).hex() for path in excludes),
        "algorithm": args.algorithm,
        "one_file_system": bool(args.one_file_system),
        "empty_files": args.empty_files,
        "chunk_size_mib": int(args.chunk_size_mib),
        "managed_classification": not bool(args.no_managed_classification),
    }


def fingerprint(payload: dict[str, object]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def initialize_new_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    roots: Sequence[str],
    config_fingerprint: str,
) -> tuple[str, int, list[RootInfo]]:
    scan_id = str(uuid.uuid4())
    invocation = {
        "argv": [safe_display(arg) for arg in sys.argv],
        "cwd": safe_display(os.getcwd()),
    }
    connection.execute(
        """
        INSERT INTO scans(
            scan_id, state, started_utc, hostname, platform, python_version,
            program_version, schema_version, algorithm, config_fingerprint,
            invocation_json, generation, path_audit_enabled, path_audit_only,
            path_warning_chars, office_path_limit, hard_path_limit, filename_limit,
            directory_name_limit, windows_prefix_length
        ) VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            utc_now(),
            socket.gethostname(),
            platform.platform(),
            platform.python_version(),
            VERSION,
            SCHEMA_VERSION,
            args.algorithm,
            config_fingerprint,
            json.dumps(invocation, ensure_ascii=True),
            int(args.audit_paths),
            int(args.path_audit_only),
            args.path_warning_chars,
            args.office_path_limit,
            args.hard_path_limit,
            args.filename_limit,
            args.directory_name_limit,
            args.windows_prefix_length,
        ),
    )
    root_infos: list[RootInfo] = []
    for ordinal, root in enumerate(roots, start=1):
        info = os.stat(root, follow_symlinks=False)
        mount_point, fs_type, source, fs_uuid = mount_details(root, info)
        cursor = connection.execute(
            """
            INSERT INTO roots(
                scan_id, ordinal, path_display, path_raw, device, mount_point,
                filesystem_type, mount_source, filesystem_uuid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                ordinal,
                safe_display(root),
                sqlite3.Binary(raw_path(root)),
                info.st_dev,
                safe_display(mount_point),
                safe_display(fs_type),
                safe_display(source),
                safe_display(fs_uuid),
            ),
        )
        root_infos.append(
            RootInfo(
                root_id=int(cursor.lastrowid),
                path=root,
                path_display=safe_display(root),
                path_raw=raw_path(root),
                device=info.st_dev,
                mount_point=safe_display(mount_point),
                filesystem_type=safe_display(fs_type),
                mount_source=safe_display(source),
                filesystem_uuid=safe_display(fs_uuid),
            )
        )
    connection.commit()
    return scan_id, 1, root_infos


def resume_scan(
    connection: sqlite3.Connection,
    config_fingerprint: str,
    legacy_config_fingerprint: str | None = None,
) -> tuple[str, int, list[RootInfo]]:
    row = connection.execute(
        """
        SELECT * FROM scans
        WHERE state IN ('running', 'interrupted', 'failed')
        ORDER BY started_utc DESC LIMIT 1
        """
    ).fetchone()
    if row is None:
        raise ValueError("No interrupted scan exists in the partial database.")
    valid_fingerprints = {config_fingerprint}
    if legacy_config_fingerprint is not None and int(row["schema_version"]) < 3:
        valid_fingerprints.add(legacy_config_fingerprint)
    if row["config_fingerprint"] not in valid_fingerprints:
        raise ValueError(
            "The interrupted scan configuration does not match this invocation. "
            "Use the same roots, exclusions, algorithm, filesystem policy, and empty-file policy."
        )
    scan_id = str(row["scan_id"])
    generation = int(row["generation"]) + 1
    connection.execute(
        """
        UPDATE scans
        SET state='running', ended_utc=NULL, interrupted_reason='', generation=?
        WHERE scan_id=?
        """,
        (generation, scan_id),
    )
    roots: list[RootInfo] = []
    for root in connection.execute(
        "SELECT * FROM roots WHERE scan_id=? ORDER BY ordinal", (scan_id,)
    ):
        path = os.fsdecode(bytes(root["path_raw"]))
        roots.append(
            RootInfo(
                root_id=int(root["id"]),
                path=path,
                path_display=str(root["path_display"]),
                path_raw=bytes(root["path_raw"]),
                device=int(root["device"]),
                mount_point=str(root["mount_point"]),
                filesystem_type=str(root["filesystem_type"]),
                mount_source=str(root["mount_source"]),
                filesystem_uuid=str(root["filesystem_uuid"]),
            )
        )
    connection.commit()
    return scan_id, generation, roots


def latest_completed_scan_id(connection: sqlite3.Connection, algorithm: str) -> str | None:
    row = connection.execute(
        """
        SELECT scan_id FROM scans
        WHERE state='completed' AND algorithm=? AND path_audit_only=0
        ORDER BY ended_utc DESC LIMIT 1
        """,
        (algorithm,),
    ).fetchone()
    return None if row is None else str(row["scan_id"])


def classify_path(root: str, path: str, enabled: bool) -> tuple[str, str, str, str]:
    if not enabled:
        return ("unclassified", "none", "classification disabled", "medium")

    try:
        relative = os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        relative = path.replace(os.sep, "/")
    lowered = "/" + relative.lower().lstrip("/")

    content_addressed_markers = (
        "/.git/objects/",
        "/nix/store/",
        "/var/lib/docker/overlay2/",
        "/var/lib/containers/storage/",
        "/cas/",
    )
    if any(marker in lowered for marker in content_addressed_markers):
        return (
            "content-addressed",
            "high",
            "path matches a content-addressed or container storage area",
            "high",
        )

    critical_prefixes = (
        "/boot/",
        "/etc/",
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib32/",
        "/lib64/",
        "/windows/",
        "/windows/system32/",
    )
    if lowered == "/boot" or any(lowered.startswith(prefix) for prefix in critical_prefixes):
        return (
            "system-critical",
            "high",
            "path is inside an operating-system or boot-critical area",
            "critical",
        )

    package_prefixes = (
        "/usr/",
        "/var/lib/dpkg/",
        "/var/lib/rpm/",
        "/var/lib/pacman/",
        "/var/cache/apt/",
        "/var/cache/dnf/",
        "/var/cache/pacman/",
    )
    if any(lowered.startswith(prefix) for prefix in package_prefixes):
        return (
            "package-managed",
            "high",
            "path is inside a package-manager or system package area",
            "critical" if lowered.startswith("/usr/") else "high",
        )

    application_markers = (
        "/.steam/",
        "/steamapps/",
        "/flatpak/",
        "/.var/app/",
        "/snap/",
        "/appdata/",
        "/program files/",
        "/program files (x86)/",
        "/programdata/",
        "/jetbrains/",
        "/pycharm",
        "/node_modules/",
        "/site-packages/",
    )
    if any(marker in lowered for marker in application_markers):
        return (
            "application-managed",
            "medium",
            "path matches an application-managed runtime, cache, or installation area",
            "high",
        )

    return (
        "user-managed",
        "medium",
        "path does not match a known managed-content area",
        "low",
    )


def walk_files(
    roots: Sequence[RootInfo],
    excludes: Sequence[str],
    one_file_system: bool,
    generation: int,
    logger: logging.Logger,
    cancel_event: threading.Event,
    path_auditor: PathAuditor | None = None,
) -> Iterator[FileTask]:
    normalized_excludes = tuple(os.path.realpath(path) for path in excludes)
    nested_excludes = nested_root_excludes(roots)
    for root in roots:
        root_excludes = normalized_excludes + nested_excludes.get(root.root_id, ())
        stack = [root.path]
        while stack and not cancel_event.is_set():
            directory = stack.pop()
            if any(is_same_or_child(directory, excluded) for excluded in root_excludes):
                continue
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if cancel_event.is_set():
                            return
                        path = entry.path
                        if any(is_same_or_child(path, excluded) for excluded in root_excludes):
                            continue
                        try:
                            if entry.is_symlink():
                                continue
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                if path_auditor is not None:
                                    path_auditor.record(root, path, "directory")
                                if one_file_system and info.st_dev != root.device:
                                    if logger.isEnabledFor(logging.DEBUG):
                                        logger.debug("Skipped mount point: %s", safe_display(path))
                                    continue
                                stack.append(path)
                            elif stat.S_ISREG(info.st_mode):
                                if path_auditor is not None:
                                    path_auditor.record(root, path, "file")
                                yield FileTask(
                                    root=root,
                                    path=path,
                                    path_display=safe_display(path),
                                    path_raw=raw_path(path),
                                    size_bytes=int(info.st_size),
                                    allocated_bytes=allocated_bytes_from_stat(info),
                                    mtime_ns=int(info.st_mtime_ns),
                                    ctime_ns=int(info.st_ctime_ns),
                                    device=int(info.st_dev),
                                    inode=int(info.st_ino),
                                    nlink=int(info.st_nlink),
                                    generation=generation,
                                )
                        except OSError as exc:
                            logger.warning("Cannot inspect %s: %s", safe_display(path), exc)
            except OSError as exc:
                logger.warning("Cannot enter directory %s: %s", safe_display(directory), exc)


def open_regular_no_follow(path: str) -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags)


def metadata_changed(before: os.stat_result, after: os.stat_result, bytes_read: int) -> bool:
    return (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or bytes_read != after.st_size
    )


def path_still_names_descriptor(path: str, descriptor_info: os.stat_result) -> bool:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return current.st_dev == descriptor_info.st_dev and current.st_ino == descriptor_info.st_ino


def empty_digest(hasher_factory: Callable[[], object]) -> str:
    return hasher_factory().hexdigest()  # type: ignore[attr-defined]


def hash_one_file(
    task: FileTask,
    hasher_factory: Callable[[], object],
    chunk_size: int,
    retries: int,
    empty_policy: str,
    tracker: ProgressTracker,
    cancel_event: threading.Event,
    classification_enabled: bool,
) -> HashResult:
    overall_started = time.monotonic()
    total_bytes_read = 0
    management = classify_path(task.root.path, task.path, classification_enabled)

    for attempt_index in range(retries + 1):
        attempt = attempt_index + 1
        fd: int | None = None
        progress_key: int | None = None
        attempt_bytes = 0
        try:
            if cancel_event.is_set():
                raise ScanInterrupted("scan cancellation requested")
            fd = open_regular_no_follow(task.path)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise OSError(errno.EINVAL, "Path is no longer a regular file")

            if before.st_size == 0:
                status = (
                    "empty_reported" if empty_policy == "report"
                    else "empty_ignored" if empty_policy == "ignore"
                    else "empty"
                )
                digest = empty_digest(hasher_factory) if empty_policy == "report" else ""
                return HashResult(
                    task=task,
                    digest=digest,
                    sample_digest=sample_digest_fd(fd, 0),
                    status=status,
                    error="",
                    bytes_read=total_bytes_read,
                    elapsed_seconds=time.monotonic() - overall_started,
                    final_size_bytes=0,
                    final_allocated_bytes=allocated_bytes_from_stat(before),
                    final_mtime_ns=before.st_mtime_ns,
                    final_ctime_ns=before.st_ctime_ns,
                    final_device=before.st_dev,
                    final_inode=before.st_ino,
                    management_class=management[0],
                    classification_confidence=management[1],
                    classification_reason=management[2],
                    cleanup_risk=management[3],
                )

            hasher = hasher_factory()
            buffer = worker_buffer(chunk_size)
            view = memoryview(buffer)
            progress_key = tracker.start_file(task.path_display, int(before.st_size), attempt)
            while True:
                if cancel_event.is_set():
                    raise ScanInterrupted("scan cancellation requested")
                count = os.readv(fd, [buffer]) if hasattr(os, "readv") else os.read(fd, chunk_size)
                if isinstance(count, bytes):
                    if not count:
                        break
                    hasher.update(count)  # type: ignore[attr-defined]
                    read_count = len(count)
                else:
                    if count == 0:
                        break
                    hasher.update(view[:count])  # type: ignore[attr-defined]
                    read_count = int(count)
                attempt_bytes += read_count
                total_bytes_read += read_count
                tracker.add_bytes(progress_key, read_count)

            after = os.fstat(fd)
            changed = metadata_changed(before, after, attempt_bytes)
            path_mismatch = not path_still_names_descriptor(task.path, after)
            if changed or path_mismatch:
                reason = (
                    "Path no longer names the hashed file"
                    if path_mismatch
                    else "File changed while being hashed"
                )
                if attempt_index < retries:
                    continue
                return HashResult(
                    task=task,
                    digest="",
                    sample_digest="",
                    status="changed",
                    error=reason,
                    bytes_read=total_bytes_read,
                    elapsed_seconds=time.monotonic() - overall_started,
                    final_size_bytes=after.st_size,
                    final_allocated_bytes=allocated_bytes_from_stat(after),
                    final_mtime_ns=after.st_mtime_ns,
                    final_ctime_ns=after.st_ctime_ns,
                    final_device=after.st_dev,
                    final_inode=after.st_ino,
                    management_class=management[0],
                    classification_confidence=management[1],
                    classification_reason=management[2],
                    cleanup_risk=management[3],
                )

            return HashResult(
                task=task,
                digest=hasher.hexdigest(),  # type: ignore[attr-defined]
                sample_digest=sample_digest_fd(fd, int(after.st_size)),
                status="ok",
                error="",
                bytes_read=total_bytes_read,
                elapsed_seconds=time.monotonic() - overall_started,
                final_size_bytes=after.st_size,
                final_allocated_bytes=allocated_bytes_from_stat(after),
                final_mtime_ns=after.st_mtime_ns,
                final_ctime_ns=after.st_ctime_ns,
                final_device=after.st_dev,
                final_inode=after.st_ino,
                management_class=management[0],
                classification_confidence=management[1],
                classification_reason=management[2],
                cleanup_risk=management[3],
            )
        except ScanInterrupted as exc:
            return HashResult(
                task=task,
                digest="",
                sample_digest="",
                status="cancelled",
                error=str(exc),
                bytes_read=total_bytes_read,
                elapsed_seconds=time.monotonic() - overall_started,
                final_size_bytes=None,
                final_allocated_bytes=None,
                final_mtime_ns=None,
                final_ctime_ns=None,
                final_device=None,
                final_inode=None,
                management_class=management[0],
                classification_confidence=management[1],
                classification_reason=management[2],
                cleanup_risk=management[3],
            )
        except OSError as exc:
            return HashResult(
                task=task,
                digest="",
                sample_digest="",
                status="error",
                error=f"{type(exc).__name__}: {exc}",
                bytes_read=total_bytes_read,
                elapsed_seconds=time.monotonic() - overall_started,
                final_size_bytes=None,
                final_allocated_bytes=None,
                final_mtime_ns=None,
                final_ctime_ns=None,
                final_device=None,
                final_inode=None,
                management_class=management[0],
                classification_confidence=management[1],
                classification_reason=management[2],
                cleanup_risk=management[3],
            )
        except Exception as exc:  # preserve the remainder of a long scan
            return HashResult(
                task=task,
                digest="",
                sample_digest="",
                status="error",
                error=f"Unexpected {type(exc).__name__}: {exc}",
                bytes_read=total_bytes_read,
                elapsed_seconds=time.monotonic() - overall_started,
                final_size_bytes=None,
                final_allocated_bytes=None,
                final_mtime_ns=None,
                final_ctime_ns=None,
                final_device=None,
                final_inode=None,
                management_class=management[0],
                classification_confidence=management[1],
                classification_reason=management[2],
                cleanup_risk=management[3],
            )
        finally:
            if progress_key is not None:
                tracker.finish_file(progress_key)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    raise AssertionError("unreachable hashing state")


def metadata_matches(task: FileTask, row: sqlite3.Row) -> bool:
    return (
        row["size_bytes"] == task.size_bytes
        and row["mtime_ns"] == task.mtime_ns
        and row["ctime_ns"] == task.ctime_ns
        and row["device"] == task.device
        and row["inode"] == task.inode
    )


def sample_digest_fd(fd: int, size: int, sample_size: int = 64 * 1024) -> str:
    """Hash deterministic beginning/middle/end samples without changing content semantics."""
    hasher = hashlib.blake2b(digest_size=16)
    positions = [0]
    if size > sample_size:
        positions.append(max((size // 2) - (sample_size // 2), 0))
        positions.append(max(size - sample_size, 0))
    seen: set[int] = set()
    original_offset = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        for position in positions:
            if position in seen:
                continue
            seen.add(position)
            os.lseek(fd, position, os.SEEK_SET)
            data = os.read(fd, min(sample_size, max(size - position, 0)))
            hasher.update(position.to_bytes(8, "little", signed=False))
            hasher.update(data)
        return hasher.hexdigest()
    finally:
        os.lseek(fd, original_offset, os.SEEK_SET)


def sample_digest(path: str, size: int, sample_size: int = 64 * 1024) -> str:
    fd = open_regular_no_follow(path)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            raise OSError(errno.EAGAIN, "file metadata changed before sample verification")
        digest = sample_digest_fd(fd, size, sample_size)
        after = os.fstat(fd)
        if metadata_changed(info, after, size):
            raise OSError(errno.EAGAIN, "file changed during sample verification")
        return digest
    finally:
        os.close(fd)


def resumable_row(
    connection: sqlite3.Connection,
    scan_id: str,
    task: FileTask,
) -> sqlite3.Row | None:
    row = connection.execute(
        "SELECT * FROM files WHERE scan_id=? AND path_raw=?",
        (scan_id, sqlite3.Binary(task.path_raw)),
    ).fetchone()
    if row is None:
        return None
    if row["status"] not in ("ok", "empty", "empty_ignored", "empty_reported", "reused"):
        return None
    return row if metadata_matches(task, row) else None


def incremental_row(
    connection: sqlite3.Connection,
    previous_scan_id: str | None,
    task: FileTask,
    algorithm: str,
    policy: str,
) -> sqlite3.Row | None:
    if previous_scan_id is None or policy == "strict":
        return None
    row = connection.execute(
        """
        SELECT * FROM files
        WHERE scan_id=? AND path_raw=? AND algorithm=?
          AND status IN ('ok', 'empty', 'empty_ignored', 'empty_reported', 'reused')
        """,
        (previous_scan_id, sqlite3.Binary(task.path_raw), algorithm),
    ).fetchone()
    if row is None or not metadata_matches(task, row):
        return None
    if policy == "sampled" and task.size_bytes > 0:
        stored_sample = str(row["sample_digest"] or "")
        if not stored_sample:
            return None
        try:
            if sample_digest(task.path, task.size_bytes) != stored_sample:
                return None
        except OSError:
            return None
    return row


def current_identity_row(
    connection: sqlite3.Connection,
    scan_id: str,
    task: FileTask,
) -> sqlite3.Row | None:
    if task.nlink <= 1:
        return None
    return connection.execute(
        """
        SELECT * FROM files
        WHERE scan_id=? AND device=? AND inode=? AND size_bytes=?
          AND mtime_ns=? AND ctime_ns=?
          AND status IN ('ok','reused','empty','empty_ignored','empty_reported')
        LIMIT 1
        """,
        (
            scan_id,
            task.device,
            task.inode,
            task.size_bytes,
            task.mtime_ns,
            task.ctime_ns,
        ),
    ).fetchone()


def mark_seen(connection: sqlite3.Connection, file_id: int, generation: int) -> None:
    connection.execute(
        "UPDATE files SET seen_generation=? WHERE id=?", (generation, file_id)
    )


def copy_reused_row(
    connection: sqlite3.Connection,
    scan_id: str,
    task: FileTask,
    source: sqlite3.Row,
    generation: int,
    classification_enabled: bool,
) -> None:
    management = classify_path(task.root.path, task.path, classification_enabled)
    connection.execute(
        """
        INSERT INTO files(
            scan_id, root_id, path_display, path_raw, size_bytes, allocated_bytes,
            mtime_ns, ctime_ns, device, inode, digest, sample_digest, algorithm, status, error,
            bytes_read, elapsed_seconds, management_class,
            classification_confidence, classification_reason, cleanup_risk,
            seen_generation, reused_from_file_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reused', '', 0, 0.0, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id, path_raw) DO UPDATE SET
            root_id=excluded.root_id,
            path_display=excluded.path_display,
            size_bytes=excluded.size_bytes,
            allocated_bytes=excluded.allocated_bytes,
            mtime_ns=excluded.mtime_ns,
            ctime_ns=excluded.ctime_ns,
            device=excluded.device,
            inode=excluded.inode,
            digest=excluded.digest,
            sample_digest=excluded.sample_digest,
            algorithm=excluded.algorithm,
            status='reused',
            error='',
            bytes_read=0,
            elapsed_seconds=0.0,
            management_class=excluded.management_class,
            classification_confidence=excluded.classification_confidence,
            classification_reason=excluded.classification_reason,
            cleanup_risk=excluded.cleanup_risk,
            seen_generation=excluded.seen_generation,
            reused_from_file_id=excluded.reused_from_file_id
        """,
        (
            scan_id,
            task.root.root_id,
            task.path_display,
            sqlite3.Binary(task.path_raw),
            task.size_bytes,
            task.allocated_bytes,
            task.mtime_ns,
            task.ctime_ns,
            task.device,
            task.inode,
            source["digest"],
            source["sample_digest"],
            source["algorithm"],
            management[0],
            management[1],
            management[2],
            management[3],
            generation,
            source["id"],
        ),
    )


def write_result(
    connection: sqlite3.Connection,
    scan_id: str,
    algorithm: str,
    result: HashResult,
) -> None:
    connection.execute(
        """
        INSERT INTO files(
            scan_id, root_id, path_display, path_raw, size_bytes, allocated_bytes,
            mtime_ns, ctime_ns, device, inode, digest, sample_digest, algorithm, status, error,
            bytes_read, elapsed_seconds, management_class,
            classification_confidence, classification_reason, cleanup_risk,
            seen_generation, reused_from_file_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(scan_id, path_raw) DO UPDATE SET
            root_id=excluded.root_id,
            path_display=excluded.path_display,
            size_bytes=excluded.size_bytes,
            allocated_bytes=excluded.allocated_bytes,
            mtime_ns=excluded.mtime_ns,
            ctime_ns=excluded.ctime_ns,
            device=excluded.device,
            inode=excluded.inode,
            digest=excluded.digest,
            sample_digest=excluded.sample_digest,
            algorithm=excluded.algorithm,
            status=excluded.status,
            error=excluded.error,
            bytes_read=excluded.bytes_read,
            elapsed_seconds=excluded.elapsed_seconds,
            management_class=excluded.management_class,
            classification_confidence=excluded.classification_confidence,
            classification_reason=excluded.classification_reason,
            cleanup_risk=excluded.cleanup_risk,
            seen_generation=excluded.seen_generation,
            reused_from_file_id=NULL
        """,
        (
            scan_id,
            result.task.root.root_id,
            result.task.path_display,
            sqlite3.Binary(result.task.path_raw),
            result.final_size_bytes,
            result.final_allocated_bytes,
            result.final_mtime_ns,
            result.final_ctime_ns,
            result.final_device,
            result.final_inode,
            result.digest,
            result.sample_digest,
            algorithm,
            result.status,
            result.error,
            result.bytes_read,
            result.elapsed_seconds,
            result.management_class,
            result.classification_confidence,
            result.classification_reason,
            result.cleanup_risk,
            result.task.generation,
        ),
    )


def update_counters(
    counters: Counters,
    counters_lock: threading.Lock,
    result: HashResult,
) -> None:
    with counters_lock:
        counters.examined += 1
        if result.status == "ok":
            counters.hashed += 1
        elif result.status in ("empty", "empty_reported"):
            counters.empty += 1
        elif result.status == "changed":
            counters.changed += 1
        elif result.status == "cancelled":
            counters.cancelled += 1
        elif result.status == "error":
            counters.errors += 1


def process_results(
    futures: Iterable[Future[HashResult]],
    connection: sqlite3.Connection,
    scan_id: str,
    algorithm: str,
    counters: Counters,
    counters_lock: threading.Lock,
    logger: logging.Logger,
    print_hashes: bool,
) -> None:
    for future in futures:
        result = future.result()
        write_result(connection, scan_id, algorithm, result)
        update_counters(counters, counters_lock, result)
        if print_hashes and result.status in ("ok", "reused", "empty_reported"):
            logger.info("HASH %s %s  %s", algorithm, result.digest, result.task.path_display)
        if result.status == "error":
            logger.warning("Failed to hash %s: %s", result.task.path_display, result.error)
        elif result.status == "changed":
            logger.warning("Skipped changing file %s: %s", result.task.path_display, result.error)


def risk_max(values: Iterable[str]) -> str:
    return max(values, key=lambda value: RISK_ORDER.get(value, 1), default="medium")


def fsync_file(handle: object) -> None:
    handle.flush()  # type: ignore[attr-defined]
    os.fsync(handle.fileno())  # type: ignore[attr-defined]


def atomic_replace(temp_path: Path, final_path: Path) -> None:
    os.replace(temp_path, final_path)
    try:
        directory_fd = os.open(final_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def remove_stale_report(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass



@contextlib.contextmanager
def report_phase(logger: logging.Logger, name: str) -> Iterator[dict[str, float]]:
    """Log a report phase and emit a warning if one SQL operation runs for a long time."""
    started = time.monotonic()
    stopped = threading.Event()

    def watchdog() -> None:
        while not stopped.wait(60.0):
            logger.warning(
                "Report phase still working: %s | elapsed %.1f seconds",
                name,
                time.monotonic() - started,
            )

    thread = threading.Thread(
        target=watchdog,
        name=f"report-watchdog-{name.replace(' ', '-')}",
        daemon=True,
    )
    logger.info("Report phase: %s", name)
    thread.start()
    timing: dict[str, float] = {"elapsed": 0.0}
    try:
        yield timing
    finally:
        stopped.set()
        thread.join(timeout=1.0)
        timing["elapsed"] = max(time.monotonic() - started, 0.0)
        logger.info("Report phase complete: %s | %.2f seconds", name, timing["elapsed"])


def progress_due(
    processed: int,
    last_processed: int,
    now: float,
    last_logged: float,
    row_interval: int = 50_000,
    time_interval: float = 5.0,
) -> bool:
    return processed - last_processed >= row_interval or now - last_logged >= time_interval


def prepare_reporting_database(
    connection: sqlite3.Connection,
    logger: logging.Logger,
) -> float:
    """Checkpoint the ingestion WAL and refresh planner statistics once."""
    with report_phase(logger, "preparing SQLite for reporting") as timing:
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA optimize")
        connection.commit()
    return timing["elapsed"]


def generate_all_hashes_csv(
    connection: sqlite3.Connection,
    scan_id: str,
    temp_path: Path,
    logger: logging.Logger,
) -> tuple[int, float]:
    total_row = connection.execute(
        "SELECT COUNT(*) AS count FROM files WHERE scan_id=?", (scan_id,)
    ).fetchone()
    total = int(total_row["count"] if total_row else 0)

    with report_phase(logger, f"exporting all-file inventory ({total} rows)") as timing:
        with restrictive_umask(), open(
            temp_path,
            "w",
            newline="",
            encoding="utf-8",
            errors="backslashreplace",
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(
                (
                    "scan_id",
                    "root",
                    "path",
                    "path_bytes_hex",
                    "apparent_size_bytes",
                    "allocated_size_bytes",
                    "sparse",
                    "mtime_utc",
                    "ctime_utc",
                    "hash",
                    "sample_hash",
                    "algorithm",
                    "status",
                    "error",
                    "logical_bytes_read",
                    "elapsed_seconds",
                    "device",
                    "inode",
                    "management_class",
                    "classification_confidence",
                    "classification_reason",
                    "cleanup_risk",
                    "reused_from_file_id",
                )
            )
            rows = connection.execute(
                """
                SELECT f.*, r.path_display AS root_display
                FROM files AS f
                JOIN roots AS r ON r.id=f.root_id
                WHERE f.scan_id=?
                ORDER BY f.path_display, f.id
                """,
                (scan_id,),
            )
            processed = 0
            last_processed = 0
            last_logged = time.monotonic()
            for row in rows:
                allocated = row["allocated_bytes"]
                apparent = row["size_bytes"]
                sparse = (
                    "yes"
                    if allocated is not None and apparent is not None and allocated < apparent
                    else "no"
                )
                writer.writerow(
                    (
                        scan_id,
                        row["root_display"],
                        row["path_display"],
                        bytes(row["path_raw"]).hex(),
                        "" if apparent is None else apparent,
                        "" if allocated is None else allocated,
                        sparse,
                        utc_timestamp(row["mtime_ns"]),
                        utc_timestamp(row["ctime_ns"]),
                        row["digest"],
                        row["sample_digest"],
                        row["algorithm"],
                        row["status"],
                        row["error"],
                        row["bytes_read"],
                        f"{row['elapsed_seconds']:.6f}",
                        "" if row["device"] is None else row["device"],
                        "" if row["inode"] is None else row["inode"],
                        row["management_class"],
                        row["classification_confidence"],
                        row["classification_reason"],
                        row["cleanup_risk"],
                        "" if row["reused_from_file_id"] is None else row["reused_from_file_id"],
                    )
                )
                processed += 1
                now = time.monotonic()
                if progress_due(processed, last_processed, now, last_logged):
                    logger.info(
                        "Report progress: all-file inventory | %d / %d rows",
                        processed,
                        total,
                    )
                    last_processed = processed
                    last_logged = now
            fsync_file(handle)
        os.chmod(temp_path, 0o600)
    return processed, timing["elapsed"]


def generate_path_audit_csv(
    connection: sqlite3.Connection,
    scan_id: str,
    temp_path: Path,
    logger: logging.Logger,
) -> tuple[int, float]:
    total_row = connection.execute(
        "SELECT COUNT(*) AS count FROM path_issues WHERE scan_id=?", (scan_id,)
    ).fetchone()
    total = int(total_row["count"] if total_row else 0)

    with report_phase(logger, f"exporting path-length findings ({total} rows)") as timing:
        with restrictive_umask(), open(
            temp_path,
            "w",
            newline="",
            encoding="utf-8",
            errors="backslashreplace",
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(
                (
                    "scan_id",
                    "severity",
                    "issue_codes",
                    "item_type",
                    "root",
                    "relative_windows_path",
                    "scanned_path",
                    "path_bytes_hex",
                    "actual_scanned_path_chars",
                    "relative_path_chars",
                    "windows_prefix_length",
                    "projected_windows_path_chars",
                    "path_warning_chars",
                    "office_path_limit",
                    "hard_path_limit",
                    "name_chars",
                    "filename_limit",
                    "longest_directory_name",
                    "longest_directory_chars",
                    "directory_name_limit",
                    "characters_over_hard_limit",
                    "recommendation",
                )
            )
            rows = connection.execute(
                """
                SELECT p.*, r.path_display AS root_display
                FROM path_issues AS p
                JOIN roots AS r ON r.id=p.root_id
                WHERE p.scan_id=?
                ORDER BY
                    CASE p.severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        ELSE 2
                    END,
                    p.projected_path_chars DESC,
                    p.path_display,
                    p.id
                """,
                (scan_id,),
            )
            processed = 0
            last_processed = 0
            last_logged = time.monotonic()
            for row in rows:
                writer.writerow(
                    (
                        scan_id,
                        row["severity"],
                        row["issue_codes"],
                        row["item_type"],
                        row["root_display"],
                        row["relative_path_display"],
                        row["path_display"],
                        bytes(row["path_raw"]).hex(),
                        row["actual_path_chars"],
                        row["relative_path_chars"],
                        row["windows_prefix_length"],
                        row["projected_path_chars"],
                        row["warning_path_chars"],
                        row["office_path_limit"],
                        row["hard_path_limit"],
                        row["name_chars"],
                        row["filename_limit"],
                        row["longest_directory_name"],
                        row["longest_directory_chars"],
                        row["directory_name_limit"],
                        max(row["projected_path_chars"] - row["hard_path_limit"], 0),
                        row["recommendation"],
                    )
                )
                processed += 1
                now = time.monotonic()
                if progress_due(processed, last_processed, now, last_logged):
                    logger.info(
                        "Report progress: path-length findings | %d / %d rows",
                        processed,
                        total,
                    )
                    last_processed = processed
                    last_logged = now
            fsync_file(handle)
        os.chmod(temp_path, 0o600)
    return processed, timing["elapsed"]


def _risk_from_rank(rank: int) -> str:
    return {0: "low", 1: "medium", 2: "high", 3: "critical"}.get(rank, "medium")


def _drop_report_temp_tables(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        DROP TABLE IF EXISTS temp.report_eligible_files;
        DROP TABLE IF EXISTS temp.report_physical_copies;
        DROP TABLE IF EXISTS temp.report_duplicate_groups;
        """
    )


def generate_duplicate_csv(
    connection: sqlite3.Connection,
    scan_id: str,
    algorithm: str,
    empty_policy: str,
    temp_path: Path,
    logger: logging.Logger,
    log_detail: str,
) -> tuple[dict[str, int], dict[str, float]]:
    """Build duplicate statistics set-wise and stream all paths with one joined query."""
    summary = {
        "groups": 0,
        "cleanup_groups": 0,
        "hardlink_only_groups": 0,
        "duplicate_paths": 0,
        "logical_duplicate_bytes": 0,
        "estimated_reclaimable_min_bytes": 0,
        "estimated_reclaimable_max_bytes": 0,
    }
    timings: dict[str, float] = {}
    statuses = "('ok','reused','empty_reported')" if empty_policy == "report" else "('ok','reused')"

    _drop_report_temp_tables(connection)
    with report_phase(logger, "materializing duplicate candidates") as timing:
        connection.execute(
            f"""
            CREATE TEMP TABLE report_eligible_files AS
            SELECT
                id, root_id, path_display, path_raw, size_bytes, allocated_bytes,
                mtime_ns, ctime_ns, device, inode, digest,
                management_class, classification_confidence,
                classification_reason, cleanup_risk
            FROM files
            WHERE scan_id=? AND status IN {statuses} AND digest <> ''
            """,
            (scan_id,),
        )
        connection.executescript(
            """
            CREATE INDEX temp.idx_report_eligible_group
                ON report_eligible_files(digest, size_bytes);
            CREATE INDEX temp.idx_report_eligible_stream
                ON report_eligible_files(digest, size_bytes, path_display, id);

            CREATE TEMP TABLE report_physical_copies AS
            SELECT
                digest,
                size_bytes,
                device,
                inode,
                MAX(COALESCE(allocated_bytes, 0)) AS allocated_bytes,
                MAX(
                    CASE
                        WHEN allocated_bytes IS NOT NULL AND allocated_bytes < size_bytes THEN 1
                        ELSE 0
                    END
                ) AS sparse
            FROM report_eligible_files
            GROUP BY digest, size_bytes, device, inode;

            CREATE INDEX temp.idx_report_physical_group
                ON report_physical_copies(digest, size_bytes);
            """
        )
    timings["candidate_materialization_seconds"] = timing["elapsed"]

    with report_phase(logger, "aggregating duplicate groups") as timing:
        connection.execute(
            """
            CREATE TEMP TABLE report_duplicate_groups AS
            WITH path_stats AS (
                SELECT
                    digest,
                    size_bytes,
                    COUNT(*) AS path_count,
                    MAX(
                        CASE cleanup_risk
                            WHEN 'critical' THEN 3
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 1
                            ELSE 0
                        END
                    ) AS risk_rank
                FROM report_eligible_files
                GROUP BY digest, size_bytes
                HAVING COUNT(*) > 1
            ),
            physical_stats AS (
                SELECT
                    digest,
                    size_bytes,
                    COUNT(*) AS physical_copy_count,
                    SUM(allocated_bytes) AS total_unique_allocated_bytes,
                    MAX(allocated_bytes) AS largest_allocated_copy,
                    MIN(allocated_bytes) AS smallest_allocated_copy,
                    MAX(sparse) AS contains_sparse_file
                FROM report_physical_copies
                GROUP BY digest, size_bytes
            ),
            combined AS (
                SELECT
                    p.digest,
                    p.size_bytes,
                    p.path_count,
                    s.physical_copy_count,
                    p.size_bytes * (p.path_count - 1) AS logical_duplicate_bytes,
                    s.total_unique_allocated_bytes,
                    s.total_unique_allocated_bytes - s.largest_allocated_copy
                        AS estimated_reclaimable_min_bytes,
                    s.total_unique_allocated_bytes - s.smallest_allocated_copy
                        AS estimated_reclaimable_max_bytes,
                    s.contains_sparse_file,
                    p.risk_rank
                FROM path_stats AS p
                JOIN physical_stats AS s
                  ON s.digest=p.digest AND s.size_bytes=p.size_bytes
            )
            SELECT
                ROW_NUMBER() OVER (
                    ORDER BY size_bytes DESC, path_count DESC, digest
                ) AS group_number,
                *
            FROM combined
            """
        )
        connection.executescript(
            """
            CREATE UNIQUE INDEX temp.idx_report_groups_number
                ON report_duplicate_groups(group_number);
            CREATE UNIQUE INDEX temp.idx_report_groups_hash_size
                ON report_duplicate_groups(digest, size_bytes);
            """
        )
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS groups,
                COALESCE(SUM(CASE WHEN physical_copy_count > 1 AND size_bytes > 0 THEN 1 ELSE 0 END), 0)
                    AS cleanup_groups,
                COALESCE(SUM(CASE WHEN physical_copy_count = 1 THEN 1 ELSE 0 END), 0)
                    AS hardlink_only_groups,
                COALESCE(SUM(path_count), 0) AS duplicate_paths,
                COALESCE(SUM(logical_duplicate_bytes), 0) AS logical_duplicate_bytes,
                COALESCE(SUM(estimated_reclaimable_min_bytes), 0)
                    AS estimated_reclaimable_min_bytes,
                COALESCE(SUM(estimated_reclaimable_max_bytes), 0)
                    AS estimated_reclaimable_max_bytes
            FROM report_duplicate_groups
            """
        ).fetchone()
        if row is not None:
            for key in summary:
                summary[key] = int(row[key] or 0)
    timings["group_aggregation_seconds"] = timing["elapsed"]

    total_rows = summary["duplicate_paths"]
    with report_phase(
        logger,
        f"exporting duplicate paths ({summary['groups']} groups, {total_rows} rows)",
    ) as timing:
        with restrictive_umask(), open(
            temp_path,
            "w",
            newline="",
            encoding="utf-8",
            errors="backslashreplace",
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(
                (
                    "duplicate_group",
                    "group_kind",
                    "cleanup_candidate",
                    "algorithm",
                    "hash",
                    "apparent_size_bytes",
                    "path_count",
                    "physical_copy_count",
                    "logical_duplicate_bytes",
                    "total_unique_allocated_bytes",
                    "estimated_reclaimable_min_bytes",
                    "estimated_reclaimable_max_bytes",
                    "contains_sparse_file",
                    "same_physical_file_only",
                    "group_cleanup_risk",
                    "root",
                    "path",
                    "path_bytes_hex",
                    "allocated_size_bytes",
                    "device",
                    "inode",
                    "mtime_utc",
                    "ctime_utc",
                    "management_class",
                    "classification_confidence",
                    "classification_reason",
                    "cleanup_risk",
                )
            )
            rows = connection.execute(
                """
                SELECT
                    g.*,
                    f.root_id,
                    f.path_display,
                    f.path_raw,
                    f.allocated_bytes,
                    f.device,
                    f.inode,
                    f.mtime_ns,
                    f.ctime_ns,
                    f.management_class,
                    f.classification_confidence,
                    f.classification_reason,
                    f.cleanup_risk,
                    r.path_display AS root_display
                FROM report_duplicate_groups AS g
                JOIN report_eligible_files AS f
                  ON f.digest=g.digest AND f.size_bytes=g.size_bytes
                JOIN roots AS r ON r.id=f.root_id
                ORDER BY g.group_number, f.path_display, f.id
                """
            )
            processed = 0
            last_processed = 0
            last_logged = time.monotonic()
            previous_group = 0
            for row in rows:
                group_number = int(row["group_number"])
                apparent_size = int(row["size_bytes"] or 0)
                physical_count = int(row["physical_copy_count"])
                hardlink_only = physical_count == 1
                group_kind = "hardlink_aliases" if hardlink_only else "physical_duplicates"
                cleanup_candidate = "no" if hardlink_only or apparent_size == 0 else "review"
                group_risk = _risk_from_rank(int(row["risk_rank"] or 0))

                if group_number != previous_group and log_detail in ("verbose", "trace"):
                    logger.info(
                        "Duplicate group %d | kind=%s | size=%s | paths=%d | physical copies=%d | estimated reclaimable=%s..%s | risk=%s | hash=%s",
                        group_number,
                        group_kind,
                        human_bytes(apparent_size),
                        int(row["path_count"]),
                        physical_count,
                        human_bytes(int(row["estimated_reclaimable_min_bytes"] or 0)),
                        human_bytes(int(row["estimated_reclaimable_max_bytes"] or 0)),
                        group_risk,
                        row["digest"],
                    )
                previous_group = group_number
                if log_detail == "trace":
                    logger.info("  %s", row["path_display"])

                writer.writerow(
                    (
                        group_number,
                        group_kind,
                        cleanup_candidate,
                        algorithm,
                        row["digest"],
                        apparent_size,
                        int(row["path_count"]),
                        physical_count,
                        int(row["logical_duplicate_bytes"] or 0),
                        int(row["total_unique_allocated_bytes"] or 0),
                        int(row["estimated_reclaimable_min_bytes"] or 0),
                        int(row["estimated_reclaimable_max_bytes"] or 0),
                        "yes" if int(row["contains_sparse_file"] or 0) else "no",
                        "yes" if hardlink_only else "no",
                        group_risk,
                        row["root_display"],
                        row["path_display"],
                        bytes(row["path_raw"]).hex(),
                        "" if row["allocated_bytes"] is None else row["allocated_bytes"],
                        "" if row["device"] is None else row["device"],
                        "" if row["inode"] is None else row["inode"],
                        utc_timestamp(row["mtime_ns"]),
                        utc_timestamp(row["ctime_ns"]),
                        row["management_class"],
                        row["classification_confidence"],
                        row["classification_reason"],
                        row["cleanup_risk"],
                    )
                )
                processed += 1
                now = time.monotonic()
                if progress_due(processed, last_processed, now, last_logged):
                    logger.info(
                        "Report progress: duplicate paths | %d / %d rows",
                        processed,
                        total_rows,
                    )
                    last_processed = processed
                    last_logged = now
            fsync_file(handle)
        os.chmod(temp_path, 0o600)
    timings["duplicate_export_seconds"] = timing["elapsed"]
    _drop_report_temp_tables(connection)
    return summary, timings


def finalize_database(connection: sqlite3.Connection, scan_id: str) -> None:
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute(
        """
        UPDATE scans
        SET state='completed', ended_utc=?, program_version=?, schema_version=?,
            interrupted_reason=''
        WHERE scan_id=?
        """,
        (utc_now(), VERSION, SCHEMA_VERSION, scan_id),
    )
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.commit()


def remove_sqlite_sidecars(database_path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            Path(str(database_path) + suffix).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def set_scan_state(
    connection: sqlite3.Connection,
    scan_id: str,
    state: str,
    reason: str,
) -> None:
    try:
        connection.execute(
            """
            UPDATE scans SET state=?, ended_utc=?, interrupted_reason=?
            WHERE scan_id=?
            """,
            (state, utc_now(), safe_display(reason), scan_id),
        )
        connection.commit()
    except (sqlite3.Error, OSError):
        pass


def count_existing_resume_rows(connection: sqlite3.Connection, scan_id: str) -> int:
    row = connection.execute(
        "SELECT COUNT(*) AS count FROM files WHERE scan_id=? AND status IN ('ok','empty','empty_ignored','empty_reported','reused')", (scan_id,)
    ).fetchone()
    return int(row["count"] if row else 0)


def install_signal_handlers(cancel_event: threading.Event) -> dict[int, object]:
    previous: dict[int, object] = {}

    def handler(signum: int, _frame: object) -> None:
        cancel_event.set()
        if signum == signal.SIGTERM:
            raise ScanInterrupted("received SIGTERM")
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, handler)
    return previous


def restore_signal_handlers(previous: dict[int, object]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)



def validate_args(args: argparse.Namespace) -> None:
    if args.path_audit_only:
        args.audit_paths = True
    if args.workers < 1:
        raise ValueError("--workers must be at least 1")
    if args.chunk_size_mib < 1:
        raise ValueError("--chunk-size-mib must be at least 1")
    if args.progress_seconds <= 0:
        raise ValueError("--progress-seconds must be greater than 0")
    if args.file_progress_seconds < 0:
        raise ValueError("--file-progress-seconds cannot be negative")
    if args.retry_changed < 0:
        raise ValueError("--retry-changed cannot be negative")
    if args.resume and args.incremental:
        raise ValueError("--resume and --incremental cannot be used together")
    if args.report_only and (args.resume or args.incremental):
        raise ValueError("--report-only cannot be combined with --resume or --incremental")
    if args.path_audit_only and args.report_only:
        raise ValueError("--path-audit-only cannot be combined with --report-only")
    if args.path_audit_only and args.incremental:
        raise ValueError("--path-audit-only cannot be combined with --incremental")
    if args.windows_prefix_length < 0:
        raise ValueError("--windows-prefix-length cannot be negative")
    if args.path_warning_chars < 1:
        raise ValueError("--path-warning-chars must be at least 1")
    if args.office_path_limit <= args.path_warning_chars:
        raise ValueError("--office-path-limit must be greater than --path-warning-chars")
    if args.hard_path_limit < args.office_path_limit:
        raise ValueError("--hard-path-limit must be at least --office-path-limit")
    if args.filename_limit < 1:
        raise ValueError("--filename-limit must be at least 1")
    if args.directory_name_limit < 1:
        raise ValueError("--directory-name-limit must be at least 1")
    if args.ignore_empty:
        args.empty_files = "ignore"
    if args.no_print_duplicates and args.log_detail != "summary":
        args.log_detail = "summary"


def select_report_scan(connection: sqlite3.Connection, algorithm: str) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM scans
        WHERE algorithm=?
        ORDER BY started_utc DESC
        LIMIT 1
        """,
        (algorithm,),
    ).fetchone()
    if row is None:
        raise ValueError(
            f"No scan using algorithm {algorithm!r} exists in the selected database."
        )
    if not bool(row["path_audit_only"]):
        count_row = connection.execute(
            "SELECT COUNT(*) AS count FROM files WHERE scan_id=?",
            (row["scan_id"],),
        ).fetchone()
        if count_row is None or int(count_row["count"] or 0) == 0:
            raise ValueError("The selected scan contains no file records to report.")
    return row



def run_scan(args: argparse.Namespace) -> int:
    validate_args(args)
    roots = validate_roots(args.roots)
    output_dir = Path(args.output_dir).expanduser().resolve()
    secure_output_directory(output_dir)

    log_path = output_dir / "scan.log"
    final_db = output_dir / "hash_index.sqlite3"
    partial_db = output_dir / "hash_index.sqlite3.partial"
    all_csv = output_dir / "all_file_hashes.csv"
    all_csv_partial = output_dir / "all_file_hashes.csv.partial"
    duplicate_csv = output_dir / "duplicate_files.csv"
    duplicate_csv_partial = output_dir / "duplicate_files.csv.partial"
    path_csv = output_dir / "path_length_violations.csv"
    path_csv_partial = output_dir / "path_length_violations.csv.partial"

    logger = configure_logging(log_path, args.log_detail)
    excludes = [
        normalize_existing_directory(path)
        if os.path.isdir(os.path.expanduser(path))
        else os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        for path in args.exclude
    ]
    for automatic in automatic_excludes(roots):
        normalized = os.path.realpath(automatic)
        if normalized not in excludes:
            excludes.append(normalized)
    output_dir_text = str(output_dir)
    if any(is_same_or_child(output_dir_text, root) for root in roots):
        excludes.append(output_dir_text)
    excludes = sorted(set(excludes))

    config = configuration_payload(args, roots, excludes)
    config_fingerprint = fingerprint(config)
    legacy_config_fingerprint = (
        fingerprint(legacy_configuration_payload(args, roots, excludes))
        if not args.audit_paths
        else None
    )

    if args.report_only:
        if not partial_db.exists():
            if not final_db.exists():
                raise ValueError(
                    f"No database exists at {partial_db} or {final_db}."
                )
            sqlite_backup(final_db, partial_db)
    elif args.resume:
        if not partial_db.exists():
            raise ValueError(f"No partial database exists at {partial_db}")
    else:
        if partial_db.exists():
            raise ValueError(
                f"An unfinished scan exists at {partial_db}. Use --resume, "
                "--report-only, or move/delete that file."
            )
        if args.incremental and final_db.exists():
            sqlite_backup(final_db, partial_db)
        else:
            with restrictive_umask():
                partial_db.touch(exist_ok=False)

    try:
        connection = open_database(partial_db)
    except Exception:
        if not args.resume and not args.report_only:
            for candidate in (
                partial_db,
                Path(str(partial_db) + "-wal"),
                Path(str(partial_db) + "-shm"),
            ):
                try:
                    candidate.unlink()
                except (FileNotFoundError, OSError):
                    pass
        raise

    scan_id = ""
    cancel_event = threading.Event()
    progress_stop_event = threading.Event()
    previous_handlers = install_signal_handlers(cancel_event)
    counters = Counters()
    counters_lock = threading.Lock()
    tracker = ProgressTracker()
    reporter: ProgressReporter | None = None
    total_started = time.monotonic()
    hashing_started: float | None = None
    hashing_elapsed = 0.0
    logical_read = 0
    previous_scan_id: str | None = None
    audit_enabled = bool(args.audit_paths)
    audit_only = bool(args.path_audit_only)
    path_auditor: PathAuditor | None = None
    path_counts = PathAuditCounters()
    path_export_rows = 0
    path_export_seconds = 0.0

    try:
        if args.report_only:
            scan_row = select_report_scan(connection, args.algorithm)
            scan_id = str(scan_row["scan_id"])
            audit_enabled = bool(scan_row["path_audit_enabled"])
            audit_only = bool(scan_row["path_audit_only"])
            path_counts = PathAuditCounters(
                examined=int(scan_row["path_audit_examined"]),
                files=int(scan_row["path_audit_files"]),
                directories=int(scan_row["path_audit_directories"]),
                findings=int(scan_row["path_audit_findings"]),
                warnings=int(scan_row["path_audit_warnings"]),
                high=int(scan_row["path_audit_high"]),
                critical=int(scan_row["path_audit_critical"]),
            )
            connection.execute(
                "UPDATE scans SET state='reporting', ended_utc=NULL, interrupted_reason='' WHERE scan_id=?",
                (scan_id,),
            )
            connection.commit()
            logger.info(
                "Starting %s %s in report-only mode | scan_id=%s | source state=%s",
                PROGRAM_NAME,
                VERSION,
                scan_id,
                scan_row["state"],
            )
            logger.info(
                "No filesystem walk or hashing will be performed | source audit_enabled=%s | source audit_only=%s",
                audit_enabled,
                audit_only,
            )
        else:
            if args.resume:
                scan_id, generation, root_infos = resume_scan(
                    connection,
                    config_fingerprint,
                    legacy_config_fingerprint,
                )
                existing_records = count_existing_resume_rows(connection, scan_id)
                logger.info(
                    "Resuming scan %s with %d reusable existing records",
                    scan_id,
                    existing_records,
                )
            else:
                if args.incremental:
                    previous_scan_id = latest_completed_scan_id(connection, args.algorithm)
                scan_id, generation, root_infos = initialize_new_scan(
                    connection, args, roots, config_fingerprint
                )

            logger.info("Starting %s %s | scan_id=%s", PROGRAM_NAME, VERSION, scan_id)
            logger.info("Roots: %s", ", ".join(info.path_display for info in root_infos))
            logger.info(
                "Algorithm=%s | workers=%d | empty_files=%s | cache_policy=%s",
                args.algorithm,
                args.workers,
                args.empty_files,
                args.cache_policy,
            )
            logger.info("Output directory: %s", safe_display(str(output_dir)))
            if excludes:
                logger.info(
                    "Excluded paths: %s",
                    ", ".join(safe_display(item) for item in excludes),
                )
            for root in root_infos:
                logger.info(
                    "Filesystem: root=%s | type=%s | source=%s | mount=%s | uuid=%s",
                    root.path_display,
                    root.filesystem_type,
                    root.mount_source,
                    root.mount_point,
                    root.filesystem_uuid or "unknown",
                )
            nested = nested_root_excludes(root_infos)
            for parent in root_infos:
                children = nested.get(parent.root_id, ())
                if children:
                    logger.info(
                        "Overlapping-root protection: %s will skip child roots: %s",
                        parent.path_display,
                        ", ".join(safe_display(child) for child in children),
                    )

            if audit_enabled:
                audit_policy = PathAuditPolicy(
                    warning_path_chars=args.path_warning_chars,
                    office_path_limit=args.office_path_limit,
                    hard_path_limit=args.hard_path_limit,
                    filename_limit=args.filename_limit,
                    directory_name_limit=args.directory_name_limit,
                    windows_prefix_length=args.windows_prefix_length,
                )
                path_auditor = PathAuditor(
                    connection=connection,
                    scan_id=scan_id,
                    generation=generation,
                    policy=audit_policy,
                    logger=logger,
                    progress_seconds=args.progress_seconds,
                )
                logger.info(
                    "Path audit enabled | mode=%s | warning=%d | high-risk=%d | critical-above=%d | filename=%d | directory=%d | Windows prefix=%d",
                    "audit-only" if audit_only else "combined",
                    audit_policy.warning_path_chars,
                    audit_policy.office_path_limit,
                    audit_policy.hard_path_limit,
                    audit_policy.filename_limit,
                    audit_policy.directory_name_limit,
                    audit_policy.windows_prefix_length,
                )

            if not audit_only:
                hasher_factory = make_hasher(args.algorithm)
                chunk_size = args.chunk_size_mib * 1024 * 1024
                reporter = ProgressReporter(
                    tracker=tracker,
                    counters=counters,
                    counters_lock=counters_lock,
                    logger=logger,
                    stop_event=progress_stop_event,
                    progress_seconds=args.progress_seconds,
                    file_progress_seconds=args.file_progress_seconds,
                    detail=args.log_detail,
                )
                hashing_started = time.monotonic()
                reporter.start()

            tasks = walk_files(
                roots=root_infos,
                excludes=excludes,
                one_file_system=args.one_file_system,
                generation=generation,
                logger=logger,
                cancel_event=cancel_event,
                path_auditor=path_auditor,
            )
            last_commit = time.monotonic()

            if audit_only:
                for task in tasks:
                    if cancel_event.is_set():
                        break
                    with counters_lock:
                        counters.discovered += 1
                    now = time.monotonic()
                    if now - last_commit >= COMMIT_SECONDS:
                        connection.commit()
                        last_commit = now
            else:
                max_pending = (
                    1
                    if args.workers == 1
                    else max(args.workers * DEFAULT_QUEUE_MULTIPLIER, args.workers)
                )
                pending: set[Future[HashResult]] = set()

                with ThreadPoolExecutor(
                    max_workers=args.workers,
                    thread_name_prefix="hashwatchdog-worker",
                ) as executor:
                    for task in tasks:
                        if cancel_event.is_set():
                            break
                        with counters_lock:
                            counters.discovered += 1

                        existing = resumable_row(connection, scan_id, task) if args.resume else None
                        if existing is not None:
                            mark_seen(connection, int(existing["id"]), generation)
                            with counters_lock:
                                counters.examined += 1
                                counters.reused += 1
                            continue

                        same_inode = current_identity_row(connection, scan_id, task)
                        if same_inode is not None:
                            copy_reused_row(
                                connection,
                                scan_id,
                                task,
                                same_inode,
                                generation,
                                not args.no_managed_classification,
                            )
                            with counters_lock:
                                counters.examined += 1
                                counters.reused += 1
                            continue

                        reused = incremental_row(
                            connection,
                            previous_scan_id,
                            task,
                            args.algorithm,
                            args.cache_policy,
                        )
                        if reused is not None:
                            copy_reused_row(
                                connection,
                                scan_id,
                                task,
                                reused,
                                generation,
                                not args.no_managed_classification,
                            )
                            with counters_lock:
                                counters.examined += 1
                                counters.reused += 1
                            continue

                        pending.add(
                            executor.submit(
                                hash_one_file,
                                task,
                                hasher_factory,
                                chunk_size,
                                args.retry_changed,
                                args.empty_files,
                                tracker,
                                cancel_event,
                                not args.no_managed_classification,
                            )
                        )
                        if len(pending) >= max_pending:
                            completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                            process_results(
                                completed,
                                connection,
                                scan_id,
                                args.algorithm,
                                counters,
                                counters_lock,
                                logger,
                                args.print_hashes,
                            )

                        now = time.monotonic()
                        if now - last_commit >= COMMIT_SECONDS:
                            connection.commit()
                            last_commit = now

                    if cancel_event.is_set():
                        for future in pending:
                            future.cancel()
                    while pending:
                        completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                        process_results(
                            completed,
                            connection,
                            scan_id,
                            args.algorithm,
                            counters,
                            counters_lock,
                            logger,
                            args.print_hashes,
                        )

            if cancel_event.is_set():
                raise ScanInterrupted("scan cancellation requested")

            if path_auditor is not None:
                path_counts = path_auditor.finish()
                logger.info(
                    "Path audit complete: %d items | %d files | %d directories | %d findings | %d critical | %d high | %d warnings",
                    path_counts.examined,
                    path_counts.files,
                    path_counts.directories,
                    path_counts.findings,
                    path_counts.critical,
                    path_counts.high,
                    path_counts.warnings,
                )

            if not audit_only:
                connection.execute(
                    "DELETE FROM files WHERE scan_id=? AND seen_generation<>?",
                    (scan_id, generation),
                )
            connection.execute(
                "UPDATE scans SET state=?, interrupted_reason='' WHERE scan_id=?",
                ("path_audit_complete" if audit_only else "hashing_complete", scan_id),
            )
            connection.commit()

            if not audit_only:
                progress_stop_event.set()
                if reporter is not None:
                    reporter.join(timeout=5.0)
                    reporter = None
                hashing_elapsed = max(
                    time.monotonic() - (hashing_started or time.monotonic()),
                    0.001,
                )
                logical_read, _tracker_elapsed, _active = tracker.snapshot()
                logger.info(
                    "Hashing complete: %s read in %.1f seconds (average %s/s)",
                    human_bytes(logical_read),
                    hashing_elapsed,
                    human_bytes(logical_read / hashing_elapsed),
                )

        report_started = time.monotonic()
        prepare_seconds = prepare_reporting_database(connection, logger)
        all_rows = 0
        all_export_seconds = 0.0
        duplicate_summary = {
            "groups": 0,
            "cleanup_groups": 0,
            "hardlink_only_groups": 0,
            "duplicate_paths": 0,
            "logical_duplicate_bytes": 0,
            "estimated_reclaimable_min_bytes": 0,
            "estimated_reclaimable_max_bytes": 0,
        }
        duplicate_timings = {
            "candidate_materialization_seconds": 0.0,
            "group_aggregation_seconds": 0.0,
            "duplicate_export_seconds": 0.0,
        }
        if not audit_only:
            all_rows, all_export_seconds = generate_all_hashes_csv(
                connection,
                scan_id,
                all_csv_partial,
                logger,
            )
            duplicate_summary, duplicate_timings = generate_duplicate_csv(
                connection=connection,
                scan_id=scan_id,
                algorithm=args.algorithm,
                empty_policy=args.empty_files,
                temp_path=duplicate_csv_partial,
                logger=logger,
                log_detail=args.log_detail,
            )
        if audit_enabled:
            path_export_rows, path_export_seconds = generate_path_audit_csv(
                connection,
                scan_id,
                path_csv_partial,
                logger,
            )
        reporting_elapsed = max(time.monotonic() - report_started, 0.001)

        finalize_database(connection, scan_id)
        connection.close()
        connection = None  # type: ignore[assignment]

        atomic_replace(partial_db, final_db)
        remove_sqlite_sidecars(partial_db)
        remove_sqlite_sidecars(final_db)
        if not audit_only:
            atomic_replace(all_csv_partial, all_csv)
            atomic_replace(duplicate_csv_partial, duplicate_csv)
        else:
            remove_stale_report(all_csv)
            remove_stale_report(duplicate_csv)
        if audit_enabled:
            atomic_replace(path_csv_partial, path_csv)
        else:
            remove_stale_report(path_csv)

        total_elapsed = max(time.monotonic() - total_started, 0.001)
        if not args.report_only and not audit_only:
            with counters_lock:
                final_counts = Counters(
                    discovered=counters.discovered,
                    examined=counters.examined,
                    hashed=counters.hashed,
                    reused=counters.reused,
                    errors=counters.errors,
                    changed=counters.changed,
                    cancelled=counters.cancelled,
                    empty=counters.empty,
                )
            logger.info(
                "Finished: %d discovered | %d examined | %d newly hashed | %d reused | %d errors | %d changed | %d empty",
                final_counts.discovered,
                final_counts.examined,
                final_counts.hashed,
                final_counts.reused,
                final_counts.errors,
                final_counts.changed,
                final_counts.empty,
            )
            logger.info(
                "Hashing phase: %s in %.1f seconds | average %s/s",
                human_bytes(logical_read),
                hashing_elapsed,
                human_bytes(logical_read / max(hashing_elapsed, 0.001)),
            )
        elif audit_only:
            logger.info("Hashing phase: skipped (path-audit-only mode)")
        else:
            logger.info("Hashing phase: skipped (report-only mode)")

        logger.info(
            "Reporting phase: %.1f seconds | prepare %.2fs | all-file export %.2fs | candidate materialization %.2fs | group aggregation %.2fs | duplicate export %.2fs | path-audit export %.2fs",
            reporting_elapsed,
            prepare_seconds,
            all_export_seconds,
            duplicate_timings["candidate_materialization_seconds"],
            duplicate_timings["group_aggregation_seconds"],
            duplicate_timings["duplicate_export_seconds"],
            path_export_seconds,
        )
        logger.info("Total runtime: %.1f seconds", total_elapsed)
        if not audit_only:
            logger.info("All-file rows exported: %d", all_rows)
            logger.info(
                "Duplicate groups=%d | cleanup review groups=%d | hard-link-only groups=%d | duplicate paths=%d",
                duplicate_summary["groups"],
                duplicate_summary["cleanup_groups"],
                duplicate_summary["hardlink_only_groups"],
                duplicate_summary["duplicate_paths"],
            )
            logger.info(
                "Logical duplicate bytes=%s | estimated physically reclaimable=%s..%s",
                human_bytes(duplicate_summary["logical_duplicate_bytes"]),
                human_bytes(duplicate_summary["estimated_reclaimable_min_bytes"]),
                human_bytes(duplicate_summary["estimated_reclaimable_max_bytes"]),
            )
            logger.info("All hashes: %s", safe_display(str(all_csv)))
            logger.info("Duplicates: %s", safe_display(str(duplicate_csv)))
        if audit_enabled:
            logger.info(
                "Path audit: %d items examined | %d findings exported | %d critical | %d high | %d warnings",
                path_counts.examined,
                path_export_rows,
                path_counts.critical,
                path_counts.high,
                path_counts.warnings,
            )
            logger.info("Path violations: %s", safe_display(str(path_csv)))
        logger.info("SQLite database: %s", safe_display(str(final_db)))
        logger.info("Log: %s", safe_display(str(log_path)))
        return 0

    except (KeyboardInterrupt, ScanInterrupted) as exc:
        cancel_event.set()
        progress_stop_event.set()
        reason = "interrupted by user" if isinstance(exc, KeyboardInterrupt) else str(exc)
        if scan_id and connection is not None:
            set_scan_state(connection, scan_id, "interrupted", reason)
        mode = "--report-only" if args.report_only else "--resume"
        logger.warning(
            "Operation interrupted. Canonical partial database remains at %s. Re-run with %s.",
            safe_display(str(partial_db)),
            mode,
        )
        return 130
    except (sqlite3.Error, OSError) as exc:
        cancel_event.set()
        progress_stop_event.set()
        state = "failed"
        if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
            state = "disk_full"
        if scan_id and connection is not None:
            set_scan_state(connection, scan_id, state, f"{type(exc).__name__}: {exc}")
        logger.error("Operation failed: %s: %s", type(exc).__name__, safe_display(str(exc)))
        logger.error("Partial database retained at %s", safe_display(str(partial_db)))
        return 1
    finally:
        cancel_event.set()
        progress_stop_event.set()
        if reporter is not None:
            reporter.join(timeout=2.0)
        if connection is not None:
            try:
                connection.commit()
            except sqlite3.Error:
                pass
            connection.close()
        restore_signal_handlers(previous_handlers)
        for temp_path in (all_csv_partial, duplicate_csv_partial, path_csv_partial):
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
        for handler in logger.handlers:
            try:
                handler.flush()
                handler.close()
            except OSError:
                pass
        logger.handlers.clear()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run_scan(args)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {safe_display(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
