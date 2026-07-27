#!/usr/bin/env python3
"""Cross-volume duplicate file scanner for Linux and Windows filesystems.

Run this from installed Linux or a Linux live environment. Windows filesystems
must first be mounted by Linux (preferably read-only). Multiple --root options
are scanned together, so duplicates can be found across different partitions,
drives, and filesystems.

Outputs:
  - all_file_hashes.csv: one row for every regular file examined
  - duplicate_files.csv: duplicate groups and every matching path
  - scan.log: progress, warnings, and errors
  - hash_index.sqlite3: searchable local index used to keep memory usage bounded
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import sqlite3
import sys
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

PROGRAM_NAME = "duplicate-hash-scanner"
VERSION = "1.0.0"
DEFAULT_CHUNK_MIB = 8
DEFAULT_PROGRESS_SECONDS = 5.0
DEFAULT_QUEUE_MULTIPLIER = 4


@dataclass(slots=True)
class FileTask:
    root: str
    path: str


@dataclass(slots=True)
class HashResult:
    root: str
    path: str
    size_bytes: int | None
    mtime_ns: int | None
    device: int | None
    inode: int | None
    digest: str
    status: str
    error: str
    bytes_read: int
    elapsed_seconds: float


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Hash regular files under one or more mounted roots and find "
            "duplicates across all roots."
        )
    )
    parser.add_argument(
        "--root",
        dest="roots",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "Root directory to scan. Repeat this option to compare multiple "
            "filesystems or partitions in one run."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="hash-scan-output",
        metavar="DIR",
        help="Directory for CSV, log, and SQLite output (default: %(default)s).",
    )
    parser.add_argument(
        "--algorithm",
        choices=("sha256", "blake2b", "blake3"),
        default="sha256",
        help=(
            "Hash algorithm. blake3 requires the optional 'blake3' package "
            "(default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Concurrent hashing workers. Use 1 for HDDs; 2-4 may help SSD/NVMe "
            "or separate physical drives (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--chunk-size-mib",
        type=int,
        default=DEFAULT_CHUNK_MIB,
        metavar="MIB",
        help="Read buffer size in MiB (default: %(default)s).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATH",
        help="Absolute path to exclude. Repeat for additional paths.",
    )
    parser.add_argument(
        "--one-file-system",
        action="store_true",
        help=(
            "Do not cross into another mounted filesystem while walking a root. "
            "Without this flag, mounted volumes beneath a root are included."
        ),
    )
    parser.add_argument(
        "--ignore-empty",
        action="store_true",
        help="Do not hash or report zero-byte files.",
    )
    parser.add_argument(
        "--progress-seconds",
        type=float,
        default=DEFAULT_PROGRESS_SECONDS,
        metavar="SECONDS",
        help="Terminal progress interval (default: %(default)s).",
    )
    parser.add_argument(
        "--print-hashes",
        action="store_true",
        help=(
            "Print every successful file hash to the terminal and scan.log. "
            "This can noticeably slow scans containing many small files."
        ),
    )
    parser.add_argument(
        "--no-print-duplicates",
        dest="print_duplicates",
        action="store_false",
        help=(
            "Do not print every duplicate group and path to the terminal. "
            "The complete duplicate CSV is still produced."
        ),
    )
    parser.set_defaults(print_duplicates=True)
    parser.add_argument(
        "--retry-changed",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Retries when a file changes during hashing (default: %(default)s)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def configure_logging(log_path: Path) -> logging.Logger:
    logger = logging.getLogger(PROGRAM_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(
        log_path, mode="w", encoding="utf-8", errors="backslashreplace"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def normalize_existing_directory(raw_path: str) -> str:
    path = os.path.abspath(os.path.expanduser(raw_path))
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {raw_path}")
    if not os.path.isdir(path):
        raise ValueError(f"Path is not a directory: {raw_path}")
    return path


def is_same_or_child(path: str, excluded: str) -> bool:
    try:
        return os.path.commonpath((path, excluded)) == excluded
    except ValueError:
        return False


def automatic_excludes(roots: Sequence[str]) -> list[str]:
    """Avoid Linux pseudo-filesystems only when scanning the live root '/'."""
    if os.path.abspath(os.sep) not in roots:
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


def utc_mtime(mtime_ns: int | None) -> str:
    if mtime_ns is None:
        return ""
    return datetime.fromtimestamp(mtime_ns / 1_000_000_000, tz=timezone.utc).isoformat()


def human_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    size = float(value)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PiB"


def walk_files(
    roots: Sequence[str],
    excludes: Sequence[str],
    one_file_system: bool,
    logger: logging.Logger,
) -> Iterator[FileTask]:
    normalized_excludes = tuple(os.path.abspath(path) for path in excludes)

    for root in roots:
        try:
            root_stat = os.stat(root, follow_symlinks=False)
        except OSError as exc:
            logger.error("Cannot stat root %s: %s", root, exc)
            continue

        root_device = root_stat.st_dev
        stack = [root]

        while stack:
            directory = stack.pop()
            if any(is_same_or_child(directory, excluded) for excluded in normalized_excludes):
                logger.info("Excluded directory: %s", directory)
                continue

            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        path = entry.path
                        if any(
                            is_same_or_child(path, excluded)
                            for excluded in normalized_excludes
                        ):
                            continue

                        try:
                            if entry.is_symlink():
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                if one_file_system:
                                    try:
                                        if entry.stat(follow_symlinks=False).st_dev != root_device:
                                            logger.info("Skipped mount point: %s", path)
                                            continue
                                    except OSError as exc:
                                        logger.warning("Cannot stat directory %s: %s", path, exc)
                                        continue
                                stack.append(path)
                            elif entry.is_file(follow_symlinks=False):
                                yield FileTask(root=root, path=path)
                        except OSError as exc:
                            logger.warning("Cannot inspect %s: %s", path, exc)
            except OSError as exc:
                logger.warning("Cannot enter directory %s: %s", directory, exc)


def hash_one_file(
    task: FileTask,
    hasher_factory: Callable[[], object],
    chunk_size: int,
    retries: int,
    ignore_empty: bool,
) -> HashResult:
    started = time.monotonic()
    last_error = ""

    for attempt in range(retries + 1):
        try:
            before = os.stat(task.path, follow_symlinks=False)
            if not os.path.isfile(task.path):
                raise OSError("Path is no longer a regular file")

            if ignore_empty and before.st_size == 0:
                return HashResult(
                    root=task.root,
                    path=task.path,
                    size_bytes=0,
                    mtime_ns=before.st_mtime_ns,
                    device=before.st_dev,
                    inode=before.st_ino,
                    digest="",
                    status="ignored_empty",
                    error="",
                    bytes_read=0,
                    elapsed_seconds=time.monotonic() - started,
                )

            hasher = hasher_factory()
            bytes_read = 0
            buffer = bytearray(chunk_size)
            view = memoryview(buffer)

            with open(task.path, "rb", buffering=0) as handle:
                while True:
                    count = handle.readinto(buffer)
                    if not count:
                        break
                    hasher.update(view[:count])  # type: ignore[attr-defined]
                    bytes_read += count

            after = os.stat(task.path, follow_symlinks=False)
            changed = (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or bytes_read != after.st_size
            )
            if changed:
                last_error = "File changed while being hashed"
                if attempt < retries:
                    continue
                return HashResult(
                    root=task.root,
                    path=task.path,
                    size_bytes=after.st_size,
                    mtime_ns=after.st_mtime_ns,
                    device=after.st_dev,
                    inode=after.st_ino,
                    digest="",
                    status="changed",
                    error=last_error,
                    bytes_read=bytes_read,
                    elapsed_seconds=time.monotonic() - started,
                )

            return HashResult(
                root=task.root,
                path=task.path,
                size_bytes=after.st_size,
                mtime_ns=after.st_mtime_ns,
                device=after.st_dev,
                inode=after.st_ino,
                digest=hasher.hexdigest(),  # type: ignore[attr-defined]
                status="ok",
                error="",
                bytes_read=bytes_read,
                elapsed_seconds=time.monotonic() - started,
            )
        except (OSError, PermissionError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            return HashResult(
                root=task.root,
                path=task.path,
                size_bytes=None,
                mtime_ns=None,
                device=None,
                inode=None,
                digest="",
                status="error",
                error=last_error,
                bytes_read=0,
                elapsed_seconds=time.monotonic() - started,
            )
        except Exception as exc:  # defensive: preserve the rest of a long scan
            last_error = f"Unexpected {type(exc).__name__}: {exc}"
            return HashResult(
                root=task.root,
                path=task.path,
                size_bytes=None,
                mtime_ns=None,
                device=None,
                inode=None,
                digest="",
                status="error",
                error=last_error,
                bytes_read=0,
                elapsed_seconds=time.monotonic() - started,
            )

    raise AssertionError("Unreachable hashing state")


def create_database(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            root TEXT NOT NULL,
            path TEXT NOT NULL,
            size_bytes INTEGER,
            mtime_ns INTEGER,
            device INTEGER,
            inode INTEGER,
            digest TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT NOT NULL
        )
        """
    )
    connection.execute("DELETE FROM files")
    connection.commit()
    return connection


def write_result(
    connection: sqlite3.Connection,
    csv_writer: csv.writer,
    result: HashResult,
) -> None:
    csv_writer.writerow(
        (
            result.root,
            result.path,
            "" if result.size_bytes is None else result.size_bytes,
            utc_mtime(result.mtime_ns),
            result.digest,
            result.status,
            result.error,
            "" if result.device is None else result.device,
            "" if result.inode is None else result.inode,
        )
    )
    connection.execute(
        """
        INSERT INTO files
            (root, path, size_bytes, mtime_ns, device, inode, digest, status, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.root,
            result.path,
            result.size_bytes,
            result.mtime_ns,
            result.device,
            result.inode,
            result.digest,
            result.status,
            result.error,
        ),
    )


def generate_duplicate_csv(
    connection: sqlite3.Connection,
    duplicate_csv_path: Path,
    algorithm: str,
    logger: logging.Logger,
    print_duplicates: bool,
) -> tuple[int, int, int]:
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_files_digest_size ON files(digest, size_bytes)"
    )
    connection.commit()

    groups = connection.execute(
        """
        SELECT digest, size_bytes, COUNT(*) AS path_count,
               COUNT(DISTINCT CAST(device AS TEXT) || ':' || CAST(inode AS TEXT))
                   AS physical_copy_count
        FROM files
        WHERE status = 'ok'
        GROUP BY digest, size_bytes
        HAVING COUNT(*) > 1
        ORDER BY size_bytes DESC, path_count DESC, digest
        """
    ).fetchall()

    total_duplicate_paths = 0
    total_logical_wasted = 0

    with open(
        duplicate_csv_path,
        "w",
        newline="",
        encoding="utf-8",
        errors="backslashreplace",
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(
            (
                "duplicate_group",
                "algorithm",
                "hash",
                "size_bytes",
                "path_count",
                "physical_copy_count",
                "logical_wasted_bytes",
                "same_physical_file_only",
                "root",
                "path",
                "device",
                "inode",
                "mtime_utc",
            )
        )

        for group_number, (digest, size_bytes, path_count, physical_count) in enumerate(
            groups, start=1
        ):
            logical_wasted = int(size_bytes or 0) * (int(path_count) - 1)
            total_duplicate_paths += int(path_count)
            total_logical_wasted += logical_wasted
            same_physical_only = "yes" if int(physical_count) == 1 else "no"

            if print_duplicates:
                logger.info(
                    "DUPLICATE GROUP %d | size=%s | paths=%d | physical copies=%d | hash=%s",
                    group_number,
                    human_bytes(int(size_bytes or 0)),
                    path_count,
                    physical_count,
                    digest,
                )

            rows = connection.execute(
                """
                SELECT root, path, device, inode, mtime_ns
                FROM files
                WHERE status = 'ok' AND digest = ? AND size_bytes = ?
                ORDER BY path
                """,
                (digest, size_bytes),
            )
            for root, path, device, inode, mtime_ns in rows:
                if print_duplicates:
                    logger.info("  %s", path)
                writer.writerow(
                    (
                        group_number,
                        algorithm,
                        digest,
                        size_bytes,
                        path_count,
                        physical_count,
                        logical_wasted,
                        same_physical_only,
                        root,
                        path,
                        device,
                        inode,
                        utc_mtime(mtime_ns),
                    )
                )

    return len(groups), total_duplicate_paths, total_logical_wasted


def validate_roots(roots: Sequence[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_root in roots:
        root = normalize_existing_directory(raw_root)
        if root not in seen:
            normalized.append(root)
            seen.add(root)
    return normalized


def warn_nested_roots(roots: Sequence[str], logger: logging.Logger) -> None:
    for index, first in enumerate(roots):
        for second in roots[index + 1 :]:
            if is_same_or_child(first, second) or is_same_or_child(second, first):
                logger.warning(
                    "Nested scan roots detected (%s and %s). Some files may be scanned twice.",
                    first,
                    second,
                )


def maybe_print_hash(
    result: HashResult,
    algorithm: str,
    enabled: bool,
    logger: logging.Logger,
) -> None:
    if enabled and result.status == "ok":
        logger.info("HASH %s %s  %s", algorithm, result.digest, result.path)


def process_completed(
    completed: Iterable[Future[HashResult]],
    connection: sqlite3.Connection,
    csv_writer: csv.writer,
    counters: dict[str, int],
    logger: logging.Logger,
    algorithm: str,
    print_hashes: bool,
) -> None:
    for future in completed:
        result = future.result()
        write_result(connection, csv_writer, result)
        maybe_print_hash(result, algorithm, print_hashes, logger)
        counters["examined"] += 1
        counters["bytes_read"] += result.bytes_read
        counters[result.status] = counters.get(result.status, 0) + 1
        if result.status == "error":
            logger.warning("Failed to hash %s: %s", result.path, result.error)
        elif result.status == "changed":
            logger.warning("Skipped changing file %s", result.path)


def run_scan(args: argparse.Namespace) -> int:
    if args.workers < 1:
        raise ValueError("--workers must be at least 1")
    if args.chunk_size_mib < 1:
        raise ValueError("--chunk-size-mib must be at least 1")
    if args.progress_seconds <= 0:
        raise ValueError("--progress-seconds must be greater than 0")
    if args.retry_changed < 0:
        raise ValueError("--retry-changed cannot be negative")

    roots = validate_roots(args.roots)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / "scan.log"
    all_hashes_path = output_dir / "all_file_hashes.csv"
    duplicate_path = output_dir / "duplicate_files.csv"
    db_path = output_dir / "hash_index.sqlite3"

    logger = configure_logging(log_path)
    warn_nested_roots(roots, logger)

    excludes = [os.path.abspath(os.path.expanduser(path)) for path in args.exclude]
    for automatic in automatic_excludes(roots):
        if automatic not in excludes:
            excludes.append(automatic)

    # Never recursively scan the output directory if it is inside a selected root.
    output_dir_str = str(output_dir)
    if any(is_same_or_child(output_dir_str, root) for root in roots):
        excludes.append(output_dir_str)

    hasher_factory = make_hasher(args.algorithm)
    chunk_size = args.chunk_size_mib * 1024 * 1024

    logger.info("Starting %s %s", PROGRAM_NAME, VERSION)
    logger.info("Roots: %s", ", ".join(roots))
    logger.info("Algorithm: %s | workers: %d", args.algorithm, args.workers)
    logger.info("Output directory: %s", output_dir)
    if excludes:
        logger.info("Excluded paths: %s", ", ".join(sorted(set(excludes))))

    connection = create_database(db_path)
    counters: dict[str, int] = {
        "examined": 0,
        "bytes_read": 0,
        "ok": 0,
        "error": 0,
        "changed": 0,
        "ignored_empty": 0,
    }
    scan_started = time.monotonic()
    last_progress = scan_started
    last_commit = scan_started

    try:
        with open(
            all_hashes_path,
            "w",
            newline="",
            encoding="utf-8",
            errors="backslashreplace",
        ) as csv_handle:
            csv_writer = csv.writer(csv_handle)
            csv_writer.writerow(
                (
                    "root",
                    "path",
                    "size_bytes",
                    "mtime_utc",
                    "hash",
                    "status",
                    "error",
                    "device",
                    "inode",
                )
            )

            tasks = walk_files(
                roots=roots,
                excludes=tuple(sorted(set(excludes))),
                one_file_system=args.one_file_system,
                logger=logger,
            )

            if args.workers == 1:
                for task in tasks:
                    result = hash_one_file(
                        task,
                        hasher_factory,
                        chunk_size,
                        args.retry_changed,
                        args.ignore_empty,
                    )
                    write_result(connection, csv_writer, result)
                    maybe_print_hash(
                        result, args.algorithm, args.print_hashes, logger
                    )
                    counters["examined"] += 1
                    counters["bytes_read"] += result.bytes_read
                    counters[result.status] = counters.get(result.status, 0) + 1
                    if result.status == "error":
                        logger.warning("Failed to hash %s: %s", result.path, result.error)
                    elif result.status == "changed":
                        logger.warning("Skipped changing file %s", result.path)

                    now = time.monotonic()
                    if now - last_progress >= args.progress_seconds:
                        elapsed = max(now - scan_started, 0.001)
                        logger.info(
                            "Progress: %d files | %s read | %s/s",
                            counters["examined"],
                            human_bytes(counters["bytes_read"]),
                            human_bytes(counters["bytes_read"] / elapsed),
                        )
                        last_progress = now
                    if now - last_commit >= 2.0:
                        connection.commit()
                        csv_handle.flush()
                        last_commit = now
            else:
                max_pending = max(args.workers * DEFAULT_QUEUE_MULTIPLIER, args.workers)
                pending: set[Future[HashResult]] = set()
                with ThreadPoolExecutor(
                    max_workers=args.workers,
                    thread_name_prefix="hasher",
                ) as executor:
                    for task in tasks:
                        pending.add(
                            executor.submit(
                                hash_one_file,
                                task,
                                hasher_factory,
                                chunk_size,
                                args.retry_changed,
                                args.ignore_empty,
                            )
                        )
                        if len(pending) >= max_pending:
                            completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                            process_completed(
                                completed,
                                connection,
                                csv_writer,
                                counters,
                                logger,
                                args.algorithm,
                                args.print_hashes,
                            )

                        now = time.monotonic()
                        if now - last_progress >= args.progress_seconds:
                            elapsed = max(now - scan_started, 0.001)
                            logger.info(
                                "Progress: %d files | %s read | %s/s",
                                counters["examined"],
                                human_bytes(counters["bytes_read"]),
                                human_bytes(counters["bytes_read"] / elapsed),
                            )
                            last_progress = now
                        if now - last_commit >= 2.0:
                            connection.commit()
                            csv_handle.flush()
                            last_commit = now

                    while pending:
                        completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                        process_completed(
                            completed,
                            connection,
                            csv_writer,
                            counters,
                            logger,
                            args.algorithm,
                            args.print_hashes,
                        )

            connection.commit()
            csv_handle.flush()

        logger.info("Hashing complete; building duplicate report")
        group_count, duplicate_paths, logical_wasted = generate_duplicate_csv(
            connection,
            duplicate_path,
            args.algorithm,
            logger,
            args.print_duplicates,
        )

        elapsed = max(time.monotonic() - scan_started, 0.001)
        logger.info(
            "Finished: %d files examined; %d hashed; %d errors; %d changed; %d empty ignored",
            counters["examined"],
            counters.get("ok", 0),
            counters.get("error", 0),
            counters.get("changed", 0),
            counters.get("ignored_empty", 0),
        )
        logger.info(
            "Read %s in %.1f seconds (average %s/s)",
            human_bytes(counters["bytes_read"]),
            elapsed,
            human_bytes(counters["bytes_read"] / elapsed),
        )
        logger.info(
            "Duplicate groups: %d | duplicate paths: %d | logical duplicate bytes: %s",
            group_count,
            duplicate_paths,
            human_bytes(logical_wasted),
        )
        logger.info("All hashes: %s", all_hashes_path)
        logger.info("Duplicates: %s", duplicate_path)
        logger.info("Log: %s", log_path)
        logger.info("SQLite index: %s", db_path)
        return 0
    finally:
        connection.close()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
