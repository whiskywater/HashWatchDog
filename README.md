# HashWatchDog

HashWatchDog is a Python-based duplicate-file scanner for Linux and Linux live environments. It recursively calculates cryptographic hashes for regular files and identifies byte-for-byte duplicates across directories, partitions, drives, and mounted Windows filesystems.

Unlike folder-level duplicate checkers, HashWatchDog treats every supplied scan root as part of one global comparison. A file on a Linux partition can therefore be matched with an identical file on an NTFS, exFAT, or other mounted filesystem.

HashWatchDog does **not** automatically delete or modify files. It produces detailed reports so the results can be reviewed safely.

## Features

- Recursively scans entire filesystems or selected directories
- Finds duplicates across unrelated folders and multiple drives
- Supports Linux filesystems and Windows filesystems mounted under Linux
- Supports SHA-256, BLAKE2b, and optional BLAKE3 hashing
- Displays scan progress and read throughput in the terminal
- Displays progress while hashing individual large files
- Writes a complete hash inventory to CSV
- Writes duplicate groups and every matching location to a separate CSV
- Records progress, warnings, errors, and results in a log file
- Stores results in SQLite to keep memory usage bounded
- Detects files that change while they are being hashed
- Distinguishes hard links from physically separate duplicate copies
- Skips symbolic links to prevent recursive directory loops
- Automatically excludes common Linux virtual filesystems when scanning `/`
- Supports multiple hashing workers for SSDs, NVMe drives, and separate disks

## Requirements

- Linux or a Linux live environment
- Python 3.10 or newer
- Read access to the files being scanned

No external Python packages are required for SHA-256 or BLAKE2b.

BLAKE3 support requires the optional `blake3` package:

```bash
python3 -m pip install blake3
