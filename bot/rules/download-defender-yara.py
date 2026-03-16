#!/usr/bin/env python3
"""
Download Microsoft Defender YARA rules (76,700+ rules).

These rules are too large to include in the git repo (292 MB, 76K+ files),
so run this script once to fetch them. The bot will auto-load them on next
start or /reload.

Usage:
    python download-defender-yara.py

Requires: git
"""

import subprocess
import sys
import shutil
from pathlib import Path

REPO_URL = "https://github.com/advanced-threat-research/defender-yara.git"
TARGET_DIR = Path(__file__).resolve().parent / "defender-yara"


def main():
    if TARGET_DIR.exists():
        count = sum(1 for _ in TARGET_DIR.rglob("*.yar"))
        count += sum(1 for _ in TARGET_DIR.rglob("*.yara"))
        if count > 0:
            print(f"defender-yara already exists with {count} rule files.")
            resp = input("Re-download? [y/N] ").strip().lower()
            if resp != "y":
                print("Skipped.")
                return
            shutil.rmtree(TARGET_DIR)

    print(f"Cloning {REPO_URL} ...")
    print("This may take a few minutes (292 MB, 76,700+ files).")

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, str(TARGET_DIR)],
            check=True,
        )
    except FileNotFoundError:
        print("ERROR: git not found. Install git and try again.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git clone failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Remove .git directory to save space
    git_dir = TARGET_DIR / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)

    count = sum(1 for _ in TARGET_DIR.rglob("*.yar"))
    count += sum(1 for _ in TARGET_DIR.rglob("*.yara"))
    print(f"Done! Downloaded {count} rule files to {TARGET_DIR}")
    print("The bot will auto-load these rules on next start or /reload.")


if __name__ == "__main__":
    main()
