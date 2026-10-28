"""
VAPT System - Clean Release Package Generator
=============================================
Creates a distribution zip archive containing source code, migrations, tests,
documentation, and configuration while strictly excluding:
- .git / repository metadata
- Virtual environments (.venv)
- Node modules (node_modules)
- Build artifacts (dist, build, *.egg-info)
- Databases and runtime caches (vapt.db, __pycache__, .pytest_cache)
- Local secrets / env files
"""

import os
import zipfile
from pathlib import Path

ROOT_DIR = Path("D:/alt")
OUTPUT_ZIP = Path("D:/alt/release/vapt_system_clean_release.zip")

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    ".pytest_cache",
    "__pycache__",
    ".vite",
    "data",
    "release",
}

EXCLUDE_FILES = {
    ".env",
    "vapt.db",
    "vapt.db-wal",
    "vapt.db-shm",
    "npm-debug.log",
}

EXCLUDE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
}


def should_include(file_path: Path) -> bool:
    rel = file_path.relative_to(ROOT_DIR)
    parts = set(rel.parts)
    if any(p in EXCLUDE_DIRS for p in parts):
        return False
    if file_path.name in EXCLUDE_FILES:
        return False
    if file_path.suffix in EXCLUDE_EXTENSIONS:
        return False
    return True


def create_release():
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    total_size = 0

    print(f"Packaging clean release from {ROOT_DIR} into {OUTPUT_ZIP}...")

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ROOT_DIR):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                fpath = Path(root) / file
                if should_include(fpath):
                    arcname = fpath.relative_to(ROOT_DIR)
                    zf.write(fpath, arcname)
                    count += 1
                    total_size += fpath.stat().st_size

    mb = total_size / (1024 * 1024)
    zip_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    print(f"Successfully created clean release package:")
    print(f"  Archive: {OUTPUT_ZIP}")
    print(f"  Total Files Included: {count}")
    print(f"  Uncompressed Size: {mb:.2f} MB")
    print(f"  Compressed Archive Size: {zip_mb:.2f} MB")


if __name__ == "__main__":
    create_release()
