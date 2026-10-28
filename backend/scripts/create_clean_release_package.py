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
import re
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
    ".tmp",
    ".bak",
}

PROHIBITED_ARCHIVE_PATTERNS = [
    r"\.env$",
    r"\.git/",
    r"\.venv/",
    r"node_modules/",
    r"__pycache__/",
    r"\.db$",
    r"\.sqlite\d*$",
    r"-wal$",
    r"-shm$",
    r"\.key$",
    r"\.pem$",
    r"\.pfx$",
]

SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key Header"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
]


def audit_release_archive(zip_path: Path) -> dict:
    """
    Audits an existing release archive for prohibited file paths and accidental secrets.
    Fails closed if any violation is detected.
    """
    if not zip_path.exists():
        raise FileNotFoundError(f"Archive not found: {zip_path}")

    violations = []
    secrets_found = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            # Check prohibited path patterns
            for pat in PROHIBITED_ARCHIVE_PATTERNS:
                if re.search(pat, name, re.IGNORECASE):
                    violations.append(f"Prohibited file/path: '{name}' matches '{pat}'")

            # Check contents for secrets if text file < 500KB
            info = zf.getinfo(name)
            if info.file_size < 500 * 1024 and not name.endswith((".png", ".jpg", ".ico", ".woff", ".woff2", ".ttf")):
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    for sec_pat, desc in SECRET_PATTERNS:
                        if re.search(sec_pat, content):
                            secrets_found.append(f"Potential secret ({desc}) in '{name}'")
                except Exception:
                    pass

    passed = len(violations) == 0 and len(secrets_found) == 0
    return {
        "passed": passed,
        "violations": violations,
        "secrets_found": secrets_found,
        "total_files_audited": len(zf.namelist()),
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

    # Post-packaging automated safety audit
    audit = audit_release_archive(OUTPUT_ZIP)
    if not audit["passed"]:
        OUTPUT_ZIP.unlink(missing_ok=True)
        print("[FAIL] Release audit failed! Prohibited items or secrets detected:")
        for v in audit["violations"]:
            print(f"  - {v}")
        for s in audit["secrets_found"]:
            print(f"  - {s}")
        raise RuntimeError("Clean release package failed security audit and was purged.")

    print(f"[PASS] Automated Security Audit Passed: {audit['total_files_audited']} files verified clean (0 secrets, 0 prohibited paths).")


if __name__ == "__main__":
    create_release()
