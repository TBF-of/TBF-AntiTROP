#!/usr/bin/env python3
"""
TBF-AntiTROP :: core scanning engine
Signature + heuristic based scanner for Termux/Linux.
This module stays stdlib-only and knows nothing about rendering — it just
collects Finding objects and reports progress via an optional callback, so
the rich-based UI layer (tbf/ui.py) can drive a live progress bar off it.
"""

import os
import re
import json
import hashlib
import shutil
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SIGNATURES_FILE = DATA_DIR / "signatures.json"
PATTERNS_FILE = DATA_DIR / "patterns.json"
QUARANTINE_DIR = Path.home() / ".tbf_quarantine"

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tbf_quarantine", "venv", ".venv"}
TEXT_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".php", ".js", ".ts",
    ".service", ".profile", ".bashrc", ".zshrc", "", ".cfg", ".conf",
    ".desktop", ".ps1", ".lua",
}
MAX_TEXT_SCAN_SIZE = 5 * 1024 * 1024  # 5 MB cap for content scanning

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(chunk)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


class Finding:
    def __init__(self, path, kind, severity, detail, rule=None):
        self.path = str(path)
        self.kind = kind          # "signature" | "heuristic" | "system" | "apk"
        self.severity = severity  # "critical" | "high" | "medium" | "low"
        self.detail = detail
        self.rule = rule

    def to_dict(self):
        return {
            "path": self.path, "kind": self.kind, "severity": self.severity,
            "detail": self.detail, "rule": self.rule,
        }


def count_by_severity(findings):
    by_sev = {}
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else f["severity"]
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return by_sev


class Scanner:
    def __init__(self, deep=False, progress_cb=None):
        """
        progress_cb: optional callable(current_path: Path) invoked before each
        file is scanned, so a UI layer can drive a live progress bar.
        """
        self.deep = deep
        self.progress_cb = progress_cb
        self.signatures = load_json(SIGNATURES_FILE, {"sha256": {}})
        self.patterns = load_json(PATTERNS_FILE, {"rules": []})
        self.findings = []
        self.scanned_files = 0
        self.start_time = None

    def _report_finding(self, f: Finding):
        self.findings.append(f)

    def check_signature(self, path: Path):
        digest = sha256_of(path)
        if digest is None:
            return
        entry = self.signatures.get("sha256", {}).get(digest)
        if entry:
            self._report_finding(Finding(
                path, "signature", "critical",
                f"совпадение по SHA256 с базой: {entry}", rule="sig:" + digest[:12],
            ))

    def check_heuristics(self, path: Path):
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size == 0 or size > MAX_TEXT_SCAN_SIZE:
            return
        if path.suffix not in TEXT_EXTS and path.name not in TEXT_EXTS:
            if not self.deep:
                return
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError, UnicodeDecodeError):
            return

        for rule in self.patterns.get("rules", []):
            try:
                if re.search(rule["pattern"], content, re.IGNORECASE | re.MULTILINE):
                    self._report_finding(Finding(
                        path, "heuristic", rule.get("severity", "medium"),
                        rule["description"], rule=rule.get("id"),
                    ))
            except re.error:
                continue

        if path.name.startswith(".") and os.access(path, os.X_OK):
            self._report_finding(Finding(
                path, "heuristic", "low",
                "скрытый файл с флагом на выполнение — часто используется для маскировки",
                rule="hidden-exec",
            ))

    def scan_path(self, target: str):
        self.start_time = time.time()
        target_path = Path(target).expanduser().resolve()

        if target_path.is_file():
            self._scan_file(target_path)
        else:
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fname in files:
                    self._scan_file(Path(root) / fname)

        return self.summary()

    def _scan_file(self, path: Path):
        try:
            if path.is_symlink() or not path.is_file():
                return
            if self.progress_cb:
                self.progress_cb(path)
            self.scanned_files += 1
            self.check_signature(path)
            self.check_heuristics(path)
        except (OSError, PermissionError):
            pass

    def summary(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            "scanned_files": self.scanned_files,
            "elapsed": elapsed,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": count_by_severity(self.findings),
        }

    def quarantine(self):
        """Move all flagged files (critical/high) into ~/.tbf_quarantine."""
        moved = []
        QUARANTINE_DIR.mkdir(exist_ok=True)
        for f in self.findings:
            if f.severity not in ("critical", "high"):
                continue
            src = Path(f.path)
            if not src.exists():
                continue
            dst = QUARANTINE_DIR / (src.name + f".{int(time.time())}.quarantined")
            try:
                shutil.move(str(src), str(dst))
                moved.append((str(src), str(dst)))
            except OSError:
                pass
        return moved
