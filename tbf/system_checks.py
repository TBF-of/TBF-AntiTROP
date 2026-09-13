#!/usr/bin/env python3
"""
TBF-AntiTROP :: system-level checks
Looks for common persistence / compromise indicators on Linux & Termux.
"""

import os
import re
import subprocess
from pathlib import Path

from .core import Finding


RC_FILES = [
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
    "~/.config/fish/config.fish",
]

SUSPICIOUS_RC_PATTERNS = [
    (r"curl\s+.*\|\s*(bash|sh)", "curl | bash в rc-файле — автозапуск удалённого кода при каждом входе"),
    (r"wget\s+.*\|\s*(bash|sh)", "wget | sh в rc-файле — автозапуск удалённого кода при каждом входе"),
    (r"nc\s+-e", "netcat reverse-shell паттерн в rc-файле"),
    (r"base64\s+-d.*\|\s*(bash|sh)", "закодированная base64-команда, исполняемая при запуске шелла"),
    (r"LD_PRELOAD=", "LD_PRELOAD в rc-файле — возможная инъекция библиотеки"),
]


def run_system_checks(quiet=False):
    findings = []
    findings += _check_rc_files()
    findings += _check_cron()
    findings += _check_ssh_keys()
    findings += _check_listening_ports()
    findings += _check_suspicious_processes()
    return findings


def _read(path: Path):
    try:
        return path.read_text(errors="ignore")
    except (OSError, PermissionError):
        return None


def _check_rc_files():
    out = []
    for rc in RC_FILES:
        p = Path(rc).expanduser()
        content = _read(p)
        if not content:
            continue
        for pattern, desc in SUSPICIOUS_RC_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                out.append(Finding(p, "system", "high", desc, rule="rc-persistence"))
    return out


def _check_cron():
    out = []
    candidates = ["crontab -l"]
    for cmd in candidates:
        try:
            res = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            content = res.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            content = ""
        if content:
            for line in content.splitlines():
                if re.search(r"(curl|wget).*\|\s*(bash|sh)", line, re.IGNORECASE):
                    out.append(Finding("crontab", "system", "critical",
                                        f"подозрительная cron-задача: {line.strip()}",
                                        rule="cron-persistence"))
    # also scan /etc/cron.d and spool dirs if readable
    for cron_dir in ("/etc/cron.d", "/var/spool/cron/crontabs", "/etc/cron.daily"):
        p = Path(cron_dir)
        if not p.exists():
            continue
        for f in p.glob("*"):
            content = _read(f)
            if content and re.search(r"(curl|wget).*\|\s*(bash|sh)", content, re.IGNORECASE):
                out.append(Finding(f, "system", "high",
                                    "подозрительная запись в системном cron", rule="cron-persistence"))
    return out


def _check_ssh_keys():
    out = []
    auth_keys = Path("~/.ssh/authorized_keys").expanduser()
    content = _read(auth_keys)
    if content:
        keys = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        if len(keys) > 5:
            out.append(Finding(auth_keys, "system", "medium",
                                f"необычно много authorized_keys ({len(keys)}) — проверь, все ли твои",
                                rule="ssh-keys-count"))
    return out


def _check_listening_ports():
    out = []
    try:
        res = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
        lines = res.stdout.splitlines()[1:]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        lines = []
    for line in lines:
        # flag high, unassigned-looking ports commonly used by shells/backdoors
        m = re.search(r":(\d{4,5})\s", line)
        if m:
            port = int(m.group(1))
            if port in (4444, 1337, 31337, 6666, 5555):
                out.append(Finding("network", "system", "high",
                                    f"открыт порт {port}, часто ассоциируемый с бэкдорами/reverse-shell",
                                    rule="suspicious-port"))
    return out


SUSPICIOUS_PROC_NAMES = ("xmrig", "kinsing", "kdevtmpfsi", "kworkerds", ".ssh-agent-fake")


def _check_suspicious_processes():
    out = []
    try:
        res = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=5)
        procs = res.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        procs = []
    for p in procs:
        name = p.strip().lower()
        for bad in SUSPICIOUS_PROC_NAMES:
            if bad in name:
                out.append(Finding(f"process:{p.strip()}", "system", "critical",
                                    "процесс похож на известный майнер/малварь по имени",
                                    rule="proc-name"))
    return out
