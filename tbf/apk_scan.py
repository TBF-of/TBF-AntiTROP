#!/usr/bin/env python3
"""
TBF-AntiTROP :: APK scanner
Лёгкий анализ .apk без androguard/aapt — только zipfile + stdlib.
Не полноценный AXML-парсер: строки (permissions, urls, class names) достаются
эвристически из бинарного manifest/dex, чего достаточно, чтобы поймать
типичные паттерны банковских троянов, дропперов и кликеров под Android.
"""

import re
import zipfile
from pathlib import Path

from .core import Finding, sha256_bytes

# Разрешения, которые сами по себе не страшны, но в комбинации — почти всегда зловред
DANGEROUS_PERMS = {
    "android.permission.SEND_SMS": "SMS",
    "android.permission.RECEIVE_SMS": "SMS",
    "android.permission.READ_SMS": "SMS",
    "android.permission.CALL_PHONE": "CALL",
    "android.permission.PROCESS_OUTGOING_CALLS": "CALL",
    "android.permission.SYSTEM_ALERT_WINDOW": "OVERLAY",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "ACCESSIBILITY",
    "android.permission.BIND_DEVICE_ADMIN": "DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES": "INSTALL",
    "android.permission.RECEIVE_BOOT_COMPLETED": "BOOT",
    "android.permission.QUERY_ALL_PACKAGES": "QUERY_APPS",
    "android.permission.READ_CONTACTS": "CONTACTS",
    "android.permission.READ_CALL_LOG": "CALL_LOG",
    "android.permission.GET_ACCOUNTS": "ACCOUNTS",
    "android.permission.RECORD_AUDIO": "MIC",
    "android.permission.CAMERA": "CAMERA",
    "android.permission.ACCESS_FINE_LOCATION": "LOCATION",
}

# Комбинации разрешений -> известный паттерн атаки
COMBO_RULES = [
    ({"SMS", "ACCESSIBILITY", "OVERLAY"}, "critical",
     "SMS + Accessibility + Overlay — классический паттерн банковского трояна "
     "(перехват СМС-кодов, фейковые окна поверх банк-приложений)"),
    ({"DEVICE_ADMIN", "ACCESSIBILITY"}, "critical",
     "Device Admin + Accessibility — приложение может сопротивляться удалению и "
     "полностью контролировать экран/ввод"),
    ({"INSTALL", "BOOT"}, "high",
     "автозапуск при загрузке + право ставить сторонние пакеты — похоже на дроппер"),
    ({"OVERLAY", "ACCESSIBILITY"}, "high",
     "Overlay + Accessibility — часто используется для фишинговых окон поверх других приложений"),
    ({"QUERY_APPS", "OVERLAY"}, "medium",
     "приложение видит список всех установленных пакетов и умеет рисовать поверх них — "
     "типично для таргетированного оверлей-фишинга"),
]

SUSPICIOUS_DEX_PATTERNS = [
    (r"DexClassLoader|PathClassLoader.*loadClass", "medium",
     "динамическая загрузка кода (DexClassLoader) — может подгружать payload после установки"),
    (r"getRuntime\(\)\.exec", "medium", "вызов Runtime.exec — исполнение shell-команд из приложения"),
    (r"su\s+-c|/system/bin/su", "medium", "обращение к su — попытка получить root-доступ"),
    (r"stratum\+tcp://|xmrig|cryptonight", "high", "строки майнера в коде приложения"),
    (r"(bc1[a-z0-9]{25,}|0x[a-fA-F0-9]{40})", "medium",
     "жёстко зашитый крипто-адрес рядом с работой с буфером обмена — возможный clipper"),
    (r"frida-gadget|frida-server", "low", "следы Frida — приложение может быть пересобрано/инструментировано"),
    (r"xposed", "low", "следы Xposed framework"),
]

SIGNATURE_FILES = ("META-INF/CERT.RSA", "META-INF/CERT.DSA", "META-INF/CERT.EC")


def _strings_from_bytes(data: bytes, min_len=5):
    """Достаём как обычные ASCII-строки, так и UTF-16LE (типично для AXML/dex)."""
    stripped = data.replace(b"\x00", b"")
    text = stripped.decode("latin-1", errors="ignore")
    return text


def scan_apk(apk_path: str, deep=False):
    apk_path = Path(apk_path).expanduser().resolve()
    findings = []

    with open(apk_path, "rb") as f:
        raw = f.read()
    digest = sha256_bytes(raw)

    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        findings.append(Finding(apk_path, "apk", "high",
                                 "файл повреждён или не является валидным APK/ZIP", rule="apk-badzip"))
        return {"sha256": digest, "findings": [f.to_dict() for f in findings], "permissions": []}

    names = zf.namelist()

    # -- подпись -------------------------------------------------------------
    signed = any(n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))
                 for n in names)
    if not signed:
        findings.append(Finding(apk_path, "apk", "high",
                                 "APK не подписан (нет META-INF/*.RSA|DSA|EC) — не должно ставиться "
                                 "штатным Android, подозрительно если вообще установилось",
                                 rule="apk-unsigned"))

    # -- манифест: разрешения -------------------------------------------------
    perms_found = set()
    manifest_bytes = zf.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
    manifest_text = _strings_from_bytes(manifest_bytes)
    for perm, tag in DANGEROUS_PERMS.items():
        if perm in manifest_text:
            perms_found.add(tag)

    for combo, severity, desc in COMBO_RULES:
        if combo.issubset(perms_found):
            findings.append(Finding(apk_path, "apk", severity, desc, rule="apk-perm-combo"))

    if perms_found and not any(f.rule == "apk-perm-combo" for f in findings):
        findings.append(Finding(
            apk_path, "apk", "low",
            "запрошены чувствительные разрешения: " + ", ".join(sorted(perms_found)),
            rule="apk-perms",
        ))

    # -- dex: паттерны в коде --------------------------------------------------
    dex_names = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    scan_targets = dex_names if deep else dex_names[:1]
    for dex_name in scan_targets:
        try:
            dex_text = _strings_from_bytes(zf.read(dex_name))
        except (KeyError, zipfile.BadZipFile):
            continue
        for pattern, severity, desc in SUSPICIOUS_DEX_PATTERNS:
            if re.search(pattern, dex_text, re.IGNORECASE):
                findings.append(Finding(f"{apk_path}!{dex_name}", "apk", severity, desc, rule="apk-dex-pattern"))

    # -- подозрительные URL в манифесте/ресурсах -------------------------------
    urls = set(re.findall(r"https?://[^\s\"'<>]{4,80}", manifest_text))
    ip_urls = [u for u in urls if re.search(r"://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u)]
    for u in ip_urls[:5]:
        findings.append(Finding(apk_path, "apk", "medium",
                                 f"URL с IP вместо домена в манифесте/ресурсах: {u}", rule="apk-ip-url"))

    # -- нативные библиотеки: список для ручного глаза -------------------------
    native_libs = sorted({n.split("/")[-1] for n in names if n.startswith("lib/") and n.endswith(".so")})

    return {
        "sha256": digest,
        "signed": signed,
        "permissions": sorted(perms_found),
        "native_libs": native_libs,
        "findings": [f.to_dict() for f in findings],
    }
