#!/usr/bin/env python3
"""
TBF-AntiTROP — жёсткий сканер для Termux/Linux.

Usage:
    python3 tbf_antitrop.py scan <path> [--deep] [--quarantine] [--json out.json]
    python3 tbf_antitrop.py apk <file.apk> [--deep] [--json out.json]
    python3 tbf_antitrop.py system
    python3 tbf_antitrop.py update --auth-key KEY [--limit 100]
    python3 tbf_antitrop.py full <path> [--quarantine] [--json out.json]
"""

import os
import sys
import json
import argparse

from tbf.core import Scanner
from tbf.system_checks import run_system_checks
from tbf.apk_scan import scan_apk
from tbf import threat_feed
from tbf import ui


def cmd_scan(args):
    ui.print_banner()
    ui.render_info(f"Сканирую: {os.path.abspath(os.path.expanduser(args.path))}")

    scanner = Scanner(deep=args.deep)
    with ui.scanning_progress() as progress:
        task = progress.add_task("scan", total=None, current="")

        def on_progress(path):
            progress.update(task, advance=1, current=str(path.name)[:40])

        scanner.progress_cb = on_progress
        result = scanner.scan_path(args.path)
        progress.update(task, current="готово")

    ui.console.print()
    ui.render_findings_table(result["findings"])
    ui.render_summary(result)

    if args.quarantine and scanner.findings:
        ui.render_info("Карантин включён — перемещаю опасные файлы...")
        moved = scanner.quarantine()
        for src, dst in moved:
            ui.render_success(f"в карантин: {src} → {dst}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        ui.render_info(f"Отчёт сохранён: {args.json}")

    return 1 if any(f["severity"] in ("critical", "high") for f in result["findings"]) else 0


def cmd_apk(args):
    ui.print_banner()
    ui.render_info(f"Анализирую APK: {os.path.abspath(os.path.expanduser(args.path))}")
    try:
        result = scan_apk(args.path, deep=args.deep)
    except FileNotFoundError:
        ui.render_error(f"файл не найден: {args.path}")
        return 2

    ui.console.print()
    ui.render_apk_report(result, args.path)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        ui.render_info(f"Отчёт сохранён: {args.json}")

    return 1 if any(f["severity"] in ("critical", "high") for f in result["findings"]) else 0


def cmd_system(args):
    ui.print_banner()
    ui.render_info("Проверка системы (cron, автозагрузка, ssh, порты, процессы)...")
    findings = [f.to_dict() for f in run_system_checks()]

    ui.console.print()
    ui.render_findings_table(findings, title="Системные индикаторы")
    critical = sum(1 for f in findings if f["severity"] in ("critical", "high"))
    return 1 if critical else 0


def cmd_update(args):
    ui.print_banner()
    auth_key = args.auth_key or os.environ.get("MB_AUTH_KEY")
    ui.render_info("Обновляю базу сигнатур с MalwareBazaar...")
    try:
        added, total = threat_feed.update_from_malwarebazaar(auth_key, limit=args.limit)
    except threat_feed.ThreatFeedError as e:
        ui.render_error(str(e))
        return 2
    ui.render_success(f"добавлено новых хэшей: {added}, всего в базе: {total}")
    return 0


def cmd_full(args):
    rc1 = cmd_scan(argparse.Namespace(path=args.path, deep=True, quarantine=args.quarantine, json=args.json))
    ui.console.print()
    rc2 = cmd_system(args)
    return max(rc1, rc2)


def main():
    parser = argparse.ArgumentParser(prog="tbf_antitrop", description="TBF-AntiTROP scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="сканировать файл/директорию")
    p_scan.add_argument("path")
    p_scan.add_argument("--deep", action="store_true", help="глубокий скан всех файлов, не только скриптов")
    p_scan.add_argument("--quarantine", action="store_true", help="переносить опасные файлы в карантин")
    p_scan.add_argument("--json", help="сохранить JSON-отчёт по указанному пути")
    p_scan.set_defaults(func=cmd_scan)

    p_apk = sub.add_parser("apk", help="анализ .apk файла")
    p_apk.add_argument("path")
    p_apk.add_argument("--deep", action="store_true", help="сканировать все classes*.dex, не только первый")
    p_apk.add_argument("--json", help="сохранить JSON-отчёт по указанному пути")
    p_apk.set_defaults(func=cmd_apk)

    p_sys = sub.add_parser("system", help="проверить систему на признаки компрометации")
    p_sys.set_defaults(func=cmd_system)

    p_update = sub.add_parser("update", help="подтянуть свежие хэши с MalwareBazaar")
    p_update.add_argument("--auth-key", help="Auth-Key от MalwareBazaar (или переменная окружения MB_AUTH_KEY)")
    p_update.add_argument("--limit", type=int, default=100, help="сколько последних записей забрать (по умолчанию 100)")
    p_update.set_defaults(func=cmd_update)

    p_full = sub.add_parser("full", help="scan + system за один проход")
    p_full.add_argument("path")
    p_full.add_argument("--quarantine", action="store_true")
    p_full.add_argument("--json", help="сохранить JSON-отчёт по указанному пути")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
