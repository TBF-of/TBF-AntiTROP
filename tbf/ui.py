#!/usr/bin/env python3
"""
TBF-AntiTROP :: UI layer (rich)
Весь визуал живёт тут — core/apk_scan/system_checks ничего не знают про печать.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, MofNCompleteColumn,
)
from rich.text import Text
from rich.align import Align
from rich import box

console = Console()

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

LOGO = r"""
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀
     ▐░▌     ▐░▌          ▐░▌
     ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄
     ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
     ▐░▌     ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀
     ▐░▌     ▐░▌          ▐░▌
     ▐░▌     ▐░▌          ▐░█▄▄▄▄▄▄▄▄▄
     ▐░▌     ▐░▌          ▐░░░░░░░░░░░▌
      ▀       ▀            ▀▀▀▀▀▀▀▀▀▀▀
"""


def print_banner():
    logo_text = Text(LOGO, style="bold magenta")
    sub = Text("A N T I - T R O P", style="bold cyan", justify="center")
    tagline = Text("жёсткий сканер для Termux/Linux", style="dim italic", justify="center")
    console.print(Align.center(logo_text))
    console.print(Align.center(sub))
    console.print(Align.center(tagline))
    console.print()


def scanning_progress():
    """Возвращает rich.Progress с колонками под сканирование файлов."""
    return Progress(
        SpinnerColumn(style="magenta"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="grey37", complete_style="magenta", finished_style="green"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[current]}"),
        console=console,
        transient=False,
    )


def _sorted_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))


def render_findings_table(findings, title="Находки"):
    if not findings:
        console.print(Panel.fit(
            "[bold green]✔ Угроз не найдено. Чисто.[/bold green]",
            border_style="green", box=box.ROUNDED,
        ))
        return

    table = Table(title=title, box=box.ROUNDED, border_style="magenta",
                  header_style="bold white on magenta", expand=True)
    table.add_column("Уровень", justify="center", width=10)
    table.add_column("Правило", style="dim", width=18)
    table.add_column("Файл", overflow="fold", ratio=2)
    table.add_column("Описание", overflow="fold", ratio=3)

    for f in _sorted_findings(findings):
        style = SEVERITY_STYLE.get(f["severity"], "")
        table.add_row(
            Text(f["severity"].upper(), style=style),
            f.get("rule") or "-",
            f["path"],
            f["detail"],
        )
    console.print(table)


def render_summary(result, elapsed_label="Время"):
    by_sev = result.get("by_severity", {})
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        if by_sev.get(sev):
            style = SEVERITY_STYLE.get(sev, "")
            parts.append(f"[{style}]{sev.upper()}: {by_sev[sev]}[/{style}]")
    summary_line = "  ".join(parts) if parts else "[bold green]угроз нет[/bold green]"

    body = (
        f"Файлов проверено: [bold]{result.get('scanned_files', '-')}[/bold]\n"
        f"{elapsed_label}: [bold]{result.get('elapsed', 0):.2f}s[/bold]\n"
        f"{summary_line}"
    )
    border = "red" if by_sev.get("critical") or by_sev.get("high") else "green"
    console.print(Panel(body, title="Итог", border_style=border, box=box.ROUNDED))


def render_apk_report(apk_result, path):
    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim")
    header.add_column()
    header.add_row("Файл:", str(path))
    header.add_row("SHA256:", apk_result["sha256"])
    header.add_row("Подписан:", "[green]да[/green]" if apk_result.get("signed") else "[bold red]НЕТ[/bold red]")
    if apk_result.get("permissions"):
        header.add_row("Опасные права:", ", ".join(apk_result["permissions"]))
    if apk_result.get("native_libs"):
        libs = apk_result["native_libs"]
        shown = ", ".join(libs[:8]) + (f" … ещё {len(libs) - 8}" if len(libs) > 8 else "")
        header.add_row("Нативные либы:", shown)

    console.print(Panel(header, title="APK-анализ", border_style="magenta", box=box.ROUNDED))
    render_findings_table(apk_result["findings"], title="Находки в APK")


def render_error(msg):
    console.print(Panel.fit(f"[bold red]✖ {msg}[/bold red]", border_style="red", box=box.ROUNDED))


def render_info(msg):
    console.print(f"[cyan]▶[/cyan] {msg}")


def render_success(msg):
    console.print(f"[bold green]✔[/bold green] {msg}")
