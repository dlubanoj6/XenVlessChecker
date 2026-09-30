#!/usr/bin/env python3
import json
import urllib.request
import urllib.parse
import sys
import time
from pathlib import Path
from collections import deque

from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, BarColumn, TextColumn, DownloadColumn, TransferSpeedColumn
from rich.text import Text
from rich.console import Console, Group

LINKS_DIR = Path("/storage/emulated/0/links")

REPOSITORIES = [
    {
        "provider": "github",
        "owner": "hiztin",
        "repo": "VLESS-PO-GRIBI",
        "branch": "main",
        "path": "deploy/subscriptions",
        "prefix": "hiztin_",
    },
    {
        "provider": "gitlab",
        "owner": "avencores",
        "repo": "goida-vpn-configs",
        "branch": "main",
        "path": "githubmirror",
        "prefix": "avencores_",
    },
    {
        "provider": "github",
        "owner": "mohammadaz2",
        "repo": "v2rayConfigsForYou",
        "branch": "main",
        "path": "configs.txt",
        "prefix": "mohammadaz2_",
    },
    {
        "provider": "github",
        "owner": "MatinGhanbari",
        "repo": "v2ray-configs",
        "branch": "main",
        "path": "subscriptions/v2ray/all_sub.txt",
        "prefix": "matinghanbari_",
    },
    {
        "provider": "github",
        "owner": "Surfboardv2ray",
        "repo": "TGParse",
        "branch": "main",
        "path": "splitted/mixed",
        "prefix": "surfboardv2ray_",
    },
    {
        "provider": "github",
        "owner": "barry-far",
        "repo": "V2ray-Config",
        "branch": "main",
        "path": "Sub1.txt",
        "prefix": "barryfar_",
    },
    {
        "provider": "github",
        "owner": "hans-thomas",
        "repo": "v2ray-subscription",
        "branch": "master",
        "path": "servers.txt",
        "prefix": "hansthomas_",
    },
    {
        "provider": "github",
        "owner": "awesome-vpn",
        "repo": "awesome-vpn",
        "branch": "master",
        "path": "all",
        "prefix": "awesomevpn_",
    },
]

console = Console()


def ask_yes_no(prompt: str) -> bool:
    ans = input(prompt).strip().lower()
    return ans in ("y", "yes", "д", "да", "")


def format_time(seconds: float) -> str:
    """Форматирует секунды в вид ММ:СС (Минуты:Секунды)."""
    mins, secs = divmod(int(seconds), 60)
    return f"{mins:02d}:{secs:02d}"


def get_repository_files(provider: str, owner: str, repo: str, path: str, branch: str):
    if provider == "github":
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Termux-List-Updater",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        parsed = json.loads(data)

        if isinstance(parsed, dict):
            if parsed.get("type") == "file":
                return [parsed]
            raise RuntimeError(parsed.get("message", "Неизвестная ошибка GitHub API"))

        if isinstance(parsed, list):
            return parsed

        raise RuntimeError("GitHub API вернул неожиданный ответ.")

    elif provider == "gitlab":
        project = urllib.parse.quote(f"{owner}/{repo}", safe="")
        encoded_path = urllib.parse.quote(path, safe="")
        url = f"https://gitlab.com/api/v4/projects/{project}/repository/tree?path={encoded_path}&ref={branch}&per_page=100"

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Termux-List-Updater"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8", errors="ignore")
        parsed = json.loads(data)

        if not isinstance(parsed, list):
            if isinstance(parsed, dict):
                raise RuntimeError(parsed.get("message", "Неизвестная ошибка GitLab API"))
            raise RuntimeError("GitLab API вернул неожиданный ответ.")

        result = []
        for item in parsed:
            if item.get("type") == "blob":
                file_path = item["path"]
                download_url = f"https://gitlab.com/{owner}/{repo}/-/raw/{branch}/{urllib.parse.quote(file_path, safe='/')}"
                result.append({
                    "type": "file",
                    "name": item["name"],
                    "path": file_path,
                    "download_url": download_url,
                })
        return result
    else:
        raise RuntimeError(f"Неизвестный provider: {provider}")


def remove_all_files_in_links(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    removed = 0
    for p in directory.iterdir():
        if p.is_file():
            try:
                p.unlink()
                removed += 1
            except Exception:
                pass
    return removed


def download_file_with_progress(url: str, out_path: Path, file_progress: Progress, task_id, timeout: int = 15):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Termux-List-Updater"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total_size = resp.headers.get("Content-Length")
        if total_size is not None:
            total_size = int(total_size)
            file_progress.update(task_id, total=total_size)

        downloaded = 0
        with open(out_path, "wb") as f:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                file_progress.update(task_id, completed=downloaded)


def make_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=9),
        Layout(name="logs", ratio=1),
    )
    return layout


def main():
    print(f"[i] Директория со списками: {LINKS_DIR}")
    need_update = ask_yes_no("[?] Обновить списки ссылок? (Y/n): ")

    if not need_update:
        print("[i] Обновление пропущено.")
        return

    removed = remove_all_files_in_links(LINKS_DIR)

    term_height = console.height or 30
    log_max_lines = max(12, term_height - 11)
    logs_queue = deque(maxlen=log_max_lines)

    total_downloaded = 0
    start_time = time.time()

    # Убран TimeRemainingColumn из верхнего прогресс-бара
    repo_progress = Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    )
    repo_task_id = repo_progress.add_task("Репозитории...", total=len(REPOSITORIES))

    file_progress = Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        DownloadColumn(),
        TransferSpeedColumn(),
    )
    file_task_id = file_progress.add_task("Файл...", total=None, visible=False)

    layout = make_layout()

    def update_ui(finished=False):
        elapsed_str = format_time(time.time() - start_time)

        if not finished:
            title = "[bold cyan]List Updater Status[/bold cyan]"
            border_style = "cyan"
            info_text = f"Удалено старых: [bold yellow]{removed}[/bold yellow] | Скачано файлов: [bold green]{total_downloaded}[/bold green] | Время: [bold yellow]{elapsed_str}[/bold yellow]"
            
            header_group = Group(
                Text.from_markup(info_text, justify="center"),
                Text(""),
                repo_progress,
                file_progress
            )
            layout["header"].update(Panel(header_group, title=title, border_style=border_style))

            log_text = Text()
            for item in logs_queue:
                log_text.append(item[0], style=item[1])
                log_text.append("\n")
            layout["logs"].update(Panel(log_text, title="[bold yellow]Лог скачивания[/bold yellow]", border_style="yellow"))
        else:
            title = "[bold green]✔ ОБНОВЛЕНИЕ ЗАВЕРШЕНО[/bold green]"
            
            header_group = Group(
                Text.from_markup("Статус: [bold green]Готово (100%)[/bold green]", justify="center"),
                Text(""),
                repo_progress
            )
            layout["header"].update(Panel(header_group, title=title, border_style="green"))

            summary_text = (
                f"\n\n"
                f"[bold cyan]📊 ИТОГИ ОБНОВЛЕНИЯ[/bold cyan]\n\n"
                f"─────────────────────────────────\n"
                f"Удалено старых файлов:   [bold red]{removed}[/bold red]\n"
                f"Скачано новых файлов:    [bold green]{total_downloaded}[/bold green]\n"
                f"Затрачено времени:       [bold yellow]{elapsed_str}[/bold yellow]\n"
                f"Директория:              [bold dim]{LINKS_DIR}[/bold dim]\n"
                f"─────────────────────────────────\n\n"
                f"[bold white on blue] Нажмите ENTER для продолжения [/bold white on blue]"
            )

            layout["logs"].update(
                Panel(
                    Text.from_markup(summary_text, justify="center"), 
                    title="[bold green]Результаты[/bold green]", 
                    border_style="green"
                )
            )

    try:
        with Live(layout, refresh_per_second=10, screen=True):
            for repo_info in REPOSITORIES:
                provider = repo_info.get("provider", "github")
                owner = repo_info["owner"]
                repo = repo_info["repo"]
                branch = repo_info["branch"]
                path = repo_info["path"]
                prefix = repo_info.get("prefix", "")

                logs_queue.append((f"[*] Источник: {provider} {owner}/{repo}", "bold cyan"))
                update_ui(finished=False)

                try:
                    items = get_repository_files(provider, owner, repo, path, branch)
                except Exception as e:
                    logs_queue.append((f"[-] Ошибка получения списка: {e}", "bold red"))
                    repo_progress.advance(repo_task_id)
                    update_ui(finished=False)
                    continue

                valid_files = [
                    item for item in items 
                    if item.get("type") == "file" and item.get("name") and item.get("download_url")
                ]

                for item in valid_files:
                    name = item["name"]
                    download_url = item["download_url"]
                    file_name = f"{prefix}{name}"
                    out_path = LINKS_DIR / file_name

                    file_progress.reset(file_task_id, description=f"Скачивание: {name}", total=None, visible=True)
                    update_ui(finished=False)

                    try:
                        download_file_with_progress(download_url, out_path, file_progress, file_task_id, timeout=15)
                        total_downloaded += 1
                        logs_queue.append((f"  [+] Скачан: {file_name}", "green"))
                    except Exception:
                        logs_queue.append((f"  [-] Ошибка скачивания: {name}", "red"))

                    update_ui(finished=False)

                file_progress.update(file_task_id, visible=False)
                repo_progress.advance(repo_task_id)
                update_ui(finished=False)

            update_ui(finished=True)
            input()

    except KeyboardInterrupt:
        console.print("\n[bold red][!] Скачивание прервано пользователем (Ctrl+C).[/bold red]")


if __name__ == "__main__":
    main()
