#!/usr/bin/env python3
import json
import urllib.request
import sys
import time
from pathlib import Path

LINKS_DIR = Path("/storage/emulated/0/links")

REPOSITORIES = [
    {
        "owner": "hiztin",
        "repo": "VLESS-PO-GRIBI",
        "branch": "main",
        "path": "deploy/subscriptions",
        "prefix": "hiztin_",
    },
    {
        "owner": "AvenCores",
        "repo": "goida-vpn-configs",
        "branch": "main",
        "path": "githubmirror",
        "prefix": "avencores_",
    },
]


def ask_yes_no(prompt: str) -> bool:
    ans = input(prompt).strip().lower()
    return ans in ("y", "yes", "д", "да")


def print_progress_bar(iteration: int, total: int, prefix: str = "", length: int = 30):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = "█" * filled_length + "-" * (length - filled_length)
    sys.stdout.write(f"\r{prefix} |{bar}| {iteration}/{total} ({percent}%)")
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write("\n")


def github_list_dir(owner: str, repo: str, path: str, branch: str):
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
    if not isinstance(parsed, list):
        raise RuntimeError("GitHub API вернул неожиданный ответ.")
    return parsed


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


def download_single_file(url: str, retries: int = 3, timeout: int = 7) -> bytes:
    """Скачивание файла с ограниченным таймаутом и повторными попытками."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Termux-List-Updater"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                raise


def download_files_to_links(files, directory: Path, prefix: str = "") -> int:
    valid_files = [
        item for item in files 
        if item.get("type") == "file" and item.get("name") and item.get("download_url")
    ]
    
    total = len(valid_files)
    if total == 0:
        print("    [!] Нет файлов для скачивания.")
        return 0

    downloaded = 0
    print_progress_bar(0, total, prefix="    Загрузка", length=30)

    for idx, item in enumerate(valid_files, start=1):
        name = item["name"]
        download_url = item["download_url"]

        try:
            content = download_single_file(download_url, retries=3, timeout=7)
            file_name = f"{prefix}{name}"
            out_path = directory / file_name

            with open(out_path, "wb") as f:
                f.write(content)
            downloaded += 1
        except Exception:
            # Если файл так и не скачался после 3 попыток — пропускаем без зависания
            pass
            
        print_progress_bar(idx, total, prefix="    Загрузка", length=30)

    return downloaded


def main():
    print(f"[i] Папка списков: {LINKS_DIR}")
    need_update = ask_yes_no("Обновить списки? (yes/no): ")

    if not need_update:
        print("[i] Обновление пропущено.")
        return

    print("[*] Удаляю старые файлы в links...")
    removed = remove_all_files_in_links(LINKS_DIR)

    total_downloaded = 0

    for repo_info in REPOSITORIES:
        owner = repo_info["owner"]
        repo = repo_info["repo"]
        branch = repo_info["branch"]
        path = repo_info["path"]
        prefix = repo_info.get("prefix", "")

        print(f"\n[*] Источник: {owner}/{repo} ({path})")
        try:
            items = github_list_dir(owner, repo, path, branch)
        except Exception as e:
            print(f"[-] Ошибка получения списка файлов: {e}")
            continue

        try:
            downloaded = download_files_to_links(items, LINKS_DIR, prefix=prefix)
            total_downloaded += downloaded
        except Exception as e:
            print(f"\n[-] Ошибка скачивания из {owner}/{repo}: {e}")

    print("\n----------------------------------------")
    print(f"[+] Готово!")
    print(f"[+] Удалено старых файлов: {removed}")
    print(f"[+] Всего скачано новых файлов: {total_downloaded}")
    print(f"[+] Путь к директории: {LINKS_DIR}")


if __name__ == "__main__":
    main()
