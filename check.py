#!/usr/bin/env python3
import os
import json
import time
import random
import base64
import socket
import shutil
import signal
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

INPUT_DIR = "/storage/emulated/0/links"
OUTPUT_FILE = "/storage/emulated/0/links/output.txt"
ERROR_LOG = "/storage/emulated/0/links/singbox_errors.log"
MAX_DELAY_MS = 2000
WORKERS = 32   # 16-32 обычно нормально для телефона

TG_TEST_HOST = "149.154.167.99"
TG_TEST_PORT = 443

LOCAL_SOCKS_HOST = "127.0.0.1"
SINGBOX_START_TIMEOUT = 5.0
CONNECT_TIMEOUT = 3.0
SINGBOX_BIN = shutil.which("sing-box") or "sing-box"

print_lock = Lock()
log_lock = Lock()


def b64_decode_loose(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def read_all_links(input_dir: str):
    # Используем set для мгновенного удаления дубликатов без перерасхода памяти
    unique_links = set()
    p = Path(input_dir)
    if not p.exists():
        return []
    
    print("[*] Сканирую файлы и собираю ссылки...")
    for txt in p.glob("*.txt"):
        if txt.name == "output.txt":
            continue
        try:
            content = txt.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in content.splitlines():
            s = line.strip().strip('"').strip("'").replace("&amp;", "&")
            if s.startswith(("vless://", "vmess://", "ss://")):
                unique_links.add(s)
                
    return list(unique_links)


def parse_vless(link: str):
    u = urlparse(link)
    if not u.hostname or not u.port or not u.username:
        raise ValueError("bad vless link")

    q = parse_qs(u.query)
    getq = lambda k, d="": (q.get(k, [d])[0] or d)

    security = getq("security", "none")
    network = getq("type", "tcp")
    flow = getq("flow", "")
    sni = getq("sni", "")
    pbk = getq("pbk", "")
    sid = getq("sid", "")
    fp = getq("fp", "")
    alpn_raw = getq("alpn", "")
    service_name = getq("serviceName", "")
    host = getq("host", "")
    path = unquote(getq("path", ""))

    if network == "raw":
        network = "tcp"

    ob = {
        "type": "vless",
        "tag": "proxy",
        "server": u.hostname,
        "server_port": int(u.port),
        "uuid": u.username
    }

    if flow:
        ob["flow"] = flow

    if network == "ws":
        ob["transport"] = {"type": "ws"}
        if path:
            ob["transport"]["path"] = path
        if host:
            ob["transport"]["headers"] = {"Host": host}
    elif network == "grpc":
        ob["transport"] = {"type": "grpc"}
        if service_name:
            ob["transport"]["service_name"] = service_name

    if security == "reality":
        ob["tls"] = {
            "enabled": True,
            "server_name": sni or u.hostname,
            "reality": {"enabled": True, "public_key": pbk}
        }
        if sid:
            ob["tls"]["reality"]["short_id"] = sid
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        if alpn_raw:
            ob["tls"]["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]
    elif security == "tls":
        ob["tls"] = {"enabled": True, "server_name": sni or u.hostname}
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        if alpn_raw:
            ob["tls"]["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]

    return ob


def parse_ss(link: str):
    raw = link[5:].split("#", 1)[0]
    method = password = host = None
    port = None

    if "@" in raw:
        left, right = raw.rsplit("@", 1)
        if ":" in left:
            cred = left
        else:
            cred = b64_decode_loose(left).decode("utf-8", errors="ignore")
        if ":" not in cred:
            raise ValueError("bad ss credential")
        method, password = cred.split(":", 1)
        host, p = right.rsplit(":", 1)
        port = int(p)
    else:
        decoded = b64_decode_loose(raw).decode("utf-8", errors="ignore")
        cred, hp = decoded.split("@", 1)
        method, password = cred.split(":", 1)
        host, p = hp.rsplit(":", 1)
        port = int(p)

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": host.strip("[]"),
        "server_port": port,
        "method": method,
        "password": password
    }


def parse_vmess(link: str):
    b64 = link[8:]
    data = b64_decode_loose(b64).decode("utf-8", errors="ignore")
    j = json.loads(data)

    host = j.get("add")
    port = int(j.get("port"))
    uuid = j.get("id")
    aid = int(j.get("aid", 0))
    net = j.get("net", "tcp")
    path = j.get("path", "")
    vm_host = j.get("host", "")
    tls = str(j.get("tls", ""))
    sni = j.get("sni", "")
    alpn = j.get("alpn", "")
    fp = j.get("fp", "")

    if not host or not port or not uuid:
        raise ValueError("bad vmess fields")

    ob = {
        "type": "vmess",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "alter_id": aid,
        "security": "auto"
    }

    if net == "ws":
        ob["transport"] = {"type": "ws"}
        if path:
            ob["transport"]["path"] = path
        if vm_host:
            ob["transport"]["headers"] = {"Host": vm_host}
    elif net == "grpc":
        ob["transport"] = {"type": "grpc"}
        if path:
            ob["transport"]["service_name"] = path

    if tls.lower() in ("tls", "1", "true"):
        ob["tls"] = {"enabled": True, "server_name": sni or host}
        if alpn:
            ob["tls"]["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}

    return ob


def outbound_from_link(link: str):
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("vmess://"):
        return parse_vmess(link)
    raise ValueError("unsupported scheme")


def build_config(link: str, socks_port: int):
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": LOCAL_SOCKS_HOST,
            "listen_port": socks_port
        }],
        "outbounds": [
            outbound_from_link(link),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {"final": "proxy"}
    }


def wait_socks_open(host: str, port: int, timeout: float):
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.35):
                return True
        except Exception:
            time.sleep(0.07)
    return False


def socks5_connect_and_measure(proxy_host, proxy_port, target_host, target_port, timeout=3.0):
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((proxy_host, proxy_port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2)[:1] != b"\x05":
            return None

        ip = socket.gethostbyname(target_host)
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + target_port.to_bytes(2, "big"))
        head = s.recv(4)
        if len(head) < 4 or head[1] != 0x00:
            return None

        atyp = head[3]
        if atyp == 0x01:
            _ = s.recv(6)
        elif atyp == 0x03:
            ln = s.recv(1)
            if not ln:
                return None
            _ = s.recv(ln[0] + 2)
        elif atyp == 0x04:
            _ = s.recv(18)
        else:
            return None

        return int((time.perf_counter() - t0) * 1000)
    except Exception:
        return None
    finally:
        s.close()


def test_one(index, total, link):
    socks_port = random.randint(20000, 60000)
    proc = None
    cfg_path = None
    try:
        cfg = build_config(link, socks_port)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            cfg_path = f.name
            json.dump(cfg, f, ensure_ascii=False)

        proc = subprocess.Popen(
            [SINGBOX_BIN, "run", "-c", cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if not wait_socks_open(LOCAL_SOCKS_HOST, socks_port, SINGBOX_START_TIMEOUT):
            err = ""
            try:
                err = proc.stderr.read(300).strip()
            except Exception:
                pass
            return (index, False, None, f"sing-box not started: {err}", link)

        delay = socks5_connect_and_measure(
            LOCAL_SOCKS_HOST, socks_port, TG_TEST_HOST, TG_TEST_PORT, CONNECT_TIMEOUT
        )
        if delay is None:
            return (index, False, None, "connect failed", link)
        if delay <= MAX_DELAY_MS:
            return (index, True, delay, "ok", link)
        return (index, False, delay, "too slow", link)

    except Exception as e:
        return (index, False, None, f"error: {e}", link)
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfg_path:
            try:
                os.remove(cfg_path)
            except Exception:
                pass


def main():
    Path(ERROR_LOG).write_text("", encoding="utf-8")
    if shutil.which("sing-box") is None:
        print("[-] sing-box не найден в PATH")
        return

    all_links = read_all_links(INPUT_DIR)
    total_found = len(all_links)
    if total_found == 0:
        print("[-] Ссылки не найдены")
        Path(OUTPUT_FILE).write_text("", encoding="utf-8")
        return

    print(f"[+] Всего найдено уникальных ссылок: {total_found}")

    # Запрос количества ссылок у пользователя
    while True:
        try:
            user_input = input(f"[?] Сколько ссылок проверить? (1-{total_found}, Enter = все): ").strip()
            if not user_input:
                count_to_check = total_found
                break
            count_to_check = int(user_input)
            if 1 <= count_to_check <= total_found:
                break
            print(f"[-] Пожалуйста, введите число от 1 до {total_found}.")
        except ValueError:
            print("[-] Ошибка: введите корректное число.")

    # Ограничиваем массив ссылок выбранным количеством
    links = all_links[:count_to_check]
    total = len(links)

    print(f"\n[*] Начинаю проверку {total} ссылок...")
    print(f"[*] Параллельных проверок: {WORKERS}")

    ok_results = []
    done = 0
    start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = [ex.submit(test_one, i + 1, total, link) for i, link in enumerate(links)]
            for f in as_completed(futures):
                idx, ok, delay, reason, link = f.result()
                done += 1

                with print_lock:
                    if ok:
                        ok_results.append((delay, link))
                        print(f"[{done}/{total}] #{idx} OK {delay} ms")
                    else:
                        if delay is None:
                            print(f"[{done}/{total}] #{idx} FAIL {reason}")
                        else:
                            print(f"[{done}/{total}] #{idx} FAIL {delay} ms ({reason})")

                if not ok:
                    with log_lock:
                        with open(ERROR_LOG, "a", encoding="utf-8") as log:
                            log.write(f"\n[# {idx}] {link}\n{reason}\n")

    except KeyboardInterrupt:
        print("\n[!] Остановлено пользователем, сохраняю что успели...")

    # Сортировка по задержке (пинг)
    ok_results.sort(key=lambda x: x[0])
    sorted_links = [item[1] for item in ok_results]

    Path(OUTPUT_FILE).write_text("\n".join(sorted_links) + ("\n" if sorted_links else ""), encoding="utf-8")
    elapsed = int(time.time() - start)

    print(f"\n[+] Готово за {elapsed} сек")
    print(f"[+] Рабочих <= {MAX_DELAY_MS} ms: {len(sorted_links)}")
    print(f"[+] Ссылки отсортированы по пингу в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
