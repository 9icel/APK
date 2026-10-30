"""
CF WS Scanner - Flet UI for ddtest.py

Install:   pip install "flet==0.28.3"
Run:       python cf_scanner_app.py          (desktop window)
           flet run --web cf_scanner_app.py  (open in phone browser)
Build APK: flet build apk                    (needs Flutter SDK, do it on a PC)
"""

import base64
import csv
import ipaddress
import os
import random
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import flet as ft

# =========================
# DEFAULTS (taken from ddtest.py)
# =========================

DEFAULT_DOMAIN = "plain-hill-f7jjjb.soleri1440-296.workers.dev"
DEFAULT_PATH = "/eyJqdW5rIjoiTDV2amRYZ2FjQiIsInByb3RvY29sIjoidmwiLCJtb2RlIjoicHJveHlpcCIsInBhbmVsSVBzIjpbXX0=?ed=2560"
DEFAULT_PORT = "443"
RANGES_FILE = "ranges.txt"
TOP_N = 20

# =========================
# PALETTE
# =========================

BG = "#0C1220"
SURFACE = "#141B2D"
SURFACE_HI = "#1B2540"
LINE = "#26324F"
TEXT = "#E6ECF8"
MUTED = "#8A97B2"
GOOD = "#3DD6C6"
WARN = "#F5B83D"
BAD = "#F2686B"
ACCENT = "#F6821F"


# =========================
# SCANNER CORE
# =========================

def generate_ips(ranges, limit):
    ips = []
    for cidr in ranges:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        ips.extend(str(ip) for ip in net.hosts())
    random.shuffle(ips)
    if limit and limit > 0:
        ips = ips[:limit]
    return ips


def make_ws_key():
    return base64.b64encode(os.urandom(16)).decode()


def build_ws_upgrade(host, path, key):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    )


def recv_until(sock, marker, max_bytes=4096, timeout=3):
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > max_bytes:
            break
    return data


def ws_send_ping(sock, payload=b"ping"):
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    sock.send(bytes([0x89, 0x80 | len(payload)]) + mask + masked)


def ws_recv_pong(sock, timeout=2):
    try:
        sock.settimeout(timeout)
        data = sock.recv(32)
        return bool(data) and (data[0] & 0x0F) == 0xA
    except Exception:
        return False


def test_ip(ip, cfg, stop):
    if stop.is_set():
        return None
    ssock = None
    try:
        start = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.create_connection((ip, cfg["port"]), timeout=cfg["timeout"])
        sock.settimeout(cfg["timeout"])
        ssock = ctx.wrap_socket(sock, server_hostname=cfg["domain"])
        tls_time = (time.time() - start) * 1000

        ssock.send(build_ws_upgrade(cfg["domain"], cfg["path"], make_ws_key()).encode())
        response = recv_until(ssock, b"\r\n\r\n", timeout=cfg["timeout"])
        decoded = response.decode(errors="ignore")

        base = {
            "ip": ip,
            "tls_latency": round(tls_time, 2),
            "avg_rtt": None,
            "min_rtt": None,
            "max_rtt": None,
            "loss": 100.0,
        }

        if "101" not in decoded:
            status_line = decoded.split("\r\n")[0] if decoded else "no response"
            return {**base, "status": "WS_FAIL", "detail": status_line[:60]}

        rtts, sent, received = [], 0, 0
        for _ in range(cfg["pings"]):
            if stop.is_set():
                break
            try:
                t = time.time()
                ws_send_ping(ssock)
                sent += 1
                if ws_recv_pong(ssock, timeout=2):
                    rtts.append((time.time() - t) * 1000)
                    received += 1
                time.sleep(0.1)
            except Exception:
                break

        loss = round((1 - received / sent) * 100, 1) if sent else 100.0

        if received == 0:
            return {**base, "status": "OK_NOPONG", "detail": "WS OK, no pong replies", "loss": loss}

        mn, mx = min(rtts), max(rtts)
        return {
            **base,
            "status": "OK",
            "detail": f"jitter {round(mx - mn, 1)}ms",
            "avg_rtt": round(sum(rtts) / len(rtts), 2),
            "min_rtt": round(mn, 2),
            "max_rtt": round(mx, 2),
            "loss": loss,
        }
    except Exception:
        return None
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except Exception:
                pass


def score(r):
    if r["avg_rtt"] is None:
        return 99999
    return r["avg_rtt"] + r["loss"] * 10


def rank(results):
    ok = sorted((r for r in results if r["status"] == "OK"), key=score)
    nopong = sorted((r for r in results if r["status"] == "OK_NOPONG"), key=lambda x: x["tls_latency"])
    fail = [r for r in results if r["status"] == "WS_FAIL"]
    return (ok + nopong + fail)[:TOP_N]


def storage_dir():
    return os.environ.get("FLET_APP_STORAGE_DATA") or os.getcwd()


# =========================
# UI
# =========================

def main(page: ft.Page):
    page.title = "CF WS Scanner"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(color_scheme_seed=ACCENT, use_material3=True)
    page.bgcolor = BG
    page.padding = 0

    state = {"running": False, "stop": threading.Event(), "results": []}

    # ---------- inputs ----------

    def field(label, value="", **kw):
        return ft.TextField(
            label=label,
            value=value,
            border_radius=12,
            filled=True,
            bgcolor=SURFACE_HI,
            border_color=LINE,
            focused_border_color=ACCENT,
            text_size=14,
            **kw,
        )

    domain = field("دامنه ورکر (SNI و Host)", DEFAULT_DOMAIN)
    path = field("مسیر WebSocket", DEFAULT_PATH, multiline=True, min_lines=1, max_lines=3)
    port = field("پورت", DEFAULT_PORT, keyboard_type=ft.KeyboardType.NUMBER, width=110)
    max_ips = field("حداکثر IP برای اسکن (۰ = همه)", "3000", keyboard_type=ft.KeyboardType.NUMBER, expand=True)

    initial_ranges = ""
    if os.path.exists(RANGES_FILE):
        try:
            with open(RANGES_FILE) as f:
                initial_ranges = f.read().strip()
        except OSError:
            pass
    ranges = field(
        "رنج‌ها (هر خط یک CIDR)",
        initial_ranges,
        multiline=True,
        min_lines=4,
        max_lines=8,
        hint_text="104.16.0.0/20",
    )

    def slider_row(label, lo, hi, val, suffix=""):
        value_text = ft.Text(f"{val}{suffix}", color=ACCENT, weight=ft.FontWeight.W_600)
        sl = ft.Slider(min=lo, max=hi, divisions=hi - lo, value=val, active_color=ACCENT)

        def on_change(e):
            value_text.value = f"{int(sl.value)}{suffix}"
            value_text.update()

        sl.on_change = on_change
        row = ft.Column(
            [
                ft.Row(
                    [ft.Text(label, size=13, color=MUTED), value_text],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                sl,
            ],
            spacing=0,
        )
        return sl, row

    threads_sl, threads_row = slider_row("تعداد thread", 5, 100, 30)
    timeout_sl, timeout_row = slider_row("Timeout", 1, 10, 3, " s")
    pings_sl, pings_row = slider_row("تعداد ping برای هر IP", 1, 10, 5)

    # ---------- status widgets ----------

    progress = ft.ProgressBar(value=0, color=ACCENT, bgcolor=SURFACE_HI, height=6, border_radius=3)
    scanned_txt = ft.Text("0 / 0", size=22, weight=ft.FontWeight.W_700, color=TEXT)
    ok_txt = ft.Text("0", size=22, weight=ft.FontWeight.W_700, color=GOOD)
    best_txt = ft.Text("-", size=22, weight=ft.FontWeight.W_700, color=TEXT)
    status_txt = ft.Text("آماده", size=12, color=MUTED)

    def stat(label, value_ctrl):
        return ft.Container(
            content=ft.Column([value_ctrl, ft.Text(label, size=12, color=MUTED)], spacing=2),
            bgcolor=SURFACE,
            border_radius=14,
            padding=14,
            expand=True,
        )

    results_col = ft.Column(spacing=10)

    # ---------- results ----------

    def copy_text(text, msg="کپی شد"):
        try:
            page.set_clipboard(text)
        except Exception:
            try:
                page.run_task(ft.Clipboard().set, text)
            except Exception:
                msg = "کپی در این نسخه از Flet پشتیبانی نمی‌شود"
        status_txt.value = msg
        status_txt.update()

    def result_card(r, idx, best_rtt, worst_rtt):
        if r["status"] == "OK":
            color = GOOD
            sub = f"TLS {r['tls_latency']}ms   Loss {r['loss']}%   {r['detail']}"
            main_val = f"{r['avg_rtt']}"
            frac = 1.0 if worst_rtt == best_rtt else 1 - (r["avg_rtt"] - best_rtt) / (worst_rtt - best_rtt + 1) * 0.75
        elif r["status"] == "OK_NOPONG":
            color = WARN
            sub = f"TLS {r['tls_latency']}ms   WS برقرار شد ولی pong نیامد"
            main_val = "-"
            frac = 0.15
        else:
            color = BAD
            sub = r["detail"]
            main_val = "-"
            frac = 0.05

        return ft.Container(
            bgcolor=SURFACE,
            border_radius=14,
            padding=14,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text(r["ip"], size=16, weight=ft.FontWeight.W_600, color=TEXT, selectable=True),
                                    ft.Text(sub, size=12, color=MUTED),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                            ft.Text(main_val, size=22, weight=ft.FontWeight.W_700, color=color),
                            ft.Text("ms" if main_val != "-" else "", size=12, color=MUTED),
                            ft.IconButton(
                                icon=ft.Icons.CONTENT_COPY,
                                icon_size=18,
                                icon_color=MUTED,
                                tooltip="کپی IP",
                                on_click=lambda e, ip=r["ip"]: copy_text(ip, f"{ip} کپی شد"),
                            ),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    ft.ProgressBar(value=max(frac, 0.04), color=color, bgcolor=SURFACE_HI, height=4, border_radius=2),
                ],
                spacing=10,
            ),
        )

    def refresh(total, scanned):
        ranked = rank(state["results"])
        oks = [r for r in ranked if r["status"] == "OK"]
        best_rtt = oks[0]["avg_rtt"] if oks else 0
        worst_rtt = oks[-1]["avg_rtt"] if oks else 0
        results_col.controls = [
            result_card(r, i, best_rtt, worst_rtt) for i, r in enumerate(ranked)
        ]
        all_ok = sum(1 for r in state["results"] if r["status"] == "OK")
        scanned_txt.value = f"{scanned} / {total}"
        ok_txt.value = str(all_ok)
        best_txt.value = f"{oks[0]['avg_rtt']}ms" if oks else "-"
        progress.value = scanned / total if total else 0
        page.update()

    # ---------- scan ----------

    def set_running(running):
        state["running"] = running
        action_btn.text = "توقف" if running else "شروع اسکن"
        action_btn.icon = ft.Icons.STOP_ROUNDED if running else ft.Icons.PLAY_ARROW_ROUNDED
        action_btn.style = ft.ButtonStyle(
            bgcolor=BAD if running else ACCENT,
            color="#101010" if not running else "#FFFFFF",
            shape=ft.RoundedRectangleBorder(radius=14),
        )
        page.update()

    def scan_worker(cfg, ips):
        total = len(ips)
        scanned = 0
        last_ui = 0.0
        ex = ThreadPoolExecutor(max_workers=cfg["threads"])
        futures = [ex.submit(test_ip, ip, cfg, state["stop"]) for ip in ips]
        try:
            for f in as_completed(futures):
                if state["stop"].is_set():
                    break
                scanned += 1
                res = f.result()
                if res:
                    state["results"].append(res)
                now = time.time()
                if now - last_ui > 0.4:
                    last_ui = now
                    refresh(total, scanned)
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

        stopped = state["stop"].is_set()
        refresh(total, scanned)
        found = sum(1 for r in state["results"] if r["status"] == "OK")
        status_txt.value = (
            f"متوقف شد، {found} IP سالم پیدا شد" if stopped
            else (f"اسکن تمام شد، {found} IP سالم پیدا شد" if found else "اسکن تمام شد، IP سالمی پیدا نشد")
        )
        set_running(False)

    def on_action(e):
        if state["running"]:
            state["stop"].set()
            status_txt.value = "در حال توقف..."
            status_txt.update()
            return

        try:
            cfg = {
                "domain": domain.value.strip(),
                "path": path.value.strip() or "/",
                "port": int(port.value or 443),
                "threads": int(threads_sl.value),
                "timeout": int(timeout_sl.value),
                "pings": int(pings_sl.value),
            }
            limit = int(max_ips.value or 0)
        except ValueError:
            status_txt.value = "پورت و حداکثر IP باید عدد باشند"
            status_txt.update()
            return

        if not cfg["domain"]:
            status_txt.value = "دامنه ورکر را وارد کنید"
            status_txt.update()
            return

        lines = [l for l in ranges.value.splitlines() if l.strip()]
        ips = generate_ips(lines, limit)
        if not ips:
            status_txt.value = "رنج معتبری وارد نشده است"
            status_txt.update()
            return

        state["stop"] = threading.Event()
        state["results"] = []
        results_col.controls = []
        status_txt.value = f"در حال اسکن {len(ips)} IP"
        set_running(True)
        refresh(len(ips), 0)
        threading.Thread(target=scan_worker, args=(cfg, ips), daemon=True).start()

    def on_copy_all(e):
        ranked = [r for r in rank(state["results"]) if r["status"] == "OK"]
        if not ranked:
            status_txt.value = "هنوز IP سالمی برای کپی وجود ندارد"
            status_txt.update()
            return
        copy_text("\n".join(r["ip"] for r in ranked), f"{len(ranked)} IP کپی شد")

    def on_save(e):
        ranked = rank(state["results"])
        if not ranked:
            status_txt.value = "نتیجه‌ای برای ذخیره نیست"
            status_txt.update()
            return
        out = os.path.join(storage_dir(), "result.csv")
        try:
            with open(out, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["IP", "Status", "TLS(ms)", "Avg_RTT(ms)", "Min_RTT(ms)", "Max_RTT(ms)", "Loss%", "Detail"])
                for r in ranked:
                    w.writerow([
                        r["ip"], r["status"], r["tls_latency"],
                        r["avg_rtt"] if r["avg_rtt"] is not None else "-",
                        r["min_rtt"] if r["min_rtt"] is not None else "-",
                        r["max_rtt"] if r["max_rtt"] is not None else "-",
                        r["loss"], r["detail"],
                    ])
            status_txt.value = f"ذخیره شد: {out}"
        except OSError as ex:
            status_txt.value = f"ذخیره نشد: {ex}"
        status_txt.update()

    action_btn = ft.FilledButton(
        "شروع اسکن",
        icon=ft.Icons.PLAY_ARROW_ROUNDED,
        on_click=on_action,
        height=52,
        expand=True,
        style=ft.ButtonStyle(
            bgcolor=ACCENT,
            color="#101010",
            shape=ft.RoundedRectangleBorder(radius=14),
        ),
    )

    # ---------- layout ----------

    def section(title, *controls):
        return ft.Container(
            bgcolor=SURFACE,
            border_radius=16,
            padding=16,
            content=ft.Column(
                [ft.Text(title, size=15, weight=ft.FontWeight.W_600, color=TEXT), *controls],
                spacing=12,
            ),
        )

    config_section = section(
        "ورکر",
        domain,
        ft.Row([path], vertical_alignment=ft.CrossAxisAlignment.START),
        ft.Row([port, max_ips], spacing=10),
    )

    ranges_section = section("رنج‌ها", ranges)

    tuning_section = section("تنظیمات اسکن", threads_row, timeout_row, pings_row)

    results_header = ft.Row(
        [
            ft.Text("بهترین IPها", size=18, weight=ft.FontWeight.W_700, color=TEXT, expand=True),
            ft.IconButton(icon=ft.Icons.COPY_ALL, icon_color=MUTED, tooltip="کپی همه IPهای سالم", on_click=on_copy_all),
            ft.IconButton(icon=ft.Icons.SAVE_ALT, icon_color=MUTED, tooltip="ذخیره result.csv", on_click=on_save),
        ],
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )

    body = ft.Column(
        [
            ft.Container(
                padding=ft.padding.only(top=8, bottom=4),
                content=ft.Column(
                    [
                        ft.Text("CF WS Scanner", size=28, weight=ft.FontWeight.W_800, color=TEXT),
                        ft.Text("پیدا کردن IP تمیز کلودفلر برای ورکر شما", size=13, color=MUTED),
                    ],
                    spacing=2,
                ),
            ),
            config_section,
            ranges_section,
            tuning_section,
            ft.Row([action_btn]),
            progress,
            ft.Row([stat("اسکن‌شده", scanned_txt), stat("IP سالم", ok_txt), stat("بهترین RTT", best_txt)], spacing=10),
            status_txt,
            results_header,
            results_col,
            ft.Container(height=24),
        ],
        spacing=14,
        scroll=ft.ScrollMode.AUTO,
        expand=True,
    )

    page.add(ft.SafeArea(ft.Container(content=body, padding=16, expand=True), expand=True))


if __name__ == "__main__":
    ft.app(target=main)
