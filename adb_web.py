#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ADB Web Console - 局域网可视化 ADB 工具后端

架构：手机浏览器 <--HTTP/JSON--> 本机 Python 服务 <--adb.exe--> 机顶盒
浏览器无法直接说 ADB 二进制协议，所以必须有一个中间层跑在电脑上。

启动：
    python adb_web.py
    python adb_web.py --port 8765 --token mytoken
启动后控制台会打印手机可访问的完整地址（含 token）。
仅用于管理自己局域网内的自有设备。
"""

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

FALLBACK_ADB = r"C:\Users\Administrator\.workbuddy-ai\tools\adb\platform-tools\adb.exe"


def resolve_adb(explicit=None):
    """按顺序定位 adb：命令行 > ADB_PATH > PATH > ANDROID_HOME > 本机默认路径。"""
    home = os.environ.get("ANDROID_HOME", "")
    candidates = [
        explicit,
        os.environ.get("ADB_PATH"),
        shutil.which("adb"),
        os.path.join(home, "platform-tools", "adb.exe"),
        os.path.join(home, "platform-tools", "adb"),
        FALLBACK_ADB,
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return FALLBACK_ADB


ADB = resolve_adb()
BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD = os.path.join(BASE, "uploads")
HTML_FILE = os.path.join(BASE, "index.html")
MAX_BODY = 300 * 1024 * 1024

TOKEN = ""
STATE = {"target": None}
CAP = {"proc": None, "remote": "/sdcard/adbweb_capture.pcap", "local": None, "started": 0}

DANGEROUS = [
    "rm -rf /", "rm -fr /", "mkfs", "dd if=", "format /", "wipe data",
    "reboot bootloader", ":(){", "> /dev/", "erase_image", "fastboot",
]
PROP_KEYS = [
    "ro.product.model", "ro.product.brand", "ro.product.name", "ro.product.device",
    "ro.build.version.release", "ro.build.version.sdk", "ro.build.display.id",
    "ro.serialno", "ro.hardware", "ro.board.platform", "ro.product.cpu.abi",
    "service.adb.tcp.port", "persist.adb.tcp.port", "ro.bootloader",
]


def adb(args, timeout=30, use_target=True, raw=False):
    """执行一次 adb 命令。args 为参数列表，不做 shell 拼接。"""
    cmd = [ADB]
    if use_target and STATE["target"]:
        cmd += ["-s", STATE["target"]]
    cmd += list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "命令超时 (%ds)" % timeout, "returncode": -1}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e), "returncode": -1}
    if raw:
        return {"ok": r.returncode == 0, "bytes": r.stdout,
                "stderr": r.stderr.decode("utf-8", "replace").strip(), "returncode": r.returncode}
    dec = lambda b: b.decode("utf-8", "replace").replace("\r\n", "\n").strip()
    return {"ok": r.returncode == 0, "stdout": dec(r.stdout),
            "stderr": dec(r.stderr), "returncode": r.returncode}


def safe_local_name(name):
    name = os.path.basename(str(name).replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name or "upload.bin"


def safe_remote_path(path):
    """去掉命令注入字符，仅允许 Android 常见路径字符。"""
    path = str(path or "/sdcard").strip()
    if any(c in path for c in [";", "|", "&", "`", "$", "\n", "\r", ">", "<"]):
        raise ValueError("路径含非法字符")
    if ".." in path:
        raise ValueError("路径不能包含 ..")
    return path


def parse_multipart(body, content_type):
    """Python 3.13 已移除 cgi，这里做最小可用的 multipart 解析。"""
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        raise ValueError("缺少 multipart boundary")
    boundary = m.group(1).strip('"').encode()
    out = {}
    for part in body.split(b"--" + boundary):
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        if data.endswith(b"\r\n"):
            data = data[:-2]
        nm = re.search(rb'name="([^"]+)"', head)
        if not nm:
            continue
        key = nm.group(1).decode("utf-8", "replace")
        fm = re.search(rb'filename="([^"]*)"', head)
        if fm:
            out[key] = {"filename": fm.group(1).decode("utf-8", "replace"), "data": data}
        else:
            out[key] = data.decode("utf-8", "replace").strip()
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "ADBWeb/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, obj)

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _authed(self):
        q = self._query()
        t = q.get("token", [None])[0] or self.headers.get("X-Token")
        return t == TOKEN

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > MAX_BODY:
            raise ValueError("上传内容过大（上限 300MB）")
        return self.rfile.read(n) if n else b""

    def _json_body(self):
        b = self._body()
        return json.loads(b.decode("utf-8")) if b else {}

    def need_device(self):
        if not STATE["target"]:
            self._json({"ok": False, "error": "尚未连接设备，请先在顶部连接"}, 400)
            return False
        return True

    # ---------------- GET ----------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(HTML_FILE, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(404, "index.html 不存在", "text/plain; charset=utf-8")
            return
        if path == "/api/ping":
            self._json({"ok": True, "adb_exists": os.path.isfile(ADB),
                        "device": STATE["target"], "token_required": True})
            return
        if not self._authed():
            self._json({"ok": False, "error": "访问口令不对，请用控制台打印的完整地址打开"}, 401)
            return
        q = self._query()
        one = lambda k, d=None: (q.get(k, [d])[0] if q.get(k) else d)
        try:
            if path == "/api/devices":
                r = adb(["devices", "-l"], use_target=False)
                self._json({"ok": True, "raw": r["stdout"] or r["stderr"], "device": STATE["target"]})
            elif path == "/api/info":
                if not self.need_device():
                    return
                r = adb(["shell", "getprop"])
                props = {}
                for line in r["stdout"].splitlines():
                    m = re.match(r"\[([^\]]+)\]:\s*\[(.*)\]", line)
                    if m:
                        props[m.group(1)] = m.group(2)
                uid = adb(["shell", "id"])["stdout"]
                self._json({"ok": True,
                            "summary": {k: props.get(k, "-") for k in PROP_KEYS},
                            "root": "uid=0" in uid, "uid": uid, "props": props})
            elif path == "/api/apps":
                if not self.need_device():
                    return
                scope = one("scope", "thirdparty")
                flag = {"thirdparty": ["-3"], "system": ["-s"], "all": []}.get(scope, ["-3"])
                r = adb(["shell", "pm", "list", "packages", "-f"] + flag)
                apps = []
                for line in r["stdout"].splitlines():
                    m = re.match(r"package:(.*?)=([^\s]+)", line)
                    if m:
                        apps.append({"path": m.group(1), "package": m.group(2)})
                kw = (one("q", "") or "").lower()
                if kw:
                    apps = [a for a in apps if kw in a["package"].lower()]
                apps.sort(key=lambda a: a["package"])
                self._json({"ok": True, "apps": apps, "count": len(apps), "raw": r["stderr"]})
            elif path == "/api/app/detail":
                if not self.need_device():
                    return
                pkg = re.sub(r"[^A-Za-z0-9._]", "", one("pkg", ""))
                r = adb(["shell", "dumpsys", "package", pkg])
                keys = ("versionName", "versionCode", "firstInstallTime", "lastUpdateTime", "codePath")
                detail = {}
                for line in r["stdout"].splitlines():
                    for k in keys:
                        if k + "=" in line and k not in detail:
                            detail[k] = line.split(k + "=", 1)[1].strip()
                self._json({"ok": True, "package": pkg, "detail": detail})
            elif path == "/api/files":
                if not self.need_device():
                    return
                p = safe_remote_path(one("path", "/sdcard"))
                r = adb(["shell", "ls", "-la", p])
                items = []
                for line in r["stdout"].splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    name = parts[-1]
                    if name in (".", ".."):
                        continue
                    items.append({"name": name, "dir": line.startswith("d"),
                                  "link": line.startswith("l"), "raw": line})
                self._json({"ok": True, "path": p, "items": items,
                            "raw": r["stdout"], "error": r["stderr"]})
            elif path == "/api/files/download":
                if not self.need_device():
                    return
                remote = safe_remote_path(one("path", ""))
                local = os.path.join(UPLOAD, "pull_" + safe_local_name(os.path.basename(remote)))
                r = adb(["pull", remote, local], timeout=180)
                if not os.path.isfile(local):
                    self._json({"ok": False, "error": "pull 失败：" + (r["stdout"] or r["stderr"])}, 500)
                    return
                with open(local, "rb") as f:
                    data = f.read()
                self._send(200, data, "application/octet-stream",
                           {"Content-Disposition": 'attachment; filename="%s"' % safe_local_name(os.path.basename(remote))})
            elif path == "/api/logcat":
                if not self.need_device():
                    return
                lines = min(max(int(one("lines", "200") or 200), 10), 5000)
                buf = one("buffer", "main") or "main"
                r = adb(["logcat", "-d", "-t", str(lines), "-b", buf], timeout=45)
                text = r["stdout"] or r["stderr"]
                kw = (one("q", "") or "").strip()
                if kw:
                    text = "\n".join(l for l in text.splitlines() if kw.lower() in l.lower())
                self._json({"ok": True, "lines": len(text.splitlines()), "text": text})
            elif path == "/api/screenshot":
                if not self.need_device():
                    return
                r = adb(["exec-out", "screencap", "-p"], timeout=45, raw=True)
                data = r.get("bytes", b"")
                if not data.startswith(b"\x89PNG") or not r["ok"]:
                    self._json({"ok": False, "error": "截图失败：" + r.get("stderr", "")}, 500)
                    return
                self._send(200, data, "image/png")
            elif path == "/api/capture/status":
                if not self.need_device():
                    return
                chk = adb(["shell", "ls /system/bin/tcpdump /system/xbin/tcpdump 2>/dev/null"])
                alive = CAP["proc"] is not None and CAP["proc"].poll() is None
                self._json({"ok": True, "tcpdump": bool(chk["stdout"].strip()),
                            "running": alive, "started": CAP["started"],
                            "pcap_ready": bool(CAP["local"] and os.path.isfile(CAP["local"]))})
            elif path == "/api/capture/download":
                if not (CAP["local"] and os.path.isfile(CAP["local"])):
                    self._json({"ok": False, "error": "还没有抓包文件，请先停止抓包"}, 404)
                    return
                with open(CAP["local"], "rb") as f:
                    data = f.read()
                self._send(200, data, "application/vnd.tcpdump.pcap",
                           {"Content-Disposition": 'attachment; filename="adbweb_capture.pcap"'})
            else:
                self._json({"ok": False, "error": "未知接口 " + path}, 404)
        except ValueError as e:
            self._json({"ok": False, "error": str(e)}, 400)
        except Exception as e:
            self._json({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}, 500)

    # ---------------- POST ----------------
    def do_POST(self):
        path = urlparse(self.path).path
        if not self._authed():
            self._json({"ok": False, "error": "访问口令不对"}, 401)
            return
        try:
            if path.startswith("/api/upload") or path in ("/api/apps/install", "/api/files/upload"):
                return self.handle_upload(path)
            data = self._json_body()
            if path == "/api/connect":
                host = str(data.get("host", "")).strip()
                if not host:
                    self._json({"ok": False, "error": "请填盒子 IP"}, 400)
                    return
                port = str(data.get("port", "5555")).strip()
                targets = ([host] if ":" in host else
                           ["%s:%s" % (host, p) for p in (["5555", "60001", "5556"] if port == "auto" else [port])])
                tried = []
                for t in targets:
                    conn = adb(["connect", t], timeout=15, use_target=False)
                    st = adb(["-s", t, "get-state"], timeout=10, use_target=False)
                    state = (st["stdout"] or st["stderr"]).strip().splitlines()
                    state = state[-1] if state else "unknown"
                    tried.append({"target": t, "connect": conn["stdout"] or conn["stderr"], "state": state})
                    if state == "device":
                        STATE["target"] = t
                        self._json({"ok": True, "target": t, "state": state, "tried": tried})
                        return
                self._json({"ok": False, "error": "未能建立设备连接", "tried": tried,
                            "hint": "确认盒子已开 ADB；若显示 unauthorized，需在电视上点『允许 USB 调试』"}, 400)
            elif path == "/api/disconnect":
                if STATE["target"]:
                    adb(["disconnect", STATE["target"]], use_target=False)
                STATE["target"] = None
                self._json({"ok": True})
            elif path == "/api/apps/uninstall":
                if not self.need_device():
                    return
                pkg = re.sub(r"[^A-Za-z0-9._]", "", str(data.get("package", "")))
                if not pkg:
                    self._json({"ok": False, "error": "缺少包名"}, 400)
                    return
                r = adb(["uninstall", pkg], timeout=90)
                self._json({"ok": "Success" in r["stdout"], "raw": r["stdout"] or r["stderr"]})
            elif path == "/api/apps/start":
                if not self.need_device():
                    return
                pkg = re.sub(r"[^A-Za-z0-9._]", "", str(data.get("package", "")))
                r = adb(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"], timeout=45)
                self._json({"ok": r["ok"], "raw": r["stdout"] or r["stderr"]})
            elif path == "/api/shell":
                if not self.need_device():
                    return
                cmd = str(data.get("cmd", "")).strip()
                if not cmd:
                    self._json({"ok": False, "error": "命令为空"}, 400)
                    return
                if len(cmd) > 2000:
                    self._json({"ok": False, "error": "命令过长"}, 400)
                    return
                low = cmd.lower()
                for bad in DANGEROUS:
                    if bad in low:
                        self._json({"ok": False, "error": "已拦截高危命令（%s），请确认后再手动执行" % bad}, 400)
                        return
                timeout = min(max(int(data.get("timeout", 30)), 5), 180)
                r = adb(["shell", cmd], timeout=timeout)
                self._json({"ok": r["ok"], "stdout": r["stdout"], "stderr": r["stderr"],
                            "returncode": r["returncode"]})
            elif path == "/api/capture/start":
                if not self.need_device():
                    return
                if CAP["proc"] and CAP["proc"].poll() is None:
                    self._json({"ok": False, "error": "抓包已在进行中"}, 400)
                    return
                chk = adb(["shell", "ls /system/bin/tcpdump /system/xbin/tcpdump 2>/dev/null"])
                if not chk["stdout"].strip():
                    self._json({"ok": False,
                                "error": "设备上没有 tcpdump（需要 root 且内置该工具）。请改用『日志』页抓 logcat。",
                                "fallback": True}, 400)
                    return
                iface = re.sub(r"[^A-Za-z0-9]", "", str(data.get("iface", "any"))) or "any"
                cmd = [ADB, "-s", STATE["target"], "shell", "tcpdump", "-i", iface,
                       "-s", "0", "-U", "-w", CAP["remote"]]
                adb(["shell", "rm -f " + CAP["remote"]], timeout=15)
                CAP["proc"] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                CAP["started"] = int(time.time())
                CAP["local"] = None
                time.sleep(1.2)
                if CAP["proc"].poll() is not None:
                    err = CAP["proc"].stderr.read().decode("utf-8", "replace") if CAP["proc"].stderr else ""
                    CAP["proc"] = None
                    self._json({"ok": False, "error": "tcpdump 启动失败（通常需要 root）：" + err[:400]}, 500)
                    return
                self._json({"ok": True, "remote": CAP["remote"], "iface": iface})
            elif path == "/api/capture/stop":
                if not self.need_device():
                    return
                p = CAP["proc"]
                if p:
                    try:
                        p.terminate()
                        p.wait(timeout=5)
                    except Exception:
                        p.kill()
                    CAP["proc"] = None
                adb(["shell", "pkill tcpdump"], timeout=15)
                local = os.path.join(UPLOAD, "adbweb_capture.pcap")
                r = adb(["pull", CAP["remote"], local], timeout=120)
                if not os.path.isfile(local):
                    self._json({"ok": False, "error": "未取到 pcap：" + (r["stdout"] or r["stderr"])}, 500)
                    return
                CAP["local"] = local
                self._json({"ok": True, "size": os.path.getsize(local), "path": local})
            else:
                self._json({"ok": False, "error": "未知接口 " + path}, 404)
        except ValueError as e:
            self._json({"ok": False, "error": str(e)}, 400)
        except json.JSONDecodeError:
            self._json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
        except Exception as e:
            self._json({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}, 500)

    def handle_upload(self, path):
        ctype = self.headers.get("Content-Type", "")
        parts = parse_multipart(self._body(), ctype)
        f = parts.get("file")
        if not isinstance(f, dict) or not f.get("data"):
            self._json({"ok": False, "error": "没有收到文件"}, 400)
            return
        name = safe_local_name(f["filename"])
        local = os.path.join(UPLOAD, name)
        with open(local, "wb") as out:
            out.write(f["data"])
        if not self.need_device():
            os.remove(local)
            return
        if path == "/api/apps/install":
            if not name.lower().endswith(".apk"):
                self._json({"ok": False, "error": "安装需要 .apk 文件"}, 400)
                return
            r = adb(["install", "-r", local], timeout=300)
            self._json({"ok": "Success" in r["stdout"] and r["ok"],
                        "raw": r["stdout"] or r["stderr"], "size": os.path.getsize(local)})
        else:
            remote = safe_remote_path(parts.get("path", "/sdcard"))
            target = remote.rstrip("/") + "/" + f["filename"].replace("\\", "/").split("/")[-1]
            r = adb(["push", local, target], timeout=300)
            self._json({"ok": r["ok"], "raw": r["stdout"] or r["stderr"], "remote": target})
        return True


def lan_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def main():
    global TOKEN, ADB
    ap = argparse.ArgumentParser(description="ADB Web Console")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--token", default="", help="访问口令，留空则自动生成")
    ap.add_argument("--adb", default="", help="adb 可执行文件路径；也可用环境变量 ADB_PATH")
    args = ap.parse_args()
    TOKEN = args.token or secrets.token_urlsafe(6)
    ADB = resolve_adb(args.adb)
    os.makedirs(UPLOAD, exist_ok=True)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    ip = lan_ip()
    print("=" * 58)
    print("ADB Web Console 已启动")
    print("  电脑打开 : http://127.0.0.1:%d/?token=%s" % (args.port, TOKEN))
    print("  手机打开 : http://%s:%d/?token=%s" % (ip, args.port, TOKEN))
    print("  访问口令 : %s" % TOKEN)
    print("  ADB 路径 : %s (%s)" % (ADB, "存在" if os.path.isfile(ADB) else "缺失"))
    print("  仅用于管理自己局域网内的自有设备；用完请关掉本窗口")
    print("=" * 58)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        srv.shutdown()


if __name__ == "__main__":
    main()
