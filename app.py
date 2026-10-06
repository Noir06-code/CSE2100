#!/usr/bin/env python3
"""Flask server: UI + REST API + WebSocket.

  POST /api/logs                 main.py / Watcher.py push log lines here -> relayed over WS (not stored)
  POST /api/scan                 {"mode":"system"} or {"mode":"dir","path":"...","recursive":true}
  POST /api/stop/<scan|watcher>  stop a running scan / the watcher
  POST /api/watcher/start        {"dir": "optional folder"}
  POST /api/threats              main.py reports a threat (needs the user's decision)
  GET  /api/threats              all threats
  POST /api/threats/<id>/delete  user approved: terminate running copies + delete the file
  POST /api/threats/<id>/ignore  user decided to keep it
  GET  /api/browse?path=         folder picker for the UI
  GET  /api/status               what is running
  WS   /ws                       real-time events: log | threat | status
"""
import hashlib
import itertools
import json
import os
import subprocess
import sys
import threading
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template, request
from flask_sock import Sock

from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, messaging

BASE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE, ".env"))
HOST = os.environ.get("AV_HOST", "127.0.0.1")
PORT = int(os.environ.get("AV_PORT", "5000"))
SELF_URL = f"http://{'127.0.0.1' if HOST in ('0.0.0.0', '::') else HOST}:{PORT}"
LEVELS = {"info", "ok", "warn", "threat", "error"}

app = Flask(__name__)
app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 25}
sock = Sock(app)

# ------------------------------------------------------------------ firebase (push alerts)
# Optional: if serviceAccountKey.json is missing, the server still runs, just without push alerts.
FIREBASE_KEY = os.environ.get("FIREBASE_KEY", os.path.join(BASE, "serviceAccountKey.json"))
firebase_ready = False
try:
    firebase_admin.initialize_app(credentials.Certificate(FIREBASE_KEY))
    firebase_ready = True
except Exception as exc:
    print(f"Firebase disabled: {exc}")

DEVICES_FILE = os.path.join(BASE, "devices.json")
PUSH_URL = os.environ.get("PUSH_URL", "").strip()  # link sent with each push, set in .env
file_lock = threading.Lock()


def _load_list(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_list(path, items):
    with file_lock:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        os.replace(tmp, path)


# Registered devices: appended when a device registers, kept across restarts.
# Each item: {"token": "...", "registered": "YYYY-MM-DD HH:MM:SS"}
devices, token_lock = _load_list(DEVICES_FILE), threading.Lock()


def send_push(title, body, data=None):
    """Push notification to every device in the registered-devices list (NOT to browsers)."""
    if not firebase_ready:
        return
    with token_lock:
        tokens = [d["token"] for d in devices]
    dead = []
    for token in tokens:
        try:
            messaging.send(messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data={**{k: str(v) for k, v in (data or {}).items()},
                      **({"url": PUSH_URL} if PUSH_URL else {})},
                token=token))
        except Exception as exc:  # bad/expired token etc.
            print("FCM error:", exc)
            if "not registered" in str(exc).lower() or "invalid" in str(exc).lower():
                dead.append(token)
    if dead:
        with token_lock:
            devices[:] = [d for d in devices if d["token"] not in dead]
            _save_list(DEVICES_FILE, devices)


@app.post("/api/register")
def register_device():
    """The phone/app posts its FCM token here: {"token": "..."}"""
    token = (request.get_json(silent=True) or {}).get("token")
    if not token:
        return jsonify(success=False, error="FCM token required"), 400
    with token_lock:
        if not any(d["token"] == token for d in devices):  # no duplicates
            devices.append({"token": token, "registered": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            _save_list(DEVICES_FILE, devices)
    return jsonify(success=True, message="Device registered for threat alerts.")


@app.get("/api/devices")
def list_devices():
    with token_lock:  # token shortened so the full FCM token is never exposed
        return jsonify([{"token": d["token"][:12] + "...", "registered": d["registered"]} for d in devices])

# ------------------------------------------------------------------ websocket hub
clients, clients_lock = set(), threading.Lock()


def broadcast(msg):
    data = json.dumps(msg)
    with clients_lock:
        for c in list(clients):
            try:
                c.send(data)
            except Exception:
                clients.discard(c)


@sock.route("/ws")
def ws(conn):
    with clients_lock:
        clients.add(conn)
    try:
        # page just opened: send every stored threat so the UI shows them all
        with tlock:
            snapshot = list(threats.values())
        for t in snapshot:
            conn.send(json.dumps({"type": "threat", "data": t}))
        while True:
            conn.receive()  # blocks until the browser disconnects
    except Exception:
        pass
    finally:
        with clients_lock:
            clients.discard(conn)


# ------------------------------------------------------------------ logs
# Logs are NOT stored on the server: they are only relayed to connected browsers.
# The browser keeps them on screen, and its Clear button just empties the screen.


def add_log(message, level="info", source="server"):
    broadcast({"type": "log", "data": {"time": datetime.now().strftime("%H:%M:%S"),
                                       "level": level, "source": source, "message": message}})


@app.post("/api/logs")
def post_log():
    d = request.get_json(silent=True) or {}
    msg = str(d.get("message", "")).strip()
    if not msg:
        return jsonify(error="message required"), 400
    level = d.get("level", "info")
    add_log(msg, level if level in LEVELS else "info", str(d.get("source", "main"))[:20])
    return jsonify(ok=True)


# ------------------------------------------------------------------ threats (need user permission)
threats, threat_ids, tlock = {}, itertools.count(1), threading.Lock()  # in memory only, not saved to disk


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@app.post("/api/threats")
def report_threat():
    d = request.get_json(silent=True) or {}
    path, file_hash = d.get("path"), d.get("hash")
    if not path or not file_hash:
        return jsonify(error="path and hash required"), 400
    with tlock:
        for t in threats.values():  # same file already known and undecided/ignored -> don't ask again
            if t["path"] == path and t["hash"] == file_hash and t["status"] in ("pending", "ignored"):
                return jsonify(t)
        t = {"id": next(threat_ids), "path": path, "hash": file_hash, "source": str(d.get("source", "main")),
             "status": "pending", "found": datetime.now().strftime("%H:%M:%S"), "note": ""}
        threats[t["id"]] = t
    broadcast({"type": "threat", "data": t})
    add_log(f"Waiting for your decision on threat: {path}", "threat")
    threading.Thread(target=send_push, daemon=True, args=(
        "Threat detected", f"{os.path.basename(path)} needs your decision",
        {"threat_id": t["id"], "path": path})).start()
    return jsonify(t), 201


@app.get("/api/threats")
def list_threats():
    return jsonify(list(threats.values()))


def remove_file(t):
    """Terminate running copies, then delete. Only ever touches a path that was reported as a threat."""
    path = t["path"]
    if not os.path.isfile(path):
        return True, "file no longer exists"
    if sha256_of(path) != t["hash"]:
        return False, "file changed since it was scanned - refusing to delete"
    killed = []
    for p in psutil.process_iter(["exe"]):
        try:
            if p.info["exe"] and os.path.realpath(p.info["exe"]) == os.path.realpath(path):
                p.kill()
                killed.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(killed, timeout=3)
    try:
        os.remove(path)
    except OSError as exc:
        return False, f"could not delete: {exc}"
    return True, f"deleted ({len(killed)} process(es) terminated)"


@app.post("/api/threats/<int:tid>/<action>")
def threat_action(tid, action):
    t = threats.get(tid)
    if not t:
        return jsonify(error="unknown threat"), 404
    if t["status"] not in ("pending", "failed"):
        return jsonify(error=f"already {t['status']}"), 409
    if action == "ignore":
        t["status"], t["note"] = "ignored", "kept by user"
    elif action == "delete":
        ok, note = remove_file(t)
        t["status"], t["note"] = ("deleted" if ok else "failed"), note
    else:
        return jsonify(error="action must be delete or ignore"), 400
    broadcast({"type": "threat", "data": t})
    add_log(f"{t['status'].capitalize()}: {t['path']} - {t['note']}", "ok" if t["status"] != "failed" else "error")
    return jsonify(t)


# ------------------------------------------------------------------ running main.py / Watcher.py
procs, plock = {}, threading.RLock()


def has_key():
    return bool(os.environ.get("VT_API_KEY"))


def status():
    with plock:
        return {"key_set": has_key(),
                "scan": {"running": "scan" in procs, "label": procs.get("scan", {}).get("label", "")},
                "watcher": {"running": "watcher" in procs, "label": procs.get("watcher", {}).get("label", "")}}


def _monitor(kind, p, label):
    _, err = p.communicate()
    with plock:
        if procs.get(kind, {}).get("proc") is p:
            procs.pop(kind)
    if err and err.strip():
        for line in err.strip().splitlines()[-4:]:
            add_log(line, "error", kind)
    code = p.returncode
    if code == 0:
        add_log(f"{label} finished.", "ok")
    elif code is not None and code < 0:
        add_log(f"{label} stopped.", "warn")
    else:
        add_log(f"{label} failed (exit code {code}).", "error")
    broadcast({"type": "status", "data": status()})


def spawn(kind, script, args, label):
    env = dict(os.environ, AV_SERVER=SELF_URL, AV_SOURCE=kind, PYTHONUNBUFFERED="1")
    p = subprocess.Popen([sys.executable, "-u", os.path.join(BASE, script), *args], cwd=BASE, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    procs[kind] = {"proc": p, "label": label}
    threading.Thread(target=_monitor, args=(kind, p, label), daemon=True).start()
    add_log(f"Started: {label}", "info")
    broadcast({"type": "status", "data": status()})


def _body_path(key):
    raw = (request.get_json(silent=True) or {}).get(key) or ""
    return os.path.abspath(os.path.expanduser(raw)) if raw else ""


@app.post("/api/scan")
def start_scan():
    d = request.get_json(silent=True) or {}
    if not has_key():
        return jsonify(error="VT_API_KEY is not set - add it to the .env file and restart the server"), 400
    with plock:
        if "scan" in procs:
            return jsonify(error="a scan is already running"), 409
        if d.get("mode") == "system":
            spawn("scan", "main.py", ["system"], "System scan")
        elif d.get("mode") == "dir":
            path = _body_path("path")
            if not os.path.isdir(path):
                return jsonify(error=f"not a folder: {path or '(empty)'}"), 400
            spawn("scan", "main.py", ["dir", path] + (["-r"] if d.get("recursive") else []),
                  f"Directory scan: {path}")
        else:
            return jsonify(error="mode must be system or dir"), 400
    return jsonify(ok=True)


@app.post("/api/watcher/start")
def start_watcher():
    if not has_key():
        return jsonify(error="VT_API_KEY is not set - add it to the .env file and restart the server"), 400
    folder = _body_path("dir")
    if folder and not os.path.isdir(folder):
        return jsonify(error=f"not a folder: {folder}"), 400
    with plock:
        if "watcher" in procs:
            return jsonify(error="watcher already running"), 409
        spawn("watcher", "Watcher.py", ["--server", SELF_URL] + (["--dir", folder] if folder else []), "Watcher")
    return jsonify(ok=True)


@app.post("/api/stop/<kind>")
def stop(kind):
    with plock:
        item = procs.get(kind)
    if not item:
        return jsonify(error="not running"), 409
    item["proc"].terminate()
    return jsonify(ok=True)


@app.get("/api/status")
def get_status():
    return jsonify(status())


# ------------------------------------------------------------------ folder picker + UI
@app.get("/api/browse")
def browse():
    raw, hidden = request.args.get("path", ""), request.args.get("hidden") == "1"
    if raw == "" and os.name == "nt":  # Windows: list drives
        drives = [{"name": d.mountpoint, "path": d.mountpoint} for d in psutil.disk_partitions()]
        return jsonify(path="", parent=None, entries=drives)
    path = os.path.abspath(os.path.expanduser(raw or "~"))
    if not os.path.isdir(path):
        return jsonify(error=f"not a folder: {path}"), 400
    try:
        names = [n for n in os.listdir(path) if (hidden or not n.startswith("."))
                 and os.path.isdir(os.path.join(path, n))]
    except OSError as exc:
        return jsonify(error=str(exc)), 403
    parent = os.path.dirname(path)
    if parent == path:
        parent = "" if os.name == "nt" else None
    return jsonify(path=path, parent=parent,
                   entries=[{"name": n, "path": os.path.join(path, n)} for n in sorted(names, key=str.lower)])


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    print(f"Guardian AV server on {SELF_URL}   (VT_API_KEY {'set' if has_key() else 'NOT SET'})")
    app.run(host=HOST, port=PORT, threaded=True, debug=False)
