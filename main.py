#!/usr/bin/env python3
"""MAIN = the scanner. Scans the whole system, a directory, or one specific program.

  python3 main.py system                 scan all running processes
  python3 main.py dir <folder> [-r]      scan executables in a folder (-r = recursive)
  python3 main.py file <program>         scan one program (path, or a name like "firefox")
  python3 main.py whitelist list|remove <path>|clear

If AV_SERVER (or --server) is set, every log line goes to POST /api/logs and every
threat to POST /api/threats on the Flask server. Watcher.py imports this module.
"""
import argparse
import hashlib
import os
import shutil
import sqlite3
import sys
import time

import psutil
import requests

import compare as vt
from fileWatcher import is_executable_file

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "antivirus.db")
SERVER = os.environ.get("AV_SERVER", "").rstrip("/")
SOURCE = os.environ.get("AV_SOURCE", "main")

_session = None
_retry_at = 0.0


# ---------------------------------------------------------------- server reporting
def _post(endpoint, payload, force=False):
    """POST JSON to the server. Never raises; backs off 10s after a failure (unless force)."""
    global _session, _retry_at
    if not SERVER or (not force and time.time() < _retry_at):
        return False
    try:
        _session = _session or requests.Session()
        _session.post(SERVER + endpoint, json=payload, timeout=5)
        return True
    except requests.RequestException:
        _retry_at = time.time() + 10
        return False


def log(message, level="info"):
    """level: info | ok | warn | threat | error"""
    print(message, flush=True)
    _post("/api/logs", {"level": level, "message": message.strip(), "source": SOURCE})


vt.emit = log  # VirusTotal messages go through the same channel


# ---------------------------------------------------------------- whitelist db
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS files (whitelisted TEXT)")
    conn.commit()
    return conn


def is_whitelisted(conn, path):
    return conn.execute("SELECT 1 FROM files WHERE whitelisted = ?", (path,)).fetchone() is not None


def whitelist_add(conn, path):
    if not is_whitelisted(conn, path):
        conn.execute("INSERT INTO files (whitelisted) VALUES (?)", (path,))
        conn.commit()


# ---------------------------------------------------------------- core scanner
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def scan_file(conn, path, tag=""):
    """Scan ONE file. Returns 'clean' | 'threat' | 'unknown' | 'skipped' | 'error'.
    Clean -> whitelisted. Threat -> reported to the server, which asks the user what to do.
    This is what Watcher.py calls."""
    if is_whitelisted(conn, path):
        return "skipped"
    log(f"[scan] {tag}{path}")
    try:
        file_hash = sha256_of(path)
        verdict = vt.compare(file_hash)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
        log(f"  cannot read: {exc}", "warn")
        return "error"
    if verdict is True:
        log(f"  !!! THREAT DETECTED: {path}", "threat")
        if SERVER and not _post("/api/threats", {"path": path, "hash": file_hash, "source": SOURCE}, force=True):
            log("  could not report threat to the server", "error")
        return "threat"
    if verdict is False:
        whitelist_add(conn, path)
        log("  clean (whitelisted)", "ok")
        return "clean"
    return "unknown"


def running_programs():
    """Paths of executables of all running processes (virtual/deleted entries skipped)."""
    exes = set()
    for p in psutil.process_iter(["exe"]):
        try:
            exe = p.info.get("exe")
            if exe and os.path.isfile(exe):
                exes.add(exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return exes


def folder_programs(directory, recursive=False):
    if recursive:
        found = [os.path.join(r, n) for r, _d, names in os.walk(directory) for n in names]
    else:
        found = [os.path.join(directory, n) for n in os.listdir(directory)]
    return [f for f in found if is_executable_file(f)]


def summarize(results):
    log("Summary: " + ", ".join(f"{results.count(k)} {k}" for k in
        ("clean", "threat", "unknown", "skipped", "error")), "threat" if "threat" in results else "info")


def _scan_many(paths):
    log(f"Found {len(paths)} program(s) to check.")
    with db() as conn:
        summarize([scan_file(conn, p, f"({i}/{len(paths)}) ") for i, p in enumerate(paths, 1)])


def scan_system():
    _scan_many(sorted(running_programs()))


def scan_dir(folder, recursive=False):
    directory = os.path.abspath(os.path.expanduser(folder))
    if not os.path.isdir(directory):
        sys.exit(f"Not a folder: {directory}")
    _scan_many(folder_programs(directory, recursive))


def scan_program(program):
    """Scan one program: a file path, or a command name found on PATH / among running processes."""
    path = os.path.abspath(os.path.expanduser(program)) if os.path.exists(os.path.expanduser(program)) else None
    if not path:
        path = shutil.which(program)
    if not path:
        for p in psutil.process_iter(["name", "exe"]):
            try:
                if p.info["name"] == program and p.info["exe"]:
                    path = p.info["exe"]
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    if not path or not os.path.isfile(path):
        sys.exit(f"Program not found: {program}")
    path = os.path.realpath(path)
    with db() as conn:
        conn.execute("DELETE FROM files WHERE whitelisted = ?", (path,))  # a specific scan always re-checks
        conn.commit()
        summarize([scan_file(conn, path)])


# ---------------------------------------------------------------- CLI
def cmd_whitelist(args):
    with db() as conn:
        if args.action == "list":
            rows = [r[0] for r in conn.execute("SELECT whitelisted FROM files ORDER BY whitelisted")]
            print("\n".join(rows) if rows else "(whitelist is empty)")
        elif args.action == "remove":
            if not args.path:
                sys.exit("Usage: main.py whitelist remove <path>")
            n = conn.execute("DELETE FROM files WHERE whitelisted = ?", (args.path,)).rowcount
            conn.commit()
            print(f"Removed {n} entr{'y' if n == 1 else 'ies'}.")
        else:
            conn.execute("DELETE FROM files")
            conn.commit()
            print("Whitelist cleared.")


def main():
    global SERVER
    ap = argparse.ArgumentParser(description="Hash-based antivirus scanner (VirusTotal lookups)")
    ap.add_argument("--server", help="report logs/threats to this server, e.g. http://127.0.0.1:5000")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("system", help="scan all running processes")
    d = sub.add_parser("dir", help="scan a folder")
    d.add_argument("folder")
    d.add_argument("-r", "--recursive", action="store_true")
    f = sub.add_parser("file", help="scan one specific program")
    f.add_argument("program", help="path or name, e.g. /usr/bin/ls or firefox")
    wl = sub.add_parser("whitelist", help="manage whitelist")
    wl.add_argument("action", choices=["list", "remove", "clear"])
    wl.add_argument("path", nargs="?")
    args = ap.parse_args()
    if args.server:
        SERVER = args.server.rstrip("/")

    if args.cmd != "whitelist" and not vt.API_KEY:
        sys.exit("VT_API_KEY is not set. Put VT_API_KEY=your_key in the .env file.")
    try:
        if args.cmd == "system":
            scan_system()
        elif args.cmd == "dir":
            scan_dir(args.folder, args.recursive)
        elif args.cmd == "file":
            scan_program(args.program)
        else:
            cmd_whitelist(args)
    except KeyboardInterrupt:
        log("Scan stopped.", "warn")


if __name__ == "__main__":
    main()
