#!/usr/bin/env python3
"""WATCHER = a hook. It only looks for NEW programs and checks them against the whitelist.
Anything not whitelisted is handed to main.scan_file(); if it is a threat, main reports it
to the Flask server (POST /api/threats) and the user decides in the UI what to delete.

  python3 Watcher.py --server http://127.0.0.1:5000
  python3 Watcher.py --server http://127.0.0.1:5000 --dir ~/Downloads -r --interval 5
"""
import argparse
import os
import sys
import time

import main  # the scanner

main.SOURCE = "watcher"


def watch(directory=None, recursive=False, interval=2.0, stop_event=None):
    main.log("Watcher started" + (f" (+ folder {directory})" if directory else ""), "info")
    handled = set()  # programs already checked this session
    with main.db() as conn:
        while not (stop_event and stop_event.is_set()):
            current = set(main.running_programs())
            if directory:
                current |= set(main.folder_programs(directory, recursive))

            for path in sorted(current - handled):
                handled.add(path)
                if main.is_whitelisted(conn, path):
                    continue  # 1) in the whitelist DB -> trusted: no VirusTotal call, no log
                main.log(f"[watcher] new program not whitelisted: {path}", "warn")
                main.scan_file(conn, path)  # 2) not whitelisted -> main asks VirusTotal
                if stop_event and stop_event.is_set():
                    return
            time.sleep(interval)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Watch for new programs and scan them via main")
    ap.add_argument("--server", default=os.environ.get("AV_SERVER", ""), help="Flask server URL to report to")
    ap.add_argument("--dir", help="also watch this folder for new executables")
    ap.add_argument("-r", "--recursive", action="store_true")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()

    main.SERVER = a.server.rstrip("/")
    if not main.vt.API_KEY:
        sys.exit("VT_API_KEY is not set. Put VT_API_KEY=your_key in the .env file.")
    folder = os.path.abspath(os.path.expanduser(a.dir)) if a.dir else None
    if folder and not os.path.isdir(folder):
        sys.exit(f"Not a folder: {folder}")
    try:
        watch(folder, a.recursive, a.interval)
    except KeyboardInterrupt:
        main.log("Watcher stopped.", "warn")
