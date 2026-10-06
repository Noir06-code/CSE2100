import os
import time
import requests

from dotenv import load_dotenv

# The key lives in the .env file next to these scripts (works from any working directory)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

API_KEY = os.environ.get("VT_API_KEY", "")
# Free VirusTotal plan = 4 lookups/minute -> one every 15s. Set VT_DELAY=0 for a paid key.
MIN_INTERVAL = float(os.environ.get("VT_DELAY", "15"))
_last_call = 0.0


def emit(message, level="info"):
    """Output hook. main.py replaces this so messages also reach the server."""
    print(message, flush=True)


def compare(file_hash):
    """True = malicious, False = clean, None = unknown / lookup failed."""
    global _last_call
    if not API_KEY:
        raise RuntimeError("VT_API_KEY is not set - put VT_API_KEY=... in the .env file.")

    wait = MIN_INTERVAL - (time.time() - _last_call)
    if wait > 0:
        if wait > 1:
            emit(f"  rate limit: waiting {wait:.0f}s before next VirusTotal lookup...")
        time.sleep(wait)
    _last_call = time.time()

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        r = requests.get(url, headers={"x-apikey": API_KEY}, timeout=20)
    except requests.RequestException as exc:
        emit(f"  network error: {exc}", "warn")
        return None

    if r.status_code == 200:
        s = r.json()["data"]["attributes"]["last_analysis_stats"]
        emit(f"  VT: malicious={s['malicious']} suspicious={s['suspicious']} clear={s['undetected']}")
        return s["malicious"] > 0
    if r.status_code == 429:
        emit("  VT rate limit hit - raise VT_DELAY.", "warn")
    elif r.status_code == 404:
        emit("  VT: hash not known.", "warn")
    else:
        emit(f"  VT API error: {r.status_code}", "warn")
    return None
