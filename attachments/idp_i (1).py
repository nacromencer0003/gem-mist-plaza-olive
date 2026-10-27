#!/usr/bin/env python3
"""
IDP i Security Monitoring — CP-UVR-1601E2-I + In-built AI Assistant
=======================================================================
(formerly "Sudarshan")

New in IDP i:
- First start: a setup screen asks you to create the administrator password (or set IDPI_LOGIN_PASS)
- 24/7 AI engine on the server (runs even with no browser open):
  * DVR offline / back online
  * Camera offline, camera faulty (no video / black screen), blur, too dark,
    too bright, angle change (tampering), frozen picture
  * Gate OPEN / CLOSED detection from the camera picture (+ open too long, after hours)
  * Face recognition (staff / VIP / watchlist / unknown person)
  * Every alert goes to the Telegram bot with a photo and the location
  * Telegram bot commands: /status /offline /issues /gates /faces /snap /help
- LIVE video in the browser (one shared ffmpeg per camera for all viewers)
- LIVE face recognition on the video: box + name drawn on the picture, "who is in front of
  the camera now" panel, toast + voice + Telegram when a person arrives
- Hourly CCTV reports (timeline of offline / blur / angle / shutter / system on-off)
- Automatic gate/shutter learning at set times + custom open/close messages
- Voice assistant: speaks new alerts aloud and answers voice questions
  ("status", "gate status", "which cameras are offline", "camera problems", "who came")

Install on Kali Linux:
  sudo apt install -y python3-opencv python3-numpy ffmpeg
Run:
  python3 idp_i.py                       -> http://127.0.0.1:8765
  python3 idp_i.py --host 0.0.0.0        (open from other PCs / phones on the network)
Model: CP PLUS CP-UVR-1601E2-I (16ch 1080P Lite hybrid DVR)

Features:
- Local LAN RTSP live (Dahua-compatible path)
- Telegram alerts (in-memory)
- In-built AI Assistant:
  * 24/7 status monitoring (cameras, incidents, link)
  * Auto-fills automation / alert messages
  * Helps understand software + DVR
  * Smart insights & suggested actions

RTSP: rtsp://USER:PASS@IP:554/cam/realmonitor?channel=N&subtype=0|1
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import urllib.request
import urllib.error
import urllib.parse
import socket
import time
import base64
import subprocess
import shutil
import os
from datetime import datetime, timedelta
from pathlib import Path

HOST, PORT = "127.0.0.1", 8765
STREAM_DIR = Path("/tmp/idpi_streams")
STREAM_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR = Path("/tmp/idpi_exports")
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
# Permanent local config (Telegram + devices). Stored next to the script.
CONFIG_PATH = Path(__file__).resolve().parent / "idpi_config.json"
OLD_CONFIG_PATH = Path(__file__).resolve().parent / "sudarshan_config.json"  # earlier version, read once

def load_config():
    global TELEGRAM_CONFIG, DEVICES, ACTIVE_DEVICE_ID
    try:
        src = CONFIG_PATH if CONFIG_PATH.is_file() else OLD_CONFIG_PATH
        if not src.is_file():
            return
        data = json.loads(src.read_text(encoding="utf-8"))
        tg = data.get("telegram") or {}
        if tg.get("bot_token") and tg.get("chat_id"):
            TELEGRAM_CONFIG["bot_token"] = str(tg["bot_token"])
            TELEGRAM_CONFIG["chat_id"] = str(tg["chat_id"])
        for d in data.get("devices") or []:
            did = d.get("id") or _new_device_id()
            DEVICES[did] = {
                "id": did,
                "name": d.get("name") or d.get("ip") or did,
                "mode": "rtsp",
                "ip": d.get("ip") or "",
                "port": int(d.get("port") or 554),
                "http_port": int(d.get("http_port") or 80),
                "username": d.get("username") or "",
                "password": d.get("password") or "",
                "channels": int(d.get("channels") or 0),
                "connected": True,
                "detected": d.get("detected") or [],
                "last_error": "",
                "rtsp_urls": d.get("rtsp_urls") or [],
                "location": d.get("location") or "",
                "type": "NVR" if str(d.get("type") or "").upper() == "NVR" else "DVR",
            }
        act = data.get("active_device")
        if act and act in DEVICES:
            ACTIVE_DEVICE_ID = act
        elif DEVICES:
            ACTIVE_DEVICE_ID = next(iter(DEVICES))
    except Exception as exc:
        print("[IDP i AI] config load error:", exc)

def save_config():
    try:
        payload = {
            "telegram": {
                "bot_token": TELEGRAM_CONFIG.get("bot_token") or "",
                "chat_id": TELEGRAM_CONFIG.get("chat_id") or "",
            },
            "active_device": ACTIVE_DEVICE_ID,
            "devices": [
                {
                    "id": d.get("id"),
                    "name": d.get("name"),
                    "ip": d.get("ip"),
                    "port": d.get("port"),
                    "http_port": d.get("http_port"),
                    "username": d.get("username"),
                    "password": d.get("password"),
                    "channels": d.get("channels"),
                    "detected": d.get("detected") or [],
                    "rtsp_urls": d.get("rtsp_urls") or [],
                    "location": d.get("location") or "",
                    "type": d.get("type") or "DVR",
                }
                for d in DEVICES.values()
            ],
        }
        CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception as exc:
        print("[IDP i AI] config save error:", exc)

TELEGRAM_CONFIG = {"bot_token": "", "chat_id": ""}
# Multi-DVR registry (in-memory). Designed for 1000+ devices; live preview is limited for performance.
DEVICES = {}  # id -> device dict
ACTIVE_DEVICE_ID = None
MAX_DEVICES = 2000
MAX_LIVE_PREVIEW = 16  # concurrent snapshot channels in UI
FFMPEG_PROCS = {}

load_config()  # runs after the globals above are defined

def _new_device_id():
    import uuid
    return "dvr-" + uuid.uuid4().hex[:10]

def get_device(dev_id=None):
    did = dev_id or ACTIVE_DEVICE_ID
    return DEVICES.get(did) if did else None

RTSP_PATH_MAIN = "/cam/realmonitor?channel={ch}&subtype=0"
RTSP_PATH_SUB = "/cam/realmonitor?channel={ch}&subtype=1"

# AI knowledge + message templates (server can also serve these)
AI_TEMPLATES = {
    "SOS": {
        "title": "CRITICAL SOS — Possible unauthorized access / tampering",
        "body": "IDP i AI detected a high-priority SOS event.\nLocation: {site}\nTime: {time}\nAction: Review live cameras immediately and verify physical security.",
        "severity": "CRITICAL",
    },
    "CAMERA OFFLINE": {
        "title": "Camera offline — connection lost",
        "body": "AI Monitor: {camera} is offline at {site}.\nPossible causes: power, cable, network, or DVR channel issue.\nSuggested: Check DVR channel status and network link.",
        "severity": "CRITICAL",
    },
    "ANGLE CHANGE": {
        "title": "Possible camera angle / view change",
        "body": "AI Monitor: View change flagged on {camera} ({site}).\nThis may indicate tampering or accidental move.\nSuggested: Compare with last known good view.",
        "severity": "WARNING",
    },
    "HEALTH CHECK": {
        "title": "Health check completed",
        "body": "AI: {camera} status = {status} at {site}. All checks logged.",
        "severity": "INFO",
    },
    "DVR LINK": {
        "title": "DVR linked",
        "body": "AI: CP-UVR-1601E2-I RTSP link established at {target}. Continuous monitoring active.",
        "severity": "INFO",
    },
}


# =============================================================================
# IDP i — 24/7 AI ENGINE
# Runs on the server all the time (even when no browser is open):
#   • DVR offline / back online
#   • Camera offline, camera faulty (no video / black screen), blur, too dark,
#     over-exposed, angle change (tampering), frozen picture
#   • Gate OPEN / CLOSED detection from the camera picture (+ open too long, after hours)
#   • Face recognition (known staff / VIP / watchlist / unknown)
#   • Every alert goes to the Telegram bot with a photo and the location
#   • Telegram bot commands: /status /offline /issues /gates /faces /snap /help
# =============================================================================
import threading
import hashlib
import io
import re
import uuid
import queue
from concurrent.futures import ThreadPoolExecutor
import csv
import atexit

try:
    import cv2
    import numpy as np
    CV_OK = True
except Exception:  # without OpenCV only DVR / camera online-offline monitoring runs
    cv2 = None
    np = None
    CV_OK = False

APP_NAME = "IDP i"
AI_DIR = Path(__file__).resolve().parent / "idpi_data"
AI_DIRS = {k: AI_DIR / k for k in ("refs", "faces", "snaps", "models")}
for _p in AI_DIRS.values():
    _p.mkdir(parents=True, exist_ok=True)
AI_STATE_PATH = AI_DIR / "ai_state.json"
AI_EVENTS_LOG = AI_DIR / "events.log"
AI_LOCK = threading.RLock()

# ---------------------------------------------------------------- login
LOGIN_ID = os.environ.get("IDPI_LOGIN_ID", "admin")
LOGIN_PASS = os.environ.get("IDPI_LOGIN_PASS", "")   # no built-in password; see _bootstrap_password()
SESSION_HOURS = 12
SESSIONS = {}            # token -> expiry time
LOGIN_FAILS = {}         # client ip -> (count, first_fail_time)
SESSION_LOCK = threading.Lock()


def login_blocked(ip):
    n, first = LOGIN_FAILS.get(ip, (0, 0))
    if n >= 5 and time.time() - first < 300:
        return int(300 - (time.time() - first))
    if time.time() - first >= 300:
        LOGIN_FAILS.pop(ip, None)
    return 0


def login_failed(ip):
    n, first = LOGIN_FAILS.get(ip, (0, time.time()))
    LOGIN_FAILS[ip] = (n + 1, first)


# ---------------------------------------------------------------- multi-user accounts + RBAC
USERS_PATH = Path(__file__).resolve().parent / "idpi_users.json"
USERS = {}
USERS_LOCK = threading.Lock()


# ---------------------------------------------------------------- password storage (scrypt)
PASSWORD_MIN = 10            # every new password (setup, reset, user accounts) must be at least this long
SCRYPT_N, SCRYPT_R, SCRYPT_P = 16384, 8, 1


def _hash_password(password):
    """Store a password with scrypt, a memory-hard hash from the Python standard library.
    Format: scrypt$N$r$p$salt_hex$hash_hex. A new random 16-byte salt is used every time."""
    import secrets as _sec
    salt = _sec.token_bytes(16)
    dk = hashlib.scrypt(str(password).encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def _check_password(password, stored):
    import hmac as _hmac
    s = str(stored or "")
    try:
        if s.startswith("scrypt$"):
            _, n, r, p, salt_hex, dig = s.split("$")
            dk = hashlib.scrypt(str(password).encode("utf-8"), salt=bytes.fromhex(salt_hex),
                                n=int(n), r=int(r), p=int(p), dklen=32)
            return _hmac.compare_digest(dk.hex(), dig)
        # Legacy format from earlier versions (salted SHA-256). Accepted, then upgraded at the next sign-in.
        salt, dig = s.split("$", 1)
        want = hashlib.sha256((salt + ":" + str(password)).encode("utf-8")).hexdigest()
        return _hmac.compare_digest(want, dig)
    except (ValueError, TypeError):
        return False


def _password_problem(pw):
    """Empty string when the password is acceptable, otherwise the reason it is not."""
    if len(pw) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters."
    if len(pw) > 200:
        return "Password must be 200 characters or fewer."
    return ""


def _same(a, b):
    import hmac as _hmac
    return _hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


# ---------------------------------------------------------------- first-time setup + password reset
SETUP_CODE = None            # one-time code printed on the server console at first start (memory only)
RESET_CODES = {}             # username -> {"hash", "exp", "tries"}: one live reset code per account (memory only)
RESET_LOCK = threading.Lock()
RESET_TTL = 10 * 60          # seconds a reset code is valid
RESET_MAX_TRIES = 5          # wrong attempts before a code is cancelled
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O or 1/I, so codes are easy to read aloud


def _new_code():
    import secrets as _sec
    c = "".join(_sec.choice(_CODE_ALPHABET) for _ in range(8))
    return c[:4] + "-" + c[4:]


def _norm_code(s):
    return str(s or "").upper().replace("-", "").replace(" ", "").strip()


def _sha(s):
    return hashlib.sha256(str(s).encode("utf-8")).hexdigest()


def setup_pending():
    with USERS_LOCK:
        return any(u.get("setup_pending") for u in USERS.values())


_RATE = {}
_RATE_LOCK = threading.Lock()


def rate_ok(key, limit, window):
    """At most `limit` actions per `window` seconds for this key (used to slow down guessing)."""
    now = time.time()
    with _RATE_LOCK:
        hits = [t for t in _RATE.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _RATE[key] = hits
            return False
        hits.append(now)
        _RATE[key] = hits
        return True


def users_load():
    global USERS, SETUP_CODE
    with USERS_LOCK:
        try:
            if USERS_PATH.is_file():
                data = json.loads(USERS_PATH.read_text(encoding="utf-8"))
                USERS = {u["username"]: u for u in (data.get("users") or []) if u.get("username")}
        except Exception as exc:
            print("[IDP i AI] users load error:", exc)
            USERS = {}
        if not USERS:
            # First start. IDPI_LOGIN_PASS (for unattended installs) is used when it meets the policy.
            # Otherwise the administrator is created with NO password, and the setup screen asks for one.
            pre = LOGIN_PASS if (LOGIN_PASS and not _password_problem(LOGIN_PASS)) else ""
            if LOGIN_PASS and not pre:
                print(f"[IDP i AI] IDPI_LOGIN_PASS is shorter than {PASSWORD_MIN} characters; using the setup screen.")
            admin = {
                "id": "u-admin",
                "username": LOGIN_ID,
                "password": _hash_password(pre) if pre else "",
                "role": "admin",
                "enabled": True,
                "created": time.time(),
                "display_name": "Administrator",
            }
            if not pre:
                admin["setup_pending"] = True
            USERS[LOGIN_ID] = admin
            try:
                USERS_PATH.write_text(json.dumps({"users": list(USERS.values())}, indent=2), encoding="utf-8")
            except Exception as exc:
                print("[IDP i AI] users bootstrap error:", exc)
    if setup_pending():
        SETUP_CODE = _new_code()


def users_save():
    with USERS_LOCK:
        try:
            tmp = USERS_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps({"users": list(USERS.values())}, indent=2), encoding="utf-8")
            tmp.replace(USERS_PATH)
        except Exception as exc:
            print("[IDP i AI] users save error:", exc)


def user_authenticate(username, password):
    upgraded = False
    with USERS_LOCK:
        u = USERS.get(str(username or "").strip())
        if not u or not u.get("enabled", True) or u.get("setup_pending"):
            return None
        stored = u.get("password") or ""
        if not _check_password(password, stored):
            return None
        if not stored.startswith("scrypt$"):          # legacy hash: upgrade now that the password is proven
            u["password"] = _hash_password(password)
            upgraded = True
        user = dict(u)
    if upgraded:
        users_save()
    return user


def session_new(user=None):
    import secrets
    tok = secrets.token_urlsafe(32)
    with SESSION_LOCK:
        SESSIONS[tok] = {
            "exp": time.time() + SESSION_HOURS * 3600,
            "username": (user or {}).get("username") or LOGIN_ID,
            "role": (user or {}).get("role") or "admin",
            "uid": (user or {}).get("id") or "",
            "display_name": (user or {}).get("display_name") or (user or {}).get("username") or LOGIN_ID,
        }
    return tok


def session_user(tok):
    """The CURRENT account behind a session token, or None when signed out, expired, disabled or deleted.
    Role, enabled state and device assignments are read from the user store on every request, so an
    administrator's change applies to the very next request."""
    if not tok:
        return None
    with SESSION_LOCK:
        info = SESSIONS.get(tok)
        if not isinstance(info, dict):
            return None
        if info.get("exp", 0) < time.time():
            SESSIONS.pop(tok, None)
            return None
        uname, uid = info.get("username"), info.get("uid")
    with USERS_LOCK:
        u = USERS.get(uname)
        live = dict(u) if (u and u.get("enabled", True) and (u.get("id") or "") == (uid or "")) else None
    if live is None:
        session_end(tok)
        return None
    with SESSION_LOCK:
        if tok in SESSIONS:
            SESSIONS[tok]["exp"] = time.time() + SESSION_HOURS * 3600
    return live


def session_valid(tok):
    return session_user(tok) is not None


def session_info(tok):
    u = session_user(tok)
    if not u:
        return None
    return {
        "username": u.get("username"),
        "role": u.get("role") or "viewer",
        "display_name": u.get("display_name") or u.get("username"),
        "uid": u.get("id") or "",
        "devices": list(u.get("devices") or []),
    }


def session_end(tok):
    with SESSION_LOCK:
        SESSIONS.pop(tok, None)


def kill_user_sessions(username):
    """Sign an account out everywhere (used when it is disabled, deleted or its password is reset)."""
    with SESSION_LOCK:
        for t in [t for t, i in SESSIONS.items() if isinstance(i, dict) and i.get("username") == username]:
            SESSIONS.pop(t, None)


# ---------------------------------------------------------------- device assignment per account
def user_device_scope(u):
    """None = every device (administrators). Otherwise the set of device IDs this account may use."""
    if u is None:
        return set()
    if u.get("role") == "admin":
        return None
    return set(u.get("devices") or [])


def device_allowed_for(u, dev_id):
    if u is None:
        return False
    if u.get("role") == "admin":
        return True            # administrators: whether the device exists is checked by the caller
    dev_id = str(dev_id or "")
    return bool(dev_id) and dev_id in DEVICES and dev_id in set(u.get("devices") or [])


def pick_device(u, requested=""):
    """Device for a request: the one asked for, else the active device if this account may use it,
    else the account's first assigned device. Returns "" when nothing is available."""
    if requested:
        return str(requested)
    if device_allowed_for(u, ACTIVE_DEVICE_ID):
        return ACTIVE_DEVICE_ID
    scope = user_device_scope(u)
    if scope is None:
        return ACTIVE_DEVICE_ID if ACTIVE_DEVICE_ID in DEVICES else next(iter(DEVICES), "")
    return next((d for d in DEVICES if d in scope), "")


def _valid_device_ids(lst):
    out = []
    for x in (lst if isinstance(lst, list) else []):
        x = str(x or "")
        if x in DEVICES and x not in out:
            out.append(x)
    return out


AUDIT_PATH = AI_DIR / "audit.log"


def audit(action, actor, target="", detail=""):
    """Append one line to the audit trail: user changes, recording exports, device removals."""
    try:
        AI_DIR.mkdir(parents=True, exist_ok=True)
        rec = {"time": datetime.now().isoformat(timespec="seconds"), "actor": actor or "",
               "action": action, "target": str(target or ""), "detail": str(detail or "")}
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as exc:
        print("[IDP i AI] audit error:", exc)


# ---------------------------------------------------------------- recording download tokens
EXPORT_TOKENS = {}   # token -> {path, uid, dev, name, exp}: one clip, bound to one account and one device
EXPORT_LOCK = threading.Lock()
EXPORT_TTL = 15 * 60  # seconds a download link stays valid


def _export_sweep_locked():
    now = time.time()
    for t, rec in list(EXPORT_TOKENS.items()):
        if rec["exp"] < now:
            EXPORT_TOKENS.pop(t, None)
            try:
                rec["path"].unlink()
            except OSError:
                pass


# ---------------------------------------------------------------- recording export jobs
# An export runs in a background worker, so the page never freezes. The browser polls
# /api/export-status for real progress (percent, downloaded size, time left). The finished
# MP4 is written to a temp name and renamed only when complete, then served from
# /downloads/<token> with HTTP Range support so phones can seek.
import logging
import secrets as _secrets

EXPORT_LOG = logging.getLogger("idpi.export")
if not EXPORT_LOG.handlers:
    _export_fh = logging.FileHandler(EXPORT_DIR / "export.log", encoding="utf-8")
    _export_fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    EXPORT_LOG.addHandler(_export_fh)
    EXPORT_LOG.setLevel(logging.INFO)
EXPORT_JOBS = {}                       # job id -> job dict (keys starting with "_" are private)
EXPORT_BY_KEY = {}                     # (user, device, channel, start, end) -> active job id
EXPORT_SEM = threading.Semaphore(2)    # at most two exports pulling from DVRs at once
EXPORT_MAX_SECONDS = 24 * 3600         # longest single export
EXPORT_MIN_FREE_BYTES = 1024 ** 3      # keep at least 1 GB free on the server
EXPORT_STALL_SECONDS = 120             # no progress from ffmpeg for this long = stuck, abort
EXPORT_ATTEMPTS = ("tcp", "udp")       # automatic second try on the other RTSP transport
EXPORT_TIME_RE = re.compile(r"\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}")


def _export_public(job):
    return {k: v for k, v in job.items() if not k.startswith("_")}


def _export_set(job, **fields):
    job.update(fields)
    job["updated"] = time.time()


def _export_jobs_sweep_locked():
    now = time.time()
    for jid, j in list(EXPORT_JOBS.items()):
        if j["state"] in ("done", "error", "cancelled") and now - j["updated"] > 3600:
            EXPORT_JOBS.pop(jid, None)


def _export_url(dev, ch, start, end):
    user = urllib.parse.quote(dev.get("username") or "", safe="")
    pw = urllib.parse.quote(dev.get("password") or "", safe="")
    port = int(dev.get("port") or 554)
    return f"rtsp://{user}:{pw}@{dev.get('ip')}:{port}/cam/playback?channel={ch}&starttime={start}&endtime={end}"


def _export_preflight(dev, start, end):
    """Checks made before any DVR traffic: time range, server disk space, and that the DVR
    answers on its RTSP port. Returns (duration_seconds, error_message)."""
    if not dev.get("ip"):
        return 0, "This DVR/NVR has no IP address saved. Edit the device in DVR Setup."
    try:
        t0 = datetime.strptime(start, "%Y_%m_%d_%H_%M_%S")
        t1 = datetime.strptime(end, "%Y_%m_%d_%H_%M_%S")
    except ValueError:
        return 0, "Start or end time is not a valid date and time."
    dur = (t1 - t0).total_seconds()
    if dur <= 0:
        return 0, "End time must be after start time."
    if dur > EXPORT_MAX_SECONDS:
        return 0, "The range is longer than 24 hours. Export it in parts."
    try:
        free = shutil.disk_usage(EXPORT_DIR).free
    except OSError as exc:
        return 0, f"Export folder on the server is not accessible: {exc}"
    if free < EXPORT_MIN_FREE_BYTES:
        return 0, "Not enough free disk space on the server for an export (at least 1 GB is needed)."
    port = int(dev.get("port") or 554)
    try:
        with socket.create_connection((dev["ip"], port), timeout=3):
            pass
    except OSError as exc:
        reason = exc.strerror or str(exc)
        return 0, f"Cannot reach the DVR/NVR at {dev['ip']}:{port} ({reason}). Check power, the network cable, and the RTSP port."
    return dur, ""


def _export_classify(err):
    """Turn raw ffmpeg output into a message a person can act on."""
    e = (err or "").lower()
    if "stalled" in e:
        return "The DVR/NVR stopped sending video. Check the network and the DVR, then retry."
    if "unauthorized" in e or "401" in e or "authorization" in e:
        return "The DVR/NVR refused the login. Check the username and password in DVR Setup."
    if "404" in e:
        return "This DVR/NVR does not offer RTSP playback at this path (404). Check the firmware."
    if "could not find tag" in e or "codec not currently supported" in e:
        return "A recorded stream could not be saved to MP4 (unsupported codec). Please report this with the server log."
    if "stream map" in e or "matches no streams" in e:
        return "The DVR/NVR returned no video for this channel and range. There may be no recording there."
    if "connection refused" in e or "timed out" in e or "no route" in e or "unreachable" in e:
        return "Lost the connection to the DVR/NVR during the export. Check the network, then retry."
    if "could not start" in e:
        return "ffmpeg could not be started on the server. Check that ffmpeg is installed."
    return "The DVR/NVR did not return a usable recording for this range. Try a different time range or retry."


def _export_ffmpeg(job, part, transport):
    """One ffmpeg pull from the DVR. Updates job progress live. Returns (ok, error_text)."""
    dev, ch, start, end = job["_dev"], job["channel"], job["start"], job["end"]
    dur = float(job["duration"])
    t0 = datetime.strptime(start, "%Y_%m_%d_%H_%M_%S")
    cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-nostats", "-loglevel", "error",
           "-progress", "pipe:1", "-rtsp_transport", transport, *ff_timeout_args(15000000),
           "-i", _export_url(dev, ch, start, end),
           "-t", str(int(dur)),
           "-map", "0:v:0", "-c:v", "copy",                 # video: stream copy, original quality
           "-map", "0:a:0?", "-c:a", "aac", "-b:a", "96k",  # audio: G.711 etc. to AAC so the MP4 plays everywhere
           "-metadata", f"title=IDP i recording CH{ch}",
           "-metadata", f"comment=DVR local time {start} to {end}",
           "-movflags", "+faststart", "-f", "mp4", "-y", str(part)]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1, errors="replace")
    except OSError as exc:
        return False, f"ffmpeg could not start: {exc}"
    job["_proc"] = proc
    err_lines = []

    def _drain_stderr():
        for ln in proc.stderr:
            err_lines.append(ln)
            if len(err_lines) > 200:
                del err_lines[:100]

    drain = threading.Thread(target=_drain_stderr, daemon=True)
    drain.start()
    finished = threading.Event()

    def _watchdog():
        while not finished.wait(2):
            if job["_cancel"]:
                proc.kill()
                return
            if time.time() - job["_last_progress"] > EXPORT_STALL_SECONDS:
                job["_stalled"] = True
                proc.kill()
                return

    threading.Thread(target=_watchdog, daemon=True).start()
    out_us, size, t_begin = 0, 0, time.time()
    try:
        for line in proc.stdout:
            key, _, val = line.strip().partition("=")
            if key == "out_time_us":
                try:
                    us = int(val)
                except ValueError:
                    continue
                if us > out_us:
                    out_us = us
                    job["_last_progress"] = time.time()
            elif key == "total_size":
                try:
                    size = int(val)
                except ValueError:
                    pass
            elif key == "progress":
                sec = max(0.0, out_us / 1e6)
                elapsed = max(0.5, time.time() - t_begin)
                speed = sec / elapsed                      # media seconds per real second
                pct = min(99.0, sec / dur * 100.0) if dur > 0 else 0.0
                eta = int((dur - sec) / speed) if speed > 0.05 and sec > 0 else None
                _export_set(job, percent=round(pct, 1), out_seconds=round(sec, 1), size=size,
                            eta_seconds=eta, message=f"Exporting from the DVR/NVR ({transport.upper()})…")
    finally:
        finished.set()
    proc.wait()
    drain.join(timeout=3)
    if job["_cancel"]:
        return False, "cancelled"
    if job.get("_stalled"):
        return False, f"stalled: no data from the DVR/NVR for {EXPORT_STALL_SECONDS} seconds"
    if proc.returncode == 0 and part.is_file() and part.stat().st_size > 1000:
        return True, ""
    err = _URL_PW.sub("rtsp://***@", "".join(err_lines)).strip()
    return False, err or f"ffmpeg exited with code {proc.returncode} and no output"


def _export_run(job_id):
    """Worker thread: runs the export (with one automatic retry on the other transport)."""
    job = EXPORT_JOBS.get(job_id)
    if job is None:
        return
    part = EXPORT_DIR / (job["_token"] + ".part.mp4")
    final = EXPORT_DIR / (job["_token"] + ".mp4")
    succeeded, last_err = False, ""
    try:
        with EXPORT_SEM:
            for attempt, transport in enumerate(EXPORT_ATTEMPTS, 1):
                if job["_cancel"]:
                    break
                _export_set(job, state="running", attempt=attempt, transport=transport, percent=0.0,
                            out_seconds=0.0, size=0, eta_seconds=None, error="", _stalled=False,
                            message=f"Connecting to the DVR/NVR ({transport.upper()})…")
                job["_last_progress"] = time.time()
                ok, err = _export_ffmpeg(job, part, transport)
                if ok:
                    succeeded = True
                    break
                last_err = err
                EXPORT_LOG.warning("job %s attempt %d (%s) failed: %s", job_id, attempt, transport, err[-500:])
                part.unlink(missing_ok=True)
        if job["_cancel"]:
            part.unlink(missing_ok=True)
            _export_set(job, state="cancelled", percent=0.0, eta_seconds=None, message="Export cancelled.")
            EXPORT_LOG.info("job %s cancelled by user", job_id)
        elif succeeded:
            os.replace(part, final)
            size = final.stat().st_size
            got = job["out_seconds"]
            note = ""
            if job["duration"] and got < job["duration"] * 0.9:
                note = f" Only {got / 60:.0f} of {job['duration'] / 60:.0f} minutes were recorded in this range."
            with EXPORT_LOCK:
                _export_sweep_locked()
                EXPORT_TOKENS[job["_token"]] = {"path": final, "uid": job["uid"], "dev": job["dev"],
                                                "name": job["filename"], "exp": time.time() + EXPORT_TTL}
            audit("recording.export", job["_user"], job["dev"],
                  f"ch{job['channel']} {job['start']} -> {job['end']} ({size} bytes)")
            _export_set(job, state="done", percent=100.0, size=size, eta_seconds=0,
                        download="/downloads/" + job["_token"],
                        message=f"Clip ready ({size // 1024} KB). Download starting.{note}")
            EXPORT_LOG.info("job %s done: %d bytes, %.0fs, attempt %d (%s)", job_id, size, got,
                            job["attempt"], job["transport"])
        else:
            reason = _export_classify(last_err)
            _export_set(job, state="error", eta_seconds=None, error=reason,
                        message="Export failed. " + reason)
            EXPORT_LOG.error("job %s failed after %d attempt(s): %s | ffmpeg: %s",
                             job_id, job["attempt"], reason, last_err[-800:])
    except Exception as exc:                   # never leave a job stuck in "running"
        part.unlink(missing_ok=True)
        EXPORT_LOG.exception("job %s crashed", job_id)
        _export_set(job, state="error", eta_seconds=None, error=f"internal error: {exc}",
                    message="Export failed (internal server error). See the server log.")
    finally:
        with EXPORT_LOCK:
            if EXPORT_BY_KEY.get(job["_key"]) == job_id:
                EXPORT_BY_KEY.pop(job["_key"], None)


def _export_start(me_u, did, data):
    """Validate, check the DVR and disk, then start a background export. Returns (http_status, payload)."""
    dev = DEVICES[did]
    try:
        ch = int(data.get("channel") or 1)
    except (TypeError, ValueError):
        return 400, {"ok": False, "message": "Channel must be a number."}
    if ch < 1 or ch > 16 or (dev.get("channels") and ch > int(dev["channels"])):
        return 400, {"ok": False, "message": f"Channel {ch} does not exist on {dev.get('name') or 'this DVR/NVR'}."}
    start = str(data.get("start", "")).strip()
    end = str(data.get("end", "")).strip()
    if not (EXPORT_TIME_RE.fullmatch(start) and EXPORT_TIME_RE.fullmatch(end)):
        return 400, {"ok": False, "message": "Time must look like YYYY_MM_DD_HH_MM_SS."}
    uid = me_u.get("id") or ""
    key = (uid, did, ch, start, end)

    def _already_running_locked():
        active = EXPORT_BY_KEY.get(key)
        if active and EXPORT_JOBS.get(active, {}).get("state") in ("queued", "running"):
            return active
        return None

    with EXPORT_LOCK:
        active = _already_running_locked()
        if active:
            return 200, {"ok": True, "job_id": active, "job": _export_public(EXPORT_JOBS[active]),
                         "message": "This export is already running. Showing its progress."}
    dur, err = _export_preflight(dev, start, end)
    if err:
        EXPORT_LOG.warning("preflight failed dev=%s ch=%s: %s", did, ch, err)
        return 400, {"ok": False, "message": err}
    now = time.time()
    job_id = _secrets.token_hex(8)
    job = {
        "id": job_id, "uid": uid, "dev": did, "dev_name": dev.get("name") or did,
        "channel": ch, "start": start, "end": end, "duration": int(dur),
        "state": "queued", "percent": 0.0, "out_seconds": 0.0, "size": 0, "eta_seconds": None,
        "attempt": 0, "transport": "", "message": "Waiting for a free export slot…", "error": "",
        "filename": "idpi_ch%d_%s_%s.mp4" % (ch, start, end), "download": "",
        "created": now, "updated": now,
        "_dev": dict(dev), "_user": me_u.get("username") or "", "_key": key,
        "_token": _secrets.token_urlsafe(24), "_cancel": False, "_proc": None,
        "_stalled": False, "_last_progress": now,
    }
    with EXPORT_LOCK:
        _export_jobs_sweep_locked()
        active = _already_running_locked()
        if active:
            return 200, {"ok": True, "job_id": active, "job": _export_public(EXPORT_JOBS[active]),
                         "message": "This export is already running. Showing its progress."}
        EXPORT_JOBS[job_id] = job
        EXPORT_BY_KEY[key] = job_id
    EXPORT_LOG.info("job %s queued: user=%s dev=%s ch=%d %s -> %s (%ds)",
                    job_id, job["_user"], did, ch, start, end, int(dur))
    threading.Thread(target=_export_run, args=(job_id,), daemon=True).start()
    return 202, {"ok": True, "job_id": job_id, "job": _export_public(job), "message": "Export started."}


def _send_file_ranged(handler, fpath, name):
    """Stream a file to the browser with HTTP Range support (needed to seek video on phones).
    Reads in small chunks, so large clips never sit whole in memory."""
    size = fpath.stat().st_size
    start, end, status = 0, size - 1, 200
    rng = (handler.headers.get("Range") or "").strip()
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng) if rng else None
    if m and size > 0 and (m.group(1) or m.group(2)):
        a, b = m.group(1), m.group(2)
        if a == "":
            start = max(0, size - int(b))           # suffix range: last N bytes
        else:
            start = int(a)
            end = min(int(b), size - 1) if b else size - 1
        if start >= size or start > end:
            handler.send_response(416)
            handler.send_header("Content-Range", f"bytes */{size}")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        status = 206
    length = end - start + 1
    handler.send_response(status)
    handler.send_header("Content-Type", "video/mp4")
    handler.send_header("Accept-Ranges", "bytes")
    handler.send_header("Content-Length", str(length))
    if status == 206:
        handler.send_header("Content-Range", f"bytes {start}-{end}/{size}")
    handler.send_header("Content-Disposition", f'attachment; filename="{name}"')
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    if handler.command == "HEAD":
        return
    try:
        with open(fpath, "rb") as fh:
            fh.seek(start)
            left = length
            while left > 0:
                chunk = fh.read(min(262144, left))
                if not chunk:
                    break
                handler.wfile.write(chunk)
                left -= len(chunk)
    except (BrokenPipeError, ConnectionResetError):
        pass  # the viewer stopped or seeked elsewhere


VIEWER_GET_OK = {
    "/", "/index.html", "/login", "/favicon.ico",
    "/api/devices", "/api/snapshot", "/api/frame", "/api/live", "/api/live-direct",
    "/api/telegram-status", "/api/me",
}
VIEWER_GET_PREFIX = ("/api/ai/status", "/api/ai/events", "/api/ai/image", "/api/ai/live-faces", "/downloads/", "/api/export-status")
VIEWER_POST_OK = {
    "/api/logout", "/api/playback-url", "/api/playback-export", "/api/export-cancel", "/api/device-select",
}


def role_allows(role, method, path):
    if role == "admin":
        return True
    path = path.split("?")[0]
    if method == "GET":
        if path in VIEWER_GET_OK:
            return True
        return any(path.startswith(pref) for pref in VIEWER_GET_PREFIX)
    if method == "POST":
        return path in VIEWER_POST_OK
    return False


users_load()


# ---------------------------------------------------------------- settings / state
AI_DEFAULTS = {
    "dvr_interval": 60,          # sec — DVR online/offline check
    "health_interval": 300,      # sec — snapshot + AI check of every camera
    "gate_interval": 5,          # sec — gate cameras
    "face_interval": 4,          # sec — face cameras
    "confirm_scans": 2,          # same problem in this many scans in a row => alert
    "dvr_fail_threshold": 3,     # failed checks in a row => DVR offline alert
    "blur_threshold": 60.0, "dark_threshold": 35.0, "bright_threshold": 225.0,
    "uniform_threshold": 8.0, "angle_threshold": 0.45,
    "gate_open_alert_min": 10, "after_hours_start": "22:00", "after_hours_end": "06:00",
    "face_match_threshold": 0.363, "face_cooldown_min": 10,
    "face_alert_unknown": 1, "face_notify_known": 0, "face_notify_vip": 1,
    "face_master": 1,
    "face_schedule_start": "",
    "face_schedule_end": "",
    "notify_recovery": 1, "bot_commands": 1,
    # shutter / gate
    "gate_confirm_sec": 30,                 # new state must last this long before it counts (people walking past)
    "gate_msg_open": "{site} site shutter opened at {time}",
    "gate_msg_closed": "{site} site shutter closed at {time}",
    "gate_learn_closed_at": "",             # e.g. 08:00 - learn the CLOSED picture automatically at this time
    "gate_learn_open_at": "",               # e.g. 13:00 - learn the OPEN picture automatically at this time
    # hourly reports
    "report_telegram": 0,                   # send a short summary of every hourly report to Telegram
    "report_keep_days": 90,
    # live video + live face recognition
    "live_fps": 10,              # frames per second sent to the browser
    "face_live_fps": 3,          # face checks per second on each live face camera
    "face_min_size": 36,         # smallest face (pixels) the AI will try to recognise
    "face_gone_sec": 6,          # person not seen for this long => "left"; seen again => new arrival
    "face_hd": 1,                # face cameras use the HD main stream (better recognition)
}
AI = {"settings": {}, "cameras": {}, "faces": [], "tg_offset": 0}


def ai_load():
    try:
        if AI_STATE_PATH.is_file():
            data = json.loads(AI_STATE_PATH.read_text(encoding="utf-8"))
            for k in AI:
                if k in data:
                    AI[k] = data[k]
        # Face recognition is ON for every camera unless the user switched it off by hand
        for c in AI["cameras"].values():
            if not c.get("face_set"):
                c["face"] = 1
    except Exception as exc:
        print("[IDP i AI] state load error:", exc)


def ai_save():
    with AI_LOCK:
        try:
            tmp = AI_STATE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(AI, indent=1), encoding="utf-8")
            tmp.replace(AI_STATE_PATH)
        except Exception as exc:
            print("[IDP i AI] state save error:", exc)


def aiS(k):
    d = AI_DEFAULTS.get(k)
    v = AI["settings"].get(k, d)
    try:
        if isinstance(d, bool) or isinstance(d, int):
            return int(float(v))
        if isinstance(d, float):
            return float(v)
    except (TypeError, ValueError):
        return d
    return v


def cam_cfg(dev_id, ch):
    key = f"{dev_id}:{ch}"
    with AI_LOCK:
        c = AI["cameras"].get(key)
        if c is None:
            c = AI["cameras"][key] = {
                "name": f"Channel {ch}", "location": "", "face": 1, "gate": 0, "gate_roi": None,
                "gate_state": "unknown", "gate_since": 0, "gate_long": 0,
                "status": "unknown", "issues": [], "score": None, "last_check": 0, "last_ok": 0,
                "blur": None, "brightness": None, "similarity": None, "night": 0,
            }
        return c


def dev_channels(dev):
    chans = dev.get("detected") or list(range(1, int(dev.get("channels") or 0) + 1))
    return [int(c) for c in chans if str(c).isdigit() or isinstance(c, int)]


def dev_location(dev):
    return (dev.get("location") or "").strip() or dev.get("name") or dev.get("ip") or "DVR"


def where_text(dev, ch=None):
    if not dev:
        return "System"
    parts = [dev_location(dev)]
    if ch:
        c = cam_cfg(dev["id"], ch)
        parts.append(f"{c.get('name') or 'Channel ' + str(ch)} (CH{ch})" + (f" · {c['location']}" if c.get("location") else ""))
    return " · ".join(parts)


# ---------------------------------------------------------------- DVR access (Basic + Digest, no proxy)
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class AuthError(Exception):
    pass


def _http_open(url, headers, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "IDP-i/1.0", **headers})
    with _DIRECT.open(req, timeout=timeout) as r:
        return r.read(), (r.headers.get("Content-Type") or "").lower()


def _digest_header(chal, url, user, pw):
    p = {m[0].lower(): (m[1] or m[2]) for m in re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]*))', chal)}
    realm, nonce = p.get("realm", ""), p.get("nonce", "")
    algo = (p.get("algorithm") or "MD5").upper()
    hf = hashlib.sha256 if algo.startswith("SHA-256") else hashlib.md5
    H = lambda s: hf(s.encode()).hexdigest()  # noqa: E731
    pu = urllib.parse.urlparse(url)
    uri = pu.path + ("?" + pu.query if pu.query else "")
    cnonce, nc = uuid.uuid4().hex[:16], "00000001"
    ha1 = H(f"{user}:{realm}:{pw}")
    if algo.endswith("-SESS"):
        ha1 = H(f"{ha1}:{nonce}:{cnonce}")
    ha2 = H(f"GET:{uri}")
    if p.get("qop"):
        resp = H(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
        hdr = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
               f'algorithm={algo}, response="{resp}", qop=auth, nc={nc}, cnonce="{cnonce}"')
    else:
        resp = H(f"{ha1}:{nonce}:{ha2}")
        hdr = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"'
    if p.get("opaque"):
        hdr += f', opaque="{p["opaque"]}"'
    return hdr


_AUTH_SCHEME = {}   # "ip:port" -> "basic" | "digest" | "none"


def http_fetch(url, user, pw, timeout=5):
    """Log in to the DVR web port exactly the way it asks for.

    CP PLUS / Dahua DVRs count every rejected login as a failed attempt and LOCK the account
    after a few (then RTSP live video is refused too). So: ask once without a password to learn
    the login type, then send only that type. Basic is never sent to a Digest-only DVR."""
    host = urllib.parse.urlsplit(url).netloc
    basic = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
    scheme = _AUTH_SCHEME.get(host)
    if scheme == "basic":
        try:
            return _http_open(url, basic, timeout)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            _AUTH_SCHEME.pop(host, None)
            raise AuthError("Wrong username/password")
    if scheme == "none":
        try:
            return _http_open(url, {}, timeout)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            _AUTH_SCHEME.pop(host, None)
            chals = e.headers.get_all("WWW-Authenticate") or []
    else:
        try:
            data = _http_open(url, {}, timeout)       # no password: just learn what the DVR wants
            _AUTH_SCHEME[host] = "none"
            return data
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            chals = e.headers.get_all("WWW-Authenticate") or []
    dig = next((c for c in chals if c.lower().startswith("digest")), None)
    if dig:
        _AUTH_SCHEME[host] = "digest"
        try:
            return _http_open(url, {"Authorization": _digest_header(dig, url, user or "", pw or "")}, timeout)
        except urllib.error.HTTPError as e2:
            if e2.code == 401:
                raise AuthError("Wrong username/password")
            raise
    if any(c.lower().startswith("basic") for c in chals):
        _AUTH_SCHEME[host] = "basic"
        try:
            return _http_open(url, basic, timeout)
        except urllib.error.HTTPError as e3:
            if e3.code == 401:
                _AUTH_SCHEME.pop(host, None)
                raise AuthError("Wrong username/password")
            raise
    raise AuthError("Wrong username/password")


SNAP_PATHS = ["/cgi-bin/snapshot.cgi?channel={ch}", "/cgi-bin/snapshot.cgi?channel={ch}&type=1",
              "/onvif-http/snapshot?Profile_{ch}"]
_snap_path_cache = {}
_dev_sems = {}
_dev_sem_lock = threading.Lock()


def dev_sem(dev_id):
    with _dev_sem_lock:
        if dev_id not in _dev_sems:
            _dev_sems[dev_id] = threading.Semaphore(2)  # max 2 requests at a time per DVR
        return _dev_sems[dev_id]


_FFV = [None]


def ff_timeout_args(us=8000000):
    """RTSP socket timeout option: '-timeout' on ffmpeg 5+, '-stimeout' on older builds."""
    if _FFV[0] is None:
        try:
            out = subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"ffmpeg version n?(\d+)\.", out)
            _FFV[0] = int(m.group(1)) if m else 7
        except Exception:
            _FFV[0] = 7
    return ["-stimeout" if _FFV[0] < 5 else "-timeout", str(us)]


def rtsp_grab(dev, ch, timeout=8):
    """One JPEG frame straight from the RTSP stream (used when the DVR's web snapshot is off)."""
    live = LIVE.get(dev.get("id") or "", ch, create=False) if dev.get("id") in DEVICES else None
    if live is not None and live.state == "live" and live.jpeg:
        return live.jpeg
    if not shutil.which("ffmpeg") or not dev.get("ip"):
        return None
    kind, transport = rtsp_variants(False)[_RTSP_PICK.get(dev.get("id"), 0) % 4]
    cmd = (["ffmpeg", "-hide_banner", "-loglevel", "error", "-rtsp_transport", transport] + ff_timeout_args(5000000)
           + ["-i", rtsp_url(dev, ch, sub=kind == "sub"), "-frames:v", "1", "-c:v", "mjpeg", "-q:v", "4", "-f", "image2", "pipe:1"])
    try:
        with dev_sem("rtsp:" + str(dev.get("id") or dev.get("ip"))):
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except Exception:
        return None
    d = r.stdout or b""
    return d if len(d) > 500 and d[:3] == b"\xff\xd8\xff" else None


def ai_snapshot(dev, ch, timeout=5, rtsp_fallback=True):
    """JPEG bytes or None. Raises AuthError on a wrong password.
    Tries the DVR web snapshot first, then the RTSP stream."""
    first = _snap_path_cache.get(dev["id"], 0)
    order = [first] + [i for i in range(len(SNAP_PATHS)) if i != first]
    for i in order:
        url = f"http://{dev['ip']}:{int(dev.get('http_port') or 80)}{SNAP_PATHS[i].format(ch=ch)}"
        try:
            with dev_sem(dev["id"]):
                data, ctype = http_fetch(url, dev.get("username") or "", dev.get("password") or "", timeout)
        except AuthError:
            raise
        except urllib.error.HTTPError:
            continue
        except Exception:
            break  # web port not reachable — don't try other web paths
        if data and len(data) > 500 and (data[:3] == b"\xff\xd8\xff" or "image" in ctype):
            _snap_path_cache[dev["id"]] = i
            return data
    return rtsp_grab(dev, ch) if rtsp_fallback else None


def tcp_ok(ip, port, timeout=3.0):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- Telegram (alerts + photos + bot)
def tg_chats():
    return [c.strip() for c in str(TELEGRAM_CONFIG.get("chat_id") or "").split(",") if c.strip()]


def _multipart(fields, files):
    b = "----idpi" + uuid.uuid4().hex
    out = io.BytesIO()
    for k, v in fields.items():
        out.write(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, (fn, data, mime) in files.items():
        out.write(f'--{b}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\nContent-Type: {mime}\r\n\r\n'.encode())
        out.write(data + b"\r\n")
    out.write(f"--{b}--\r\n".encode())
    return out.getvalue(), f"multipart/form-data; boundary={b}"


def tg_api(method, fields=None, files=None, timeout=25):
    token = TELEGRAM_CONFIG.get("bot_token") or ""
    if not token:
        return False, "Telegram bot token is not set."
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        if files:
            body, ctype = _multipart(fields or {}, files)
        else:
            body, ctype = json.dumps(fields or {}).encode(), "application/json"
        req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read().decode("utf-8"))
        return bool(res.get("ok")), res
    except urllib.error.HTTPError as e:
        try:
            return False, json.loads(e.read().decode()).get("description", f"HTTP {e.code}")
        except Exception:
            return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"Could not reach Telegram: {e}"


def tg_send(text, chats=None):
    ok_any, last = False, "No chat ID"
    for c in chats or tg_chats():
        ok, last = tg_api("sendMessage", {"chat_id": c, "text": text[:4000], "disable_web_page_preview": True})
        ok_any = ok_any or ok
    return ok_any, last


def tg_photo(caption, img, chats=None):
    ok_any = False
    for c in chats or tg_chats():
        ok, _ = tg_api("sendPhoto", {"chat_id": c, "caption": caption[:1000]}, {"photo": ("snap.jpg", img, "image/jpeg")})
        if not ok:
            ok, _ = tg_api("sendMessage", {"chat_id": c, "text": caption[:4000]})
        ok_any = ok_any or ok
    return ok_any


# ---------------------------------------------------------------- events
EVENT_LABEL = {
    "DVR_OFFLINE": "DVR OFFLINE", "DVR_ONLINE": "DVR back ONLINE", "DVR_AUTH": "DVR LOGIN FAILED",
    "CAMERA_OFFLINE": "CAMERA OFFLINE", "CAMERA_ONLINE": "Camera back ONLINE",
    "NO_VIDEO": "CAMERA FAULTY / NO VIDEO", "BLUR": "CAMERA BLURRY", "TOO_DARK": "CAMERA TOO DARK",
    "OVEREXPOSED": "CAMERA OVER-EXPOSED", "ANGLE_CHANGE": "CAMERA ANGLE CHANGED", "FROZEN": "CAMERA FROZEN / HUNG",
    "ISSUE_CLEARED": "Camera problem resolved",
    "GATE_OPEN": "GATE OPENED", "GATE_CLOSED": "GATE CLOSED", "GATE_OPEN_LONG": "GATE OPEN TOO LONG",
    "FACE_WATCHLIST": "WATCHLIST PERSON SEEN", "FACE_VIP": "VIP ARRIVED", "FACE_KNOWN": "Known person seen",
    "FACE_UNKNOWN": "UNKNOWN PERSON SEEN", "SYSTEM": "System",
}
ISSUE_TEXT = {
    "NO_VIDEO": "Camera faulty — no video (black/blank picture or lens covered)",
    "BLUR": "Picture is blurry", "TOO_DARK": "Picture is too dark",
    "OVEREXPOSED": "Picture is too bright / over-exposed",
    "ANGLE_CHANGE": "Camera angle has changed (possible tampering)", "FROZEN": "Picture is frozen (camera/DVR hung)",
}
ISSUE_FIX = {
    "OFFLINE": "Check the camera power adapter, cable/BNC connector and DVR channel.",
    "NO_VIDEO": "Check on site: lens covered, camera lost power, or faulty camera / night IR.",
    "BLUR": "Clean the lens (dust, cobwebs, water marks) and adjust the focus.",
    "TOO_DARK": "Check the IR LEDs / lighting and that IR turns on at night.",
    "OVEREXPOSED": "Direct sun/light is hitting the lens — change the angle or WDR/BLC setting.",
    "ANGLE_CHANGE": "Camera has moved — possible tampering. Set it back, then click 'Reset angle'.",
    "FROZEN": "Same picture keeps repeating — reboot the DVR/camera.",
}
ISSUE_SEV = {"NO_VIDEO": "CRITICAL", "ANGLE_CHANGE": "CRITICAL", "FROZEN": "WARNING",
             "BLUR": "WARNING", "TOO_DARK": "WARNING", "OVEREXPOSED": "WARNING"}
ISSUE_PENALTY = {"NO_VIDEO": 100, "ANGLE_CHANGE": 45, "FROZEN": 60, "BLUR": 35, "TOO_DARK": 25, "OVEREXPOSED": 20}
SEV_ICON = {"CRITICAL": "🔴", "WARNING": "🟠", "INFO": "🟢"}

AI_EVENTS = []
AI_EVENT_SEQ = [0]
TG_QUEUE = queue.Queue()


def ai_event(etype, severity, dev=None, ch=None, details="", image=None, notify=True, extra=None):
    with AI_LOCK:
        AI_EVENT_SEQ[0] += 1
        eid = AI_EVENT_SEQ[0]
    img_name = ""
    if image:
        img_name = f"snaps/ev{eid}_{uuid.uuid4().hex[:6]}.jpg"
        try:
            (AI_DIR / img_name).write_bytes(image)
        except Exception:
            img_name = ""
    cam = cam_cfg(dev["id"], ch) if (dev and ch) else None
    e = {"id": eid, "ts": time.time(), "time": datetime.now().strftime("%d %b %Y %H:%M:%S"),
         "type": etype, "severity": severity, "title": EVENT_LABEL.get(etype, etype),
         "site": dev_location(dev) if dev else "System", "dvr": (dev or {}).get("name", ""),
         "dvr_id": (dev or {}).get("id", ""), "ch": ch, "camera": cam["name"] if cam else "",
         "cam_location": cam["location"] if cam else "", "where": where_text(dev, ch),
         "details": details, "image": img_name, **(extra or {})}
    with AI_LOCK:
        AI_EVENTS.append(e)
        if len(AI_EVENTS) > 1000:
            del AI_EVENTS[:200]
    try:
        with open(AI_EVENTS_LOG, "a", encoding="utf-8") as f:
            f.write(f"{e['time']} [{severity}] {e['title']} | {e['where']} | {details}\n".replace("\n", " ") + "\n")
    except Exception:
        pass
    print(f"[IDP i AI] {SEV_ICON.get(severity, '')} {e['title']} — {e['where']} — {details}".replace("\n", " "))
    if notify and tg_chats() and TELEGRAM_CONFIG.get("bot_token"):
        TG_QUEUE.put((e, image))
    _cleanup_snaps()
    return e


def _cleanup_snaps(keep=600):
    files = sorted(AI_DIRS["snaps"].glob("ev*.jpg"), key=lambda p: p.stat().st_mtime)
    for p in files[:-keep]:
        p.unlink(missing_ok=True)


def format_alert(e):
    lines = [f"{SEV_ICON.get(e['severity'], '')} {e['title']}",
             f"📍 Location: {e['where']}"]
    if e["dvr"]:
        lines.append(f"🖥 DVR: {e['dvr']}")
    if e["details"]:
        lines.append(f"ℹ️ {e['details']}")
    lines += [f"🕒 {e['time']}", f"— {APP_NAME} AI · 24/7 monitoring"]
    return "\n".join(lines)


def telegram_worker():
    while True:
        e, img = TG_QUEUE.get()
        batch = [(e, img)]
        time.sleep(1.5)  # let a burst collect
        while not TG_QUEUE.empty() and len(batch) < 200:
            batch.append(TG_QUEUE.get())
        try:
            if len(batch) > 12:  # many at once (power/network outage) => one digest message
                lines = [f"⚠️ {APP_NAME} ALERT DIGEST — {len(batch)} alerts at once ({datetime.now():%d %b %H:%M})"]
                for be, _ in batch[:40]:
                    lines.append(f"{SEV_ICON.get(be['severity'], '')} {be['title']} — {be['where']}")
                if len(batch) > 40:
                    lines.append(f"… and {len(batch) - 40} more. See the dashboard → Alerts.")
                tg_send("\n".join(lines))
            else:
                for be, bimg in batch:
                    if bimg:
                        tg_photo(format_alert(be), bimg)
                    else:
                        tg_send(format_alert(be))
                    time.sleep(0.4)
        except Exception as exc:
            print("[IDP i AI] Telegram error:", exc)


# ---------------------------------------------------------------- image AI
def decode_jpeg(b):
    if not CV_OK or not b:
        return None
    return cv2.imdecode(np.frombuffer(b, np.uint8), cv2.IMREAD_COLOR)


def encode_jpeg(img, q=82):
    ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, q])
    return buf.tobytes() if ok else None


def is_night(img):
    small = cv2.resize(img, (64, 48), interpolation=cv2.INTER_AREA)
    return float(cv2.cvtColor(small, cv2.COLOR_BGR2HSV)[..., 1].mean()) < 14  # IR mode = black & white


def _norm(a):
    a = a.astype(np.float32)
    return (a - a.mean()) / (a.std() + 1e-6)


def grad_sig(gray, size=(80, 60)):
    s = cv2.resize(gray, size, interpolation=cv2.INTER_AREA)
    s = cv2.GaussianBlur(cv2.equalizeHist(s), (3, 3), 0)
    return cv2.magnitude(cv2.Sobel(s, cv2.CV_32F, 1, 0), cv2.Sobel(s, cv2.CV_32F, 0, 1))


def similarity(a, b):
    if a is None or b is None or a.shape != b.shape:
        return None
    return float(cv2.matchTemplate(a.astype(np.float32), b.astype(np.float32), cv2.TM_CCOEFF_NORMED)[0][0])


def ref_path(dev_id, ch, kind):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", f"{dev_id}_{ch}_{kind}")
    return AI_DIRS["refs"] / f"{safe}.npz"


def load_ref(dev_id, ch, kind):
    p = ref_path(dev_id, ch, kind)
    if not p.is_file():
        return None
    try:
        z = np.load(p)
        return {"sig": z["sig"], "blur": float(z["blur"])}
    except Exception:
        return None


def save_ref(dev_id, ch, kind, sig, blur=0.0):
    np.savez(ref_path(dev_id, ch, kind), sig=sig, blur=np.float32(blur))


def clear_refs(dev_id, ch, prefix):
    for p in AI_DIRS["refs"].glob(re.sub(r"[^A-Za-z0-9_-]", "", f"{dev_id}_{ch}_{prefix}") + "*"):
        p.unlink(missing_ok=True)


def analyze_frame(img, dev_id, ch):
    h, w = img.shape[:2]
    if w > 640:
        img = cv2.resize(img, (640, int(h * 640 / w)), interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    bright, contrast = float(gray.mean()), float(gray.std())
    blur = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    night = is_night(img)
    issues, sim = [], None
    if contrast < aiS("uniform_threshold") and (blur < 4 or contrast < 3):
        issues.append("NO_VIDEO")  # single colour / black / blue screen = camera faulty or lens covered
    elif contrast < aiS("uniform_threshold"):
        issues.append("TOO_DARK" if bright < 128 else "OVEREXPOSED")
    else:
        kind = "angle_night" if night else "angle_day"
        ref = load_ref(dev_id, ch, kind)
        bt = aiS("blur_threshold") * (0.6 if night else 1.0)
        if blur < bt or (ref and ref["blur"] > 0 and blur < 0.3 * ref["blur"] and blur < 2.5 * bt):
            issues.append("BLUR")
        if bright < aiS("dark_threshold"):
            issues.append("TOO_DARK")
        elif bright > aiS("bright_threshold"):
            issues.append("OVEREXPOSED")
        sig = grad_sig(gray)
        if ref is None:
            if not issues:
                save_ref(dev_id, ch, kind, sig, blur)  # first healthy picture = correct angle
        else:
            sim = similarity(sig, ref["sig"])
            if sim is not None and sim < aiS("angle_threshold"):
                issues.append("ANGLE_CHANGE")
    return {"brightness": round(bright, 1), "blur": round(blur, 1), "night": int(night),
            "similarity": None if sim is None else round(sim, 3), "issues": issues}


def gate_sig(img, roi):
    h, w = img.shape[:2]
    x, y, rw, rh = [float(v) for v in (roi or [0, 0, 1, 1])]
    x0, y0 = int(max(0, x) * w), int(max(0, y) * h)
    x1, y1 = int(min(1, x + rw) * w), int(min(1, y + rh) * h)
    crop = img[y0:max(y0 + 8, y1), x0:max(x0 + 8, x1)]
    g = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
    g = cv2.GaussianBlur(cv2.equalizeHist(cv2.resize(g, (96, 96), interpolation=cv2.INTER_AREA)), (5, 5), 0)
    return np.hstack([_norm(g), _norm(cv2.magnitude(cv2.Sobel(g, cv2.CV_32F, 1, 0), cv2.Sobel(g, cv2.CV_32F, 0, 1)))])



def face_ai_active_now():
    """Global Face AI master switch + optional daily time window (HH:MM to HH:MM)."""
    if not int(aiS("face_master") or 0):
        return False
    s = str(aiS("face_schedule_start") or "").strip()
    e = str(aiS("face_schedule_end") or "").strip()
    if not s and not e:
        return True
    if not (re.match(r"^\d\d:\d\d$", s) and re.match(r"^\d\d:\d\d$", e)):
        return True
    tnow = datetime.now().strftime("%H:%M")
    if s > e:
        return s <= tnow or tnow < e
    return s <= tnow < e


def in_after_hours():
    try:
        s, e = aiS("after_hours_start"), aiS("after_hours_end")
        t = datetime.now().strftime("%H:%M")
        return (s <= t or t < e) if s > e else (s <= t < e)
    except Exception:
        return False


def fmt_dur(sec):
    sec = int(max(0, sec or 0))
    if sec < 60:
        return f"{sec} sec"
    if sec < 3600:
        return f"{sec // 60} min"
    if sec < 86400:
        return f"{sec // 3600} h {(sec % 3600) // 60} min"
    return f"{sec // 86400} days {(sec % 86400) // 3600} h"


def find_changed_area(a, b):
    """Area that differs most between two grey pictures (gate open vs closed) -> [x, y, w, h] fractions or None."""
    if a.shape != b.shape:
        b = cv2.resize(b, (a.shape[1], a.shape[0]))
    if a.shape[1] > 640:
        nh = int(a.shape[0] * 640 / a.shape[1])
        a, b = cv2.resize(a, (640, nh)), cv2.resize(b, (640, nh))
    h, w = a.shape[:2]
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    d = cv2.absdiff(cv2.GaussianBlur(clahe.apply(a), (9, 9), 0), cv2.GaussianBlur(clahe.apply(b), (9, 9), 0))
    if float(d.mean()) < 3:
        return None
    _, m = cv2.threshold(d, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    m = cv2.morphologyEx(m, cv2.MORPH_OPEN, np.ones((5, 5), np.uint8))
    m = cv2.morphologyEx(m, cv2.MORPH_CLOSE, np.ones((25, 25), np.uint8))
    cnts, _ = cv2.findContours(m, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not cnts:
        return None
    c = max(cnts, key=cv2.contourArea)
    area = cv2.contourArea(c) / float(h * w)
    if area < 0.02 or area > 0.85:      # nothing changed / whole picture changed (light, camera moved)
        return None
    x, y, bw, bh = cv2.boundingRect(c)
    px, py = 0.02 * w, 0.02 * h
    x0, y0 = max(0, x - px) / w, max(0, y - py) / h
    x1, y1 = min(w, x + bw + px) / w, min(h, y + bh + py) / h
    return [round(x0, 4), round(y0, 4), round(x1 - x0, 4), round(y1 - y0, 4)]


def clock12(ts):
    return datetime.fromtimestamp(ts).strftime("%I:%M %p").lstrip("0")


def find_changed_area(a, b):
    """Area that differs most between two grey pictures (gate open vs closed) -> [x, y, w, h] fractions or None."""
    if a.shape != b.shape:
        b = cv2.resize(b, (a.shape[1], a.shape[0]))
    if a.shape[1] > 640:
        nh = int(a.shape[0] * 640 / a.shape[1])
        a, b = cv2.resize(a, (640, nh)), cv2.resize(b, (640, nh))
    h, w = a.shape[:2]
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    d = cv2.absdiff(cv2.GaussianBlur(clahe.apply(a), (9, 9), 0), cv2.GaussianBlur(clahe.apply(b), (9, 9), 0))
    if float(d.mean()) < 3:
        return None
    _, m = cv2.threshold(d, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    m = cv2.morphologyEx(m, cv2.MORPH_OPEN, np.ones((5, 5), np.uint8))
    m = cv2.morphologyEx(m, cv2.MORPH_CLOSE, np.ones((25, 25), np.uint8))
    cnts, _ = cv2.findContours(m, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not cnts:
        return None
    c = max(cnts, key=cv2.contourArea)
    area = cv2.contourArea(c) / float(h * w)
    if area < 0.02 or area > 0.85:      # nothing changed / whole picture changed (light, camera moved)
        return None
    x, y, bw, bh = cv2.boundingRect(c)
    px, py = 0.02 * w, 0.02 * h
    x0, y0 = max(0, x - px) / w, max(0, y - py) / h
    x1, y1 = min(w, x + bw + px) / w, min(h, y + bh + py) / h
    return [round(x0, 4), round(y0, 4), round(x1 - x0, 4), round(y1 - y0, 4)]


# ---------------------------------------------------------------- timeline + hourly reports
REPORT_DIR = AI_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
TIMELINE_PATH = AI_DIR / "timeline.jsonl"
TIMELINE_OPEN_PATH = AI_DIR / "timeline_open.json"
HEARTBEAT_PATH = AI_DIR / "heartbeat.json"
HEARTBEAT_SEC = 10
SYSTEM_OFF_AFTER = float(os.environ.get("IDPI_TEST_SYSTEM_OFF_AFTER", "60"))

# timeline kind -> report column
REPORT_COL = {"OFFLINE": "CAMERA OFF", "NO_VIDEO": "CAMERA OFF", "BLUR": "BLURRED", "ANGLE_CHANGE": "ANGLE CHANGED",
              "FROZEN": "OTHER", "TOO_DARK": "OTHER", "OVEREXPOSED": "OTHER"}
REPORT_NAME = {"OFFLINE": "CAMERA OFF", "NO_VIDEO": "CAMERA OFF (no video)", "BLUR": "BLURRED",
               "ANGLE_CHANGE": "ANGLE CHANGED", "FROZEN": "FROZEN", "TOO_DARK": "TOO DARK", "OVEREXPOSED": "TOO BRIGHT",
               "DVR_OFFLINE": "DVR OFFLINE", "GATE_OPEN": "SHUTTER OPENED", "GATE_CLOSED": "SHUTTER CLOSED"}


class Timeline:
    """Start/end of every problem (and shutter open/close moments), kept on disk for the reports."""

    def __init__(self):
        self.lock = threading.Lock()
        try:
            self.open = json.loads(TIMELINE_OPEN_PATH.read_text(encoding="utf-8"))
        except Exception:
            self.open = {}

    @staticmethod
    def _key(kind, dev_id, ch):
        return f"{kind}|{dev_id}|{ch or 0}"

    def _save_open(self):
        tmp = TIMELINE_OPEN_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.open), encoding="utf-8")
        tmp.replace(TIMELINE_OPEN_PATH)

    def _append(self, ev):
        with open(TIMELINE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")

    @staticmethod
    def _base(kind, dev, ch, t, details):
        cam = cam_cfg(dev["id"], ch) if (dev and ch) else None
        return {"kind": kind, "dev": (dev or {}).get("id", ""), "dvr": (dev or {}).get("name") or (dev or {}).get("ip", ""),
                "site": dev_location(dev) if dev else "System", "ch": ch or 0,
                "camera": cam["name"] if cam else "", "start": round(t, 1), "details": (details or "").split("\n")[0][:200]}

    def start(self, kind, dev, ch, t, details=""):
        k = self._key(kind, (dev or {}).get("id", ""), ch)
        with self.lock:
            if k in self.open:
                return
            self.open[k] = self._base(kind, dev, ch, t, details)
            self._save_open()

    def end(self, kind, dev_id, ch, t, note=""):
        k = self._key(kind, dev_id, ch)
        with self.lock:
            ev = self.open.pop(k, None)
            if not ev:
                return
            ev["end"] = round(max(t, ev["start"]), 1)
            if note:
                ev["note"] = note
            self._append(ev)
            self._save_open()

    def instant(self, kind, dev, ch, t, details=""):
        ev = self._base(kind, dev, ch, t, details)
        ev["end"] = ev["start"]
        with self.lock:
            self._append(ev)

    def add_closed(self, ev):
        with self.lock:
            self._append(ev)

    def close_all(self, t, note):
        for k in list(self.open):
            kind, dev_id, ch = k.split("|")
            self.end(kind, dev_id, int(ch), t, note)

    def events(self, a, b):
        out = []
        with self.lock:
            if TIMELINE_PATH.is_file():
                with open(TIMELINE_PATH, encoding="utf-8") as f:
                    for line in f:
                        try:
                            ev = json.loads(line)
                        except ValueError:
                            continue
                        s_, e_ = ev["start"], ev["end"]
                        if (s_ == e_ and a <= s_ < b) or (s_ < b and e_ > a):
                            out.append(ev)
            for ev in self.open.values():
                if ev["start"] < b:
                    out.append(dict(ev, end=None))
        return out

    def prune(self, before):
        with self.lock:
            if not TIMELINE_PATH.is_file():
                return
            keep = []
            with open(TIMELINE_PATH, encoding="utf-8") as f:
                for line in f:
                    try:
                        if json.loads(line)["end"] >= before:
                            keep.append(line if line.endswith("\n") else line + "\n")
                    except (ValueError, KeyError):
                        pass
            tmp = TIMELINE_PATH.with_suffix(".tmp")
            tmp.write_text("".join(keep), encoding="utf-8")
            tmp.replace(TIMELINE_PATH)


TIMELINE = Timeline()


def _hms(ts, day_end=None):
    if day_end is not None and ts >= day_end:
        return "24:00:00"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _dur(sec):
    sec = int(round(max(0, sec)))
    h, m, s_ = sec // 3600, sec % 3600 // 60, sec % 60
    return f"{h}h {m:02d}m {s_:02d}s" if h else f"{m}m {s_:02d}s"


def system_timeline(a, b, evs):
    """SYSTEM ON / OFF segments between a and b (epoch seconds)."""
    first = REPORTER.first_start or time.time()
    offs = []
    if first > a:
        offs.append((a, min(first, b), "software not started yet"))
    for ev in evs:
        if ev["kind"] == "SYSTEM_OFF":
            s_, e_ = max(ev["start"], a), min(ev["end"] or b, b)
            if e_ > s_:
                offs.append((s_, e_, ev.get("details", "")))
    offs.sort()
    out, cur = [], a
    for s_, e_, r in offs:
        if s_ > cur:
            out.append({"start": cur, "end": s_, "state": "SYSTEM ON", "reason": ""})
        if e_ > cur:
            out.append({"start": max(s_, cur), "end": e_, "state": "SYSTEM OFF", "reason": r})
        cur = max(cur, e_)
    if b > cur:
        out.append({"start": cur, "end": b, "state": "SYSTEM ON", "reason": ""})
    return out


def union_seconds(intervals):
    total, cur_s, cur_e = 0.0, None, None
    for s_, e_ in sorted(intervals):
        if cur_e is None or s_ > cur_e:
            total += (cur_e - cur_s) if cur_e is not None else 0
            cur_s, cur_e = s_, e_
        else:
            cur_e = max(cur_e, e_)
    return total + ((cur_e - cur_s) if cur_e is not None else 0)


def build_report(hour_start, dev_filter=""):
    """Everything that happened in one hour: SYSTEM ON/OFF, DVR/camera problems, shutter open/close."""
    h = hour_start.replace(minute=0, second=0, microsecond=0)
    a = h.timestamp()
    b_full = (h + timedelta(hours=1)).timestamp()
    now = time.time()
    b = min(b_full, now)
    partial = now < b_full
    evs = TIMELINE.events(a, b)
    system = system_timeline(a, b, evs)
    on_sec = sum(x["end"] - x["start"] for x in system if x["state"] == "SYSTEM ON")

    rows, gates = [], []
    for ev in evs:
        k = ev["kind"]
        if dev_filter and ev.get("dev") != dev_filter:
            continue
        if k in ("GATE_OPEN", "GATE_CLOSED"):
            gates.append(ev)
            continue
        if k not in REPORT_COL and k != "DVR_OFFLINE":
            continue
        s_, e_raw = ev["start"], ev["end"]
        s_c, e_c = max(s_, a), min(e_raw if e_raw is not None else b, b)
        if e_c <= s_c:
            continue
        rows.append({**ev, "s": s_c, "e": e_c, "earlier": s_ < a,
                     "continues": (e_raw is None or e_raw > b_full) and not partial})
    rows.sort(key=lambda r: (r["site"], r["dvr"], r["ch"], r["s"]))
    gates.sort(key=lambda g: g["start"])

    spans = {}
    for r in rows:
        col = "DVR OFFLINE" if r["kind"] == "DVR_OFFLINE" else REPORT_COL[r["kind"]]
        key = (r["site"], r["dvr"], r["ch"], r.get("camera") or ("—" if not r["ch"] else f"Channel {r['ch']}"))
        spans.setdefault(key, {}).setdefault(col, []).append((r["s"], r["e"]))
    per_cam = {}
    for key, cols in spans.items():
        for col, iv in cols.items():
            per_cam.setdefault(key, {})[col] = union_seconds(iv)    # overlapping problems are counted once
    devs = [d for d in DEVICES.values() if d.get("ip") and (not dev_filter or d["id"] == dev_filter)]
    n_cams = sum(len(dev_channels(d)) for d in devs)
    return {"hour": h, "a": a, "b": b, "b_full": b_full, "partial": partial, "created": now,
            "site": dev_location(DEVICES[dev_filter]) if dev_filter in DEVICES else "All sites",
            "system": system, "on_sec": on_sec, "rows": rows, "gates": gates, "per_cam": per_cam,
            "n_dvrs": len(devs), "n_cams": n_cams}


def report_text(R):
    h, end = R["hour"], R["hour"] + timedelta(hours=1)
    L = [f"{APP_NAME} HOURLY CCTV REPORT",
         f"Site     : {R['site']}   ({R['n_dvrs']} DVR, {R['n_cams']} cameras)",
         f"Hour     : {h:%d-%m-%Y}  {h:%H}:00 - {end:%H}:00" + ("   (PARTIAL - hour not finished)" if R["partial"] else ""),
         f"Created  : {datetime.fromtimestamp(R['created']):%d-%m-%Y %H:%M:%S}", "",
         f"SYSTEM   (on for {_dur(R['on_sec'])})"]
    for x in R["system"]:
        L.append(f"  {_hms(x['start'])} - {_hms(x['end'], R['b_full'])}   {_dur(x['end'] - x['start']):<11} "
                 f"{x['state']:<11} {x['reason']}".rstrip())
    L += ["", "SHUTTER"]
    if not R["gates"]:
        L.append("  No shutter opening or closing in this hour.")
    for g in R["gates"]:
        L.append(f"  {_hms(g['start'])}   {REPORT_NAME[g['kind']]:<15} {g['site']} / {g['camera']} (CH{g['ch']})"
                 + (f"  - {g['details']}" if g.get("details") else ""))
    L += ["", "PROBLEM SUMMARY (time with the problem in this hour)"]
    if not R["per_cam"]:
        L.append(f"  No problems - all {R['n_cams']} cameras fine.")
    else:
        L.append(f"  {'SITE / CAMERA':<44} {'DVR OFFLINE':<12} {'CAMERA OFF':<12} {'BLURRED':<12} {'ANGLE CHANGED':<14} {'OTHER':<10}")
        for (site, dvr, ch, cam), cols in sorted(R["per_cam"].items()):
            name = f"{site} / {cam}" + (f" (CH{ch})" if ch else " (whole DVR)")
            cells = [_dur(cols[c]) if cols.get(c) else "-" for c in ("DVR OFFLINE", "CAMERA OFF", "BLURRED", "ANGLE CHANGED", "OTHER")]
            L.append(f"  {name[:44]:<44} {cells[0]:<12} {cells[1]:<12} {cells[2]:<12} {cells[3]:<14} {cells[4]:<10}")
        L.append(f"  Cameras without problems: {max(0, R['n_cams'] - sum(1 for k in R['per_cam'] if k[2]))}")
    L += ["", "EVENTS"]
    if not R["rows"]:
        L.append("  No problems in this hour.")
    for r in R["rows"]:
        flags = (["started before this hour"] if r["earlier"] else []) + (["still going on at end of hour"] if r["continues"] else [])
        where = f"{r['site']} / " + (f"{r['camera']} (CH{r['ch']})" if r["ch"] else f"DVR {r['dvr']}")
        L.append(f"  {_hms(r['s'])} - {_hms(r['e'], R['b_full'])}   {_dur(r['e'] - r['s']):<11} {REPORT_NAME.get(r['kind'], r['kind']):<22} "
                 f"{where}" + (f"  - {r['details']}" if r.get("details") else "") + (f"  [{', '.join(flags)}]" if flags else ""))
    return "\n".join(L) + "\n"


def report_csv(R):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["site", "dvr", "channel", "camera", "date", "hour", "event", "start", "end", "duration_seconds",
                "started_before_hour", "continues_after_hour", "details"])
    h = R["hour"]
    hour_txt = f"{h:%H}:00-{(h + timedelta(hours=1)):%H}:00"
    for x in R["system"]:
        w.writerow(["SYSTEM", "", "", "", f"{h:%Y-%m-%d}", hour_txt, x["state"], _hms(x["start"]), _hms(x["end"], R["b_full"]),
                    int(x["end"] - x["start"]), "", "", x["reason"]])
    for g in R["gates"]:
        w.writerow([g["site"], g["dvr"], g["ch"], g["camera"], f"{h:%Y-%m-%d}", hour_txt, REPORT_NAME[g["kind"]],
                    _hms(g["start"]), _hms(g["start"]), 0, "", "", g.get("details", "")])
    for r in R["rows"]:
        w.writerow([r["site"], r["dvr"], r["ch"] or "", r.get("camera", ""), f"{h:%Y-%m-%d}", hour_txt,
                    REPORT_NAME.get(r["kind"], r["kind"]), _hms(r["s"]), _hms(r["e"], R["b_full"]), int(r["e"] - r["s"]),
                    "yes" if r["earlier"] else "", "yes" if r["continues"] else "", r.get("details", "")])
    return "\ufeff" + out.getvalue()      # BOM so Excel shows Hindi/emoji correctly


def report_telegram_text(R):
    h = R["hour"]
    lines = [f"📊 {APP_NAME} hourly report · {h:%d %b} {h:%H}:00-{(h + timedelta(hours=1)):%H}:00",
             f"🖥 System on {_dur(R['on_sec'])}" + ("" if R["on_sec"] >= 3599 else " ⚠️")]
    for g in R["gates"][:10]:
        lines.append(f"🚪 {_hms(g['start'])[:5]} {REPORT_NAME[g['kind']].lower()} — {g['site']}")
    if R["per_cam"]:
        lines.append(f"⚠️ Problems on {len(R['per_cam'])} camera(s)/DVR(s):")
        for (site, dvr, ch, cam), cols in sorted(R["per_cam"].items())[:15]:
            what = ", ".join(f"{c.lower()} {_dur(v)}" for c, v in cols.items() if v)
            lines.append(f"• {site} / {cam}" + (f" CH{ch}" if ch else "") + f": {what}")
        if len(R["per_cam"]) > 15:
            lines.append(f"… and {len(R['per_cam']) - 15} more (see the website → Reports)")
    else:
        lines.append("✅ No camera problems.")
    return "\n".join(lines)


def _day_bounds(day_txt):
    d = datetime.strptime(day_txt, "%Y-%m-%d")
    return d, d + timedelta(days=1)


def report_day_text(day_txt, dev_filter=""):
    """All hourly reports of one day in one text file."""
    d, _ = _day_bounds(day_txt)
    now = datetime.now()
    parts = []
    for i in range(24):
        h = d + timedelta(hours=i)
        if h > now:
            break
        parts.append(report_text(build_report(h, dev_filter)))
    if not parts:
        return f"No data: {day_txt} is in the future.\n"
    return ("\n" + "=" * 100 + "\n\n").join(parts)


def _range_bounds(from_txt, to_txt):
    a_dt, _ = _day_bounds(from_txt)
    _, b_dt = _day_bounds(to_txt or from_txt)
    if b_dt <= a_dt:
        raise ValueError("'To' date must be on or after 'From' date")
    if (b_dt - a_dt).days > 400:
        raise ValueError("Choose at most 400 days")
    return a_dt, b_dt


def _fmt_dt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def range_events_csv(from_txt, to_txt, dev_filter=""):
    """Every SYSTEM ON/OFF period, problem and shutter event in the date range - one row each."""
    a_dt, b_dt = _range_bounds(from_txt, to_txt)
    a, b = a_dt.timestamp(), min(b_dt.timestamp(), time.time())
    evs = TIMELINE.events(a, b) if b > a else []
    rows = []
    for x in system_timeline(a, b, evs) if b > a else []:
        rows.append((x["start"], ["SYSTEM", "", "", "", x["state"], _fmt_dt(x["start"]), _fmt_dt(x["end"]),
                                  int(x["end"] - x["start"]), "", x["reason"]]))
    for ev in evs:
        k = ev["kind"]
        if k == "SYSTEM_OFF" or (dev_filter and ev.get("dev") != dev_filter):
            continue
        if k not in REPORT_NAME:
            continue
        s_ = ev["start"]
        e_ = ev["end"] if ev["end"] is not None else b
        rows.append((s_, [ev["site"], ev["dvr"], ev["ch"] or "", ev.get("camera", ""), REPORT_NAME[k], _fmt_dt(s_),
                          _fmt_dt(e_), int(max(0, min(e_, b) - max(s_, a))),
                          "yes" if ev["end"] is None else "", ev.get("details", "")]))
    rows.sort(key=lambda r: r[0])
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["site", "dvr", "channel", "camera", "event", "start", "end", "duration_seconds_in_range",
                "still_going_on", "details"])
    for _, r in rows:
        w.writerow(r)
    return "\ufeff" + out.getvalue()


def range_summary_csv(from_txt, to_txt, dev_filter=""):
    """One row per day per camera: minutes with each problem + first shutter opening / last closing."""
    a_dt, b_dt = _range_bounds(from_txt, to_txt)
    now = time.time()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["date", "site", "dvr", "channel", "camera", "system_on_min", "system_off_min", "dvr_offline_min",
                "camera_off_min", "blurred_min", "angle_changed_min", "other_problems_min",
                "shutter_first_opened", "shutter_last_closed", "shutter_opened_count", "shutter_closed_count"])
    day = a_dt
    while day < b_dt:
        a = day.timestamp()
        b = min((day + timedelta(days=1)).timestamp(), now)
        if b <= a:
            break
        evs = TIMELINE.events(a, b)
        sysl = system_timeline(a, b, evs)
        on = sum(x["end"] - x["start"] for x in sysl if x["state"] == "SYSTEM ON")
        off = sum(x["end"] - x["start"] for x in sysl if x["state"] == "SYSTEM OFF")
        w.writerow([f"{day:%Y-%m-%d}", "SYSTEM", "", "", "", round(on / 60, 1), round(off / 60, 1)] + [""] * 9)
        cams = {}
        for ev in evs:
            if ev["kind"] == "SYSTEM_OFF" or (dev_filter and ev.get("dev") != dev_filter):
                continue
            key = (ev["site"], ev["dvr"], ev["ch"] or 0, ev.get("camera") or ("" if not ev["ch"] else f"Channel {ev['ch']}"))
            c = cams.setdefault(key, {"iv": {}, "open": [], "closed": []})
            if ev["kind"] == "GATE_OPEN":
                c["open"].append(ev["start"])
            elif ev["kind"] == "GATE_CLOSED":
                c["closed"].append(ev["start"])
            elif ev["kind"] == "DVR_OFFLINE" or ev["kind"] in REPORT_COL:
                col = "DVR OFFLINE" if ev["kind"] == "DVR_OFFLINE" else REPORT_COL[ev["kind"]]
                s_, e_ = max(ev["start"], a), min(ev["end"] if ev["end"] is not None else b, b)
                if e_ > s_:
                    c["iv"].setdefault(col, []).append((s_, e_))
        for (site, dvr, ch, cam), c in sorted(cams.items()):
            mins = {col: round(union_seconds(iv) / 60, 1) for col, iv in c["iv"].items()}
            w.writerow([f"{day:%Y-%m-%d}", site, dvr, ch or "", cam, "", "", mins.get("DVR OFFLINE", ""),
                        mins.get("CAMERA OFF", ""), mins.get("BLURRED", ""), mins.get("ANGLE CHANGED", ""),
                        mins.get("OTHER", ""),
                        clock12(min(c["open"])) if c["open"] else "", clock12(max(c["closed"])) if c["closed"] else "",
                        len(c["open"]) or "", len(c["closed"]) or ""])
        day += timedelta(days=1)
    return "\ufeff" + out.getvalue()


class Reporter:
    """SYSTEM ON/OFF bookkeeping + writes the hourly report files."""

    def __init__(self):
        self.first_start = None
        self.state_path = REPORT_DIR / "state.json"

    def heartbeat(self, clean=False):
        try:
            tmp = HEARTBEAT_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps({"time": time.time(), "clean_stop": clean,
                                       "first_start": self.first_start}), encoding="utf-8")
            tmp.replace(HEARTBEAT_PATH)
        except Exception as exc:
            print("[IDP i AI] heartbeat error:", exc)

    def startup(self):
        now = time.time()
        try:
            hb = json.loads(HEARTBEAT_PATH.read_text(encoding="utf-8"))
        except Exception:
            hb = None
        self.first_start = (hb or {}).get("first_start") or now
        if hb:
            last = float(hb["time"])
            TIMELINE.close_all(last, "monitoring stopped")
            if now - last > SYSTEM_OFF_AFTER:
                reason = ("software was stopped" if hb.get("clean_stop") else
                          "computer or software stopped unexpectedly (power cut, crash or shutdown)")
                TIMELINE.add_closed({"kind": "SYSTEM_OFF", "dev": "", "dvr": "", "site": "System", "ch": 0, "camera": "",
                                     "start": round(last, 1), "end": round(now, 1), "details": reason})
                print(f"[IDP i AI] SYSTEM OFF from {datetime.fromtimestamp(last):%d %b %H:%M:%S} to "
                      f"{datetime.fromtimestamp(now):%H:%M:%S} ({reason})")
        self.heartbeat()
        atexit.register(lambda: self.heartbeat(clean=True))

    def report_paths(self, h):
        folder = REPORT_DIR / f"{h:%Y-%m-%d}"
        name = f"{h:%H}.00-{h.hour + 1:02d}.00"
        return folder, folder / f"{name}.txt", folder / f"{name}.csv"

    def write(self, h):
        R = build_report(h)
        folder, txt, csvp = self.report_paths(h)
        folder.mkdir(parents=True, exist_ok=True)
        txt.write_text(report_text(R), encoding="utf-8")
        csvp.write_text(report_csv(R), encoding="utf-8")
        return R

    def tick(self):
        now = datetime.now()
        try:
            st = json.loads(self.state_path.read_text(encoding="utf-8"))
            last = datetime.fromisoformat(st["last_hour"])
        except Exception:
            last = datetime.fromtimestamp(self.first_start).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
        last = max(last, now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=48))
        h = last + timedelta(hours=1)
        while h + timedelta(hours=1, minutes=1) <= now:
            R = self.write(h)
            print(f"[IDP i AI] hourly report written: {h:%Y-%m-%d %H}:00")
            self.state_path.write_text(json.dumps({"last_hour": h.isoformat()}), encoding="utf-8")
            if aiS("report_telegram") and TELEGRAM_CONFIG.get("bot_token") and tg_chats() and \
                    h + timedelta(hours=2) > now:           # don't flood Telegram with old hours after downtime
                tg_send(report_telegram_text(R))
            h += timedelta(hours=1)

    def cleanup(self):
        keep = max(1, aiS("report_keep_days"))
        cutoff = datetime.now() - timedelta(days=keep)
        for d in REPORT_DIR.iterdir():
            if d.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.name) and datetime.strptime(d.name, "%Y-%m-%d") < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        TIMELINE.prune(cutoff.timestamp())

    def run(self):
        last_tick = last_clean = 0
        while True:
            self.heartbeat()
            if time.time() - last_tick >= 30:
                try:
                    self.tick()
                except Exception as exc:
                    print("[IDP i AI] report error:", exc)
                last_tick = time.time()
            if time.time() - last_clean >= 6 * 3600:
                try:
                    self.cleanup()
                except Exception as exc:
                    print("[IDP i AI] report cleanup error:", exc)
                last_clean = time.time()
            time.sleep(HEARTBEAT_SEC)


REPORTER = Reporter()



# ---------------------------------------------------------------- face recognition (YuNet + SFace)
FACE_MODELS = {
    "det": ("face_detection_yunet_2023mar.onnx",
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"),
    "rec": ("face_recognition_sface_2021dec.onnx",
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"),
}


class FaceEngine:
    def __init__(self):
        self.lock = threading.Lock()
        self.det = self.rec = None
        self.error = ""
        self.gallery = None

    def ready(self):
        if self.det is not None:
            return True
        if not CV_OK:
            self.error = "OpenCV is not installed (Kali: sudo apt install python3-opencv python3-numpy)"
            return False
        if not hasattr(cv2, "FaceDetectorYN"):
            self.error = "Face recognition needs OpenCV 4.8 or newer (pip install -U opencv-python)"
            return False
        with self.lock:
            if self.det is not None:
                return True
            try:
                paths = {}
                for k, (fn, url) in FACE_MODELS.items():
                    p = AI_DIRS["models"] / fn
                    if not p.is_file() or p.stat().st_size < 100_000:
                        print("[IDP i AI] Downloading face model:", fn)
                        with urllib.request.urlopen(url, timeout=120) as r:
                            p.with_suffix(".part").write_bytes(r.read())
                        p.with_suffix(".part").replace(p)
                    paths[k] = p
                self.det = cv2.FaceDetectorYN.create(str(paths["det"]), "", (320, 320), 0.85, 0.3, 5000)
                self.rec = cv2.FaceRecognizerSF.create(str(paths["rec"]), "")
                self.error = ""
                return True
            except Exception as e:
                self.error = (f"Face model failed to load: {e}. Download the two .onnx models from "
                              f"github.com/opencv/opencv_zoo into '{AI_DIRS['models']}'.")
                return False

    def detect(self, img, min_size=40):
        if not self.ready():
            return []
        h, w = img.shape[:2]
        scale = min(1.0, 1280.0 / w)
        im = cv2.resize(img, (int(w * scale), int(h * scale))) if scale < 1 else img
        out = []
        with self.lock:
            self.det.setInputSize((im.shape[1], im.shape[0]))
            _, dets = self.det.detect(im)
            if dets is None:
                return out
            for f in dets:
                if f[2] < min_size * scale or f[3] < min_size * scale:
                    continue
                feat = self.rec.feature(self.rec.alignCrop(im, f)).flatten().astype(np.float32)
                feat /= (np.linalg.norm(feat) + 1e-9)
                x, y, bw, bh = [int(v / scale) for v in f[:4]]
                pad = int(0.25 * max(bw, bh))
                crop = img[max(0, y - pad):y + bh + pad, max(0, x - pad):x + bw + pad]
                out.append({"box": (x, y, bw, bh), "feat": feat, "crop": crop})
        return out

    def match(self, feat):
        if self.gallery is None:
            rows = [f for f in AI["faces"] if f.get("emb")]
            mat = np.array([f["emb"] for f in rows], dtype=np.float32) if rows else None
            self.gallery = (rows, mat)
        rows, mat = self.gallery
        if mat is None:
            return None, 0.0
        sims = mat @ feat
        i = int(np.argmax(sims))
        return rows[i], float(sims[i])


FACE = FaceEngine()


# ---------------------------------------------------------------- the 24/7 monitor

def gate_mark_image(dev, ch, state, img):
    """Save a picture of the gate in this state. Finds the gate area automatically if none is set.
    Returns a message; raises ValueError if the picture can't be used."""
    c = cam_cfg(dev["id"], ch)
    mode = "night" if is_night(img) else "day"
    kind = f"gate_{state}_{mode}"
    other = "closed" if state == "open" else "open"
    jpg = AI_DIRS["refs"] / (ref_path(dev["id"], ch, kind).stem + ".jpg")
    other_jpg = AI_DIRS["refs"] / (ref_path(dev["id"], ch, f"gate_{other}_{mode}").stem + ".jpg")
    msg = ""
    if not c.get("gate_roi"):
        if other_jpg.is_file():
            o = cv2.imdecode(np.frombuffer(other_jpg.read_bytes(), np.uint8), cv2.IMREAD_GRAYSCALE)
            roi = find_changed_area(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), o) if o is not None else None
            if roi is None:
                raise ValueError(f"The {state.upper()} and {other.upper()} pictures look the same - is the shutter really "
                                 f"{state} now? (Nothing was saved.)")
            c["gate_roi"] = roi
            msg = " Shutter area found automatically."
    elif other_jpg.is_file():
        o = decode_jpeg(other_jpg.read_bytes())
        ref_other = load_ref(dev["id"], ch, f"gate_{other}_{mode}")
        if o is not None and ref_other is not None:
            sim = similarity(gate_sig(img, c["gate_roi"]), ref_other["sig"])
            if sim is not None and sim > 0.9:
                raise ValueError(f"This picture looks like the shutter is {other.upper()}, not {state} "
                                 f"(match {sim:.2f}). Nothing was saved.")
    jpg.write_bytes(encode_jpeg(img, 90) or b"")
    # (re)compute all saved gate pictures with the current gate area
    if c.get("gate_roi"):
        for st in ("open", "closed"):
            for md in ("day", "night"):
                j = AI_DIRS["refs"] / (ref_path(dev["id"], ch, f"gate_{st}_{md}").stem + ".jpg")
                im = decode_jpeg(j.read_bytes()) if j.is_file() else None
                if im is not None:
                    save_ref(dev["id"], ch, f"gate_{st}_{md}", gate_sig(im, c["gate_roi"]))
    c.update({"gate": 1, "gate_state": state, "gate_since": time.time(), "gate_long": 0})
    ai_save()
    have_other = other_jpg.is_file()
    nxt = "" if have_other else f" Next: mark it {other.upper()} when it is {other}."
    return f"Shutter {state.upper()} picture saved ({'night/IR' if mode == 'night' else 'day'} mode).{msg}{nxt}"

# ---------------------------------------------------------------- AI API helpers (used by the web server)
def _find_dev(did):
    d = DEVICES.get(str(did or ""))
    if not d:
        raise ValueError("DVR not found")
    return d

class AIMonitor:
    def __init__(self):
        self.stop = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="idpi-ai")
        self.fast = ThreadPoolExecutor(max_workers=16, thread_name_prefix="idpi-fast")
        self.dvr_fail = {}
        self.dvr_state = {}
        self.auth_blocked = set()
        self.issue_count = {}       # (dev, ch, issue) -> consecutive scans
        self.active = set()         # alerts currently raised
        self.offline_count = {}
        self.last_hash = {}
        self.frozen_count = {}
        self.gate_pending = {}
        self.gate_learn = {}        # (dev, ch, state) -> pictures collected for automatic learning
        self.first_seen = {}        # problem key -> time it was first seen (for report start times)
        self.face_cool = {}
        self.stats = {"dvr_scan": 0, "health_scan": 0, "gate_scan": 0, "face_scan": 0, "started": time.time()}
        self.wake = {"dvr": threading.Event(), "health": threading.Event()}

    def start(self):
        ai_load()
        for name, fn, key in (("dvr", self.dvr_sweep, "dvr_interval"), ("health", self.health_sweep, "health_interval"),
                              ("gate", self.gate_sweep, "gate_interval"), ("face", self.face_sweep, "face_interval")):
            threading.Thread(target=self._loop, args=(name, fn, key), daemon=True, name=f"idpi-{name}").start()
        threading.Thread(target=telegram_worker, daemon=True, name="idpi-telegram").start()
        threading.Thread(target=self._bot_loop, daemon=True, name="idpi-bot").start()
        threading.Thread(target=self._saver, daemon=True, name="idpi-save").start()
        ai_event("SYSTEM", "INFO", details=f"{APP_NAME} AI engine started (24/7). OpenCV AI: {'ON' if CV_OK else 'OFF'}",
                 notify=False)
        try:
            REPORTER.startup()
        except Exception as exc:
            print('[IDP i AI] reporter startup:', exc)

    def _loop(self, name, fn, key):
        time.sleep({"dvr": 3, "health": 15, "gate": 20, "face": 25}[name])
        while not self.stop.is_set():
            t0 = time.time()
            try:
                fn()
            except Exception as exc:
                print(f"[IDP i AI] {name} loop error:", exc)
            wait = max(2, aiS(key) - (time.time() - t0))
            ev = self.wake.get(name)
            if ev:
                ev.wait(wait)
                ev.clear()
            else:
                self.stop.wait(wait)

    def _saver(self):
        while not self.stop.wait(30):
            ai_save()

    @staticmethod
    def _safe(fn, *a):
        try:
            fn(*a)
        except Exception as exc:
            print("[IDP i AI] check error:", exc)

    @staticmethod
    def devices():
        return [dict(d) for d in list(DEVICES.values()) if d.get("ip")]

    # ---------- DVR ----------
    def dvr_sweep(self):
        devs = self.devices()
        list(self.pool.map(lambda d: self._safe(self.check_dvr, d), devs))
        self.stats["dvr_scan"] = time.time()

    def check_dvr(self, dev):
        did = dev["id"]
        up = tcp_ok(dev["ip"], dev.get("port") or 554) or tcp_ok(dev["ip"], dev.get("http_port") or 80)
        prev = self.dvr_state.get(did, "unknown")
        if up:
            self.dvr_fail[did] = 0
            if prev == "offline":
                try:
                    TIMELINE.end("DVR_OFFLINE", did, None, time.time())
                except Exception:
                    pass
                self.first_seen.pop(("dvr", did), None)
                ai_event("DVR_ONLINE", "INFO", dev, details="DVR is reachable again.", notify=bool(aiS("notify_recovery")))
            self.dvr_state[did] = "online"
            return
        n = self.dvr_fail.get(did, 0) + 1
        self.dvr_fail[did] = n
        if n >= aiS("dvr_fail_threshold") and prev != "offline":
            self.dvr_state[did] = "offline"
            self.first_seen.setdefault(("dvr", did), time.time())
            try:
                TIMELINE.start("DVR_OFFLINE", dev, None, self.first_seen.get(("dvr", did), time.time()),
                               f"Cannot connect to {dev['ip']}")
            except Exception:
                pass
            ai_event("DVR_OFFLINE", "CRITICAL", dev,
                     details=f"Cannot connect to {dev['ip']}. Check power, internet/router, or whether the DVR has hung.")

    # ---------- camera health ----------
    def health_sweep(self):
        jobs = []
        for dev in self.devices():
            if self.dvr_state.get(dev["id"]) == "offline" or dev["id"] in self.auth_blocked:
                continue
            jobs += [(dev, ch) for ch in dev_channels(dev)]
        list(self.pool.map(lambda j: self._safe(self.check_camera, *j), jobs))
        self.stats["health_scan"] = time.time()
        ai_save()

    def _raise_once(self, key, etype, sev, dev, ch, details, image=None):
        if key in self.active:
            return
        self.active.add(key)
        self.first_seen.setdefault(key, time.time())
        try:
            TIMELINE.start(key[2] if len(key) > 2 else etype, dev, ch, self.first_seen.get(key, time.time()), details)
        except Exception:
            pass
        ai_event(etype, sev, dev, ch, details=details, image=image)

    def _clear(self, key, dev, ch, details):
        if key in self.active:
            self.active.discard(key)
            try:
                TIMELINE.end(key[2] if len(key) > 2 else "OFFLINE", key[0], ch, time.time())
            except Exception:
                pass
            self.first_seen.pop(key, None)
            ai_event("ISSUE_CLEARED" if key[2] != "OFFLINE" else "CAMERA_ONLINE", "INFO", dev, ch,
                     details=details, notify=bool(aiS("notify_recovery")))

    def check_camera(self, dev, ch):
        did = dev["id"]
        cam = cam_cfg(did, ch)
        try:
            jpeg = ai_snapshot(dev, ch, timeout=6)
        except AuthError:
            if did not in self.auth_blocked:
                self.auth_blocked.add(did)
                ai_event("DVR_AUTH", "CRITICAL", dev, details="The DVR rejected the username/password. Camera checks "
                         "for this DVR are paused so the account does not lock. Fix the password in DVR Setup.")
            return
        cam["last_check"] = time.time()
        okey = (did, ch, "OFFLINE")
        if not jpeg:
            st = LIVE.get(did, ch, create=False)
            if st is not None and st.state == "live" and st.jpeg:
                jpeg = st.jpeg                     # live video works => use its picture
        if not jpeg:
            if not (tcp_ok(dev["ip"], dev.get("http_port") or 80, 2) or tcp_ok(dev["ip"], dev.get("port") or 554, 2)):
                return  # whole DVR unreachable — handled by the DVR check
            n = self.offline_count.get((did, ch), 0) + 1
            self.offline_count[(did, ch)] = n
            if n >= aiS("confirm_scans"):
                cam["status"], cam["score"] = "offline", 0
                self._raise_once(okey, "CAMERA_OFFLINE", "CRITICAL", dev, ch,
                                 f"No picture from this camera.\n💡 {ISSUE_FIX['OFFLINE']}")
            return
        self.offline_count[(did, ch)] = 0
        cam["last_ok"] = time.time()
        self._clear(okey, dev, ch, "Camera is sending pictures again.")
        img = decode_jpeg(jpeg)
        if img is None:
            cam["status"], cam["issues"], cam["score"] = "ok", [], None
            return
        r = analyze_frame(img, did, ch)
        issues = r["issues"]
        h = hashlib.md5(jpeg).hexdigest()
        fz = self.frozen_count.get((did, ch), 0) + 1 if self.last_hash.get((did, ch)) == h else 0
        self.frozen_count[(did, ch)], self.last_hash[(did, ch)] = fz, h
        if fz >= 2:
            issues.append("FROZEN")
        cam.update({k: r[k] for k in ("brightness", "blur", "night", "similarity")})
        cam["issues"] = issues
        cam["score"] = max(0, 100 - sum(ISSUE_PENALTY.get(i, 20) for i in issues))
        cam["status"] = "novideo" if "NO_VIDEO" in issues else ("issue" if issues else "ok")
        for iss in ISSUE_TEXT:
            k = (did, ch, iss)
            if iss in issues:
                n = self.issue_count.get(k, 0) + 1
                self.issue_count[k] = n
                if n >= aiS("confirm_scans"):
                    self._raise_once(k, iss, ISSUE_SEV.get(iss, "WARNING"), dev, ch,
                                     f"{ISSUE_TEXT[iss]}.\n💡 {ISSUE_FIX[iss]}", image=jpeg)
            else:
                self.issue_count.pop(k, None)
                self._clear(k, dev, ch, f"{ISSUE_TEXT[iss]} — resolved.")

    # ---------- gates ----------
    def gate_cams(self):
        out = []
        for dev in self.devices():
            if self.dvr_state.get(dev["id"]) == "offline" or dev["id"] in self.auth_blocked:
                continue
            for ch in dev_channels(dev):
                c = cam_cfg(dev["id"], ch)
                if c.get("gate"):
                    out.append((dev, ch))
        return out

    def gate_sweep(self):
        if not CV_OK:
            return
        jobs = self.gate_cams()
        if shutil.which("ffmpeg"):
            for dev, ch in jobs:
                try:
                    LIVE.get(dev["id"], ch, keep=True)
                except RuntimeError as exc:
                    print("[IDP i AI] live gate:", exc)
        list(self.fast.map(lambda j: self._safe(self.check_gate, *j), jobs))
        self.stats["gate_scan"] = time.time()

    @staticmethod
    def gate_ref(did, ch, state, night):
        for mode in (("night", "day") if night else ("day", "night")):
            ref = load_ref(did, ch, f"gate_{state}_{mode}")
            if ref is not None:
                return ref["sig"]
        return None


    def auto_learn_gate(self, dev, ch, cam, img):
        """At configured times of day, collect a few frames and mark OPEN/CLOSED automatically."""
        if not CV_OK:
            return
        now = datetime.now()
        for state in ("closed", "open"):
            at = str(aiS(f"gate_learn_{state}_at") or "").strip()
            if not at or not re.match(r"^\d\d:\d\d$", at):
                continue
            try:
                hh, mm = map(int, at.split(":"))
                start = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            except Exception:
                continue
            done_key = f"gate_auto_{state}"
            if not (start <= now < start + timedelta(minutes=15)) or cam.get(done_key) == now.strftime("%Y-%m-%d"):
                continue
            k = (dev["id"], ch, state)
            buf = self.gate_learn.setdefault(k, [])
            if not buf or time.time() - buf[-1][0] >= float(os.environ.get("IDPI_TEST_LEARN_SPACING", "20")):
                buf.append((time.time(), img.copy() if hasattr(img, "copy") else img))
            if len(buf) >= 3:
                try:
                    shapes = {tuple(b[1].shape) for b in buf}
                    if len(shapes) != 1:
                        continue
                    med = np.median(np.stack([b[1] for b in buf]), axis=0).astype(np.uint8)
                    self.gate_learn.pop(k, None)
                    cam[done_key] = now.strftime("%Y-%m-%d")
                    msg = gate_mark_image(dev, ch, state, med)
                    ai_event("SYSTEM", "INFO", dev, ch,
                             details=f"Shutter {state.upper()} picture learned automatically. {msg}", notify=False)
                except Exception as exc:
                    ai_event("SYSTEM", "WARNING", dev, ch, notify=False,
                             details=f"Automatic shutter {state} picture at {at} not used: {exc}")

    def check_gate(self, dev, ch):
        did = dev["id"]
        cam = cam_cfg(did, ch)
        jpeg = None
        if shutil.which("ffmpeg"):
            try:
                st = LIVE.get(did, ch, keep=True)
                if st is not None and st.state == "live" and st.jpeg:
                    jpeg = st.jpeg
            except RuntimeError:
                pass
        if jpeg is None:
            try:
                jpeg = ai_snapshot(dev, ch, timeout=4)
            except AuthError:
                return
        img = decode_jpeg(jpeg)
        if img is None:
            return
        try:
            self.auto_learn_gate(dev, ch, cam, img)
        except Exception as exc:
            print("[IDP i AI] gate auto-learn error:", exc)
        night = is_night(img)
        ro, rc = self.gate_ref(did, ch, "open", night), self.gate_ref(did, ch, "closed", night)
        if ro is None or rc is None or not cam.get("gate_roi"):
            return  # gate not calibrated yet (mark OPEN and CLOSED first)
        sig = gate_sig(img, cam.get("gate_roi"))
        so, sc = similarity(sig, ro) or 0, similarity(sig, rc) or 0
        cand = "open" if so - sc > 0.05 else "closed" if sc - so > 0.05 else None
        cur, t, key = cam.get("gate_state", "unknown"), time.time(), (did, ch)
        if cand is None or cand == cur:
            self.gate_pending.pop(key, None)
            lim = aiS("gate_open_alert_min")
            if cur == "open" and lim > 0 and not cam.get("gate_long") and cam.get("gate_since") and t - cam["gate_since"] > lim * 60:
                cam["gate_long"] = 1
                ai_event("GATE_OPEN_LONG", "CRITICAL" if in_after_hours() else "WARNING", dev, ch, image=jpeg,
                         details=f"Gate has been open for {fmt_dur(t - cam['gate_since'])}. Please check.")
            return
        prev = self.gate_pending.get(key)
        if prev and prev[0] == cand:
            first_t, n = prev[1], prev[2] + 1
        else:
            first_t, n = t, 1
        self.gate_pending[key] = (cand, first_t, n)
        need_sec = max(0, int(aiS("gate_confirm_sec") or 0))
        if need_sec:
            if t - first_t < need_sec:
                return
        elif n < 2:  # same result twice in a row => confirmed
            return
        self.gate_pending.pop(key, None)
        was_since = cam.get("gate_since") or 0
        cam.update({"gate_state": cand, "gate_since": t, "gate_long": 0})
        if cur == "unknown":
            ai_event("GATE_OPEN" if cand == "open" else "GATE_CLOSED", "INFO", dev, ch, image=jpeg,
                     details=f"Initial gate state: {cand.upper()}", notify=False)
            return
        site = dev_location(dev)
        tstr = datetime.now().strftime("%H:%M")
        try:
            TIMELINE.instant("GATE_OPEN" if cand == "open" else "GATE_CLOSED", dev, ch, t,
                             f"shutter {cand}")
        except Exception:
            pass
        if cand == "open":
            ah = in_after_hours()
            msg = (aiS("gate_msg_open") or "{site} site shutter opened at {time}").format(site=site, time=tstr)
            ai_event("GATE_OPEN", "CRITICAL" if ah else "WARNING", dev, ch, image=jpeg,
                     details=("🌙 AFTER HOURS! " if ah else "") + msg)
        else:
            dur = t - was_since if was_since else 0
            msg = (aiS("gate_msg_closed") or "{site} site shutter closed at {time}").format(site=site, time=tstr)
            ai_event("GATE_CLOSED", "INFO", dev, ch, image=jpeg,
                     details=msg + (f" (was open {fmt_dur(dur)})" if dur else ""))

    # ---------- faces ----------
    def face_sweep(self):
        if not CV_OK:
            return
        if not face_ai_active_now():
            return
        jobs = []
        for dev in self.devices():
            if self.dvr_state.get(dev["id"]) == "offline" or dev["id"] in self.auth_blocked:
                continue
            jobs += [(dev, ch) for ch in dev_channels(dev) if cam_cfg(dev["id"], ch).get("face")]
        if not jobs:
            return
        if FACE.det is None and time.time() - getattr(self, "_face_fail_at", 0) < 600:
            return  # last model load failed — retry every 10 minutes, not every few seconds
        if not FACE.ready():
            self._face_fail_at = time.time()
            return
        if shutil.which("ffmpeg"):
            # Face cameras run on the LIVE video (several checks per second), not on snapshots.
            snap_jobs = []
            for dev, ch in jobs:
                try:
                    st = LIVE.get(dev["id"], ch, keep=True)
                    if st.state == "error" and st.out is None:
                        snap_jobs.append((dev, ch))   # no live video => check faces on snapshots
                except RuntimeError as exc:
                    print("[IDP i AI] live face:", exc)
                    snap_jobs.append((dev, ch))
            if snap_jobs:
                list(self.fast.map(lambda j: self._safe(self.check_faces, *j), snap_jobs))
            self.stats["face_scan"] = time.time()
            return
        list(self.fast.map(lambda j: self._safe(self.check_faces, *j), jobs))
        self.stats["face_scan"] = time.time()
        if len(self.face_cool) > 20000:
            cutoff = time.time() - 3600
            self.face_cool = {k: v for k, v in self.face_cool.items() if v > cutoff}

    def check_faces(self, dev, ch):
        """Snapshot fallback (no ffmpeg, or the live video of this camera is not working)."""
        try:
            jpeg = ai_snapshot(dev, ch, timeout=4, rtsp_fallback=not shutil.which("ffmpeg"))
        except AuthError:
            return
        img = decode_jpeg(jpeg)
        if img is None:
            return
        th = aiS("face_match_threshold")
        for f in FACE.detect(img, min_size=aiS("face_min_size")):
            row, sim = FACE.match(f["feat"])
            who, cat = (row["name"], row["category"]) if (row and sim >= th) else ("Unknown person", "unknown")
            self.face_event(dev, ch, img, f["box"], who, cat, sim)

    def face_event(self, dev, ch, img, box, who, cat, sim):
        """Log + Telegram for one recognised face (with per-person cooldown). Returns True if logged."""
        key = (who, dev["id"], ch)
        if time.time() - self.face_cool.get(key, 0) < aiS("face_cooldown_min") * 60:
            return False
        self.face_cool[key] = time.time()
        vis = img.copy()
        draw_face(vis, box, f"{who} {sim:.2f}", cat)
        pic = encode_jpeg(vis)
        extra = {"person": who, "category": cat, "match": round(float(sim), 3)}
        if cat == "watchlist":
            ai_event("FACE_WATCHLIST", "CRITICAL", dev, ch, image=pic, extra=extra,
                     details=f"⛔ Watchlist person: {who} (match {sim:.2f}). Check immediately.")
        elif cat == "vip":
            ai_event("FACE_VIP", "INFO", dev, ch, image=pic, details=f"⭐ {who} (match {sim:.2f})", extra=extra,
                     notify=bool(aiS("face_notify_vip")))
        elif cat == "known":
            ai_event("FACE_KNOWN", "INFO", dev, ch, image=pic, details=f"{who} (match {sim:.2f})", extra=extra,
                     notify=bool(aiS("face_notify_known")))
        else:
            ai_event("FACE_UNKNOWN", "WARNING", dev, ch, image=pic, extra=extra,
                     details=f"Face not in the enrolled list (best match {sim:.2f}).",
                     notify=bool(aiS("face_alert_unknown")))
        return True

    # ---------- summary ----------
    def summary(self, allowed=None):
        cams = []
        for dev in [d for d in self.devices() if allowed is None or d["id"] in allowed]:
            dvr_off = self.dvr_state.get(dev["id"]) == "offline"
            for ch in dev_channels(dev):
                c = cam_cfg(dev["id"], ch)
                cams.append({"dev": dev["id"], "dvr": dev.get("name") or dev["ip"], "site": dev_location(dev),
                             "ch": ch, "dvr_offline": dvr_off, **{k: c.get(k) for k in (
                                 "name", "location", "status", "issues", "score", "last_check", "face", "gate",
                                 "gate_state", "gate_since", "blur", "brightness", "similarity", "night")}})
        live = [c for c in cams if not c["dvr_offline"]]
        cnt = lambda pred: sum(1 for c in live if pred(c))  # noqa: E731
        scores = [c["score"] for c in live if c["score"] is not None]
        devs = [{"id": d["id"], "name": d.get("name") or d["ip"], "ip": d["ip"], "location": d.get("location") or "",
                 "status": self.dvr_state.get(d["id"], "unknown"), "auth_blocked": d["id"] in self.auth_blocked}
                for d in self.devices() if allowed is None or d["id"] in allowed]
        return {
            "cv_ok": CV_OK, "face_error": FACE.error, "telegram": bool(TELEGRAM_CONFIG.get("bot_token") and tg_chats()),
            "stats": self.stats, "devices": devs, "cameras": cams,
            "counts": {
                "dvr_total": len(devs), "dvr_offline": sum(1 for d in devs if d["status"] == "offline"),
                "cam_total": len(cams), "cam_offline": cnt(lambda c: c["status"] == "offline") + sum(1 for c in cams if c["dvr_offline"]),
                "cam_faulty": cnt(lambda c: "NO_VIDEO" in (c["issues"] or [])),
                "blur": cnt(lambda c: "BLUR" in (c["issues"] or [])),
                "angle": cnt(lambda c: "ANGLE_CHANGE" in (c["issues"] or [])),
                "frozen": cnt(lambda c: "FROZEN" in (c["issues"] or [])),
                "dark": cnt(lambda c: "TOO_DARK" in (c["issues"] or []) or "OVEREXPOSED" in (c["issues"] or [])),
                "ok": cnt(lambda c: c["status"] == "ok"),
                "gates": sum(1 for c in cams if c["gate"]), "gates_open": sum(1 for c in cams if c["gate"] and c["gate_state"] == "open"),
                "faces_enrolled": len(AI["faces"]), "face_cams": sum(1 for c in cams if c["face"]),
                "avg_score": round(sum(scores) / len(scores)) if scores else None,
            },
            "settings": {k: aiS(k) for k in AI_DEFAULTS},
        }

    def status_text(self):
        s = self.summary()
        c = s["counts"]
        return (f"🛡 {APP_NAME} status · {datetime.now():%d %b %Y %H:%M}\n"
                f"🖥 DVR online: {c['dvr_total'] - c['dvr_offline']}/{c['dvr_total']}\n"
                f"📷 Cameras OK: {c['ok']}/{c['cam_total']} · offline {c['cam_offline']} · faulty {c['cam_faulty']}\n"
                f"🔎 Blur {c['blur']} · angle changed {c['angle']} · frozen {c['frozen']} · dark/bright {c['dark']}\n"
                f"📊 Avg health score: {c['avg_score'] if c['avg_score'] is not None else '—'}\n"
                f"🚪 Gates open: {c['gates_open']}/{c['gates']}\n"
                f"🙂 Face cameras: {c['face_cams']} · enrolled people: {c['faces_enrolled']}")

    # ---------- Telegram bot commands ----------
    def _bot_loop(self):
        while not self.stop.is_set():
            if not (aiS("bot_commands") and TELEGRAM_CONFIG.get("bot_token") and tg_chats()):
                self.stop.wait(15)
                continue
            ok, res = tg_api("getUpdates", {"timeout": 25, "offset": AI.get("tg_offset", 0),
                                            "allowed_updates": ["message"]}, timeout=40)
            if not ok:
                self.stop.wait(10)
                continue
            for u in res.get("result", []):
                AI["tg_offset"] = u["update_id"] + 1
                m = u.get("message") or {}
                chat = str((m.get("chat") or {}).get("id", ""))
                if chat not in tg_chats():
                    continue  # only accept commands from configured chats
                try:
                    self.handle_cmd(chat, (m.get("text") or "").strip())
                except Exception as e:
                    tg_send(f"Command error: {e}", [chat])

    def handle_cmd(self, chat, text):
        if not text.startswith("/"):
            return
        parts = text.split()
        cmd = parts[0].split("@")[0].lower()
        reply = lambda t: tg_send(t, [chat])  # noqa: E731
        s = self.summary()
        if cmd in ("/start", "/help"):
            reply(f"🛡 {APP_NAME} bot commands:\n/status — current status\n/offline — offline DVRs and cameras\n"
                  "/issues — faulty, blurry, angle-changed, frozen cameras\n/gates — state of every gate\n"
                  "/faces — recent face detections\n/snap <DVR name or IP> <CH> — live photo")
        elif cmd == "/status":
            reply(self.status_text())
        elif cmd == "/offline":
            d = [x for x in s["devices"] if x["status"] == "offline"]
            c = [x for x in s["cameras"] if x["status"] == "offline" and not x["dvr_offline"]]
            reply("\n".join([f"🔴 Offline DVRs ({len(d)}):"] + [f"• {x['location'] or x['name']} ({x['ip']})" for x in d]
                            + ["", f"🔴 Offline cameras ({len(c)}):"] + [f"• {x['site']} / {x['name']} CH{x['ch']}" for x in c]))
        elif cmd == "/issues":
            c = [x for x in s["cameras"] if x["issues"]]
            reply("\n".join([f"🟠 Camera problems ({len(c)}):"] + [
                f"• {x['site']} / {x['name']} CH{x['ch']} — " + ", ".join(ISSUE_TEXT.get(i, i) for i in x["issues"])
                for x in c]) if c else "All cameras look fine 👍")
        elif cmd == "/gates":
            g = [x for x in s["cameras"] if x["gate"]]
            reply("\n".join(["🚪 Gates:"] + [
                f"{'🔴 OPEN' if x['gate_state'] == 'open' else '🟢 CLOSED' if x['gate_state'] == 'closed' else '⚪ unknown'} "
                f"— {x['site']} / {x['name']} CH{x['ch']}"
                + (f" (since {fmt_dur(time.time() - x['gate_since'])})" if x.get("gate_since") else "") for x in g])
                  if g else "No gate cameras are set up yet.")
        elif cmd == "/faces":
            ev = [e for e in AI_EVENTS if e["type"].startswith("FACE_")][-10:]
            reply("\n".join(["🙂 Recent faces:"] + [f"• {e['time']} — {e['details']} — {e['where']}" for e in reversed(ev)])
                  if ev else "No faces detected yet.")
        elif cmd == "/snap":
            if len(parts) < 3 or not parts[-1].isdigit():
                reply("Use: /snap <DVR name or IP> <CH>   e.g. /snap 192.168.1.108 3")
                return
            q, ch = " ".join(parts[1:-1]).lower(), int(parts[-1])
            dev = next((d for d in self.devices() if d["ip"] == q or q in (d.get("name") or "").lower()
                        or q in (d.get("location") or "").lower()), None)
            if not dev:
                reply("DVR not found.")
                return
            try:
                img = ai_snapshot(dev, ch)
            except AuthError:
                img = None
            if img:
                tg_photo(f"📷 {where_text(dev, ch)} — {datetime.now():%d %b %Y %H:%M:%S}", img, [chat])
            else:
                reply("No snapshot (camera offline or password problem).")
        else:
            reply("Unknown command. Send /help.")


AI_MON = AIMonitor()


# =============================================================================
# LIVE VIDEO + LIVE FACE RECOGNITION
#   One ffmpeg per camera reads the RTSP stream and is shared by every viewer
#   (dashboard, live view, enlarged view). For cameras with "Face AI" ON, the
#   AI checks the live picture several times a second, draws a box + name on
#   the video, keeps a "who is in front of the camera now" list, and logs /
#   sends to Telegram when a person arrives.
# =============================================================================
LIVE_MAX = int(os.environ.get("IDPI_LIVE_MAX", "64"))
FACE_COLORS = {"watchlist": (0, 0, 255), "vip": (0, 200, 255), "known": (0, 200, 0), "unknown": (255, 160, 0)}
_URL_PW = re.compile(r"rtsp://[^@\s/]+@")


_RTSP_PICK = {}                     # dev_id -> index of the RTSP variant that worked last


def rtsp_variants(hd):
    first, second = ("main", "sub") if hd else ("sub", "main")
    return [(first, "tcp"), (second, "tcp"), (first, "udp"), (second, "udp")]


def rtsp_url(dev, ch, sub=True):
    # same encoding as Sudarshan (proven on this DVR)
    user = urllib.parse.quote(dev.get("username") or "", safe="")
    pw = urllib.parse.quote(dev.get("password") or "", safe="")
    tpl = RTSP_PATH_SUB if sub else RTSP_PATH_MAIN
    return f"rtsp://{user}:{pw}@{dev.get('ip')}:{int(dev.get('port') or 554)}{tpl.format(ch=ch)}"


def draw_face(img, box, label, cat):
    x, y, w, h = [int(v) for v in box]
    color = FACE_COLORS.get(cat, FACE_COLORS["unknown"])
    th = max(2, img.shape[1] // 450)
    cv2.rectangle(img, (x, y), (x + w, y + h), color, th)
    scale = max(0.5, img.shape[1] / 1600)
    (tw, tht), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, scale, 2)
    ty = y - 8 if y - tht - 14 > 0 else y + h + tht + 8
    cv2.rectangle(img, (x, ty - tht - 6), (x + tw + 8, ty + 4), color, -1)
    cv2.putText(img, label, (x + 4, ty), cv2.FONT_HERSHEY_SIMPLEX, scale, (0, 0, 0), 2, cv2.LINE_AA)


def friendly_rtsp_error(raw):
    t = (raw or "").lower()
    if "401" in t or "unauthorized" in t:
        return "Wrong DVR username or password."
    if "connection refused" in t:
        return "DVR refused the connection - check the IP, RTSP port (554) and that RTSP is enabled on the DVR."
    if "timed out" in t or "timeout" in t or "no route" in t or "unreachable" in t:
        return "DVR did not answer - check that it is powered on and on the same network."
    if "404" in t or "not found" in t:
        return "This channel has no video on the DVR."
    if "461" in t or "unsupported transport" in t:
        return "The DVR rejected RTSP over TCP - check the DVR's RTSP settings."
    short = _URL_PW.sub("rtsp://***@", (raw or "").strip())[-200:]
    return short or "No video from the DVR (check IP, password, RTSP port 554)."


class LiveStream:
    def __init__(self, dev_id, ch, keep=False):
        self.dev_id, self.ch, self.keep = dev_id, int(ch), bool(keep)
        self.cond = threading.Condition()
        self.jpeg = self.out = None          # latest raw frame / frame sent to viewers
        self.seq = 0
        self.viewers, self.last_view = 0, time.time()
        self.state, self.error, self.hd = "starting", "", False
        self.faces, self.faces_at = [], 0.0   # faces on screen right now
        self.present = {}                     # person key -> info (arrival tracking)
        self.unknowns, self.unk_no = [], 0
        self.proc = None
        self.stop_ev = threading.Event()
        threading.Thread(target=self._reader, daemon=True, name=f"idpi-live-{ch}").start()
        threading.Thread(target=self._face_loop, daemon=True, name=f"idpi-liveface-{ch}").start()

    # ---------- video ----------
    def _want_hd(self):
        return bool(self.keep and aiS("face_hd") and cam_cfg(self.dev_id, self.ch).get("face"))

    def _idle(self):
        return not self.keep and self.viewers <= 0 and time.time() - self.last_view > 10

    def _reader(self):
        backoff = 2
        while not self.stop_ev.is_set():
            dev = DEVICES.get(self.dev_id)
            if not dev:
                self.state, self.error = "error", "DVR removed"
                break
            hd = self._want_hd()
            width = 1280 if hd else 960
            variants = rtsp_variants(hd)
            vi = getattr(self, "_vi", None)
            if vi is None:
                vi = _RTSP_PICK.get(self.dev_id, 0) % len(variants)
            stream_kind, transport = variants[vi]
            cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-rtsp_transport", transport, *ff_timeout_args(),
                   "-fflags", "nobuffer", "-flags", "low_delay", "-i", rtsp_url(dev, self.ch, sub=stream_kind == "sub"), "-an",
                   # exactly Sudarshan's working output (ffmpeg -> MJPEG); frames are cut out of it below
                   "-vf", f"fps={max(1, min(25, aiS('live_fps')))},scale={width}:-2",
                   "-c:v", "mjpeg", "-q:v", "6", "-f", "mpjpeg", "-boundary_tag", "idpi", "pipe:1"]
            err = [""]
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as exc:
                self.state, self.error = "error", f"ffmpeg could not start: {exc}"
                self.stop_ev.wait(15)
                continue
            threading.Thread(target=self._drain, args=(self.proc.stderr, err), daemon=True).start()
            self.state, self.hd, buf = "connecting", hd, b""
            while not self.stop_ev.is_set():
                chunk = self.proc.stdout.read1(65536)
                if not chunk:
                    break
                buf += chunk
                while True:
                    a = buf.find(b"\xff\xd8")
                    if a < 0:
                        buf = buf[-1:]
                        break
                    b = buf.find(b"\xff\xd9", a + 2)
                    if b < 0:
                        buf = buf[a:]
                        break
                    self._new_frame(buf[a:b + 2])
                    buf = buf[b + 2:]
                    backoff = 2
                    if getattr(self, "_vi", None) != vi:
                        self._vi = vi
                        _RTSP_PICK[self.dev_id] = vi    # remember what works for this DVR
                if len(buf) > 8_000_000:
                    buf = b""
                if self._idle():
                    self.stop_ev.set()
                elif self._want_hd() != hd:
                    break  # Face AI switched on/off => reopen with the right stream (HD / sub)
            self._kill()
            if self.stop_ev.is_set():
                break
            self.state = "error"
            self.error = friendly_rtsp_error(err[0])
            if self._idle():
                break
            wrong_pw = "401" in err[0] or "unauthorized" in err[0].lower()
            if self.seq == 0 and not wrong_pw and vi + 1 < len(variants):
                self._vi = vi + 1                     # try the next way: main stream, then UDP
                self.stop_ev.wait(1)
                continue
            self._vi = None
            self.stop_ev.wait(30 if wrong_pw else backoff)   # wrong password: wait, so the DVR does not lock the account
            backoff = min(30, backoff * 2)
        self.state = "stopped"
        self.stop_ev.set()
        with self.cond:
            self.cond.notify_all()

    @staticmethod
    def _drain(pipe, store):
        try:
            for line in iter(pipe.readline, b""):
                store[0] = (store[0] + line.decode("utf-8", "replace"))[-800:]
        except Exception:
            pass

    def _kill(self):
        p = self.proc
        if p:
            try:
                p.kill()
                p.wait(timeout=3)
            except Exception:
                pass

    def close(self):
        self.stop_ev.set()
        self._kill()

    def _new_frame(self, jpeg):
        self.state, self.error = "live", ""
        out = jpeg
        faces = self.faces
        if faces and CV_OK and time.time() - self.faces_at < 1.5:
            img = decode_jpeg(jpeg)
            if img is not None:
                for f in faces:
                    draw_face(img, f["px"], f"{f['name']} {int(round(f['sim'] * 100))}%" if f["category"] != "unknown"
                              else f["name"], f["category"])
                out = encode_jpeg(img, 80) or jpeg
        with self.cond:
            self.jpeg, self.out = jpeg, out
            self.seq += 1
            self.cond.notify_all()

    def wait_frame(self, timeout):
        self.last_view = time.time()
        with self.cond:
            self.cond.wait_for(lambda: self.out is not None or self.stop_ev.is_set(), timeout)
            return self.out is not None

    def serve(self, wfile):
        """Write a multipart MJPEG stream to one browser until it disconnects."""
        with self.cond:
            self.viewers += 1
        last = -1
        try:
            while not self.stop_ev.is_set():
                with self.cond:
                    if self.seq == last:
                        self.cond.wait(5)
                    if self.seq == last:
                        continue
                    last, frame = self.seq, self.out
                wfile.write(b"--idpi\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(frame)).encode()
                            + b"\r\n\r\n" + frame + b"\r\n")
                wfile.flush()
                self.last_view = time.time()
        finally:
            with self.cond:
                self.viewers -= 1
            self.last_view = time.time()

    # ---------- live face recognition ----------
    def _face_loop(self):
        last = -1
        while not self.stop_ev.is_set():
            self.stop_ev.wait(1.0 / max(1, min(10, aiS("face_live_fps"))))
            if not CV_OK or not cam_cfg(self.dev_id, self.ch).get("face") or not face_ai_active_now():
                self.faces = []
                continue
            dev = DEVICES.get(self.dev_id)
            with self.cond:
                jpeg, seq = self.jpeg, self.seq
            if not dev or jpeg is None or seq == last:
                continue
            last = seq
            if FACE.det is None and not FACE.ready():
                self.stop_ev.wait(30)
                continue
            img = decode_jpeg(jpeg)
            if img is None:
                continue
            try:
                found = FACE.detect(img, min_size=aiS("face_min_size"))
                self._update_faces(dev, img, found)
            except Exception as exc:
                print("[IDP i AI] live face error:", exc)

    def _unknown_key(self, feat, t):
        self.unknowns = [u for u in self.unknowns if t - u[2] < 120]
        best = None
        for i, (k, uf, _) in enumerate(self.unknowns):
            sim = float(np.dot(uf, feat))
            if sim > 0.45 and (best is None or sim > best[1]):
                best = (i, sim)
        if best:
            k = self.unknowns[best[0]][0]
            self.unknowns[best[0]] = (k, feat, t)
            return k
        self.unk_no += 1
        k = f"unk:{self.unk_no}"
        self.unknowns.append((k, feat, t))
        return k

    def _update_faces(self, dev, img, found):
        t, (h, w) = time.time(), img.shape[:2]
        th, gone = aiS("face_match_threshold"), aiS("face_gone_sec")
        cur = []
        pres = dict(self.present)          # edit a copy, swap it in at the end (readers never see a half-changed dict)
        for f in found:
            row, sim = FACE.match(f["feat"])
            if row and sim >= th:
                key, name, cat = "id:" + row["id"], row["name"], row["category"]
            else:
                key, cat = self._unknown_key(f["feat"], t), "unknown"
                name = "Unknown #" + key.split(":")[1]
            x, y, bw, bh = f["box"]
            cur.append({"key": key, "name": name, "category": cat, "sim": round(float(sim), 3),
                        "px": (x, y, bw, bh), "box": [round(x / w, 4), round(y / h, 4), round(bw / w, 4), round(bh / h, 4)]})
            p = pres.get(key)
            if p is None or t - p["last"] > gone:      # new arrival in front of this camera
                thumb = ""
                crop = f.get("crop")
                if crop is not None and crop.size:
                    sc = 96.0 / max(crop.shape[:2])
                    small = cv2.resize(crop, (max(1, int(crop.shape[1] * sc)), max(1, int(crop.shape[0] * sc))))
                    tb = encode_jpeg(small, 75)
                    thumb = "data:image/jpeg;base64," + base64.b64encode(tb).decode() if tb else ""
                p = pres[key] = {"key": key, "first": t, "thumb": thumb, "best": 0.0}
                AI_MON.face_event(dev, self.ch, img, f["box"], "Unknown person" if cat == "unknown" else name, cat, sim)
            pres[key] = dict(p, name=name, category=cat, sim=round(float(sim), 3), last=t,
                             best=max(p["best"], round(float(sim), 3)))
        self.present = {k: v for k, v in pres.items() if t - v["last"] <= max(60, gone * 5)}
        self.faces, self.faces_at = cur, t

    def info(self):
        return {"dev": self.dev_id, "ch": self.ch, "state": self.state, "error": self.error, "viewers": self.viewers,
                "face_ai": bool(self.keep), "hd": self.hd, "faces_now": len(self.faces) if time.time() - self.faces_at < 2 else 0}


class LiveManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.streams = {}

    def get(self, dev_id, ch, keep=None, create=True):
        k = (dev_id, int(ch))
        with self.lock:
            s = self.streams.get(k)
            if s is not None and s.stop_ev.is_set():
                self.streams.pop(k, None)
                s = None
            if s is None:
                if not create:
                    return None
                if len(self.streams) >= LIVE_MAX:
                    # free streams nobody is watching any more (e.g. the DVR you switched away from)
                    idle = sorted((x for x in self.streams.values() if not x.keep and x.viewers <= 0
                                   and time.time() - x.last_view > 3), key=lambda x: x.last_view)
                    for x in idle[:len(self.streams) - LIVE_MAX + 1]:
                        x.close()
                        self.streams.pop((x.dev_id, x.ch), None)
                if len(self.streams) >= LIVE_MAX:
                    raise RuntimeError(f"Live stream limit reached ({LIVE_MAX} cameras at once). "
                                       "Close some live views or raise IDPI_LIVE_MAX.")
                s = self.streams[k] = LiveStream(dev_id, ch, keep=bool(keep))
            elif keep is not None:
                s.keep = bool(keep)
            return s

    def face_count(self):
        return sum(1 for x in list(self.streams.values()) if x.keep and not x.stop_ev.is_set())

    def stop(self, dev_id):
        with self.lock:
            for k in [k for k in self.streams if k[0] == dev_id]:
                self.streams.pop(k).close()

    def snapshot(self, allowed=None):
        with self.lock:
            streams = [s for s in self.streams.values() if not s.stop_ev.is_set()
                       and (allowed is None or s.dev_id in allowed)]
        t = time.time()
        people = []
        for s in streams:
            dev = DEVICES.get(s.dev_id)
            if not dev:
                continue
            cam = cam_cfg(s.dev_id, s.ch)
            for p in list(s.present.values()):
                if t - p["last"] <= aiS("face_gone_sec"):
                    people.append({"dev": s.dev_id, "ch": s.ch, "site": dev_location(dev), "camera": cam.get("name"),
                                   "cam_location": cam.get("location") or "", "name": p["name"], "category": p["category"],
                                   "match": p["sim"], "best": p["best"], "since": p["first"], "last": p["last"],
                                   "thumb": p["thumb"]})
        order = {"watchlist": 0, "unknown": 1, "vip": 2, "known": 3}
        people.sort(key=lambda x: (order.get(x["category"], 9), -x["since"]))
        return {"ok": True, "people": people, "streams": [s.info() for s in streams],
                "ffmpeg": bool(shutil.which("ffmpeg")), "cv_ok": CV_OK, "face_error": FACE.error, "time": t}


LIVE = LiveManager()
_SNAP_FRAMES = {}   # (dev_id, ch) -> (time, jpeg, seq) for snapshot mode


# ---------------------------------------------------------------- AI API helpers (used by the web server)
def _find_dev(did):
    d = DEVICES.get(str(did or ""))
    if not d:
        raise ValueError("DVR not found")
    return d


def run_diagnose(dev, ch=1):
    """Step-by-step live-video test on one DVR channel. Returns a list of report lines."""
    out = []

    def say(ok, text):
        out.append(("[OK]   " if ok is True else "[FAIL] " if ok is False else "[INFO] ") + text)

    ip, rp, hp = dev.get("ip"), int(dev.get("port") or 554), int(dev.get("http_port") or 80)
    say(None, f"DVR {dev.get('name') or ip} - {ip}  RTSP port {rp}  web port {hp}  user '{dev.get('username')}'  channel {ch}")
    ff = shutil.which("ffmpeg")
    say(bool(ff), "ffmpeg installed: " + (ff or "NO - run: sudo apt install ffmpeg"))
    if ff:
        try:
            say(None, subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True, timeout=5).stdout.splitlines()[0])
        except Exception:
            pass
    say(CV_OK, "OpenCV (face recognition): " + ("yes" if CV_OK else "NO - run: sudo apt install python3-opencv python3-numpy"))
    rtsp_up, web_up = tcp_ok(ip, rp, 3), tcp_ok(ip, hp, 3)
    say(rtsp_up, f"RTSP port {ip}:{rp} reachable from this PC")
    say(web_up, f"Web port {ip}:{hp} reachable from this PC")
    if web_up:
        url = f"http://{ip}:{hp}/cgi-bin/snapshot.cgi?channel={ch}"
        try:
            _http_open(url, {}, 4)
            say(None, "Web snapshot works without a login")
        except urllib.error.HTTPError as e:
            say(None, f"Web login type the DVR asks for: {(e.headers.get('WWW-Authenticate') or 'none')[:70]} (HTTP {e.code})")
        except Exception as e:
            say(False, f"Web port answered badly: {e}")
        try:
            snap = ai_snapshot(dev, ch, timeout=5, rtsp_fallback=False)
            say(bool(snap), f"Web snapshot with your password: " + (f"picture OK ({len(snap)} bytes)" if snap else "no picture"))
        except AuthError:
            say(False, "Web snapshot: the DVR REJECTED the username/password. Either it is wrong, "
                       "or the DVR has LOCKED the account after failed logins (restart the DVR or wait 30 min).")
    if ff and rtsp_up:
        for kind, tr in (("sub", "tcp"), ("main", "tcp"), ("sub", "udp")):
            url = rtsp_url(dev, ch, sub=kind == "sub")
            cmd = (["ffmpeg", "-hide_banner", "-loglevel", "error", "-rtsp_transport", tr] + ff_timeout_args()
                   + ["-i", url, "-frames:v", "1", "-c:v", "mjpeg", "-f", "image2", "pipe:1"])
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=20)
                ok, err = (r.stdout or b"")[:3] == b"\xff\xd8\xff", r.stderr.decode("utf-8", "replace")
            except subprocess.TimeoutExpired:
                ok, err = False, "timed out (no picture in 20 s)"
            shown = _URL_PW.sub("rtsp://***@", url)
            say(ok, f"RTSP {kind} stream over {tr.upper()}: " + ("PICTURE OK" if ok else friendly_rtsp_error(err))
                + f"\n         url: {shown}" + ("" if ok else "\n         ffmpeg said: " + _URL_PW.sub("rtsp://***@", err.strip())[-260:]))
    st = LIVE.get(dev["id"], ch, create=False) if dev.get("id") in DEVICES else None
    if st is not None:
        say(st.state == "live", f"IDP i live engine for CH{ch}: {st.state}" + (f" - {st.error}" if st.error else ""))
    say(None, f"Live streams open in IDP i right now: {len(LIVE.streams)}")
    if dev.get("id") in AI_MON.auth_blocked:
        say(False, "AI checks for this DVR are PAUSED because the DVR rejected the password earlier.")
    return out


def ai_api_post(path, data):
    """Returns a dict for every /api/ai/* POST endpoint."""
    if path == "/api/ai/camera":
        dev = _find_dev(data.get("dev"))
        ch = int(data.get("ch") or 1)
        c = cam_cfg(dev["id"], ch)
        for k in ("name", "location"):
            if k in data:
                c[k] = str(data[k] or "")[:120] or (f"Channel {ch}" if k == "name" else "")
        for k in ("face", "gate"):
            if k in data:
                c[k] = 1 if data[k] else 0
        if "gate_roi" in data:
            c["gate_roi"] = [max(0.0, min(1.0, float(v))) for v in (data["gate_roi"] or [0, 0, 1, 1])][:4]
            c["gate_state"] = "unknown"
            clear_refs(dev["id"], ch, "gate")  # new gate area => old open/closed pictures no longer valid
        if "face" in data:
            c["face_set"] = True       # manual choice: keep it (no auto-on for this camera)
        if c.get("face"):
            threading.Thread(target=FACE.ready, daemon=True).start()
        if "face" in data:
            if c["face"] and shutil.which("ffmpeg"):
                try:
                    LIVE.get(dev["id"], ch, keep=True)
                except RuntimeError as exc:
                    raise ValueError(str(exc))
            else:
                s = LIVE.get(dev["id"], ch, create=False)
                if s:
                    s.keep, s.faces = False, []
        ai_save()
        msg = "Saved"
        if "face" in data:
            msg = ("Face AI ON — this camera is now checked live, several times a second." if c["face"]
                   else "Face AI OFF for this camera.")
            if c["face"] and not shutil.which("ffmpeg"):
                msg += " (ffmpeg is not installed, so it falls back to a snapshot every few seconds: sudo apt install ffmpeg)"
        return {"ok": True, "message": msg}
    if path == "/api/ai/device-location":
        dev = _find_dev(data.get("id"))
        dev["location"] = str(data.get("location") or "")[:120]
        save_config()
        return {"ok": True, "message": "Location saved"}
    if path == "/api/ai/reset-angle":
        if not CV_OK:
            raise ValueError("Install OpenCV first: sudo apt install python3-opencv python3-numpy")
        dev = _find_dev(data.get("dev"))
        ch = int(data.get("ch") or 1)
        clear_refs(dev["id"], ch, "angle")
        AI_MON.active.discard((dev["id"], ch, "ANGLE_CHANGE"))
        AI_MON._safe(AI_MON.check_camera, dict(dev), ch)
        return {"ok": True, "message": "Angle reset — the current picture is now the correct angle."}
    if path == "/api/ai/check":
        dev = _find_dev(data.get("dev"))
        ch = int(data.get("ch") or 1)
        AI_MON._safe(AI_MON.check_camera, dict(dev), ch)
        c = cam_cfg(dev["id"], ch)
        return {"ok": True, "message": f"Checked: {c['status']}" + (f" — {', '.join(c['issues'])}" if c["issues"] else "")}
    if path == "/api/ai/device-type":
        dev = DEVICES.get(str(data.get("id") or ""))
        if not dev:
            raise ValueError("Device not found.")
        dev["type"] = "NVR" if str(data.get("type") or "").upper() == "NVR" else "DVR"
        save_config()
        return {"ok": True, "message": f"{dev.get('name') or dev.get('ip')} is now shown as {dev['type']}."}
    if path == "/api/ai/diagnose":
        did = str(data.get("dev") or ACTIVE_DEVICE_ID or "")
        dev = DEVICES.get(did)
        if not dev:
            raise ValueError("No DVR selected. Add or select a DVR first.")
        lines = run_diagnose(dev, int(data.get("ch") or (dev_channels(dev) or [1])[0]))
        print("\n".join(["", "=== IDP i DIAGNOSE ==="] + lines + [""]))
        return {"ok": True, "report": "\n".join(lines)}
    if path == "/api/ai/scan":
        kind = "dvr" if data.get("kind") == "dvr" else "health"
        AI_MON.wake[kind].set()
        return {"ok": True, "message": ("DVR" if kind == "dvr" else "Camera health") + " scan started."}
    if path == "/api/ai/gate-mark":
        if not CV_OK:
            raise ValueError("Install OpenCV first: sudo apt install python3-opencv python3-numpy")
        dev = _find_dev(data.get("dev"))
        ch = int(data.get("ch") or 1)
        state = "open" if data.get("state") == "open" else "closed"
        try:
            jpeg = ai_snapshot(dev, ch)
        except AuthError:
            raise ValueError("Wrong DVR password")
        img = decode_jpeg(jpeg)
        if img is None:
            raise ValueError("Could not get a snapshot from this camera")
        c = cam_cfg(dev["id"], ch)
        mode = "night" if is_night(img) else "day"
        save_ref(dev["id"], ch, f"gate_{state}_{mode}", gate_sig(img, c.get("gate_roi") or [0, 0, 1, 1]))
        (AI_DIRS["refs"] / (ref_path(dev["id"], ch, f"gate_{state}_{mode}").stem + ".jpg")).write_bytes(jpeg)
        c.update({"gate": 1, "gate_state": state, "gate_since": time.time(), "gate_long": 0})
        ai_save()
        return {"ok": True, "message": f"Gate {state.upper()} picture saved ({'night/IR' if mode == 'night' else 'day'} mode)."}
    if path == "/api/ai/face-enroll":
        if not FACE.ready():
            raise ValueError(FACE.error or "Face engine is not ready")
        name = str(data.get("name") or "").strip()[:80]
        cat = data.get("category") if data.get("category") in ("known", "vip", "watchlist") else "known"
        if not name:
            raise ValueError("Enter a name")
        raw = str(data.get("image") or "")
        raw = raw.split(",", 1)[1] if raw.startswith("data:") else raw
        img = decode_jpeg(base64.b64decode(raw))
        if img is None:
            raise ValueError("Could not read the photo (use JPG/PNG)")
        faces = FACE.detect(img, min_size=30)
        if not faces:
            raise ValueError("No face found in the photo — use a clear, front-facing photo")
        f = max(faces, key=lambda x: x["box"][2] * x["box"][3])
        fid = uuid.uuid4().hex[:10]
        (AI_DIRS["faces"] / f"face_{fid}.jpg").write_bytes(encode_jpeg(f["crop"]) or b"")
        with AI_LOCK:
            AI["faces"].append({"id": fid, "name": name, "category": cat, "emb": [round(float(v), 6) for v in f["feat"]],
                                "image": f"faces/face_{fid}.jpg", "created": time.time()})
        FACE.gallery = None
        ai_save()
        return {"ok": True, "message": f"{name} ({cat}) enrolled." + (" The photo had more than one face — used the largest." if len(faces) > 1 else "")}
    if path == "/api/ai/face-delete":
        fid = str(data.get("id") or "")
        with AI_LOCK:
            for f in [x for x in AI["faces"] if x["id"] == fid]:
                (AI_DIR / f["image"]).unlink(missing_ok=True)
            AI["faces"] = [x for x in AI["faces"] if x["id"] != fid]
        FACE.gallery = None
        ai_save()
        return {"ok": True, "message": "Deleted"}
    if path == "/api/ai/settings":
        for k, v in (data or {}).items():
            if k in AI_DEFAULTS:
                d = AI_DEFAULTS[k]
                if isinstance(d, str) and (k.startswith("after_hours") or k.startswith("face_schedule")):
                    vv = str(v).strip()
                    if vv and not re.match(r"^\d\d:\d\d$", vv):
                        raise ValueError(f"{k}: enter time as HH:MM (e.g. 09:00) or leave empty")
                    v = vv
                try:
                    AI["settings"][k] = type(d)(float(v)) if isinstance(d, (int, float)) and not isinstance(d, bool) else str(v)
                except ValueError:
                    raise ValueError(f"{k}: enter a number")
        ai_save()
        return {"ok": True, "message": "AI settings saved."}
    raise ValueError("Unknown endpoint")


def ai_api_get(path, qs, me=None):
    scope = user_device_scope(me)   # None = administrator (all devices); set = viewer's devices
    """Returns (content_type, body_bytes) or dict for /api/ai/* GET endpoints."""
    q = lambda k, d="": (qs.get(k) or [d])[0]  # noqa: E731
    if path == "/api/ai/status":
        return AI_MON.summary(scope)
    if path == "/api/ai/live-faces":
        return LIVE.snapshot(scope)
    if path == "/api/ai/events":
        since = int(q("since", "0") or 0)
        typ = q("type")
        with AI_LOCK:
            ev = [e for e in AI_EVENTS if e["id"] > since and (not typ or e["type"].startswith(typ))
                  and (scope is None or e.get("dvr_id") in scope)]
        return {"ok": True, "events": ev[-200:], "last": AI_EVENT_SEQ[0]}
    if path == "/api/ai/faces":
        return {"ok": True, "faces": [{k: f[k] for k in ("id", "name", "category", "image", "created")} for f in AI["faces"]],
                "cv_ok": CV_OK, "error": FACE.error}
    if path == "/api/ai/gate-refs":
        did, ch = q("dev"), int(q("ch", "1") or 1)
        refs = {}
        for st in ("open", "closed"):
            for mode in ("day", "night"):
                jp = AI_DIRS["refs"] / (ref_path(did, ch, f"gate_{st}_{mode}").stem + ".jpg")
                refs[f"{st}_{mode}"] = f"refs/{jp.name}" if jp.is_file() else None
        c = cam_cfg(did, ch) if did in DEVICES else {}
        return {"ok": True, "refs": refs, "roi": c.get("gate_roi"), "gate": c.get("gate"), "state": c.get("gate_state")}
    if path == "/api/ai/image" and scope is not None:
        rel = q("p")
        if rel.startswith("snaps/"):      # event pictures: only from devices this account may use
            with AI_LOCK:
                if not any(e.get("image") == rel and e.get("dvr_id") in scope for e in AI_EVENTS):
                    return None
        elif not rel.startswith("faces/"):  # gate reference pictures are administrator-only
            return None
    if path == "/api/ai/image":
        p = (AI_DIR / q("p")).resolve()
        if p.parent.parent != AI_DIR.resolve() or p.parent.name not in ("snaps", "refs", "faces") or p.suffix != ".jpg" or not p.is_file():
            return None
        return ("image/jpeg", p.read_bytes())
    if path in ("/api/ai/report", "/api/ai/report.txt", "/api/ai/report.csv"):
        try:
            h = datetime.strptime(f"{q('date')} {q('hour', '0')}", "%Y-%m-%d %H")
        except ValueError:
            return {"ok": False, "message": "Choose a date and hour"}
        R = build_report(h, q("dev"))
        fmt = path.rsplit(".", 1)[-1] if "." in path else q("format", "json")
        if fmt == "csv":
            return ("text/csv; charset=utf-8", report_csv(R).encode("utf-8"))
        if fmt == "txt":
            return ("text/plain; charset=utf-8", report_text(R).encode("utf-8"))
        return {"ok": True, "text": report_text(R), "partial": R["partial"], "problems": len(R["rows"]),
                "gates": len(R["gates"]), "system_on_sec": int(R["on_sec"])}

    if path == "/api/ai/report-day.txt":
        try:
            return ("text/plain; charset=utf-8", report_day_text(q("date"), q("dev")).encode("utf-8"))
        except ValueError:
            return ("text/plain; charset=utf-8", b"Choose a date.")
    if path in ("/api/ai/report-range-events.csv", "/api/ai/report-range-summary.csv"):
        try:
            fn = range_events_csv if "events" in path else range_summary_csv
            return ("text/csv; charset=utf-8", fn(q("from"), q("to"), q("dev")).encode("utf-8"))
        except ValueError as exc:
            return ("text/plain; charset=utf-8", f"Error: {exc}".encode("utf-8"))
    if path == "/api/ai/reports":
        out_r = []
        for d in sorted(REPORT_DIR.glob("20*-*-*"), reverse=True)[:7]:
            for f in sorted(d.glob("*.txt"), reverse=True):
                out_r.append({"date": d.name, "hour": f.stem[:2], "label": f"{d.name} {f.stem.replace('.', ':')}"})
        return {"ok": True, "reports": out_r[:72]}

    return None


LOGIN_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDP i | Sign in</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 20% 10%,#0a2a45 0,#020d1b 55%);color:#e8f3ff;font:14px/1.5 Inter,system-ui,"Segoe UI",Arial,sans-serif;padding:20px}
.box{width:min(380px,100%);background:linear-gradient(145deg,#061d32,#041629);border:1px solid #123b5d;border-radius:12px;padding:30px 28px;box-shadow:0 20px 60px #0008}
.brand{display:flex;gap:12px;align-items:center;margin-bottom:22px}
.logo{width:52px;height:52px;border-radius:50%;background:linear-gradient(145deg,#d9f3ff,#2476c7);color:#05182b;border:2px solid #8dd5ff;font-size:24px;display:grid;place-items:center;font-weight:900;box-shadow:0 0 22px #167bc355}
h1{margin:0;font-size:24px;letter-spacing:.4px}
.sub{font-size:11px;color:#9bb5cf;letter-spacing:.5px}
label{display:block;font-size:12px;color:#9bb5cf;margin:14px 0 5px}
input{width:100%;padding:11px 12px;border-radius:6px;border:1px solid #194566;background:#031425;color:#e8f3ff;font:inherit}
input:focus{outline:2px solid #2c9cff;outline-offset:1px}
button{width:100%;margin-top:20px;padding:11px;border-radius:6px;border:1px solid #1988e9;background:#0868bf;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.12)} button:disabled{opacity:.6;cursor:wait}
.err{min-height:20px;margin-top:12px;font-size:12px;color:#ff6c7b}
.foot{margin-top:18px;font-size:11px;color:#6f8ca8;text-align:center}
</style></head><body>
<form class="box" id="f" autocomplete="off">
  <div class="brand"><div class="logo">◉</div><div><h1>IDP i</h1><div class="sub">AI CCTV MONITORING · SIGN IN</div></div></div>
  <label for="u">Login ID</label><input id="u" name="username" autocomplete="username" required autofocus>
  <label for="p">Password</label><input id="p" name="password" type="password" autocomplete="new-password" data-lpignore="true" required>
  <button id="b" type="submit">Sign in</button>
  <div class="err" id="e" role="alert"></div>
  <div class="foot" style="margin-top:14px"><a href="/reset" style="color:#7fc4ff">Forgot password?</a></div>
  <div class="foot">Authorised staff only. All access is logged.</div>
</form>
<script>
// never let the browser put a saved password into the field (also after back/forward)
window.addEventListener('pageshow', () => { document.getElementById('p').value = ''; });
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const b = document.getElementById('b'), e = document.getElementById('e');
  b.disabled = true; e.textContent = '';
  try {
    const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username: document.getElementById('u').value.trim(), password: document.getElementById('p').value})});
    const j = await r.json();
    if (j.ok) { location.href = '/'; return; }
    e.textContent = j.message || 'Wrong login ID or password.';
  } catch (x) { e.textContent = 'Could not reach the IDP i server.'; }
  b.disabled = false; document.getElementById('p').value = ''; document.getElementById('p').focus();
});
</script>
</body></html>
'''

_AUTH_STYLE = LOGIN_HTML.split("<style>", 1)[1].split("</style>", 1)[0]   # same look as sign-in

SETUP_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDP i | First-time setup</title>
<style>''' + _AUTH_STYLE + r'''</style></head><body>
<form class="box" id="f" autocomplete="off">
  <div class="brand"><div class="logo">◉</div><div><h1>IDP i</h1><div class="sub">FIRST-TIME SETUP</div></div></div>
  <p style="font-size:13px;color:#bed4eb;margin:0 0 4px">Create the administrator password. The setup code is printed on the IDP i server console when it starts. If IDP runs as a service, read it with <code>journalctl -u idpi</code>.</p>
  <label for="c">Setup code</label><input id="c" autocomplete="off" required autofocus>
  <label for="p1">New password (at least 10 characters)</label><input id="p1" type="password" autocomplete="new-password" data-lpignore="true" required>
  <label for="p2">Confirm password</label><input id="p2" type="password" autocomplete="new-password" data-lpignore="true" required>
  <button id="b" type="submit">Create password</button>
  <div class="err" id="e" role="alert"></div>
  <div class="foot">Authorised staff only. All access is logged.</div>
</form>
<script>
window.addEventListener('pageshow', () => { document.getElementById('p1').value = ''; document.getElementById('p2').value = ''; });
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const b = document.getElementById('b'), e = document.getElementById('e');
  const p1 = document.getElementById('p1'), p2 = document.getElementById('p2');
  e.textContent = '';
  if (p1.value !== p2.value) { e.textContent = 'The two passwords do not match.'; p2.value = ''; p2.focus(); return; }
  if (p1.value.length < 10) { e.textContent = 'Use at least 10 characters.'; return; }
  b.disabled = true;
  try {
    const r = await fetch('/api/setup', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({code: document.getElementById('c').value.trim(), password: p1.value, confirm: p2.value})});
    const j = await r.json();
    if (j.ok) { location.href = '/login'; return; }
    e.textContent = j.message || 'Setup failed.';
  } catch (x) { e.textContent = 'Could not reach the IDP i server.'; }
  b.disabled = false;
});
</script></body></html>
'''

RESET_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDP i | Reset password</title>
<style>''' + _AUTH_STYLE + r'''</style></head><body>
<form class="box" id="f" autocomplete="off">
  <div class="brand"><div class="logo">◉</div><div><h1>IDP i</h1><div class="sub">RESET PASSWORD</div></div></div>
  <p style="font-size:13px;color:#bed4eb;margin:0 0 4px">Enter your login ID. A reset code is printed on the IDP i server console (or in its service log, <code>journalctl -u idpi</code>). Ask the person who runs the server if you cannot see it.</p>
  <label for="u">Login ID</label><input id="u" name="username" autocomplete="username" required autofocus>
  <div id="s2" style="display:none">
    <div id="m" style="font-size:12px;color:#bed4eb;margin-top:12px;line-height:1.5"></div>
    <label for="c">Reset code</label><input id="c" autocomplete="off">
    <label for="p1">New password (at least 10 characters)</label><input id="p1" type="password" autocomplete="new-password" data-lpignore="true">
    <label for="p2">Confirm new password</label><input id="p2" type="password" autocomplete="new-password" data-lpignore="true">
  </div>
  <button id="b" type="submit">Send reset code</button>
  <div class="err" id="e" role="alert"></div>
  <div class="foot"><a href="/login" style="color:#7fc4ff">Back to sign in</a></div>
</form>
<script>
let stage = 1;
const $ = id => document.getElementById(id);
window.addEventListener('pageshow', () => { $('p1').value = ''; $('p2').value = ''; });
$('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const b = $('b'), e = $('e');
  e.textContent = '';
  b.disabled = true;
  try {
    if (stage === 1) {
      const r = await fetch('/api/reset/request', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({username: $('u').value.trim()})});
      const j = await r.json();
      if (!r.ok) { e.textContent = j.message || 'Could not request a code.'; b.disabled = false; return; }
      $('m').textContent = j.message;
      $('u').readOnly = true;
      $('s2').style.display = 'block';
      b.textContent = 'Reset password';
      stage = 2;
      $('c').focus();
    } else {
      if ($('p1').value !== $('p2').value) { e.textContent = 'The two passwords do not match.'; $('p2').value = ''; b.disabled = false; return; }
      if ($('p1').value.length < 10) { e.textContent = 'Use at least 10 characters.'; b.disabled = false; return; }
      const r = await fetch('/api/reset/confirm', {method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({username: $('u').value.trim(), code: $('c').value.trim(),
                              password: $('p1').value, confirm: $('p2').value})});
      const j = await r.json();
      if (j.ok) { location.href = '/login'; return; }
      e.textContent = j.message || 'Reset failed.';
    }
  } catch (x) { e.textContent = 'Could not reach the IDP i server.'; }
  b.disabled = false;
});
</script></body></html>
'''

HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDP i | CCTV + AI</title>
<style>
:root{--bg:#03101f;--panel:#061a2d;--panel2:#0a2239;--line:#123957;--muted:#9bb5cf;--text:#e8f3ff;--green:#20d879;--amber:#ffb52e;--red:#ff4255;--blue:#2c9cff}
*{box-sizing:border-box}body{margin:0;background:#020d1b;color:var(--text);font:13px/1.5 Inter,system-ui,Segoe UI,Arial,sans-serif}
button,select,input,textarea{font:inherit}button{border:1px solid var(--line);border-radius:5px;padding:9px 12px;color:var(--text);background:#0a2a45;cursor:pointer}button:hover{filter:brightness(1.15)}button.primary{background:#0868bf;border-color:#1988e9}button.danger{background:#611b2b;border-color:#a83345}button.ghost{background:transparent}
.shell{min-height:100vh;background:linear-gradient(120deg,#03101f,#04182b 60%,#03101f)}
.top{height:74px;margin:0;padding:10px 22px;border-bottom:1px solid #123451;background:#041426;position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;align-items:center;gap:16px}
.brand{display:flex;gap:12px;align-items:center}.logo{width:54px;height:48px;border-radius:50%;background:linear-gradient(145deg,#d9f3ff,#2476c7);color:#05182b;border:2px solid #8dd5ff;font-size:25px;display:grid;place-items:center;font-weight:900;box-shadow:0 0 20px #167bc344}
.brand h1{font-size:24px;letter-spacing:.5px;font-weight:750;margin:0}.sub{font-size:10px;letter-spacing:.6px;color:#bed4eb}
.status{color:#c8d9ec;white-space:nowrap;font-size:12px}.status .dot{color:#20d879;box-shadow:0 0 8px #20d879}
.ai-badge{display:inline-flex;align-items:center;gap:6px;background:#0a2a3a;border:1px solid #1a5a7a;padding:5px 10px;border-radius:20px;font-size:11px;color:#7dd3fc}
.ai-badge .pulse{width:8px;height:8px;border-radius:50%;background:#20d879;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.mic-btn{display:inline-flex;align-items:center;gap:6px;border-radius:20px;padding:6px 12px;font-size:12px;border:1px solid #1a5a7a;background:#0a2a3a;color:#7dd3fc;cursor:pointer}
.mic-btn.listening{background:#3b1220;border-color:#a83345;color:#ffb2b8;animation:pulse 1s infinite}
.mic-btn .mic-dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.voice-hint{font-size:10px;color:var(--muted);margin-top:6px}
.notice{margin:12px 14px 8px 234px;border-radius:5px;padding:7px 10px;font-size:10px;background:#1c2020;border:1px solid #54472c;color:#d8c79f}
.nav{position:fixed;z-index:15;left:0;top:74px;bottom:0;width:220px;overflow-y:auto;margin:0;padding:12px 8px;display:flex;flex-direction:column;gap:5px;background:#031426;border-right:1px solid #123451}
.nav button{width:100%;text-align:left;border-radius:5px;background:transparent;border:1px solid transparent;padding:12px 13px;font-size:13px;color:#c7d8ea}.nav button.active{background:linear-gradient(90deg,#086bd0,#0755a8);border-color:#1687f3;color:#fff}
.page{display:none;margin-left:220px;padding:14px 14px 20px}.page.active{display:block}
.card{background:linear-gradient(145deg,#061d32,#041629);border:1px solid #123b5d;border-radius:7px;padding:14px;box-shadow:0 3px 12px #0002}
.grid{display:grid;gap:12px}.stats{grid-template-columns:repeat(4,minmax(0,1fr));margin-bottom:12px}
.stat-head{font-size:10px;letter-spacing:.7px;color:#9ab5d1}.stat-num{font-size:27px;margin:5px 0;font-weight:750}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}.blue{color:var(--blue)}.muted{color:var(--muted)}
.layout{grid-template-columns:minmax(0,1.55fr) minmax(290px,.8fr);gap:12px}
.cameras{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.cam{padding:0;border-radius:5px;overflow:hidden}.feed{height:150px;background:linear-gradient(155deg,#12394a,#1d4a52 35%,#081c2c 36%,#0a2a3b 68%,#15394b);border-bottom:1px solid #1b4969;display:grid;place-items:center;position:relative}
.feed-label{position:absolute;z-index:2;top:8px;left:8px;background:#04101de8;padding:3px 7px;border-radius:4px;font-size:9px;border:1px solid #173d59}
.feed-state{position:absolute;z-index:2;right:8px;top:8px;font-size:9px}
.cam-body{padding:9px}.cam-title{display:flex;justify-content:space-between;gap:8px;align-items:start}.cam-title h3{font-size:12px;margin:0}.cam-meta{font-size:10px;color:var(--muted);margin:4px 0 10px}
.actions{display:flex;gap:5px;flex-wrap:wrap}.actions button{font-size:10px;padding:6px 7px;border-radius:4px}
.pill{display:inline-block;border-radius:30px;padding:3px 7px;font-size:9px;font-weight:700;background:#21334b;color:#c5d5e9}
.pill.online{background:#073b2c;color:#30e58a}.pill.offline{background:#4c1624;color:#ff6c7b}.pill.warn{background:#493313;color:#ffc04e}
.list{display:grid;gap:8px}.event{display:flex;gap:10px;align-items:start;padding:9px;background:#06182a;border:1px solid #12344e;border-radius:5px}
.event-icon{height:28px;width:28px;display:grid;place-items:center;border-radius:5px;background:#24354b;flex-shrink:0;font-size:12px}
.event-title{font-weight:650;font-size:12px}.event-meta{font-size:10px;color:var(--muted);margin-top:2px}.event-time{font-size:10px;color:var(--muted);margin-left:auto;white-space:nowrap}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}h2{font-size:15px;margin:0 0 10px}h3{font-size:12px;margin:0}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:520px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;font-size:12px}th{color:var(--muted);font-weight:600}
input,select,textarea{background:#031425!important;color:#e8f3ff!important;border:1px solid #194566!important;border-radius:5px!important;padding:10px;width:100%}
label.muted{display:block;margin-bottom:4px;font-size:11px}
.footer{margin-left:220px;border-top:1px solid #123451;padding:14px;color:#7796b4;text-align:center;font-size:10px}
.toast{position:fixed;right:20px;top:20px;z-index:30;width:min(390px,calc(100% - 40px));padding:16px;border:1px solid #a14b56;border-radius:13px;background:#321d29;box-shadow:0 12px 50px #0008;display:none}
.toast.show{display:block}.toast h3{color:#ffb2b8;margin:0 0 6px}.toast p{font-size:12px;color:#e6cbd0;margin:0 0 12px}
.rtsp-box{font-family:ui-monospace,monospace;font-size:11px;background:#02101c;border:1px solid #1a3a55;padding:8px;border-radius:5px;word-break:break-all;margin:6px 0}
.hidden{display:none!important}
/* ---- dashboard (picture layout) ---- */
.top-links{display:flex;align-items:center;margin:0 auto}
.top-links a{color:#c7d8ea;padding:0 14px;border-right:1px solid #2a4a6a;cursor:pointer;font-size:13px;text-decoration:none;white-space:nowrap}
.top-links a:last-child{border-right:0}.top-links a:hover{color:#fff}
.sd-admin{font-size:12px;color:#c7d8ea;margin:0 4px}
.sd-wrap{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:14px;align-items:start}
.sd-main,.sd-side,.sd-col{display:flex;flex-direction:column;gap:14px;min-width:0}
.sd-cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.sd-card,.sd-panel{background:linear-gradient(180deg,#081e36,#05162a);border:1px solid #173d61;border-radius:10px;padding:14px;min-width:0}
.sd-card{display:flex;gap:12px;align-items:center}
.sd-card b{font-size:14px}
.sd-ico{width:50px;height:50px;border-radius:10px;display:grid;place-items:center;font-size:24px;background:#0c2b4b;flex-shrink:0}
.sd-ico.blue{background:#0a5bd0}.sd-ico.green{background:#0c6b3b}
.sd-state{font-size:12px;margin-top:6px;font-weight:600}.sd-state.ok{color:#2ee07e}.sd-state.warn{color:#ffb52e}.sd-state.bad{color:#ff5468}
.sd-brand{color:#ff2b3a;font-weight:800;letter-spacing:.5px;font-size:15px}
.sd-tabs{display:flex;gap:2px;border-bottom:1px solid #173d61;margin-bottom:12px}
.sd-tabs button{background:transparent;border:0;border-bottom:2px solid transparent;border-radius:6px 6px 0 0;padding:9px 16px;color:#c7d8ea;font-size:13px}
.sd-tabs button.active{border-bottom-color:#1687f3;color:#fff;background:#0b2c50}
.sd-tabs.small button{padding:6px 12px;font-size:11px;flex:1}
.sd-split{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.sd-group{min-width:0}
.sd-ghead{display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:14px}
.sd-gico{width:30px;height:30px;border-radius:6px;display:grid;place-items:center;font-size:15px}.sd-gico.red{background:#b3192b}.sd-gico.blue{background:#0a5bd0}
.sd-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.sd-grid.wide{grid-template-columns:repeat(4,minmax(0,1fr))}
.sd-tile{position:relative;aspect-ratio:16/10;background:#000;border:1px solid #24496e;border-radius:6px;overflow:hidden;cursor:zoom-in}
.sd-tile img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.sd-tlabel{position:absolute;z-index:2;left:0;top:0;right:58px;background:linear-gradient(90deg,#000d,#0000);padding:4px 7px;font-size:11px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sd-live{position:absolute;z-index:2;right:5px;top:4px;font-size:10px;font-weight:700;background:#000a;padding:1px 6px;border-radius:3px}
.sd-live i{display:inline-block;width:7px;height:7px;border-radius:50%;background:#7a8ea3;margin-right:4px;vertical-align:0}
.sd-live.on i{background:#ff2b3a;box-shadow:0 0 6px #ff2b3a}.sd-live.snap i{background:#ffb52e}.sd-live.off i{background:#555}
.sd-wm{position:absolute;z-index:2;right:7px;bottom:5px;font-size:10px;font-weight:700;color:#ffffffb8;letter-spacing:.4px}
.sd-tile .livemsg{font-size:10px}.sd-tile .inview{bottom:20px}
.sd-empty{border:1px dashed #2a557e;border-radius:8px;padding:34px 12px;text-align:center;color:#8fb0cc;font-size:12px}
.sd-empty button{margin-top:10px}
.sd-bottom{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:14px;align-items:start}
.sd-phead{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.sd-phead h3{margin:0;font-size:14px}.sd-phead a{color:#3aa0ff;font-size:12px;cursor:pointer}
.sd-table{width:100%;border-collapse:collapse;font-size:12px}
.sd-table th{text-align:left;color:#9bb6cf;font-weight:600;padding:7px 6px;border-bottom:1px solid #173d61;white-space:nowrap}
.sd-table td{padding:8px 6px;border-bottom:1px solid #0f2c47;vertical-align:middle}
.sd-pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;white-space:nowrap}
.sd-pill.sos{background:#d11f35;color:#fff}.sd-pill.warn{background:#e3a01c;color:#1a1200}.sd-pill.ok{background:#1aa35a;color:#fff}
.sd-sevdot{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;font-size:10px;margin-right:6px;color:#fff}
.sd-sevdot.sos{background:#d11f35}.sd-sevdot.warn{background:#e3a01c}.sd-sevdot.ok{background:#1aa35a}
.sd-sos{border-color:#5a1f2c}
.sd-sos-item{background:#1b0f1a;border:1px solid #4a1d2a;border-radius:8px;padding:10px;margin-bottom:8px}
.sd-sos-item.warn{background:#1c1710;border-color:#4d3c1d}
.sd-sos-item .t{display:flex;justify-content:space-between;gap:6px;font-weight:700;font-size:12px}
.sd-sos-item .t span.c{color:#ff6b7c}.sd-sos-item.warn .t span.c{color:#ffc04d}
.sd-sos-item .d{font-size:11px;color:#c7d8ea;margin:4px 0 6px}
.sd-sos-item .a{text-align:right}.sd-sos-item button{font-size:10px;padding:3px 12px}
.sd-qa{display:flex;flex-direction:column;gap:6px}.sd-qa button{text-align:left;font-size:12px;padding:9px 12px}
.sd-rep{display:flex;align-items:center;gap:10px;padding:8px;border:1px solid #173d61;border-radius:7px;margin-bottom:6px}
.sd-rep .i{width:30px;height:30px;border-radius:50%;background:#0c2b4b;display:grid;place-items:center;flex-shrink:0}
.sd-rep .n{flex:1;min-width:0;font-size:12px}.sd-rep .n div{font-size:10px;color:#8fb0cc}
.sd-rep button{font-size:10px;padding:4px 10px}
.sd-dev{display:flex;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid #0f2c47;font-size:12px}
.sd-dev:last-child{border-bottom:0}
.sd-dev .logo2{width:64px;height:44px;border-radius:6px;background:#1a1220;display:grid;place-items:center;font-size:11px;flex-shrink:0}
.sd-health{display:flex;gap:16px;align-items:center}
.sd-legend{flex:1;font-size:12px}.sd-legend div{display:flex;justify-content:space-between;padding:3px 0}
.sd-legend i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px}
.nav .sd-nbadge,.sd-nbadge{background:#e0263b;color:#fff;border-radius:10px;padding:1px 7px;font-size:10px;font-weight:700;margin-left:8px}
.nav .sd-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#e0263b;margin-left:8px}
.sd-navbrand{margin-top:auto;padding:14px 8px 6px;border-top:1px solid #123451}
.sd-navdev{font-size:12px;margin-top:8px}.sd-chk{display:inline-grid;place-items:center;width:16px;height:16px;border-radius:50%;background:#1aa35a;color:#fff;font-size:10px;margin-right:6px}
.sd-navdev.off .sd-chk{background:#d11f35}
.sd-classic{margin-top:14px}.sd-classic summary{cursor:pointer;color:#9bb6cf;font-size:12px}
@media(max-width:1250px){.sd-wrap{grid-template-columns:1fr}.top-links{display:none}}
@media(max-width:1000px){.sd-split,.sd-bottom,.sd-cards{grid-template-columns:1fr}.sd-grid.wide{grid-template-columns:repeat(2,minmax(0,1fr))}}
#allCameras .feed{height:250px}
.feed{cursor:zoom-in}
.inview{position:absolute;z-index:2;left:6px;right:6px;bottom:6px;display:flex;flex-wrap:wrap;gap:4px;pointer-events:none}
.inview span{background:#04101de8;border:1px solid #2a6a9a;border-radius:4px;padding:2px 6px;font-size:10px;font-weight:600}
.inview .known{border-color:#20d879;color:#5ff0a4}.inview .vip{border-color:#ffb52e;color:#ffd27a}
.inview .watchlist{border-color:#ff4255;color:#ff8a95}.inview .unknown{border-color:#2c9cff;color:#8cc8ff}
.livemsg{position:absolute;z-index:3;left:10px;right:10px;top:50%;transform:translateY(-50%);text-align:center;font-size:11px;color:#ffd27a;background:#04101dd0;border:1px solid #54472c;border-radius:5px;padding:6px 8px;pointer-events:none}
.livemsg.small{top:auto;bottom:30px;transform:none;font-size:9px;padding:3px 6px;opacity:.9}
.faceai-tag{position:absolute;z-index:2;left:8px;top:30px;background:#073b2c;color:#30e58a;border-radius:4px;padding:2px 6px;font-size:9px;font-weight:700}
.people{display:grid;gap:8px;grid-template-columns:repeat(auto-fill,minmax(230px,1fr))}
.person{display:flex;gap:10px;align-items:center;padding:8px;background:#06182a;border:1px solid #12344e;border-radius:6px}
.person img,.person .noimg{width:52px;height:52px;border-radius:6px;object-fit:cover;flex-shrink:0;background:#0a2540;display:grid;place-items:center;font-size:22px}
.person.watchlist{border-color:#a83345;background:#2a0f18}.person.unknown{border-color:#1a5a7a}
/* AI panel */
.ai-panel{display:flex;flex-direction:column;height:calc(100vh - 160px);min-height:420px}
.ai-chat{flex:1;overflow-y:auto;padding:12px;background:#04101c;border:1px solid #123b5d;border-radius:8px;margin-bottom:10px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:92%;padding:10px 12px;border-radius:10px;font-size:12px;line-height:1.45}
.msg.ai{align-self:flex-start;background:#0a2540;border:1px solid #1a4a6d}
.msg.user{align-self:flex-end;background:#0d3a5c;border:1px solid #2a6a9a}
.msg .role{font-size:10px;color:var(--muted);margin-bottom:4px}
.ai-input-row{display:flex;gap:8px}
.ai-input-row input{flex:1}
.ai-insights{font-size:12px}
.ai-insights li{margin:6px 0}
.insight-ok{color:var(--green)}.insight-warn{color:var(--amber)}.insight-bad{color:var(--red)}
.monitor-bar{display:flex;align-items:center;gap:10px;padding:8px 12px;background:#061a28;border:1px solid #123b5d;border-radius:6px;margin-bottom:12px;font-size:11px}
.monitor-bar .live{color:var(--green);font-weight:600}
@media(max-width:900px){.nav{width:175px}.page{margin-left:175px}.notice{margin-left:188px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.layout{grid-template-columns:1fr}}
.pb-progress{margin-top:12px;padding:12px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08)}
.pb-bar{height:10px;border-radius:6px;background:rgba(255,255,255,.08);overflow:hidden}
.pb-bar>div{height:100%;width:0;background:linear-gradient(90deg,#2b8cff,#34c759);transition:width .6s ease}
.pb-row{display:flex;justify-content:space-between;align-items:baseline;gap:8px;flex-wrap:wrap;font-size:12px;margin-top:6px}
.pb-status{font-size:13px;margin-top:8px}
@media(max-width:700px){
  .card select,.card input,.card button,.card a.primary{min-height:44px;font-size:16px}
  .card .actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .card .actions>*{width:100%;text-align:center}
  #pbPlayer{max-height:none}
}
@media(max-width:600px){.nav{position:static;width:auto;flex-direction:row;overflow-x:auto;border-right:0;border-bottom:1px solid #123451}.page{margin-left:0}.notice{margin:9px}.top{position:static}.cameras{grid-template-columns:1fr}.footer{margin-left:0}}
</style></head><body>
<div class="shell">
<header class="top">
  <div class="brand"><div class="logo">◉</div><div><h1>IDP i</h1><div class="sub">CCTV monitoring · Always on</div></div></div>
  <div class="top-links"><a onclick="go('devices')">Remote Access</a><a onclick="go('cctv')">Live CCTV</a><a onclick="go('alerts')">Tamper Alert</a><a onclick="go('aimon')">Smart Monitoring</a></div>
  <div class="status">
    <span class="ai-badge"><span class="pulse"></span> AI Monitor ON</span>
    &nbsp;
    <button type="button" class="mic-btn" id="micBtn" onclick="toggleVoice()" title="Voice commands">
      <span class="mic-dot"></span> <span id="micLabel">🎤 Voice</span>
    </button>
    <button type="button" class="mic-btn" id="voiceAlertBtn" onclick="toggleVoiceAlerts()" title="Speak new alerts aloud">🔊 Voice alerts</button>
    <span class="sd-admin">👤 Admin</span>
    <button type="button" class="mic-btn" onclick="logout()" title="Sign out">⎋ Logout</button>
    &nbsp;|&nbsp; <span class="dot">●</span> Online &nbsp;|&nbsp; <span id="connBadge">No DVR linked</span>
  </div>
</header>
<div class="notice">Connect DVR (Setup) with IP → Live View shows camera snapshots. Telegram is saved on disk. SOS / offline / angle alerts auto-send when configured. Same LAN required for live feed.</div>
<nav class="nav">
  <button class="active" data-page="overview">⌂　Dashboard</button>
  <button data-page="cctv">▣　Live View</button>
  <button data-page="devices" class="admin-only">▤　Devices (DVR Setup)</button>
  <button data-page="overview" data-sdtab="DVR">🖴　DVR<span class="sd-dot hidden" id="sdDotDVR"></span></button>
  <button data-page="overview" data-sdtab="NVR">🖧　NVR<span class="sd-dot hidden" id="sdDotNVR"></span></button>
  <button data-page="alerts" class="admin-only">♧　Alerts & SOS<span class="sd-nbadge hidden" id="sdNavSos">0</span></button>
  <button data-page="reports" class="admin-only">▤　Reports</button>
  <button data-page="logs" class="admin-only">☰　Logs</button>
  <button data-page="aimon" data-scroll="aiSettingsCard" class="admin-only">⚙　Settings</button>
  <button data-page="playback">▶　Playback</button>
  <button data-page="ai" class="admin-only">✦　AI Assistant</button>
  <button data-page="aimon" class="admin-only">◉　AI Camera Health</button>
  <button data-page="gates" class="admin-only">🚪　Gate Detection</button>
  <button data-page="faces" class="admin-only">🙂　Face Recognition</button>
  <button data-page="locations" class="admin-only">⌖　Locations</button>
  <button data-page="users" class="admin-only">👤　Users</button>
  <div class="sd-navbrand"><div class="sd-brand" style="font-size:20px">IDP</div>
    <div class="sd-navdev" id="sdNavDVR"><span class="sd-chk">✓</span> DVR <span class="muted">—</span></div>
    <div class="sd-navdev" id="sdNavNVR"><span class="sd-chk">✓</span> NVR <span class="muted">—</span></div>
    <div class="muted" style="font-size:10px;margin-top:12px;text-align:center">🛡 Your Security, Our Priority</div></div>
</nav>

<section class="page active" id="overview">
 <div class="sd-wrap">
  <div class="sd-main">
   <div class="sd-cards">
    <div class="sd-card"><div class="sd-ico blue">🔗</div><div><b>Remote Access</b><div class="muted">Directly connected to your devices</div><div id="sdRemote" class="sd-state">● Checking…</div></div></div>
    <div class="sd-card"><div class="sd-ico">🖴</div><div><div class="sd-brand">IDP</div><b>DVR + NVR</b><div class="muted">Live Feed | Recording | Playback</div><div class="muted" id="sdDevCount" style="font-size:11px">—</div></div></div>
    <div class="sd-card"><div class="sd-ico green">🛡</div><div><b>Security Status</b><div class="muted">Monitored 24/7</div><div id="sdSecurity" class="sd-state">● Checking…</div></div></div>
   </div>
   <div class="sd-panel">
    <div class="sd-tabs"><button class="active" data-sdtab="live" onclick="sdSetTab('live')">Live View</button><button data-sdtab="DVR" onclick="sdSetTab('DVR')">DVR</button><button data-sdtab="NVR" onclick="sdSetTab('NVR')">NVR</button>
     <span class="muted" style="margin-left:auto;align-self:center;font-size:11px">Click a camera to enlarge</span></div>
    <div id="sdFeeds"><div class="sd-empty">Loading cameras…</div></div>
   </div>
   <div class="sd-bottom">
    <div class="sd-panel">
     <div class="sd-phead"><h3>🔔 Recent Events &amp; Alerts</h3><a onclick="go('logs')">View All</a></div>
     <div style="overflow-x:auto"><table class="sd-table"><thead><tr><th>Time</th><th>Device</th><th>Channel</th><th>Event</th><th>Status</th></tr></thead><tbody id="sdEvents"><tr><td colspan="5" class="muted">No events yet.</td></tr></tbody></table></div>
    </div>
    <div class="sd-col">
     <div class="sd-panel"><div class="sd-phead"><h3>🖧 Device Status</h3><a onclick="go('devices')">Manage</a></div><div id="sdDevices"><div class="muted">No device added yet.</div></div></div>
     <div class="sd-panel"><div class="sd-phead"><h3>📷 Camera Health</h3><a onclick="go('aimon')">Details</a></div><div id="sdHealth" class="sd-health"></div></div>
    </div>
   </div>
  </div>
  <div class="sd-side">
   <div class="sd-panel sd-sos"><div class="sd-phead"><h3>🚨 SOS / Security Alerts</h3><span class="sd-nbadge" id="sdSosCount">0</span></div><div id="sdSos"><div class="muted">No open alerts. All good.</div></div></div>
   <div class="sd-panel"><div class="sd-phead"><h3>⚡ Quick Actions</h3></div><div class="sd-qa">
     <button onclick="go('cctv')">📹　View All Cameras</button>
     <button onclick="go('devices')">🔗　Remote Access</button>
     <button onclick="go('reports')">📄　Download Report</button>
     <button onclick="sdCsv(SD.events.slice().reverse(), 'idpi-logs.csv')">🗎　Export Logs</button>
     <button class="danger" onclick="triggerSOS()">⚠　Trigger SOS</button></div></div>
   <div class="sd-panel"><div class="sd-phead"><h3>📊 Reports</h3><a onclick="go('reports')">View All</a></div>
     <div class="sd-tabs small"><button class="active" data-sdrange="1" onclick="sdSetRange(1)">Today</button><button data-sdrange="7" onclick="sdSetRange(7)">7 Days</button><button data-sdrange="30" onclick="sdSetRange(30)">30 Days</button></div>
     <div id="sdReports"></div></div>
  </div>
 </div>
 <details class="card sd-classic"><summary>Classic overview — AI insights, quick tests and active-DVR cameras</summary>
  <div class="monitor-bar">
    <span class="live">● AI MONITORING</span>
    <span id="aiMonitorText">Scanning cameras & events…</span>
    <span style="margin-left:auto" id="aiLastScan" class="muted">—</span>
  </div>
  <div class="grid stats">
    <div class="card"><div class="stat-head">CAMERAS ONLINE <span class="green">●</span></div><div class="stat-num" id="onlineCount">0/16</div><div class="muted">CP-UVR-1601E2-I</div></div>
    <div class="card"><div class="stat-head">DVR LINK <span class="blue">▣</span></div><div class="stat-num" id="dvrLink">—</div><div class="muted" id="dvrMode">Not connected</div></div>
    <div class="card"><div class="stat-head">OPEN INCIDENTS <span class="red">◆</span></div><div class="stat-num" id="incidentCount">0</div><div class="muted">AI tracked</div></div>
    <div class="card"><div class="stat-head">AI STATUS <span class="amber">✦</span></div><div class="stat-num" style="font-size:18px" id="aiHealth">Active</div><div class="muted">Always on</div></div>
  </div>
  <div class="grid layout">
    <div class="card">
      <div class="section-head"><h2>Live View — CP-UVR-1601E2-I</h2><button class="ghost" onclick="go('cctv')">View all →</button></div>
      <div class="grid cameras" id="overviewCameras"></div>
    </div>
    <div class="card">
      <div class="section-head"><h2>AI Insights</h2><button class="ghost" onclick="go('ai')">Open AI →</button></div>
      <ul class="ai-insights" id="aiInsightsList"></ul>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h2>Quick Actions</h2>
      <div class="actions">
        <button class="danger" onclick="triggerSOS()">⚠ Trigger SOS</button>
        <button onclick="simulateOffline()">▣ Camera Offline</button>
        <button onclick="simulateAngle()">⌖ Angle Change</button>
        <button onclick="resetDemo()">↻ Reset</button>
      </div>
      <div class="section-head" style="margin-top:14px"><h2>Recent Events</h2></div>
      <div class="list" id="recentEvents"></div>
    </div>
  </div>
 </details>
</section>

<section class="page" id="logs">
  <div class="section-head"><div><h2>Logs</h2><div class="muted">Every event the AI recorded (newest first)</div></div>
    <div class="actions"><select id="logFilter" onchange="renderLogs()" style="min-width:170px"><option value="">All events</option><option value="CRITICAL">SOS / Critical</option><option value="WARNING">Warning</option><option value="INFO">Normal</option></select>
    <button onclick="sdCsv(sdLogRows(), 'idpi-logs.csv')">⬇ Export CSV</button></div></div>
  <div class="card" style="overflow-x:auto"><table class="sd-table"><thead><tr><th>Time</th><th>Device</th><th>Site</th><th>Channel</th><th>Event</th><th>Details</th><th>Status</th></tr></thead><tbody id="logRows"><tr><td colspan="7" class="muted">No events yet.</td></tr></tbody></table></div>
</section>

<section class="page" id="cctv">
  <div class="section-head">
    <div><h2>CCTV Live View</h2><div class="muted">Local RTSP · Copy URL → VLC for playback</div></div>
    <div class="actions" style="align-items:center"><label class="muted" for="liveDevSel" style="margin:0">DVR</label>
      <input id="liveDevSearch" placeholder="Search DVR…" oninput="filterLiveDevSel()" style="max-width:160px">
      <select id="liveDevSel" style="min-width:240px" onchange="if(this.value) selectDevice(this.value)"><option value="">No DVR added yet</option></select>
      <button onclick="runDiagnose()">🩺 Diagnose</button>
      <span class="pill" id="livePill">NO STREAM</span></div>
  </div>
  <div class="card hidden" id="diagCard" style="margin-bottom:12px">
    <div class="section-head"><h2 style="margin:0">🩺 Live video diagnose</h2>
      <div class="actions"><button onclick="copyText(document.getElementById('diagOut').textContent)">Copy</button>
      <button onclick="document.getElementById('diagCard').classList.add('hidden')">Close</button></div></div>
    <pre id="diagOut" style="white-space:pre-wrap;font-size:11px;margin:8px 0 0;max-height:360px;overflow:auto"></pre>
  </div>
  <div class="card" style="margin-bottom:12px">
    <div class="section-head"><div><h2 style="margin:0">🙂 Live Face Recognition — who is in front of the cameras now</h2>
      <div class="muted" style="font-size:11px">Turn on <b>🙂 Face AI</b> on a camera below. The AI checks the live video several times a second, draws the name on the video, and alerts when someone arrives.</div></div>
      <span class="pill" id="liveFaceState">—</span></div>
    <div class="people" id="livePeople"><div class="muted">Nobody in front of the face cameras right now.</div></div>
  </div>
  <div class="grid cameras" id="allCameras"></div>
  <div class="card" style="margin-top:12px">
    <h2>RTSP URLs</h2>
    <p class="muted" style="font-size:11px">Browser often cannot play RTSP. Use VLC → Media → Open Network Stream.</p>
    <div id="rtspList" class="list"></div>
  </div>
</section>


<section class="page" id="playback">
  <div class="section-head">
    <div><h2>▶ Playback & Download</h2><div class="muted">View recorded time range (RTSP playback) and export a clip to MP4</div></div>
    <span class="pill">Recorded footage</span>
  </div>
  <div class="grid layout">
    <div class="card">
      <h2>Search / open playback</h2>
      <p class="muted" style="font-size:12px">Select active DVR channels, set start & end time. Browser cannot play RTSP; use VLC or export MP4 below.</p>
      <label class="muted">DVR / NVR</label>
      <select id="pbDevice" style="margin-bottom:10px"></select>
      <label class="muted">Channel</label>
      <select id="pbChannel" style="margin-bottom:10px"></select>
      <label class="muted">Start time</label>
      <input id="pbStart" type="datetime-local" style="margin-bottom:10px">
      <label class="muted">End time</label>
      <input id="pbEnd" type="datetime-local" style="margin-bottom:10px">
      <div class="actions">
        <button class="primary" type="button" onclick="buildPlayback()">Build playback URL</button>
        <button type="button" onclick="copyPlayback()">Copy RTSP</button>
        <button id="pbBtnExport" class="primary" type="button" onclick="exportClip()">Download MP4 clip</button>
      </div>
      <div id="pbResult" class="muted" style="font-size:12px;margin-top:12px">Connect a DVR first, then choose channel and time.</div>
      <div id="pbProgress" class="pb-progress" style="display:none">
        <div class="pb-row"><b id="pbPct">0%</b><span id="pbDetail" class="muted"></span></div>
        <div class="pb-bar" style="margin-top:8px"><div id="pbBarFill"></div></div>
        <div id="pbStatusLine" class="pb-status"></div>
        <div class="actions" style="margin-top:10px">
          <button id="pbCancelBtn" type="button" onclick="pbCancel()" style="display:none">Cancel</button>
          <button id="pbRetryBtn" class="primary" type="button" onclick="pbRetry()" style="display:none">Retry download</button>
          <a id="pbSaveBtn" href="#" class="primary" style="display:none">↓ Save file</a>
        </div>
      </div>
      <div class="rtsp-box" id="pbUrl" style="margin-top:10px;display:none"></div>
    </div>
    <div class="card">
      <h2>How playback works</h2>
      <div class="list">
        <div class="event"><div class="event-icon blue">1</div><div><div class="event-title">Active DVR</div><div class="event-meta">Use DVR Setup → Select the device that holds the recordings.</div></div></div>
        <div class="event"><div class="event-icon blue">2</div><div><div class="event-title">Time range</div><div class="event-meta">Start/end must match when the DVR was recording that channel.</div></div></div>
        <div class="event"><div class="event-icon blue">3</div><div><div class="event-title">VLC playback</div><div class="event-meta">Copy RTSP → VLC → Open Network Stream for full playback controls.</div></div></div>
        <div class="event"><div class="event-icon blue">4</div><div><div class="event-title">Download</div><div class="event-meta">Exports run in the background with live progress (percent, size, time left). Video is copied losslessly; audio is converted to AAC so the MP4 plays on phones and PCs. Up to 24 hours per export.</div></div></div>
      </div>
      <div class="notice" style="margin-top:12px;margin-bottom:0">Path used: /cam/playback?channel=N&amp;starttime=...&amp;endtime=... (CP PLUS / Dahua style). If your firmware differs, paste the working VLC URL and we can adjust.</div>
      <h2 style="margin-top:14px">Recent exports</h2>
      <div id="pbExports" class="list muted">No exports yet.</div>
    </div>
  </div>

      <div id="pbPlayerBox" class="card" style="margin-top:12px;background:#09121f;display:none">
        <h2>Clip player</h2>
        <p class="muted" style="font-size:11px">Play, pause, seek, and speed controls for the exported MP4. Original device recordings are never modified.</p>
        <video id="pbPlayer" controls playsinline style="width:100%;max-height:420px;background:#000;border-radius:6px"></video>
        <div class="actions" style="margin-top:8px;flex-wrap:wrap">
          <button type="button" onclick="pbCtl('play')">Play</button>
          <button type="button" onclick="pbCtl('pause')">Pause</button>
          <button type="button" onclick="pbCtl('back')">⏪ −10s</button>
          <button type="button" onclick="pbCtl('fwd')">⏩ +10s</button>
          <button type="button" onclick="pbCtl('slow')">0.5×</button>
          <button type="button" onclick="pbCtl('norm')">1×</button>
          <button type="button" onclick="pbCtl('fast')">2×</button>
          <a id="pbDownloadLink" href="#" download style="display:none" class="primary">↓ Save file</a>
        </div>
      </div>
</section>

<section class="page" id="devices">
  <div class="section-head">
    <div><h2>Connect DVR / NVR</h2><div class="muted">Local RTSP recommended for live test</div></div>
    <span class="pill">MODEL READY</span>
  </div>
  <div class="notice" style="margin:0 0 14px 0">Same LAN · Enable RTSP on DVR (port 554) · Password never saved to disk</div>
  <div class="grid layout">
    <div class="card">
      <h2>Connection</h2>
      <form id="deviceForm" onsubmit="connectDevice(event)">
        <label class="muted" for="recName">Device name (optional)</label>
        <input id="recName" placeholder="Warehouse DVR / Site-01" style="margin-bottom:12px">
        <label class="muted" for="recType">Device type</label>
        <select id="recType" style="margin-bottom:12px"><option value="DVR" selected>DVR</option><option value="NVR">NVR</option></select>
        <label class="muted" for="recProtocol">Connection Type</label>
        <select id="recProtocol" style="margin-bottom:12px">
          <option value="rtsp" selected>Local RTSP (LAN)</option>
          <option value="instaon">InstaOn / Serial (cloud — SDK needed)</option>
        </select>
        <p class="muted" style="font-size:11px;margin:0 0 10px">Multi-DVR: connect many devices (up to 2000). Only active device channels are previewed live (max 16) for performance.</p>
        <div id="rtspFields">
          <label class="muted" for="recIP">DVR IP</label>
          <input id="recIP" placeholder="192.168.1.108" style="margin-bottom:12px">
          <label class="muted" for="recPort">RTSP Port</label>
          <input id="recPort" type="number" value="554" style="margin-bottom:12px">
          <label class="muted" for="recHttp">HTTP Port (web / snapshot)</label>
          <input id="recHttp" type="number" value="80" style="margin-bottom:12px">
          <label class="muted" for="recChannels">Max channels to scan (1–16)</label>
          <input id="recChannels" type="number" min="1" max="16" value="16" style="margin-bottom:12px">
          <label class="muted" style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
            <input id="recAuto" type="checkbox" checked style="width:auto"> Auto-detect active channels
          </label>
        </div>
        <div id="instaFields" class="hidden">
          <label class="muted" for="recSerial">Serial Number</label>
          <input id="recSerial" placeholder="From DVR sticker" style="margin-bottom:12px">
        </div>
        <label class="muted" for="recUser">Username</label>
        <input id="recUser" required placeholder="admin" style="margin-bottom:12px">
        <label class="muted" for="recPass">Password</label>
        <input id="recPass" type="password" required placeholder="DVR password" style="margin-bottom:14px">
        <button class="primary" type="submit" style="width:100%">⇄ Connect</button>
      </form>
      <div id="recResult" class="muted" style="font-size:12px;margin-top:12px">Ready for Local RTSP.</div>
      <div id="livePanel" class="card hidden" style="margin-top:12px;background:#09121f">
        <h2>Status</h2>
        <div id="connectionStatus" class="muted">—</div>
        <div id="streamHint" style="margin-top:10px;font-size:11px" class="muted"></div>
      </div>
    </div>
    <div class="card">
      <h2>AI tip — how to connect</h2>
      <div class="list">
        <div class="event"><div class="event-icon blue">1</div><div><div class="event-title">Same network</div><div class="event-meta">PC + DVR on one LAN. Find IP from DVR Network menu or router.</div></div></div>
        <div class="event"><div class="event-icon blue">2</div><div><div class="event-title">Enable RTSP</div><div class="event-meta">DVR → Network → RTSP → Enable, port 554.</div></div></div>
        <div class="event"><div class="event-icon blue">3</div><div><div class="event-title">Connect here</div><div class="event-meta">Local RTSP + IP + credentials. AI will start monitoring channels.</div></div></div>
        <div class="event"><div class="event-icon blue">4</div><div><div class="event-title">View in VLC</div><div class="event-meta">Copy RTSP from Live View → VLC Open Network Stream.</div></div></div>
      </div>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <div class="section-head"><div><h2>Registered DVRs</h2><div class="muted">Add many devices — click Select to view channels</div></div><span class="pill" id="recCount">0 devices</span></div>
    <div class="actions" style="margin-bottom:10px;flex-wrap:wrap">
      <input id="devSearch" placeholder="Search DVR by name, IP, location…" oninput="filterDeviceList()" style="max-width:360px;flex:1">
      <span class="muted" style="font-size:12px" id="devSearchHint"></span>
    </div>
    <div class="table-wrap"><table><thead><tr><th>NAME</th><th>IP</th><th>USER</th><th>CH</th><th>ACTIVE</th><th></th></tr></thead><tbody id="recRows"><tr><td colspan="6" class="muted">No devices yet. Connect a DVR above.</td></tr></tbody></table></div>
  </div>
</section>

<section class="page" id="ai">
  <div class="section-head">
    <div><h2>✦ AI Assistant + Voice</h2><div class="muted">Always monitoring · Voice commands · Auto message fill</div></div>
    <span class="pill online">MONITOR ON</span>
  </div>
  <div class="grid layout">
    <div class="card ai-panel">
      <div class="ai-chat" id="aiChat"></div>
      <div class="ai-input-row">
        <input id="aiInput" placeholder="Type or use 🎤 Voice — SOS, status, live view…" onkeydown="if(event.key==='Enter')askAI()">
        <button class="mic-btn" id="micBtnAi" onclick="toggleVoice()" title="Hold-style: click to start/stop">🎤</button>
        <button class="primary" onclick="askAI()">Send</button>
      </div>
      <div class="voice-hint" id="voiceHint">Voice commands: "status" · "gate status" · "which cameras are offline" · "camera problems" · "who came" · "latest alert" · "check all cameras" · "SOS" · "dashboard" · "live view" · "help" (Chrome/Edge). New alerts are spoken aloud when 🔊 Voice alerts is ON.</div>
      <div class="actions" style="margin-top:8px">
        <button onclick="askPreset('How do I find the DVR IP?')">Find IP</button>
        <button onclick="askPreset('How do I connect RTSP?')">RTSP connect</button>
        <button onclick="askPreset('Telegram setup')">Telegram</button>
        <button onclick="askPreset('SOS message auto fill')">Auto message</button>
        <button onclick="askPreset('What is the current status?')">Status</button>
        <button onclick="toggleVoice()">🎤 Voice on/off</button>
      </div>
    </div>
    <div class="card">
      <h2>AI continuous monitor</h2>
      <p class="muted" style="font-size:12px">Every few seconds cameras, incidents, and DVR link are checked. Critical changes show insights and optional alerts.</p>
      <ul class="ai-insights" id="aiSideInsights"></ul>
      <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
      <h2>Auto-fill message</h2>
      <p class="muted" style="font-size:11px">Choose an event type — AI fills the message. Copy it or send via Telegram.</p>
      <label class="muted">Event type</label>
      <select id="autoMsgType" style="margin-bottom:10px" onchange="fillAutoMessage()">
        <option value="SOS">SOS / Critical</option>
        <option value="CAMERA OFFLINE">Camera Offline</option>
        <option value="ANGLE CHANGE">Angle Change</option>
        <option value="HEALTH CHECK">Health Check</option>
        <option value="CUSTOM">Custom (AI draft)</option>
      </select>
      <label class="muted">Site / Camera (optional)</label>
      <input id="autoMsgSite" placeholder="Main Site / Channel 1" style="margin-bottom:10px" oninput="fillAutoMessage()">
      <label class="muted">Message (AI filled)</label>
      <textarea id="autoMsgBody" rows="6" style="margin-bottom:10px"></textarea>
      <div class="actions">
        <button class="primary" onclick="copyAutoMessage()">Copy message</button>
        <button onclick="sendAutoAsAlert()">Send as alert + Telegram</button>
      </div>
    </div>
  </div>
</section>

<section class="page" id="locations">
  <h2>Location Management</h2>
  <p class="muted">Illustrative sites linked to channels.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:12px" id="locationSites"></div>
</section>

<section class="page" id="alerts">
  <div class="section-head">
    <div><h2>Security Alerts & Incident Log</h2><div class="muted">Telegram + AI-assisted messages</div></div>
    <button onclick="resetDemo()">Reset</button>
  </div>
  <div class="card" style="margin-bottom:14px">
    <h2>Phone Notifications (Telegram)</h2>
    <p class="muted" style="font-size:12px">Bot token & chat ID are kept on this PC only. With a group chat ID, every member of the group gets the alerts.</p>
    <form onsubmit="configureTelegram(event)" class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px">
      <label>Bot Token<input id="tgToken" type="password" required placeholder="Bot token"></label>
      <label>Chat ID<input id="tgChat" required placeholder="Personal or group ID"></label>
      <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
        <button class="primary" type="submit">Save</button>
        <button type="button" onclick="testTelegram()">Test Alert</button>
      </div>
    </form>
    <div id="tgResult" class="muted" style="font-size:12px;margin-top:10px">Checking saved Telegram settings…</div>
    <p class="muted" style="font-size:11px">Bot token & chat ID are saved on this computer (idpi_config.json) so they stay after restart. Alerts keep sending for SOS / offline / warnings.</p>
  </div>
  <div class="card table-wrap">
    <table><thead><tr><th>EVENT ID</th><th>TYPE</th><th>DESCRIPTION</th><th>LOCATION</th><th>SEVERITY</th><th>TIME</th></tr></thead><tbody id="alertRows"></tbody></table>
  </div>
</section>

<section class="page" id="reports">
  <div class="section-head">
    <div><h2>Security Reports</h2><div class="muted">Hourly timelines · camera health & history</div></div>
    <button class="primary" onclick="downloadReport()">↓ Export CSV</button>
  </div>
  <div class="card" style="margin-bottom:14px">
    <h2>⏱ Hourly reports</h2>
    <p class="muted" style="font-size:11px">Every hour the AI writes a report: SYSTEM ON / OFF, DVR offline, CAMERA OFF, BLURRED, ANGLE CHANGED (start, end, duration) and every shutter OPENED / CLOSED time. Saved automatically 1 minute after each hour ends (folder idpi_data/reports). Pick any hour below — the current hour shows as PARTIAL.</p>
    <div class="actions" style="margin-bottom:10px;flex-wrap:wrap">
      <input id="hrDate" type="date" style="max-width:170px">
      <select id="hrHour" style="max-width:120px"></select>
      <select id="hrDev" style="max-width:260px"><option value="">All sites / DVRs</option></select>
      <button class="primary" onclick="hrView()">View</button>
      <button onclick="hrDownload('txt')">↓ TXT</button>
      <button onclick="hrDownload('csv')">↓ CSV (Excel)</button>
      <select id="hrRecent" onchange="hrPickRecent()" style="max-width:220px"><option value="">Saved reports…</option></select>
    </div>
    <div class="actions" style="margin-bottom:10px;flex-wrap:wrap;align-items:center">
      <span class="muted" style="font-size:12px">Whole day of the chosen date:</span>
      <button onclick="hrDayDownload()">↓ Whole day TXT (24 hours)</button>
    </div>
    <div class="actions" style="margin-bottom:10px;flex-wrap:wrap;align-items:center">
      <span class="muted" style="font-size:12px">Date range:</span>
      <input id="hrFrom" type="date" style="max-width:170px"><span class="muted">to</span><input id="hrTo" type="date" style="max-width:170px">
      <button onclick="hrRangeDownload('events')" title="Every problem and shutter open/close, one row each, with start/end date-time">↓ All events CSV</button>
      <button onclick="hrRangeDownload('summary')" title="One row per day per camera: minutes off/blurred/angle changed + first shutter opening and last closing">↓ Daily summary CSV</button>
    </div>
    <div id="hrMsg" class="muted" style="font-size:12px;margin-bottom:6px"></div>
    <pre id="hrOut" style="white-space:pre;overflow:auto;max-height:520px;background:#04101c;border:1px solid #1b4969;border-radius:5px;padding:10px;font-size:11px;line-height:1.45;margin:0">Choose a date and hour, then click View.</pre>
  </div>
  <div class="grid stats">
    <div class="card"><div class="stat-head">ONLINE</div><div class="stat-num green" id="rOnline">0</div></div>
    <div class="card"><div class="stat-head">OFFLINE</div><div class="stat-num red" id="rOffline">0</div></div>
    <div class="card"><div class="stat-head">ANGLE FLAGS</div><div class="stat-num amber" id="rAngle">0</div></div>
    <div class="card"><div class="stat-head">EVENTS</div><div class="stat-num blue" id="rEvents">1</div></div>
  </div>
  <div class="card"><h2>Camera Health</h2>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>NAME</th><th>SITE</th><th>STATUS</th><th>VIEW</th></tr></thead><tbody id="reportCameras"></tbody></table></div>
  </div>
</section>


<section class="page" id="aimon">
  <div class="section-head">
    <div><h2>◉ AI Camera Health — 24/7</h2><div class="muted">The AI checks every camera all the time: offline, faulty (no video), blur, dark, angle change, frozen. Every problem goes to Telegram with a photo.</div></div>
    <div class="actions"><button onclick="aiScan('dvr')">↻ Check DVRs now</button><button class="primary" onclick="aiScan('health')">↻ Check all cameras now</button></div>
  </div>
  <div id="aiNotices"></div>
  <div class="grid stats">
    <div class="card"><div class="stat-head">CAMERAS OK</div><div class="stat-num green" id="aiOk">—</div><div class="muted" id="aiOk2"></div></div>
    <div class="card"><div class="stat-head">OFFLINE / FAULTY</div><div class="stat-num red" id="aiOff">—</div><div class="muted" id="aiOff2"></div></div>
    <div class="card"><div class="stat-head">BLUR / ANGLE / FROZEN</div><div class="stat-num amber" id="aiIss">—</div><div class="muted" id="aiIss2"></div></div>
    <div class="card"><div class="stat-head">GATES OPEN</div><div class="stat-num blue" id="aiGates">—</div><div class="muted" id="aiGates2"></div></div>
  </div>
  <div class="monitor-bar"><span class="live">● AI ENGINE</span><span id="aiScanLine">—</span></div>
  <div class="card table-wrap" style="margin-bottom:12px">
    <div class="actions" style="margin-bottom:10px"><input id="aiQ" placeholder="Search camera / location / DVR" oninput="renderAiCams()" style="max-width:320px">
      <select id="aiFilter" onchange="renderAiCams()" style="max-width:220px"><option value="">All cameras</option><option value="bad">Only problems</option><option value="offline">Offline / faulty</option><option value="gate">Gate cameras</option><option value="face">Face cameras</option></select></div>
    <table><thead><tr><th></th><th>LOCATION / DVR</th><th>CH</th><th>CAMERA</th><th>STATUS</th><th>SCORE</th><th>PROBLEMS</th><th>CHECKED</th><th>FACE</th><th>ACTIONS</th></tr></thead><tbody id="aiCamRows"></tbody></table>
  </div>
  <div class="grid layout">
    <div class="card">
      <h2>DVR locations</h2>
      <p class="muted" style="font-size:11px">Give each DVR its location name (for example "Gurgaon Hub"). Telegram alerts show this location.</p>
      <div class="table-wrap"><table><thead><tr><th>DVR</th><th>IP</th><th>STATUS</th><th>LOCATION</th><th></th></tr></thead><tbody id="aiDevRows"></tbody></table></div>
    </div>
    <div class="card" id="aiSettingsCard">
      <h2>AI settings</h2>
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:0 10px">
        <div><label class="muted">Camera check every (sec)</label><input data-ai="health_interval" type="number"></div>
        <div><label class="muted">DVR check every (sec)</label><input data-ai="dvr_interval" type="number"></div>
        <div><label class="muted">Gate check every (sec)</label><input data-ai="gate_interval" type="number"></div>
        <div><label class="muted">Face check every (sec)</label><input data-ai="face_interval" type="number"></div>
        <div><label class="muted">Gate open too long (min, 0 = off)</label><input data-ai="gate_open_alert_min" type="number"></div>
        <div><label class="muted">Confirm problem after (scans)</label><input data-ai="confirm_scans" type="number"></div>
        <div><label class="muted">After hours start</label><input data-ai="after_hours_start" placeholder="22:00"></div>
        <div><label class="muted">After hours end</label><input data-ai="after_hours_end" placeholder="06:00"></div>
        <div><label class="muted">Blur limit (lower = blurry)</label><input data-ai="blur_threshold" type="number" step="any"></div>
        <div><label class="muted">Angle match limit (lower = changed)</label><input data-ai="angle_threshold" type="number" step="any"></div>
        <div><label class="muted">Live video FPS</label><input data-ai="live_fps" type="number"></div>
        <div><label class="muted">Live face checks per second</label><input data-ai="face_live_fps" type="number"></div>
        <div><label class="muted">Smallest face (pixels)</label><input data-ai="face_min_size" type="number"></div>
        <div><label class="muted">Person "left" after (sec)</label><input data-ai="face_gone_sec" type="number"></div>
        <div><label class="muted">Face AI active from (HH:MM, empty = always)</label><input data-ai="face_schedule_start" placeholder="09:00"></div>
        <div><label class="muted">Face AI active until (HH:MM)</label><input data-ai="face_schedule_end" placeholder="18:00"></div>
      </div>
      <div class="actions" style="margin:10px 0;flex-wrap:wrap;align-items:center;gap:10px">
        <button type="button" id="faceMasterBtn" class="primary" onclick="toggleFaceMaster()">🙂 Face recognition ON</button>
        <span class="muted" style="font-size:12px" id="faceMasterHint">Master switch for all cameras. Use schedule times to limit hours.</span>
      </div>
      <input type="hidden" data-ai="face_master" id="faceMasterVal" value="1">
      <label class="muted"><input type="checkbox" data-ai="face_hd" style="width:auto"> Face cameras use HD main stream (better recognition, more CPU)</label>
      <label class="muted"><input type="checkbox" data-ai="face_alert_unknown" style="width:auto"> Telegram alert for unknown faces</label>
      <label class="muted"><input type="checkbox" data-ai="face_notify_known" style="width:auto"> Telegram alert for known staff too</label>
      <label class="muted"><input type="checkbox" data-ai="notify_recovery" style="width:auto"> Telegram "back to normal" messages</label>
      <label class="muted"><input type="checkbox" data-ai="bot_commands" style="width:auto"> Telegram bot commands (/status /offline /issues /gates /snap)</label>
      <div class="actions" style="margin-top:10px"><button class="primary" onclick="saveAiSettings()">Save AI settings</button></div>
      <div id="aiSetMsg" class="muted" style="font-size:12px;margin-top:8px"></div>
    </div>
  </div>
</section>

<section class="page" id="gates">
  <div class="section-head">
    <div><h2>🚪 Gate Open / Close Detection</h2><div class="muted">Pick the camera that sees the gate → draw a box on the gate → mark it CLOSED and OPEN once in daylight and once at night. The AI then tells Telegram whenever this gate opens or closes.</div></div>
  </div>
  <div class="grid layout">
    <div class="card">
      <h2>Gate setup</h2>
      <div class="actions" style="margin-bottom:8px"><select id="gateCam" style="max-width:420px"></select><button onclick="gateLoad()">📷 Get snapshot</button></div>
      <div class="muted" style="font-size:11px;margin-bottom:6px">Draw a box over the gate with your mouse or finger.</div>
      <canvas id="roiCanvas" width="640" height="360" style="max-width:100%;border:1px solid #1b4969;border-radius:5px;cursor:crosshair;touch-action:none;display:block"></canvas>
      <div class="actions" style="margin-top:10px">
        <button onclick="gateSaveRoi()">💾 Save gate area + turn ON</button>
        <button class="primary" onclick="gateMark('closed')">🟢 Gate is CLOSED now — mark</button>
        <button class="danger" onclick="gateMark('open')">🔴 Gate is OPEN now — mark</button>
        <button onclick="gateOff()">Turn gate OFF</button>
      </div>
      <div id="gateMsg" class="muted" style="font-size:12px;margin-top:8px"></div>
      <div id="gateRefs" class="actions" style="margin-top:8px"></div>
    </div>
    <div class="card">
      <div class="section-head"><h2>All gates</h2><button onclick="loadGates()">↻</button></div>
      <div class="table-wrap"><table style="min-width:340px"><thead><tr><th>LOCATION</th><th>CAMERA</th><th>STATE</th><th>SINCE</th></tr></thead><tbody id="gateRows"></tbody></table></div>
      <h2 style="margin-top:14px">Gate events</h2><div class="list" id="gateEvents"></div>
    </div>
  </div>
</section>

<section class="page" id="faces">
  <div class="section-head">
    <div><h2>🙂 Face Recognition</h2><div class="muted">Enroll staff, VIPs and watchlist people. Turn on "Face" for a camera on the AI Camera Health page. Watchlist and unknown people are sent to Telegram with a photo.</div>
  <div class="card" style="margin-bottom:14px">
    <h2>🙂 Face recognition control</h2>
    <p class="muted" style="font-size:12px">Master ON/OFF and daily hours. Per-camera Face AI buttons still pick which cameras are watched.</p>
    <div class="actions" style="flex-wrap:wrap;align-items:center;gap:10px">
      <button type="button" id="faceMasterBtn2" class="primary" onclick="toggleFaceMaster()">🙂 Face recognition ON</button>
      <label class="muted">From <input data-ai="face_schedule_start" placeholder="09:00" style="width:90px;display:inline-block"></label>
      <label class="muted">To <input data-ai="face_schedule_end" placeholder="18:00" style="width:90px;display:inline-block"></label>
      <button type="button" onclick="saveAiSettings()">Save schedule</button>
    </div>
  </div></div>
  </div>
  <div id="faceNotice"></div>
  <div class="grid layout">
    <div class="card">
      <h2>Enroll a person</h2>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px">
        <div><label class="muted">Name</label><input id="faceName" placeholder="Ramesh (Guard)"></div>
        <div><label class="muted">Category</label><select id="faceCat"><option value="known">Known / Staff</option><option value="vip">VIP</option><option value="watchlist">Watchlist (alert)</option></select></div>
        <div><label class="muted">Photo(s)</label><input id="faceFile" type="file" accept="image/*" multiple></div>
      </div>
      <p class="muted" style="font-size:11px">Use a clear, front-facing photo. 2–3 photos in different light improve accuracy.</p>
      <div class="actions"><button class="primary" onclick="enrollFace(this)">Enroll</button></div>
      <div id="faceMsg" class="muted" style="font-size:12px;margin-top:8px"></div>
      <h2 style="margin-top:14px">Enrolled (<span id="faceCount">0</span>)</h2>
      <div id="faceGrid" style="display:grid;gap:8px;grid-template-columns:repeat(auto-fill,minmax(120px,1fr))"></div>
    </div>
    <div class="card"><h2>Right now in front of the cameras</h2><div class="people" id="livePeopleFaces" style="margin-bottom:14px"></div>
      <h2>Recent face detections</h2><div class="list" id="faceEvents"></div></div>
  </div>
</section>

<div id="imgModal" onclick="this.style.display='none';const m=document.getElementById('imgModalImg');m.removeAttribute('data-src');m.classList.remove('live-snap');m.src=BLANK_IMG" style="display:none;position:fixed;inset:0;background:#000c;z-index:60;place-items:center;padding:20px"><img id="imgModalImg" alt="" style="max-width:96vw;max-height:90vh;border-radius:6px"></div>


<section class="page" id="users">
  <div class="section-head">
    <div><h2>👤 User management</h2><div class="muted">Administrators manage accounts · Viewers can only use Live View and Playback</div></div>
    <span class="pill">ADMIN</span>
  </div>
  <div class="grid layout">
    <div class="card">
      <h2>Create user</h2>
      <label class="muted">Username</label>
      <input id="newUserName" placeholder="operator1" style="margin-bottom:10px">
      <label class="muted">Display name</label>
      <input id="newUserDisplay" placeholder="Site operator" style="margin-bottom:10px">
      <label class="muted">Password (min 10)</label>
      <input id="newUserPass" type="password" style="margin-bottom:10px">
      <label class="muted">Role</label>
      <select id="newUserRole" style="margin-bottom:12px">
        <option value="viewer">Viewer — live view &amp; playback only</option>
        <option value="admin">Administrator — full access</option>
      </select>
      <label class="muted">Location</label>
      <input id="newUserLoc" placeholder="e.g. Main gate" style="margin-bottom:10px">
      <label class="muted">Assigned DVR / NVR devices (viewers see only these)</label>
      <div id="newUserDevices" class="muted" style="font-size:12px;margin:4px 0 12px">Loading devices…</div>
      <button class="primary" type="button" onclick="createUser()">Create account</button>
      <div id="userMsg" class="muted" style="font-size:12px;margin-top:10px"></div>
    </div>
    <div class="card">
      <h2>Accounts</h2>
      <p class="muted" style="font-size:12px">Viewers cannot change devices, settings, AI, or users. Access is enforced on the server.</p>
      <div class="table-wrap"><table><thead><tr><th>USER</th><th>ROLE</th><th>STATUS</th><th></th></tr></thead>
        <tbody id="userRows"><tr><td colspan="4" class="muted">Loading…</td></tr></tbody></table></div>
    </div>
  </div>
  <div class="card" id="accessCard" style="margin-top:14px">
    <h2>Device &amp; location access</h2>
    <p class="muted" style="font-size:12px">Pick an account, its location and the DVR/NVR devices it may open. Administrators always see every device. Changes apply on that account's next request, and its open sessions are checked against them.</p>
    <label class="muted">Account</label>
    <select id="accUser" onchange="accUserChanged()" style="margin-bottom:10px"></select>
    <label class="muted">Location</label>
    <input id="accLoc" placeholder="e.g. Main gate" style="margin-bottom:10px">
    <label class="muted">Assigned DVR / NVR devices</label>
    <div id="accDevices" class="muted" style="font-size:12px;margin:4px 0 12px"></div>
    <button class="primary" type="button" onclick="saveAccess()">Save access</button>
    <div id="accMsg" class="muted" style="font-size:12px;margin-top:10px"></div>
  </div>
</section>

<div class="footer">IDP i AI · 24/7 AI monitor · Local RTSP · Telegram alerts</div>
</div>

<div class="toast" id="toast"><h3 id="toastTitle">SECURITY ALERT</h3><p id="toastBody"></p><button onclick="dismissToast()">Acknowledge</button></div>

<script>
const MODEL = 'CCTV DVR/NVR';
const BLANK_IMG = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
var FEED_KEYS = {};
var SD = {tab:'live', range:1, devices:[], events:[], key:'', busy:false};
var LIVE_FACES = {people:[], streams:[]};
const MAX_CH = 16;
let initial = [];
for (let i = 1; i <= MAX_CH; i++) {
  initial.push({
    id: 'CAM-' + String(i).padStart(3,'0'),
    name: 'Channel ' + i,
    site: i <= 8 ? 'Main Site' : 'Secondary Site',
    type: 'DVR', status: 'Offline', angle: 'Normal', ch: i,
    rtspMain: '', rtspSub: '', snap: ''
  });
}
let cameras = structuredClone(initial);
let events = [{id:'EVT-1001',type:'SYSTEM',title:'IDP i AI started — ' + MODEL,site:'Local',severity:'INFO',time:now()}];
let eventNo = 1002;
let profile = {connected:false, mode:'', target:'', user:'', channels:0};
let lastInsightKey = '';
let aiChatHistory = [];

const AI_KB = [
  {
    q:['ip','ip address','find ip','how to find','ip kaise','ip nikal','ip batao'],
    en:'How to find the DVR IP:\n1) On the DVR monitor: Main Menu → Network → TCP/IP → IP Address\n2) Router admin page → Connected Devices / DHCP clients\n3) CP PLUS ConfigTool or KVMS Pro → network scan\nIP is usually 192.168.x.x. PC and DVR must be on the same LAN.',
  },
  {
    q:['rtsp','connect','live','stream','vlc','live kaise','stream kaise'],
    en:'Live connect (CP-UVR-1601E2-I):\n1) On DVR: enable RTSP (Network → RTSP, port 554)\n2) Here: DVR Setup → Local RTSP → enter IP, username, password\n3) Live View → Copy RTSP → VLC → Media → Open Network Stream\nPath: /cam/realmonitor?channel=N&subtype=0 (main) or subtype=1 (sub).',
  },
  {
    q:['telegram','bot','notification','alert phone','telegram setup','telegram kaise'],
    en:'Telegram setup:\n1) Create a bot with @BotFather → copy the token\n2) Open your bot and press Start\n3) Get chat ID via @userinfobot (personal) or add bot to a group and read getUpdates (group IDs are negative)\n4) Alerts page → save token + chat ID → Test Alert\nUsing a group chat ID delivers alerts to all members.',
  },
  {
    q:['sos','message','auto fill','automation','template','message auto','auto message'],
    en:'AI auto-fill:\nOpen AI Assistant → choose event type (SOS / Offline / Angle) → the message is filled automatically.\nCopy it or click "Send as alert + Telegram".\nThe AI monitor also shows insights on critical events.',
  },
  {
    q:['status','monitor','health','current status','status kya','kya hai','abhi status'],
    en: null, dynamic: 'status'
  },
  {
    q:['instaon','cloud','serial'],
    en:'InstaOn cloud P2P works with official CP PLUS apps (gCMOB / iCMOB). This prototype uses Local RTSP for reliable live testing. Real InstaOn integration needs the official SDK, which is not public.',
  },
  {
    q:['model','uvr','1601','channels'],
    en:'CP-UVR-1601E2-I: 16-channel 1080P Lite hybrid DVR. Supports HDCVI/AHD/TVI/CVBS/IP. Protocols: RTSP, ONVIF, InstaOn. Up to ~18 IP channels in hybrid mode. CMS: KVMS Pro. Mobile: gCMOB / iCMOB.',
  },
  {
    q:['help','how to','software','guide','madad','madad chahiye','help karo'],
    en:'I am IDP i AI. I continuously monitor cameras and events, auto-fill alert messages, and help with the DVR and this software.\nPages: Dashboard, Live View, DVR Setup, AI Assistant, Alerts, Reports.\nAsk about: IP, RTSP, Telegram, SOS messages, or say "What is the current status?"',
  },
];



function now(){ return new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function go(p){
  document.querySelectorAll('.page').forEach(x => x.classList.toggle('active', x.id === p));
  document.querySelectorAll('.nav button').forEach(x => x.classList.toggle('active', x.dataset.page === p && !x.dataset.sdtab && !x.dataset.scroll));
  render();
  if (p === 'ai') { fillAutoMessage(); scrollAiChat(); }
  if (p === 'playback') fillPlaybackChannels();
  if (p === 'cctv') startLiveRefresh();
  syncLiveImgs(); pollLiveFaces();
  if (p === 'alerts') loadTelegramStatus();
  if (p === 'aimon') loadAiStatus();
  if (p === 'gates') loadGates();
  if (p === 'faces') loadFaces();
  if (p === 'users') loadUsers();
  if (p === 'reports' && typeof hrInit === 'function') hrInit();
  if (p === 'overview' || p === 'logs') setTimeout(sdRefresh, 0);
}
document.querySelectorAll('.nav button').forEach(b => b.addEventListener('click', () => {
  go(b.dataset.page);
  if (b.dataset.sdtab) sdSetTab(b.dataset.sdtab);
  if (b.dataset.scroll) { const el = document.getElementById(b.dataset.scroll); if (el) el.scrollIntoView({behavior:'smooth'}); }
  if (b.dataset.sdtab || b.dataset.scroll) document.querySelectorAll('.nav button').forEach(x => x.classList.toggle('active', x === b));
}));
document.getElementById('recProtocol').addEventListener('change', function(){
  const rtsp = this.value === 'rtsp';
  document.getElementById('rtspFields').classList.toggle('hidden', !rtsp);
  document.getElementById('instaFields').classList.toggle('hidden', rtsp);
});

function pill(status){
  return `<span class="pill ${status==='Online'?'online':status==='Offline'?'offline':'warn'}">${esc(String(status).toUpperCase())}</span>`;
}
function camCard(c){
  const off = c.status !== 'Online';
  const hasSnap = !!c.snap;
  const hasUrl = !!(c.rtspSub || c.rtspMain);
  let feedInner;
  if (hasSnap && !c.manualOff) {
    const liveSrc = esc(c.snap).replace('/api/snapshot', '/api/frame');
    feedInner = `<img class="live-snap" data-live="1" data-ch="${c.ch}" data-src="${liveSrc}" src="${BLANK_IMG}" alt="CH${c.ch}" style="width:100%;height:100%;object-fit:contain;position:absolute;inset:0;background:#000">`
      + `<div class="livemsg">Connecting to camera…</div>`
      + `<div class="inview" data-dev="${esc(c.devId||'')}" data-ch="${c.ch}"></div>` + (c.face ? '<span class="faceai-tag">🙂 FACE AI</span>' : '');
  } else if (!off && hasUrl) {
    feedInner = `<div style="text-align:center;padding:8px;font-size:11px;z-index:1"><div style="margin-bottom:6px">● LINKED</div><button onclick="copyText('${esc(c.rtspSub||c.rtspMain)}')" style="font-size:10px">Copy RTSP</button></div>`;
  } else {
    feedInner = `<div style="font-size:28px;color:#7a9bb0;z-index:1">${hasUrl?'▣':'▧'}</div>`;
  }
  const enlarge = (hasSnap && !c.manualOff) ? ` onclick="openLive('${esc(c.snap).replace('/api/snapshot', '/api/frame')}')"` : '';
  return `<div class="card cam"><div class="feed" style="position:relative;overflow:hidden"${enlarge}><span class="feed-label">${esc(c.id)} · CH${c.ch||'-'}</span><span class="feed-state">${pill(c.status)}</span>${feedInner}</div>
    <div class="cam-body"><div class="cam-title"><div><h3>${esc(c.name)}</h3><div class="cam-meta">${esc(c.site)} · ${MODEL}</div></div>
    ${c.angle==='Changed'?'<span class="pill warn">ANGLE</span>':''}</div>
    <div class="actions">
      <button onclick="toggleCamera('${c.id}')">${off?'Mark Online':'Mark Offline'}</button>
      <button onclick="toggleAngle('${c.id}')">Angle</button>
      <button onclick="checkCamera('${c.id}')">Health</button>
      ${(c.devId && hasSnap)?`<button onclick="toggleFaceAI('${esc(c.devId)}',${c.ch},${c.face?0:1})" class="${c.face?'primary':''}">🙂 Face AI ${c.face?'ON':'OFF'}</button>`:''}
      ${hasUrl?`<button onclick="copyText('${esc(c.rtspSub||c.rtspMain)}')">RTSP</button>`:''}
    </div></div></div>`;
}
function siteCard(site){
  const cs = cameras.filter(c => c.site === site);
  const online = cs.filter(c => c.status === 'Online').length;
  return `<div class="card"><div style="display:flex;gap:12px;align-items:center">
    <div style="font-size:22px">⌖</div><div><div style="font-weight:700">${esc(site)}</div><div class="muted" style="font-size:10px">${MODEL}</div></div>
    <div style="margin-left:auto">${pill(online===cs.length && cs.length?'Online':'Partial')}</div></div>
    <div style="display:flex;justify-content:space-between;border-top:1px solid var(--line);margin-top:12px;padding-top:10px;font-size:11px;color:var(--muted)">
    <span>${cs.length} channels</span><span>${online} online</span></div></div>`;
}
function eventCard(e){
  const col = e.severity==='CRITICAL'?'red':e.severity==='WARNING'?'amber':'green';
  return `<div class="event"><div class="event-icon ${col}">${e.severity==='CRITICAL'?'⚠':e.severity==='WARNING'?'◆':'✓'}</div>
    <div style="min-width:0"><div class="event-title">${esc(e.title)}</div><div class="event-meta">${esc(e.id)} · ${esc(e.site)}</div></div>
    <div class="event-time">${esc(e.time)}</div></div>`;
}

function buildStatusAnswerBase(){
  const online = cameras.filter(c => c.status==='Online').length;
  const offline = cameras.length - online;
  const angles = cameras.filter(c => c.angle==='Changed').length;
  const open = events.filter(e => e.severity!=='INFO').length;
  return `AI status report (${now()}):\n• DVR link: ${profile.connected ? 'ON ('+profile.target+')' : 'OFF — connect from DVR Setup'}\n• Cameras online: ${online}/${cameras.length}\n• Offline: ${offline}\n• Angle flags: ${angles}\n• Open incidents: ${open}\n• Model: ${MODEL}\nContinuous AI monitor is active. Critical events show insights and Telegram alerts (if configured).`;
}

function aiReply(text){
  const t = (text||'').trim().toLowerCase();
  if (!t) return 'Ask me about IP, RTSP, Telegram, SOS messages, or status.';
  for (const item of AI_KB) {
    if (item.q.some(k => t.includes(k))) {
      if (item.dynamic === 'status') return buildStatusAnswer();
      return item.en;
    }
  }
  return 'I am IDP i AI (CP-UVR-1601E2-I).\nI did not understand that. Try:\n• "How do I find the DVR IP?"\n• "How do I connect RTSP?"\n• "Telegram setup"\n• "SOS message auto fill"\n• "What is the current status?"\nOr use Auto-fill message on the AI Assistant page.';
}

function pushChat(role, text){
  aiChatHistory.push({role, text, time: now()});
  if (aiChatHistory.length > 40) aiChatHistory.shift();
  const box = document.getElementById('aiChat');
  const div = document.createElement('div');
  div.className = 'msg ' + (role === 'user' ? 'user' : 'ai');
  div.innerHTML = `<div class="role">${role === 'user' ? 'You' : 'IDP i AI'} · ${esc(now())}</div>${esc(text).replace(/\n/g,'<br>')}`;
  box.appendChild(div);
  scrollAiChat();
}
function scrollAiChat(){
  const box = document.getElementById('aiChat');
  if (box) box.scrollTop = box.scrollHeight;
}
function askAI(){
  const input = document.getElementById('aiInput');
  const q = (input.value||'').trim();
  if (!q) return;
  pushChat('user', q);
  input.value = '';
  setTimeout(() => {
    const ans = aiReply(q);
    pushChat('ai', ans);
    speakText(ans);
  }, 200);
}
function askPreset(q){
  document.getElementById('aiInput').value = q;
  askAI();
}

/* ========== Voice commands (Web Speech API) ========== */
let voiceListening = false;
let recognition = null;
let voiceSupported = false;

function initVoice(){
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) {
    voiceSupported = false;
    const h = document.getElementById('voiceHint');
    if (h) h.textContent = 'Voice is supported best in Chrome or Edge. This browser has no SpeechRecognition.';
    return;
  }
  voiceSupported = true;
  recognition = new SR();
  recognition.continuous = false;
  recognition.interimResults = false;
  recognition.lang = 'en-IN';
  recognition.maxAlternatives = 3;

  recognition.onstart = function(){
    voiceListening = true;
    setMicUI(true);
  };
  recognition.onend = function(){
    voiceListening = false;
    setMicUI(false);
  };
  recognition.onerror = function(ev){
    voiceListening = false;
    setMicUI(false);
    if (ev.error === 'not-allowed') {
      pushChat('ai', 'Microphone permission denied. Allow the mic in browser settings.');
    } else if (ev.error !== 'aborted' && ev.error !== 'no-speech') {
      pushChat('ai', 'Voice error: ' + ev.error + '. Try Chrome/Edge and check the microphone.');
    }
  };
  recognition.onresult = function(ev){
    let transcript = '';
    for (let i = ev.resultIndex; i < ev.results.length; i++) {
      if (ev.results[i].isFinal) transcript += ev.results[i][0].transcript;
    }
    transcript = (transcript || '').trim();
    if (!transcript) return;
    handleVoiceCommand(transcript);
  };
}

function setMicUI(on){
  ['micBtn','micBtnAi'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.toggle('listening', on);
  });
  const lab = document.getElementById('micLabel');
  if (lab) lab.textContent = on ? 'Listening…' : '🎤 Voice';
}

function toggleVoice(){
  if (!voiceSupported || !recognition) {
    initVoice();
    if (!voiceSupported) {
      alert('Voice commands need Chrome or Edge with microphone permission.');
      return;
    }
  }
  if (voiceListening) {
    try { recognition.stop(); } catch(e) {}
    voiceListening = false;
    setMicUI(false);
    return;
  }
  try {
    recognition.lang = 'en-IN';
    recognition.start();
  } catch(e) {
    try { recognition.stop(); } catch(x) {}
    setTimeout(() => { try { recognition.start(); } catch(y) {} }, 300);
  }
}

function speakText(text){
  if (!window.speechSynthesis) return;
  try {
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(String(text).slice(0, 400));
    u.lang = 'en-IN';
    u.rate = 1.05;
    window.speechSynthesis.speak(u);
  } catch(e) {}
}

function handleVoiceCommandBase(raw){
  const t = raw.toLowerCase().trim();
  pushChat('user', '🎤 ' + raw);

  // Navigation
  if (/\b(dashboard|home|overview)\b/.test(t) || t.includes('dash board')) {
    go('overview'); pushChat('ai', 'Opened Dashboard.'); speakText('Dashboard'); return;
  }
  if (/\b(live view|cctv|cameras|live)\b/.test(t)) {
    go('cctv'); pushChat('ai', 'Opened Live View. Copy RTSP URLs into VLC to play.'); speakText('Live view'); return;
  }
  if (/\b(dvr|setup|connect|nvr)\b/.test(t)) {
    go('devices'); pushChat('ai', 'Opened DVR Setup. Enter Local RTSP IP, username, and password.'); speakText('DVR setup'); return;
  }
  if (/\b(ai assistant|assistant|help page)\b/.test(t) || t === 'ai') {
    go('ai'); pushChat('ai', 'Opened AI Assistant. Speak or type your question.'); speakText('AI assistant'); return;
  }
  if (/\b(alerts|alert|sos page|incidents)\b/.test(t)) {
    go('alerts'); pushChat('ai', 'Opened Alerts.'); speakText('Alerts'); return;
  }
  if (/\b(reports|report)\b/.test(t)) {
    go('reports'); pushChat('ai', 'Opened Reports.'); speakText('Reports'); return;
  }
  if (/\b(location|locations|sites)\b/.test(t)) {
    go('locations'); pushChat('ai', 'Opened Locations.'); return;
  }

  // Actions
  if (/\b(sos|emergency|critical alert|trigger sos)\b/.test(t)) {
    triggerSOS();
    pushChat('ai', 'SOS triggered. Critical alert logged; Telegram sent if configured.');
    speakText('SOS alert sent');
    return;
  }
  if (/\b(camera offline|offline|simulate offline)\b/.test(t)) {
    simulateOffline();
    pushChat('ai', 'Camera offline event simulated.');
    speakText('Camera offline');
    return;
  }
  if (/\b(angle|tamper|view change)\b/.test(t)) {
    simulateAngle();
    pushChat('ai', 'Angle change flag simulated.');
    speakText('Angle change flagged');
    return;
  }
  if (/\b(status|health|monitor|report status|current status)\b/.test(t)) {
    const ans = buildStatusAnswer();
    pushChat('ai', ans);
    speakText('Status ready. Check chat.');
    return;
  }
  if (/\b(reset|reset demo)\b/.test(t)) {
    resetDemo();
    pushChat('ai', 'Demo reset.');
    speakText('Reset done');
    return;
  }
  if (/\b(stop listening|stop voice|quiet)\b/.test(t)) {
    try { recognition.stop(); } catch(e) {}
    pushChat('ai', 'Voice listening stopped.');
    return;
  }

  // Fall through to AI Q&A (IP, RTSP, Telegram, etc.)
  const ans = aiReply(t);
  pushChat('ai', ans);
  speakText(ans.split('\n')[0]);
}

initVoice();

function fillAutoMessage(){
  const type = document.getElementById('autoMsgType').value;
  const site = document.getElementById('autoMsgSite').value.trim() || 'Main Site';
  const t = now();
  let body = '';
  if (type === 'SOS') {
    body = `IDP i AI — CRITICAL SOS\nModel: ${MODEL}\nPossible unauthorized access / tampering detected.\nLocation: ${site}\nTime: ${t}\nAction: Review live cameras now and verify physical security.`;
  } else if (type === 'CAMERA OFFLINE') {
    body = `IDP i AI — Camera Offline\n${site} connection lost on ${MODEL}.\nTime: ${t}\nCheck: power, cable, network, DVR channel.\nAI monitor will keep tracking.`;
  } else if (type === 'ANGLE CHANGE') {
    body = `IDP i AI — Angle / View Change\nPossible view change on ${site} (${MODEL}).\nTime: ${t}\nSuggested: Compare with last known good view; may be tampering.`;
  } else if (type === 'HEALTH CHECK') {
    body = `IDP i AI — Health Check\n${site} checked at ${t}.\nStatus logged. Continuous monitoring active.`;
  } else {
    body = `IDP i AI draft\nSite: ${site}\nTime: ${t}\nModel: ${MODEL}\n(Write details below or choose another event type for full template.)`;
  }
  document.getElementById('autoMsgBody').value = body;
}
function copyAutoMessage(){
  const t = document.getElementById('autoMsgBody').value;
  navigator.clipboard.writeText(t).then(() => alert('Message copied')).catch(() => prompt('Copy:', t));
}
function sendAutoAsAlert(){
  const type = document.getElementById('autoMsgType').value;
  const body = document.getElementById('autoMsgBody').value;
  const site = document.getElementById('autoMsgSite').value.trim() || 'Main Site';
  const sev = (type === 'SOS' || type === 'CAMERA OFFLINE') ? 'CRITICAL' : (type === 'ANGLE CHANGE' ? 'WARNING' : 'INFO');
  const title = body.split('\n')[0].replace('IDP i AI — ','').slice(0,80) || type;
  addEvent(type === 'CUSTOM' ? 'AI MSG' : type, title, site, sev);
  alert('Alert logged. Telegram sent if configured.');
}

/* Continuous AI monitor */
function runAiMonitor(){
  const online = cameras.filter(c => c.status==='Online').length;
  const offline = cameras.filter(c => c.status==='Offline').length;
  const angles = cameras.filter(c => c.angle==='Changed').length;
  const open = events.filter(e => e.severity!=='INFO').length;
  const linked = profile.connected;

  const insights = [];
  if (!linked) insights.push({cls:'insight-warn', text:'DVR is not linked — connect via DVR Setup (Local RTSP) so live channels can be monitored.'});
  else insights.push({cls:'insight-ok', text:`DVR link OK (${profile.target}). AI is tracking ${profile.channels||0} channel(s).`});
  if (offline > 0 && linked) insights.push({cls:'insight-bad', text:`${offline} camera(s) offline. AI flagged this — check Live View / Health.`});
  if (angles > 0) insights.push({cls:'insight-warn', text:`${angles} angle-change flag(s). Possible tampering — review the view.`});
  if (open > 0) insights.push({cls:'insight-bad', text:`${open} open incident(s) need review.`});
  if (linked && offline === 0 && angles === 0 && open === 0) insights.push({cls:'insight-ok', text:'All monitored channels stable. No open critical incidents.'});
  insights.push({cls:'insight-ok', text:`Last AI scan: ${now()} · Model ${MODEL}`});

  const html = insights.map(i => `<li class="${i.cls}">${esc(i.text)}</li>`).join('');
  const el1 = document.getElementById('aiInsightsList');
  const el2 = document.getElementById('aiSideInsights');
  if (el1) el1.innerHTML = html;
  if (el2) el2.innerHTML = html;

  let monitorLine = linked
    ? `Monitoring ${online} online / ${offline} offline · ${angles} angle flags · ${open} incidents`
    : 'Waiting for DVR link — connect from DVR Setup';
  document.getElementById('aiMonitorText').textContent = monitorLine;
  document.getElementById('aiLastScan').textContent = 'Scan ' + now();
  document.getElementById('aiHealth').textContent = linked ? (offline || open ? 'Alert' : 'OK') : 'Standby';

  // Optional: soft system note when state changes significantly
  const key = `${linked}|${online}|${offline}|${angles}|${open}`;
  if (lastInsightKey && key !== lastInsightKey && (offline > 0 || angles > 0 || open > 0)) {
    // don't spam events — insights already update
  }
  lastInsightKey = key;
}

async function connectDevice(ev){
  ev.preventDefault();
  const mode = document.getElementById('recProtocol').value;
  const user = document.getElementById('recUser').value.trim();
  const pass = document.getElementById('recPass').value;
  const result = document.getElementById('recResult');
  const panel = document.getElementById('livePanel');
  const status = document.getElementById('connectionStatus');
  const hint = document.getElementById('streamHint');
  if (!user || !pass) { result.textContent = 'Username and password are required.'; return; }

  if (mode === 'instaon') {
    const serial = document.getElementById('recSerial').value.trim();
    if (!serial) { result.textContent = 'Enter the serial number.'; return; }
    panel.classList.remove('hidden');
    status.textContent = 'InstaOn: official SDK is not configured.';
    hint.textContent = 'For live testing, use Local RTSP.';
    result.textContent = 'InstaOn noted. AI recommends Local RTSP for live tests.';
    profile = {connected:false, mode:'InstaOn', target:serial, user, channels:0};
    document.getElementById('recPass').value = '';
    updateProfileTable();
    addEvent('REMOTE DVR', 'InstaOn request SN ' + serial, 'Remote', 'INFO');
    runAiMonitor();
    return;
  }

  const ip = document.getElementById('recIP').value.trim();
  const port = parseInt(document.getElementById('recPort').value, 10) || 554;
  const httpPort = parseInt(document.getElementById('recHttp').value, 10) || 80;
  let chCount = Math.max(1, Math.min(16, parseInt(document.getElementById('recChannels').value, 10) || 16));
  const autoDetect = document.getElementById('recAuto').checked;
  if (!ip) { result.textContent = 'Enter the DVR IP address.'; return; }
  result.textContent = autoDetect ? 'Detecting channels + building streams…' : 'Building streams…';
  try {
    const r = await fetch('/api/connect-rtsp', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        ip, port, http_port: httpPort, username:user, password:pass,
        channels:chCount, auto_detect: autoDetect,
        name: (document.getElementById('recName').value||'').trim() || ip,
        device_type: (document.getElementById('recType')||{}).value || 'DVR'
      })
    });
    const j = await r.json();
    if (!j.ok) { result.textContent = j.message || 'Failed'; panel.classList.remove('hidden'); status.textContent = j.message; return; }
    applyStreamsFromServer(j);
    panel.classList.remove('hidden');
    const n = (j.streams||[]).length;
    status.innerHTML = '<span class="green">Saved</span> — '+esc(ip)+' · '+n+' ch · devices: '+(j.device_count||'?');
    hint.textContent = j.http_up
      ? 'Live snapshots on active device. Add more DVRs anytime (1000+ supported).'
      : 'HTTP closed on this DVR — enable web for live preview. Device still registered.';
    result.textContent = j.message || 'OK';
    document.getElementById('recPass').value = '';
    document.getElementById('connBadge').textContent = (j.device_count||1)+' DVR(s)';
    document.getElementById('livePill').textContent = j.http_up ? 'LIVE SNAP' : 'RTSP ONLY';
    document.getElementById('livePill').className = 'pill online';
    addEvent('DVR LINK', 'Device '+(j.device_id||'')+' @ '+ip, 'Local LAN', 'INFO');
    await refreshDeviceList();
loadMe();
    render();
    runAiMonitor();
    startLiveRefresh();
    pushChat('ai', 'DVR registered: '+ip+'. Total devices: '+(j.device_count||1)+'. Channels: '+(j.detected||[]).join(', '));
    go('cctv');
  } catch(e) { result.textContent = 'Server unreachable.'; console.error(e); }
}

function applyStreamsFromServer(j){
  cameras.forEach(c => { c.status='Offline'; c.rtspMain=''; c.rtspSub=''; c.snap=''; c.devId=''; });
  const detected = j.detected || [];
  (j.streams||[]).forEach(s => {
    let cam = cameras.find(c => c.ch === s.ch);
    if (!cam) return;
    cam.rtspMain = s.main;
    cam.rtspSub = s.sub;
    cam.snap = s.snap || '';
    cam.devId = j.device_id || '';
    cam.status = 'Online';
    cam.name = 'Channel ' + s.ch;
  });
  const n = (j.streams||[]).length || detected.length;
  profile = {connected:true, mode:'Local RTSP', target:(j.streams&&j.streams[0])?j.streams[0].main.replace(/^rtsp:\/\//,'').split('@').pop():'', user:'', channels:n, deviceId:j.device_id, deviceCount:j.device_count||1};
}

async function refreshDeviceList(){
  try {
    const r = await fetch('/api/devices');
    const j = await r.json();
    window._DEV_LIST = j.devices || [];
    document.getElementById('recCount').textContent = (j.count||0)+' devices';
    filterDeviceList();
    const cb = document.getElementById('connBadge'); if (cb) cb.textContent = (j.count||0)+' DVR(s)';
    fillLiveDevSel(j);
  } catch(e) {}
}
function filterDeviceList(){
  const q = ((document.getElementById('devSearch')||{}).value || '').trim().toLowerCase();
  const body = document.getElementById('recRows'); if (!body) return;
  const all = window._DEV_LIST || [];
  const list = q ? all.filter(d => [d.name, d.ip, d.location, d.username, d.type].join(' ').toLowerCase().includes(q)) : all;
  const hint = document.getElementById('devSearchHint');
  if (hint) hint.textContent = q ? (list.length + ' match(es)') : '';
  if (!all.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">No devices yet. Connect a DVR above.</td></tr>';
    return;
  }
  if (!list.length) {
    body.innerHTML = '<tr><td colspan="6" class="muted">No DVR matches your search.</td></tr>';
    return;
  }
  body.innerHTML = list.map(d => `<tr>
      <td>${esc(d.name||d.ip)} <span class="pill">${esc(d.type||'DVR')}</span></td>
      <td>${esc(d.ip)}:${d.port||554}</td>
      <td>${esc(d.username||'')}</td>
      <td>${(d.detected&&d.detected.length)||d.channels||'—'}</td>
      <td>${d.active?'<span class="pill online">ACTIVE</span>':'<span class="pill">—</span>'}</td>
      <td>
        <button onclick="selectDevice('${esc(d.id)}')" style="font-size:10px;padding:4px 8px">Select</button>
        <button onclick="removeDevice('${esc(d.id)}')" style="font-size:10px;padding:4px 8px">Remove</button>
        <button onclick="setDevType('${esc(d.id)}','${(d.type||'DVR')==='NVR'?'DVR':'NVR'}")" style="font-size:10px;padding:4px 8px">Make ${(d.type||'DVR')==='NVR'?'DVR':'NVR'}</button>
      </td>
    </tr>`).join('');
}
function fillLiveDevSel(j){
  if (j && j.devices) window._DEV_LIST = j.devices;
  filterLiveDevSel();
}
function filterLiveDevSel(){
  const sel = document.getElementById('liveDevSel'); if (!sel) return;
  const q = ((document.getElementById('liveDevSearch')||{}).value || '').trim().toLowerCase();
  const all = window._DEV_LIST || [];
  const list = q ? all.filter(d => [d.name, d.ip, d.location, d.type].join(' ').toLowerCase().includes(q)) : all;
  const cur = sel.value;
  const html = list.length
    ? list.map(d => `<option value="${esc(d.id)}">${esc(d.name||d.ip)} (${esc(d.ip)})</option>`).join('')
    : `<option value="">${all.length ? 'No match' : 'No DVR added yet'}</option>`;
  sel.innerHTML = html;
  if (cur && list.some(d => d.id === cur)) sel.value = cur;
  else if (!q) {
    const act = all.find(d => d.active);
    if (act) sel.value = act.id;
  }
}

async function selectDevice(id, stayOnPage){
  const r = await fetch('/api/device-select', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id})});
  const j = await r.json();
  if (!j.ok) { alert(j.message||'Select failed'); return; }
  applyStreamsFromServer(j);
  await refreshDeviceList();
  render();
  startLiveRefresh();
  if (!stayOnPage) go('cctv');            // on start-up stay on the Dashboard
  addEvent('DVR LINK', 'Active device '+id, 'Local LAN', 'INFO');
}

async function removeDevice(id){
  if (!confirm('Remove this DVR from the registry?')) return;
  await fetch('/api/device-remove', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id})});
  await refreshDeviceList();
  profile = {connected:false, mode:'', target:'', user:'', channels:0};
  cameras.forEach(c => { c.status='Offline'; c.snap=''; c.rtspMain=''; c.rtspSub=''; });
  render();
}

let liveRefreshTimer = null;
function startLiveRefresh(){
  if (liveRefreshTimer) clearInterval(liveRefreshTimer);
  liveRefreshTimer = setInterval(() => {
    document.querySelectorAll('img.live-snap').forEach(img => {
      if (img.getAttribute('data-live')) return;  // live MJPEG streams update themselves
      const ch = img.getAttribute('data-ch');
      if (!ch) return;
      img.src = '/api/snapshot?ch=' + ch + '&t=' + Date.now();
    });
  }, 1500);
}

function updateProfileTable(){ refreshDeviceList(); }

function render(){
  const online = cameras.filter(c => c.status==='Online').length;
  const open = events.filter(e => e.severity!=='INFO').length;
  document.getElementById('onlineCount').textContent = online+'/'+cameras.length;
  document.getElementById('incidentCount').textContent = open;
  document.getElementById('dvrLink').textContent = profile.connected ? 'ON' : 'OFF';
  document.getElementById('dvrMode').textContent = profile.mode || 'Not connected';

  const show = profile.connected ? cameras.filter(c => c.snap||c.rtspMain||c.rtspSub).slice(0,4) : cameras.slice(0,4);
  setFeeds('overviewCameras', show, '<div class="muted">Connect DVR first</div>');
  setFeeds('allCameras', profile.connected ? cameras.filter(c => c.snap||c.rtspMain||c.rtspSub).slice(0,16) : cameras.slice(0,8), '');
  document.getElementById('locationSites').innerHTML = ['Main Site','Secondary Site'].map(siteCard).join('');
  document.getElementById('recentEvents').innerHTML = events.slice(0,5).map(eventCard).join('') || '<div class="muted">No events</div>';
  document.getElementById('alertRows').innerHTML = events.map(e =>
    `<tr><td>${esc(e.id)}</td><td>${esc(e.type)}</td><td>${esc(e.title)}</td><td>${esc(e.site)}</td>
     <td><span class="pill ${e.severity==='CRITICAL'?'offline':e.severity==='WARNING'?'warn':'online'}">${esc(e.severity)}</span></td>
     <td>${esc(e.time)}</td></tr>`).join('');
  document.getElementById('rOnline').textContent = online;
  document.getElementById('rOffline').textContent = cameras.length - online;
  document.getElementById('rAngle').textContent = cameras.filter(c => c.angle==='Changed').length;
  document.getElementById('rEvents').textContent = events.length;
  document.getElementById('reportCameras').innerHTML = cameras.filter(c => c.ch <= (profile.channels||4)).map(c =>
    `<tr><td>${esc(c.id)}</td><td>${esc(c.name)}</td><td>${esc(c.site)}</td><td>${pill(c.status)}</td><td>${pill(c.angle==='Changed'?'Flagged':'Normal')}</td></tr>`).join('');

  const rtspEl = document.getElementById('rtspList');
  const withUrl = cameras.filter(c => c.rtspMain||c.rtspSub);
  rtspEl.innerHTML = withUrl.length
    ? withUrl.map(c => `<div class="event"><div class="event-icon blue">CH${c.ch}</div><div style="min-width:0;flex:1">
        <div class="event-title">${esc(c.name)}</div><div class="rtsp-box">${esc(c.rtspSub||c.rtspMain)}</div>
        <button onclick="copyText('${esc(c.rtspSub||c.rtspMain)}')" style="font-size:10px;margin-top:4px">Copy</button></div></div>`).join('')
    : '<div class="muted">Connect via Local RTSP first.</div>';
  updateProfileTable();
  runAiMonitor();
}

function copyText(t){
  navigator.clipboard.writeText(t).then(() => alert('RTSP copied — paste into VLC')).catch(() => prompt('Copy:', t));
}
function addEvent(type, title, site, severity='WARNING'){
  const e = {id:'EVT-'+eventNo++, type, title, site, severity, time:now()};
  events.unshift(e);
  render();
  if (severity !== 'INFO') {
    showToast(title, site+' · '+e.id, severity);
    sendPhoneAlert(e);
    // AI narrates critical events into chat if open
    if (document.getElementById('ai')?.classList.contains('active')) {
      pushChat('ai', 'Monitor alert: '+title+' @ '+site+' ['+severity+']');
    }
  }
  return e;
}
async function configureTelegram(ev){
  ev.preventDefault();
  const token = document.getElementById('tgToken').value.trim();
  const chat = document.getElementById('tgChat').value.trim();
  const out = document.getElementById('tgResult');
  out.textContent = 'Saving…';
  try {
    const r = await fetch('/api/telegram-config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({bot_token:token, chat_id:chat})});
    const j = await r.json();
    out.textContent = j.message || (j.ok?'Saved permanently.':'Failed');
    if (j.ok) { document.getElementById('tgToken').value = ''; loadTelegramStatus(); }
  } catch(e){ out.textContent = 'Server unreachable'; }
}
async function testTelegram(){
  const out = document.getElementById('tgResult');
  out.textContent = 'Sending…';
  try {
    const r = await fetch('/api/telegram-test', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
    const j = await r.json();
    out.textContent = j.message || (j.ok?'Sent':'Failed');
  } catch(e){ out.textContent = 'Server unreachable'; }
}
async function sendPhoneAlert(e){
  try {
    await fetch('/api/notify', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({id:e.id, type:e.type, title:e.title, site:e.site, severity:e.severity, time:e.time})});
  } catch(err){}
}
function showToast(title, body, severity){
  document.getElementById('toastTitle').textContent = severity==='CRITICAL'?'SOS / CRITICAL':'SECURITY EVENT';
  document.getElementById('toastBody').textContent = title+' — '+body;
  document.getElementById('toast').classList.add('show');
}
function dismissToast(){ document.getElementById('toast').classList.remove('show'); }
function triggerSOS(){ addEvent('SOS','Potential unauthorized access / tampering','Main Site','CRITICAL'); }
function toggleCamera(id){
  const c = cameras.find(x => x.id===id); if (!c) return;
  c.status = c.status==='Online'?'Offline':'Online';
  c.manualOff = c.status === 'Offline';
  addEvent('CAMERA STATUS', c.name+' is now '+c.status, c.site, c.status==='Offline'?'CRITICAL':'INFO');
}
function simulateOffline(){
  const c = cameras.find(x => x.status==='Online') || cameras[0];
  c.status = 'Offline';
  addEvent('CAMERA OFFLINE', c.name+' connection lost', c.site, 'CRITICAL');
}
function toggleAngle(id){
  const c = cameras.find(x => x.id===id); if (!c) return;
  c.angle = c.angle==='Normal'?'Changed':'Normal';
  addEvent('ANGLE CHANGE', c.name+(c.angle==='Changed'?' view change flagged':' flag cleared'), c.site, c.angle==='Changed'?'WARNING':'INFO');
}
function simulateAngle(){
  const c = cameras.find(x => x.angle==='Normal') || cameras[0];
  c.angle = 'Changed';
  addEvent('ANGLE CHANGE', 'Possible view change: '+c.name, c.site, 'WARNING');
}
function checkCamera(id){
  const c = cameras.find(x => x.id===id);
  if (c) addEvent('HEALTH CHECK', c.name+' status: '+c.status, c.site, 'INFO');
}
function resetDemo(){
  cameras = structuredClone(initial);
  events = [{id:'EVT-1001',type:'SYSTEM',title:'IDP i AI reset — '+MODEL,site:'Local',severity:'INFO',time:now()}];
  eventNo = 1002;
  profile = {connected:false, mode:'', target:'', user:'', channels:0};
  document.getElementById('connBadge').textContent = 'No DVR linked';
  document.getElementById('livePill').textContent = 'NO STREAM';
  document.getElementById('livePill').className = 'pill';
  dismissToast();
  render();
  pushChat('ai', 'Demo reset. AI monitor is on standby — continuous tracking starts after you link the DVR.');
}
function downloadReport(){
  const rows = [['Event ID','Type','Description','Location','Severity','Time'],
    ...events.map(e => [e.id,e.type,e.title,e.site,e.severity,e.time]),
    [], ['Camera ID','Name','Site','Status','View'],
    ...cameras.map(c => [c.id,c.name,c.site,c.status,c.angle])];
  const csv = rows.map(r => r.map(v => '"'+String(v??'').replaceAll('"','""')+'"').join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  a.download = 'idp-i-report.csv';
  a.click();
}

// Boot AI
pushChat('ai', 'Hello. I am IDP i AI for CCTV monitoring.\n• I continuously monitor cameras and events\n• I auto-fill alert messages\n• I help with IP, RTSP, Telegram, and SOS workflows\n\nConnect from DVR Setup, or ask me a question.');
fillAutoMessage();
render();

function pad2(n){ return String(n).padStart(2,'0'); }
function toDahuaTime(localVal){
  // datetime-local -> YYYY_MM_DD_HH_MM_SS
  if (!localVal) return '';
  const d = new Date(localVal);
  if (isNaN(d.getTime())) return '';
  return d.getFullYear()+'_'+pad2(d.getMonth()+1)+'_'+pad2(d.getDate())+'_'+pad2(d.getHours())+'_'+pad2(d.getMinutes())+'_'+pad2(d.getSeconds());
}
let PB_DEVICES = [];
async function fillPlaybackChannels(){
  try { const r = await fetch('/api/devices'); PB_DEVICES = (await r.json()).devices || []; }
  catch(e) { PB_DEVICES = []; }
  const dsel = document.getElementById('pbDevice');
  if (dsel) {
    const prev = dsel.value;
    dsel.innerHTML = PB_DEVICES.length
      ? PB_DEVICES.map(d => `<option value="${esc(d.id)}">${esc(d.name || d.id)}${d.active ? ' (active)' : ''}</option>`).join('')
      : '<option value="">No DVR/NVR assigned to this account</option>';
    if (prev && PB_DEVICES.some(d => d.id === prev)) dsel.value = prev;
    dsel.onchange = pbChannelOptions;
  }
  pbChannelOptions();
  // default times: last hour
  const end = new Date();
  const start = new Date(end.getTime() - 60*60*1000);
  const toLocal = (d) => {
    const off = d.getTimezoneOffset()*60000;
    return new Date(d - off).toISOString().slice(0,16);
  };
  const s = document.getElementById('pbStart');
  const e = document.getElementById('pbEnd');
  if (s && !s.value) s.value = toLocal(start);
  if (e && !e.value) e.value = toLocal(end);
}
function pbChannelOptions(){
  const sel = document.getElementById('pbChannel');
  const dsel = document.getElementById('pbDevice');
  if (!sel) return;
  const dev = PB_DEVICES.find(d => d.id === (dsel ? dsel.value : '')) || null;
  const prevCh = parseInt(sel.value, 10) || 0;
  const n = dev && Number(dev.channels) > 0 ? Math.min(16, Number(dev.channels)) : 16;
  const camList = dev && dev.active ? cameras : [];   // camera names are only known for the active DVR
  let html = '';
  for (let c = 1; c <= n; c++) {
    const cam = camList.find(x => x.ch === c);
    html += `<option value="${c}">${esc(cam ? cam.name : 'Channel ' + c)} (CH${c})</option>`;
  }
  sel.innerHTML = html;
  if (prevCh >= 1 && prevCh <= n) sel.value = String(prevCh);
}
let lastPlaybackUrl = '';
async function buildPlayback(){
  const ch = parseInt(document.getElementById('pbChannel').value,10)||1;
  const st = toDahuaTime(document.getElementById('pbStart').value);
  const et = toDahuaTime(document.getElementById('pbEnd').value);
  const out = document.getElementById('pbResult');
  const box = document.getElementById('pbUrl');
  if (!st || !et) { out.textContent = 'Set start and end time.'; return; }
  out.textContent = 'Building playback URL…';
  try {
    const r = await fetch('/api/playback-url', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({channel: ch, start: st, end: et})
    });
    const j = await r.json();
    if (!j.ok) { out.textContent = j.message || 'Failed'; return; }
    lastPlaybackUrl = j.url || '';
    box.style.display = 'block';
    box.textContent = lastPlaybackUrl;
    out.textContent = j.message || 'Playback URL ready. Open in VLC or export MP4.';
  } catch(e) { out.textContent = 'Server unreachable'; }
}
function copyPlayback(){
  if (!lastPlaybackUrl) { alert('Build playback URL first'); return; }
  navigator.clipboard.writeText(lastPlaybackUrl).then(()=>alert('Copied — paste into VLC')).catch(()=>prompt('Copy', lastPlaybackUrl));
}
let pbJobId = '', pbTimer = null, pbBusy = false;
function pbSize(b){
  b = Number(b) || 0;
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  return Math.max(1, Math.round(b / 1024)) + ' KB';
}
function pbEta(s){
  if (s == null) return 'estimating time left…';
  s = Math.max(0, Math.round(s));
  if (s < 60) return s + ' s left';
  if (s < 3600) return Math.floor(s / 60) + ' min ' + (s % 60) + ' s left';
  return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min left';
}
function pbSetBusy(on){
  const b = document.getElementById('pbBtnExport');
  if (b) { b.disabled = on; b.textContent = on ? 'Exporting…' : 'Download MP4 clip'; }
}
function pbRender(j){
  const box = document.getElementById('pbProgress');
  if (!box) return;
  box.style.display = 'block';
  const pct = Math.max(0, Math.min(100, Number(j.percent) || 0));
  document.getElementById('pbBarFill').style.width = pct.toFixed(1) + '%';
  document.getElementById('pbPct').textContent = pct.toFixed(0) + '%';
  const parts = [];
  if (j.size) parts.push(pbSize(j.size) + ' downloaded');
  if (j.state === 'running' || j.state === 'queued') parts.push(pbEta(j.eta_seconds));
  if (j.attempt > 1) parts.push('attempt ' + j.attempt + ' of 2');
  document.getElementById('pbDetail').textContent = parts.join(' · ');
  document.getElementById('pbStatusLine').textContent = j.message || '';
  const running = j.state === 'queued' || j.state === 'running';
  document.getElementById('pbCancelBtn').style.display = running ? 'inline-block' : 'none';
  document.getElementById('pbRetryBtn').style.display = (j.state === 'error' || j.state === 'cancelled') ? 'inline-block' : 'none';
  const save = document.getElementById('pbSaveBtn');
  save.style.display = j.state === 'done' ? 'inline-block' : 'none';
  if (j.state === 'done' && j.download) { save.href = j.download; save.setAttribute('download', j.filename || 'clip.mp4'); }
}
function pbFail(msg){
  clearInterval(pbTimer); pbTimer = null; pbBusy = false; pbSetBusy(false);
  pbRender({state: 'error', percent: 0, message: msg});
}
async function exportClip(){
  if (pbBusy) return;                       // no duplicate requests from double taps
  const dev = document.getElementById('pbDevice').value;
  const ch = parseInt(document.getElementById('pbChannel').value, 10) || 1;
  const st = toDahuaTime(document.getElementById('pbStart').value);
  const et = toDahuaTime(document.getElementById('pbEnd').value);
  if (!dev) { pbFail('Choose a DVR/NVR first.'); return; }
  if (!st || !et) { pbFail('Set both a start and an end time.'); return; }
  pbBusy = true; pbSetBusy(true);
  pbRender({state: 'queued', percent: 0, message: 'Checking the DVR/NVR and starting the export…'});
  let j;
  try {
    const r = await fetch('/api/playback-export', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({dev: dev, channel: ch, start: st, end: et})
    });
    j = await r.json();
  } catch (e) { pbFail('Cannot reach the IDP i server. Check the network connection, then retry.'); return; }
  if (!j.ok) { pbFail(j.message || 'The export could not start.'); return; }
  pbJobId = j.job_id;
  pbRender(j.job || {state: 'queued', percent: 0, message: j.message});
  pbTimer = setInterval(pbPoll, 1000);
  pbPoll();
}
async function pbPoll(){
  if (!pbJobId) return;
  let j;
  try {
    const r = await fetch('/api/export-status?id=' + encodeURIComponent(pbJobId));
    j = await r.json();
  } catch (e) {
    document.getElementById('pbStatusLine').textContent = 'Connection interrupted. Still trying to reach the server…';
    return;
  }
  if (!j.ok) { pbFail(j.message || 'Lost track of this export.'); return; }
  const job = j.job;
  pbRender(job);
  if (job.state === 'done' || job.state === 'error' || job.state === 'cancelled') {
    clearInterval(pbTimer); pbTimer = null; pbBusy = false; pbSetBusy(false);
    if (job.state === 'done') pbFinished(job);
  }
}
function pbFinished(job){
  const vid = document.getElementById('pbPlayer'), box = document.getElementById('pbPlayerBox');
  if (box && vid) { box.style.display = 'block'; vid.src = job.download; vid.load(); }
  const a = document.createElement('a');
  a.href = job.download; a.download = job.filename || 'clip.mp4';
  document.body.appendChild(a); a.click(); a.remove();
  const list = document.getElementById('pbExports');
  if (list) {
    if (list.textContent.indexOf('No exports yet') !== -1) list.innerHTML = '';
    const row = document.createElement('div');
    row.className = 'event';
    row.innerHTML = `<div class="event-icon green">↓</div><div><div class="event-title">${esc(job.filename || 'clip.mp4')}</div>` +
      `<div class="event-meta">${esc(job.message || '')}</div>` +
      `<a href="${esc(job.download)}" download style="color:var(--blue);font-size:11px">Download again</a></div>`;
    list.prepend(row);
  }
}
async function pbCancel(){
  if (!pbJobId) return;
  document.getElementById('pbStatusLine').textContent = 'Cancelling…';
  try {
    await fetch('/api/export-cancel', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({job_id: pbJobId})});
  } catch (e) { /* the poll loop will show the real state */ }
}
function pbRetry(){ exportClip(); }

async function loadTelegramStatus(){
  try {
    const r = await fetch('/api/telegram-status');
    const j = await r.json();
    const out = document.getElementById('tgResult');
    if (!out) return;
    if (j.configured) {
      out.innerHTML = '<span class="green">Telegram saved permanently</span> — chat '+esc(j.chat_id||'')+' · alerts will auto-send';
      const chat = document.getElementById('tgChat');
      if (chat && !chat.value) chat.value = j.chat_id || '';
    } else {
      out.textContent = 'Not configured — save bot token + chat ID once.';
    }
  } catch(e) {}
}

async function restoreActiveDeviceOnBoot(){
  try {
    const r = await fetch('/api/devices');
    const j = await r.json();
    if (!j.devices || !j.devices.length) return;
    const active = j.devices.find(d => d.active) || j.devices[0];
    if (active) await selectDevice(active.id, true);
    document.getElementById('connBadge').textContent = (j.count||0)+' DVR(s)';
  } catch(e) {}
}

loadTelegramStatus();
restoreActiveDeviceOnBoot();
setInterval(runAiMonitor, 5000);
refreshDeviceList();

/* ==================================================================
   IDP i — 24/7 AI engine (server) + live alerts + voice assistant
   ================================================================== */
async function aiGet(path){
  try { const r = await fetch(path, {cache:'no-store'}); if (r.status === 401) { location.href = '/login'; return {ok:false}; } return await r.json(); }
  catch(e){ return {ok:false, message:'Could not reach the IDP i server'}; }
}
async function aiPost(path, body){
  try { const r = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body||{})});
    if (r.status === 401) { location.href = '/login'; return {ok:false}; } return await r.json(); }
  catch(e){ return {ok:false, message:'Could not reach the IDP i server'}; }
}
async function logout(){ await fetch('/api/logout', {method:'POST'}); location.href = '/login'; }
const aiImg = p => '/api/ai/image?p=' + encodeURIComponent(p);
function openImg(src){ const m = document.getElementById('imgModalImg'); m.removeAttribute('data-src'); m.classList.remove('live-snap'); m.src = src; document.getElementById('imgModal').style.display = 'grid'; }
function aiAgo(t){ if(!t) return '—'; const s = Math.floor(Date.now()/1000 - t); if (s < 60) return s+'s ago'; if (s < 3600) return Math.floor(s/60)+'m ago'; if (s < 86400) return Math.floor(s/3600)+'h ago'; return Math.floor(s/86400)+'d ago'; }
function aiSay(id, text, ok=true){ const el = document.getElementById(id); if (el) el.innerHTML = `<span class="${ok?'green':'red'}">${esc(text)}</span>`; }
const AI_ISSUE = {NO_VIDEO:'Faulty / no video', BLUR:'Blurry', TOO_DARK:'Too dark', OVEREXPOSED:'Too bright', ANGLE_CHANGE:'Angle changed', FROZEN:'Frozen'};
function aiPill(c){
  if (c.dvr_offline) return '<span class="pill offline">DVR OFFLINE</span>';
  const m = {ok:['online','OK'], offline:['offline','OFFLINE'], novideo:['offline','FAULTY'], issue:['warn','PROBLEM'], unknown:['','CHECKING']}[c.status] || ['', c.status];
  return `<span class="pill ${m[0]}">${m[1]}</span>`;
}

let AI_STATUS = null, AI_SETTINGS_FILLED = false;
async function loadAiStatus(){
  const j = await aiGet('/api/ai/status'); if (!j || !j.counts) return;
  AI_STATUS = j; const c = j.counts, st = j.stats || {};
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('aiOk', `${c.ok}/${c.cam_total}`); set('aiOk2', c.avg_score==null ? 'health score —' : `avg health score ${c.avg_score}`);
  set('aiOff', c.cam_offline + c.cam_faulty); set('aiOff2', `${c.cam_offline} offline · ${c.cam_faulty} faulty · ${c.dvr_offline} DVR offline`);
  set('aiIss', c.blur + c.angle + c.frozen + c.dark); set('aiIss2', `blur ${c.blur} · angle ${c.angle} · frozen ${c.frozen} · light ${c.dark}`);
  set('aiGates', `${c.gates_open}/${c.gates}`); set('aiGates2', `face cameras ${c.face_cams} · people ${c.faces_enrolled}`);
  set('aiScanLine', `DVR check ${aiAgo(st.dvr_scan)} · camera check ${aiAgo(st.health_scan)} · gates ${aiAgo(st.gate_scan)} · faces ${aiAgo(st.face_scan)} · running since ${new Date((st.started||0)*1000).toLocaleString()}`);
  const n = [];
  if (!j.cv_ok) n.push('OpenCV is not installed — only offline checks are running. For blur / angle / gate / face AI install: <b>sudo apt install python3-opencv python3-numpy</b> and restart.');
  if (!j.telegram) n.push('Telegram is not set up — go to Alerts &amp; SOS and save the bot token and chat ID, or alerts will not reach your phone.');
  if (j.devices.some(d=>d.auth_blocked)) n.push('A DVR rejected the password — camera checks for it are paused. Fix it in DVR Setup.');
  if (!j.devices.length) n.push('No DVR added yet — add one in DVR Setup and the AI starts checking it automatically.');
  const nb = document.getElementById('aiNotices'); if (nb) nb.innerHTML = n.map(x=>`<div class="card" style="border-color:#54472c;background:#1c2020;color:#e6d4a6;font-size:12px;margin-bottom:10px">${x}</div>`).join('');
  renderAiCams();
  const dr = document.getElementById('aiDevRows');
  if (dr) dr.innerHTML = j.devices.map((d,i)=>`<tr><td>${esc(d.name)}</td><td>${esc(d.ip)}</td><td>${d.status==='offline'?'<span class="pill offline">OFFLINE</span>':d.status==='online'?'<span class="pill online">ONLINE</span>':'<span class="pill">CHECKING</span>'}</td>
    <td><input id="devLoc${i}" value="${esc(d.location)}" placeholder="e.g. Gurgaon Hub"></td><td><button onclick="saveDevLocation('${esc(d.id)}','devLoc${i}')">Save</button></td></tr>`).join('') || '<tr><td colspan="5" class="muted">No DVRs yet.</td></tr>';
  if (!AI_SETTINGS_FILLED) { document.querySelectorAll('[data-ai]').forEach(el=>{ const v = j.settings[el.dataset.ai]; if (el.type==='checkbox') el.checked = !!Number(v); else el.value = v ?? ''; }); AI_SETTINGS_FILLED = true; syncFaceMasterBtns(); }
  syncCamerasFromAi();
  const gc = document.getElementById('gateCam');
  if (gc && !gc.options.length) gc.innerHTML = j.cameras.map(x=>`<option value="${esc(x.dev)}|${x.ch}">${esc(x.site)} / ${esc(x.name)} (CH${x.ch})</option>`).join('') || '<option value="">Add a DVR first</option>';
}
function renderAiCams(){
  const el = document.getElementById('aiCamRows'); if (!el || !AI_STATUS) return;
  const q = (document.getElementById('aiQ').value||'').toLowerCase(), f = document.getElementById('aiFilter').value;
  const rows = AI_STATUS.cameras.map((c,i)=>({c,i})).filter(({c})=>{
    if (q && !(`${c.site} ${c.dvr} ${c.name} ${c.location}`.toLowerCase().includes(q))) return false;
    if (f==='bad') return c.dvr_offline || (c.issues&&c.issues.length) || c.status==='offline';
    if (f==='offline') return c.dvr_offline || c.status==='offline' || c.status==='novideo';
    if (f==='gate') return c.gate; if (f==='face') return c.face; return true; });
  el.innerHTML = rows.map(({c,i})=>{
    const iss = (c.issues||[]).map(x=>`<span class="pill warn">${AI_ISSUE[x]||x}</span>`).join(' ');
    const sc = c.score==null ? '—' : `<b class="${c.score>=80?'green':c.score>=50?'amber':'red'}">${c.score}</b>`;
    return `<tr><td><button onclick="openImg('/api/snapshot?dev=${encodeURIComponent(c.dev)}&ch=${c.ch}&t='+Date.now())" title="Live snapshot" style="font-size:10px;padding:4px 7px">👁</button></td>
      <td>${esc(c.site)}<div class="muted" style="font-size:10px">${esc(c.dvr)}</div></td><td>${c.ch}</td>
      <td>${esc(c.name)}<div class="muted" style="font-size:10px">${esc(c.location||'')}</div></td><td>${aiPill(c)}</td><td>${sc}</td>
      <td>${iss}${c.night?' <span class="pill">IR</span>':''}${c.gate?` <span class="pill">GATE ${esc((c.gate_state||'').toUpperCase())}</span>`:''}</td>
      <td class="muted" style="font-size:10px">${aiAgo(c.last_check)}</td>
      <td><input type="checkbox" style="width:auto" ${c.face?'checked':''} onchange="aiCamSet(${i},{face:this.checked})"></td>
      <td><div class="actions"><button onclick="aiEditCam(${i})">✎ Name</button><button onclick="aiCheckCam(${i},this)">↻ Check</button><button onclick="aiResetAngle(${i},this)" title="Use the current picture as the correct angle">⌖ Reset angle</button><button onclick="gateFor(${i})">🚪 Gate</button></div></td></tr>`;
  }).join('') || '<tr><td colspan="10" class="muted">No cameras yet. Add a DVR in DVR Setup.</td></tr>';
}
function syncCamerasFromAi(){
  if (!AI_STATUS || !profile.deviceId || typeof cameras === 'undefined') return;
  let changed = false;
  AI_STATUS.cameras.filter(c=>c.dev===profile.deviceId).forEach(c=>{
    const cam = cameras.find(x=>x.ch===c.ch); if (!cam || (!cam.snap && !cam.rtspMain)) return;
    if (cam.face !== !!c.face) { cam.face = !!c.face; changed = true; }
    if (cam.manualOff) return;                      // you marked it offline by hand => keep it
    if (c.status==='unknown' && !c.dvr_offline) return;
    let st = (c.dvr_offline || c.status==='offline' || c.status==='novideo') ? 'Offline' : 'Online';
    if (st === 'Offline' && tileHasLive(c.ch)) st = 'Online';   // live video is coming in => it is online
    const ang = (c.issues||[]).includes('ANGLE_CHANGE') ? 'Changed' : 'Normal';
    const nm = c.name || cam.name;
    if (cam.status!==st || cam.angle!==ang || cam.name!==nm){ cam.status=st; cam.angle=ang; cam.name=nm; changed=true; }
  });
  if (changed) render();
}
async function aiCamSet(i, obj){ const c = AI_STATUS.cameras[i]; const j = await aiPost('/api/ai/camera', Object.assign({dev:c.dev, ch:c.ch}, obj)); if (!j.ok) alert(j.message); loadAiStatus(); }
function aiEditCam(i){ const c = AI_STATUS.cameras[i];
  const n = prompt('Camera name:', c.name||''); if (n===null) return;
  const l = prompt('Camera location (e.g. Main gate, Loading bay 2):', c.location||''); if (l===null) return;
  aiCamSet(i, {name:n, location:l}); }
async function aiCheckCam(i, btn){ const c = AI_STATUS.cameras[i]; btn.disabled = true; const j = await aiPost('/api/ai/check', {dev:c.dev, ch:c.ch}); btn.disabled = false; showToast('Camera check', j.message||'', j.ok?'INFO':'WARNING'); loadAiStatus(); }
async function aiResetAngle(i, btn){ if (!confirm('Use the current picture as the correct camera angle?')) return; const c = AI_STATUS.cameras[i]; btn.disabled = true; const j = await aiPost('/api/ai/reset-angle', {dev:c.dev, ch:c.ch}); btn.disabled = false; showToast('Angle', j.message||'', j.ok?'INFO':'WARNING'); loadAiStatus(); }
async function aiScan(kind){ const j = await aiPost('/api/ai/scan', {kind}); showToast('AI scan', j.message||'', 'INFO'); }
async function saveDevLocation(id, inputId){ const j = await aiPost('/api/ai/device-location', {id, location:document.getElementById(inputId).value}); showToast('Location', j.message||'', j.ok?'INFO':'WARNING'); loadAiStatus(); }

function faceMasterOn(){
  const el = document.getElementById('faceMasterVal');
  if (el) return !!Number(el.value);
  const s = (window.AI_STATUS && AI_STATUS.settings) || {};
  return Number(s.face_master !== undefined ? s.face_master : 1) !== 0;
}
function syncFaceMasterBtns(){
  const on = faceMasterOn();
  const label = on ? '🙂 Face recognition ON' : '🙂 Face recognition OFF';
  const cls = on ? 'primary' : '';
  ['faceMasterBtn','faceMasterBtn2'].forEach(id => {
    const b = document.getElementById(id); if (!b) return;
    b.textContent = label; b.className = cls;
  });
  const h = document.getElementById('faceMasterHint');
  if (h) {
    const st = ((window.AI_STATUS||{}).settings||{});
    const a = (st.face_schedule_start||'').trim(), b = (st.face_schedule_end||'').trim();
    h.textContent = !on ? 'Face recognition is OFF for all cameras.'
      : (a && b ? `Active daily ${a} – ${b} (outside this window it stays off).` : 'ON for all cameras that have Face AI enabled (no time limit).');
  }
}
async function toggleFaceMaster(){
  const el = document.getElementById('faceMasterVal');
  const cur = el ? !!Number(el.value) : true;
  const next = cur ? 0 : 1;
  if (el) el.value = String(next);
  document.querySelectorAll('[data-ai="face_master"]').forEach(x => { if (x.type==='checkbox') x.checked = !!next; else x.value = String(next); });
  syncFaceMasterBtns();
  await saveAiSettings();
  if (typeof loadAiStatus === 'function') loadAiStatus();
}

async function saveAiSettings(){ const body = {}; document.querySelectorAll('[data-ai]').forEach(el=>body[el.dataset.ai] = el.type==='checkbox' ? (el.checked?1:0) : el.value);
  const j = await aiPost('/api/ai/settings', body); aiSay('aiSetMsg', j.message||'', j.ok); }

/* ---------- live AI alerts (toast + voice + event log) ---------- */
let AI_LAST_EV = -1;
let VOICE_ALERTS = (localStorage.getItem('idpi_voice_alerts') ?? '1') === '1';
function updateVoiceAlertBtn(){ const b = document.getElementById('voiceAlertBtn'); if (b) b.innerHTML = VOICE_ALERTS ? '🔊 Voice alerts ON' : '🔇 Voice alerts OFF'; }
function toggleVoiceAlerts(){ VOICE_ALERTS = !VOICE_ALERTS; localStorage.setItem('idpi_voice_alerts', VOICE_ALERTS?'1':'0'); updateVoiceAlertBtn(); speakText(VOICE_ALERTS?'Voice alerts on':'Voice alerts off'); }
function aiEventToLocal(e){
  return {id:'AI-'+e.id, type:e.title, title:e.title + (e.details ? ' — ' + e.details.split('\n')[0] : ''), site:e.where, severity:e.severity, time:(e.time||'').slice(-8)};
}
function spokenAlert(e){
  const what = e.title.toLowerCase().replace('/', ' or ');
  return `Alert. ${what}. ${e.where.replace(/\(CH(\d+)\)/,'channel $1')}.`;
}
async function pollAiEvents(){
  const first = AI_LAST_EV < 0;
  const j = await aiGet('/api/ai/events?since=' + Math.max(0, AI_LAST_EV)); if (!j || !j.ok) return;
  const list = j.events || [];
  if (first) { list.slice(-15).forEach(e=>events.unshift(aiEventToLocal(e))); AI_LAST_EV = j.last; render(); return; }
  if (!list.length) return;
  AI_LAST_EV = Math.max(AI_LAST_EV, ...list.map(e=>e.id));
  list.forEach(e=>events.unshift(aiEventToLocal(e)));
  if (events.length > 300) events.length = 300;
  render();
  const imp = list.filter(e=>e.severity!=='INFO');
  if (imp.length) {
    const e = imp[imp.length-1];
    showToast(e.title + (imp.length>1?` (+${imp.length-1} more)`:''), e.where + (e.details?' · '+e.details.split('\n')[0]:''), e.severity);
    if (VOICE_ALERTS) speakText(spokenAlert(e) + (imp.length>1 ? ` And ${imp.length-1} more alerts.` : ''), 'en');
    if (document.getElementById('ai')?.classList.contains('active')) pushChat('ai', 'AI alert: ' + e.title + ' @ ' + e.where);
  }
  const arrivals = list.filter(e => String(e.type||'').startsWith('FACE_') && e.severity === 'INFO');
  if (arrivals.length && !imp.length) {
    const e = arrivals[arrivals.length-1];
    showToast((e.category==='vip'?'⭐ VIP arrived: ':'🙂 Arrived: ') + (e.person||e.details), e.where, 'INFO');
    if (VOICE_ALERTS) speakText(`${e.person||'Someone'} is at ${e.camera||'the camera'}.`, 'en');
  }
  if (document.getElementById('gates')?.classList.contains('active')) loadGates();
  if (document.getElementById('faces')?.classList.contains('active')) loadFaces();
}

/* ---------- gate setup ---------- */
let ROI = [0.25,0.25,0.5,0.5], ROI_IMG = null;
function gateSel(){ const v = (document.getElementById('gateCam').value||'').split('|'); return {dev:v[0], ch:Number(v[1]||1)}; }
function drawRoi(){
  const cv = document.getElementById('roiCanvas'); if (!cv) return; const g = cv.getContext('2d'); g.clearRect(0,0,cv.width,cv.height);
  if (ROI_IMG) g.drawImage(ROI_IMG,0,0,cv.width,cv.height); else { g.fillStyle='#04101c'; g.fillRect(0,0,cv.width,cv.height); g.fillStyle='#9bb5cf'; g.font='14px sans-serif'; g.fillText('Choose the gate camera, then click "Get snapshot"',20,30); }
  g.strokeStyle='#ffb52e'; g.lineWidth=3; g.setLineDash([8,5]); g.strokeRect(ROI[0]*cv.width, ROI[1]*cv.height, ROI[2]*cv.width, ROI[3]*cv.height); g.setLineDash([]);
  g.fillStyle='#ffb52e'; g.font='bold 14px sans-serif'; g.fillText('GATE', ROI[0]*cv.width+6, ROI[1]*cv.height+18);
}
(function roiEvents(){
  const cv = document.getElementById('roiCanvas'); if (!cv) return; let start = null;
  const pos = e => { const r = cv.getBoundingClientRect(); return [Math.min(1,Math.max(0,(e.clientX-r.left)/r.width)), Math.min(1,Math.max(0,(e.clientY-r.top)/r.height))]; };
  cv.addEventListener('pointerdown', e=>{ start = pos(e); cv.setPointerCapture(e.pointerId); });
  cv.addEventListener('pointermove', e=>{ if(!start) return; const p = pos(e); ROI = [Math.min(start[0],p[0]), Math.min(start[1],p[1]), Math.abs(p[0]-start[0]), Math.abs(p[1]-start[1])]; drawRoi(); });
  cv.addEventListener('pointerup', ()=>{ start = null; if (ROI[2]<0.03||ROI[3]<0.03){ ROI=[0.25,0.25,0.5,0.5]; drawRoi(); } });
  drawRoi();
})();
async function gateLoad(){
  const s = gateSel(); if (!s.dev) { aiSay('gateMsg','Choose a camera first',false); return; }
  aiSay('gateMsg','Getting snapshot…');
  const r = await aiGet(`/api/ai/gate-refs?dev=${encodeURIComponent(s.dev)}&ch=${s.ch}`); if (r.ok && r.roi) ROI = r.roi; showRefs(r);
  const img = new Image();
  img.onload = () => { ROI_IMG = img; const cv = document.getElementById('roiCanvas'); cv.width = Math.min(1280, img.naturalWidth); cv.height = Math.round(cv.width*img.naturalHeight/img.naturalWidth); drawRoi(); aiSay('gateMsg','Draw a box over the gate, then click "Save gate area".'); };
  img.onerror = () => aiSay('gateMsg','Could not get a snapshot — check the DVR and camera.', false);
  img.src = `/api/snapshot?dev=${encodeURIComponent(s.dev)}&ch=${s.ch}&t=${Date.now()}`;
}
function showRefs(r){
  const el = document.getElementById('gateRefs'); if (!r || !r.ok) { el.innerHTML=''; return; }
  const lab = {closed_day:'CLOSED (day)', open_day:'OPEN (day)', closed_night:'CLOSED (night)', open_night:'OPEN (night)'};
  el.innerHTML = Object.entries(lab).map(([k,l])=> r.refs[k] ? `<div style="text-align:center"><img src="${aiImg(r.refs[k])}" onclick="openImg(this.src)" style="width:96px;height:56px;object-fit:cover;border-radius:4px;border:1px solid #1b4969;cursor:zoom-in"><div class="green" style="font-size:10px">✓ ${l}</div></div>` : `<div class="muted" style="font-size:10px;width:96px;text-align:center">✗ ${l} not marked</div>`).join('');
}
async function gateSaveRoi(){ const s = gateSel(); if (!s.dev) return; const j = await aiPost('/api/ai/camera', {dev:s.dev, ch:s.ch, gate_roi:ROI, gate:true});
  aiSay('gateMsg', j.ok ? 'Gate area saved. Now mark the gate CLOSED and OPEN (once in daylight, once at night).' : j.message, j.ok); showRefs(await aiGet(`/api/ai/gate-refs?dev=${encodeURIComponent(s.dev)}&ch=${s.ch}`)); loadGates(); }
async function gateMark(state){ const s = gateSel(); if (!s.dev) return; aiSay('gateMsg','Saving…'); const j = await aiPost('/api/ai/gate-mark', {dev:s.dev, ch:s.ch, state});
  aiSay('gateMsg', j.message||'', j.ok); showRefs(await aiGet(`/api/ai/gate-refs?dev=${encodeURIComponent(s.dev)}&ch=${s.ch}`)); loadGates(); }
async function gateOff(){ const s = gateSel(); if (!s.dev) return; await aiPost('/api/ai/camera', {dev:s.dev, ch:s.ch, gate:false}); aiSay('gateMsg','Gate monitoring is OFF for this camera.'); loadGates(); }
function gateFor(i){ const c = AI_STATUS.cameras[i]; go('gates'); const gc = document.getElementById('gateCam'); gc.value = `${c.dev}|${c.ch}`; gateLoad(); }
function aiEventRow(e){
  const col = e.severity==='CRITICAL'?'red':e.severity==='WARNING'?'amber':'green';
  return `<div class="event"><div class="event-icon ${col}">${e.severity==='CRITICAL'?'⚠':e.severity==='WARNING'?'◆':'✓'}</div>
    <div style="min-width:0;flex:1"><div class="event-title">${esc(e.title)}</div><div class="event-meta">${esc(e.where)}</div><div class="event-meta">${esc(e.details||'').replace(/\n/g,'<br>')}</div></div>
    ${e.image?`<img src="${aiImg(e.image)}" onclick="openImg(this.src)" style="width:86px;height:52px;object-fit:cover;border-radius:4px;border:1px solid #1b4969;cursor:zoom-in">`:''}
    <div class="event-time">${esc((e.time||'').slice(-8))}</div></div>`;
}
async function loadGates(){
  await loadAiStatus();
  const g = (AI_STATUS ? AI_STATUS.cameras : []).filter(c=>c.gate);
  document.getElementById('gateRows').innerHTML = g.map(c=>`<tr><td>${esc(c.site)}</td><td>${esc(c.name)} (CH${c.ch})</td>
    <td>${c.gate_state==='open'?'<span class="pill offline">OPEN</span>':c.gate_state==='closed'?'<span class="pill online">CLOSED</span>':'<span class="pill">NOT MARKED</span>'}</td><td class="muted" style="font-size:10px">${aiAgo(c.gate_since)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No gate cameras yet.</td></tr>';
  const e = await aiGet('/api/ai/events?type=GATE_'); if (e.ok) document.getElementById('gateEvents').innerHTML = e.events.slice(-15).reverse().map(aiEventRow).join('') || '<div class="muted">No gate events yet.</div>';
}

/* ---------- hourly reports ---------- */
let HR_READY = false;
async function hrInit(){
  const hs = document.getElementById('hrHour'); if (!hs) return;
  if (!HR_READY) {
    hs.innerHTML = Array.from({length:24}, (_,i)=>{ const a=String(i).padStart(2,'0'), b=String(i+1).padStart(2,'0'); return `<option value="${a}">${a}:00 - ${b}:00</option>`; }).join('');
    const d = new Date(Date.now() - 3600*1000);
    document.getElementById('hrDate').value = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    hs.value = String(d.getHours()).padStart(2,'0'); HR_READY = true;
    const ymd = x => `${x.getFullYear()}-${String(x.getMonth()+1).padStart(2,'0')}-${String(x.getDate()).padStart(2,'0')}`;
    document.getElementById('hrTo').value = ymd(new Date()); document.getElementById('hrFrom').value = ymd(new Date(Date.now() - 29*86400*1000));
  }
  const st = await aiGet('/api/ai/status'); const dv = document.getElementById('hrDev'); const keep = dv.value;
  if (st.ok !== false && st.devices) dv.innerHTML = '<option value="">All sites / DVRs</option>' + st.devices.map(d=>`<option value="${esc(d.id)}">${esc(d.location||d.name)} (${esc(d.ip)})</option>`).join('');
  dv.value = keep;
  const r = await aiGet('/api/ai/reports'); const rs = document.getElementById('hrRecent');
  if (r.ok) rs.innerHTML = '<option value="">Saved reports…</option>' + r.reports.map(x=>`<option value="${x.date}|${x.hour}">${esc(x.label)}</option>`).join('');
}
function hrQuery(){ return `date=${encodeURIComponent(document.getElementById('hrDate').value)}&hour=${encodeURIComponent(document.getElementById('hrHour').value)}&dev=${encodeURIComponent(document.getElementById('hrDev').value)}`; }
async function hrView(){
  aiSay('hrMsg','Building report…'); const j = await aiGet('/api/ai/report?' + hrQuery());
  if (!j.ok) { aiSay('hrMsg', j.message||'Could not build the report', false); return; }
  document.getElementById('hrOut').textContent = j.text;
  aiSay('hrMsg', `${j.partial?'PARTIAL (hour not finished) · ':''}${j.problems} problem event(s) · ${j.gates} shutter event(s) · system on ${Math.round(j.system_on_sec/60)} min`, true);
}
async function hrFetchSave(url, name){
  aiSay('hrMsg','Preparing download…');
  const r = await fetch(url, {cache:'no-store'}); if (r.status === 401) { location.href = '/login'; return; }
  const blob = await r.blob();
  if (!r.ok || blob.type.startsWith('text/plain') && (await blob.text()).startsWith('Error')) { aiSay('hrMsg', r.ok ? (await blob.text()) : 'Download failed', false); return; }
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); aiSay('hrMsg','Downloaded ' + name, true);
}
function hrSiteTag(){ const dv = document.getElementById('hrDev'); return dv.value ? '_' + (dv.options[dv.selectedIndex].text.split(' (')[0].replace(/[^A-Za-z0-9_-]+/g,'-')) : ''; }
function hrDownload(fmt){ hrFetchSave(`/api/ai/report.${fmt}?` + hrQuery(), `report_${document.getElementById('hrDate').value}_${document.getElementById('hrHour').value}00${hrSiteTag()}.${fmt}`); }
function hrDayDownload(){ const d = document.getElementById('hrDate').value; if (!d) { aiSay('hrMsg','Choose a date',false); return; }
  hrFetchSave(`/api/ai/report-day.txt?date=${encodeURIComponent(d)}&dev=${encodeURIComponent(document.getElementById('hrDev').value)}`, `report_${d}_full-day${hrSiteTag()}.txt`); }
function hrRangeDownload(kind){ const f = document.getElementById('hrFrom').value, t = document.getElementById('hrTo').value;
  if (!f || !t) { aiSay('hrMsg','Choose both dates',false); return; }
  if (t < f) { aiSay('hrMsg','"To" date must be after "From" date',false); return; }
  hrFetchSave(`/api/ai/report-range-${kind}.csv?from=${encodeURIComponent(f)}&to=${encodeURIComponent(t)}&dev=${encodeURIComponent(document.getElementById('hrDev').value)}`, `${kind==='events'?'events':'daily-summary'}_${f}_to_${t}${hrSiteTag()}.csv`); }
function hrPickRecent(){ const v = document.getElementById('hrRecent').value; if (!v) return; const [d,h] = v.split('|'); document.getElementById('hrDate').value = d; document.getElementById('hrHour').value = h; hrView(); }

/* ---------- faces ---------- */
function fileToJpeg(file, max=1280){ return new Promise((res,rej)=>{ const img = new Image(); img.onload = ()=>{ const s = Math.min(1, max/Math.max(img.width,img.height)); const c = document.createElement('canvas'); c.width = Math.round(img.width*s); c.height = Math.round(img.height*s); c.getContext('2d').drawImage(img,0,0,c.width,c.height); URL.revokeObjectURL(img.src); res(c.toDataURL('image/jpeg',0.9)); }; img.onerror = rej; img.src = URL.createObjectURL(file); }); }
async function enrollFace(btn){
  const files = [...document.getElementById('faceFile').files]; const name = document.getElementById('faceName').value.trim();
  if (!name || !files.length) { aiSay('faceMsg','Enter a name and choose a photo',false); return; }
  btn.disabled = true; const out = [];
  for (const f of files) { aiSay('faceMsg','Processing '+f.name+'…'); try { const image = await fileToJpeg(f); const j = await aiPost('/api/ai/face-enroll', {name, category:document.getElementById('faceCat').value, image}); out.push((j.ok?'✓ ':'✗ ')+f.name+': '+(j.message||'')); } catch(e) { out.push('✗ '+f.name+': could not read the file'); } }
  btn.disabled = false; document.getElementById('faceMsg').innerHTML = out.map(esc).join('<br>'); document.getElementById('faceFile').value=''; loadFaces();
}
async function delFace(id){ if (!confirm('Delete this person?')) return; await aiPost('/api/ai/face-delete', {id}); loadFaces(); }
async function loadFaces(){
  const j = await aiGet('/api/ai/faces'); if (!j.ok) return;
  const cat = {known:['STAFF','online'], vip:['VIP','warn'], watchlist:['WATCHLIST','offline']};
  document.getElementById('faceCount').textContent = j.faces.length;
  document.getElementById('faceGrid').innerHTML = j.faces.map(f=>`<div class="card" style="padding:7px;text-align:center"><img src="${aiImg(f.image)}" onclick="openImg(this.src)" style="width:100%;aspect-ratio:1;object-fit:cover;border-radius:4px;cursor:zoom-in"><div><b>${esc(f.name)}</b></div><span class="pill ${cat[f.category][1]}">${cat[f.category][0]}</span> <button onclick="delFace('${esc(f.id)}')" style="font-size:10px;padding:3px 7px">✕</button></div>`).join('') || '<div class="muted">Nobody enrolled yet.</div>';
  document.getElementById('faceNotice').innerHTML = !j.cv_ok ? '<div class="card" style="background:#1c2020;color:#e6d4a6;margin-bottom:10px">Install OpenCV for face recognition: <b>sudo apt install python3-opencv python3-numpy</b></div>' : (j.error ? `<div class="card" style="background:#1c2020;color:#e6d4a6;margin-bottom:10px">${esc(j.error)}</div>` : '');
  const e = await aiGet('/api/ai/events?type=FACE_'); if (e.ok) document.getElementById('faceEvents').innerHTML = e.events.slice(-20).reverse().map(aiEventRow).join('') || '<div class="muted">No faces detected yet.</div>';
}

/* ---------- voice assistant: real AI answers ---------- */
function aiStatusLines(){
  if (!AI_STATUS) return '\nAI engine: loading…';
  const c = AI_STATUS.counts;
  return `\n24/7 AI engine:\n• Cameras OK: ${c.ok}/${c.cam_total}\n• Offline: ${c.cam_offline} · Faulty (no video): ${c.cam_faulty}\n• Blurry: ${c.blur} · Angle changed: ${c.angle} · Frozen: ${c.frozen}\n• Gates open: ${c.gates_open}/${c.gates}\n• DVRs offline: ${c.dvr_offline}/${c.dvr_total}`;
}
function aiSpokenStatus(){
  if (!AI_STATUS) return 'The AI engine is still loading.';
  const c = AI_STATUS.counts;
  const bad = c.cam_offline + c.cam_faulty + c.blur + c.angle + c.frozen;
  return `${c.ok} of ${c.cam_total} cameras are fine. ` + (bad ? `${c.cam_offline} offline, ${c.cam_faulty} faulty, ${c.blur} blurry, ${c.angle} with angle changed. ` : 'No camera problems. ') + `${c.gates_open} gates open.`;
}
function aiProblemList(kind){
  if (!AI_STATUS) return [];
  return AI_STATUS.cameras.filter(c => kind==='offline'
    ? (c.dvr_offline || c.status==='offline' || c.status==='novideo')
    : (c.issues||[]).some(i=>i!=='NO_VIDEO'));
}
function handleVoiceCommand(raw){
  const t = raw.toLowerCase().trim();
  const reply = (text, spoken) => { pushChat('user', '🎤 ' + raw); pushChat('ai', text); speakText(spoken || text.split('\n')[0]); };
  if (/\b(simulate|demo|test alert)\b/.test(t)) return handleVoiceCommandBase(raw);
  if (/voice alert/.test(t)) { if (/off|band|stop|disable/.test(t) === VOICE_ALERTS) toggleVoiceAlerts(); reply('Voice alerts are ' + (VOICE_ALERTS?'ON':'OFF') + '.'); return; }
  if (/\b(gate|gates|door|shutter|darwaza|darwaja)\b/.test(t)) {
    const g = AI_STATUS ? AI_STATUS.cameras.filter(c=>c.gate) : [];
    if (!g.length) { reply('No gate cameras are set up yet. Open the Gates page to set one up.'); go('gates'); return; }
    const open = g.filter(c=>c.gate_state==='open');
    reply(['Gates:'].concat(g.map(c=>`• ${c.site} / ${c.name}: ${(c.gate_state||'not marked').toUpperCase()}`)).join('\n'),
          open.length ? `${open.length} gate${open.length>1?'s are':' is'} open: ` + open.map(c=>c.site+' '+c.name).join(', ') : 'All gates are closed.');
    return;
  }
  if (/\b(face|faces|chehra|kaun aaya|who came|who is there|visitors?|person|people)\b/.test(t)) {
    aiGet('/api/ai/events?type=FACE_').then(j=>{ const ev = (j.events||[]).slice(-5).reverse();
      reply(ev.length ? ['Recent faces:'].concat(ev.map(e=>`• ${e.time} — ${e.details} — ${e.where}`)).join('\n') : 'No faces detected yet.',
            ev.length ? 'Last face: ' + ev[0].details.replace(/\(.*\)/,'') + ' at ' + ev[0].site : 'No faces detected yet.'); });
    return;
  }
  if (/\b(offline|band|kharab|faulty|not working|dead|chal nahi|broken|down)\b/.test(t)) {
    const l = aiProblemList('offline');
    reply(l.length ? [`Offline / faulty cameras (${l.length}):`].concat(l.map(c=>`• ${c.site} / ${c.name} CH${c.ch} — ${c.dvr_offline?'DVR offline':c.status==='novideo'?'faulty, no video':'offline'}`)).join('\n') : 'All cameras are online.',
          l.length ? `${l.length} cameras are offline or faulty. First one: ${l[0].site}, ${l[0].name}.` : 'All cameras are online.');
    return;
  }
  if (/\b(blur|blurry|dhundh|angle|tamper|tampering|frozen|atka|problems?|issues?|hygiene|dark|andhera)\b/.test(t)) {
    const l = aiProblemList('issues');
    reply(l.length ? [`Camera problems (${l.length}):`].concat(l.map(c=>`• ${c.site} / ${c.name} CH${c.ch} — ${(c.issues||[]).map(i=>AI_ISSUE[i]||i).join(', ')}`)).join('\n') : 'No blur, angle or frozen problems right now.',
          l.length ? `${l.length} cameras have problems. ${l[0].site}, ${l[0].name}: ${(l[0].issues||[]).map(i=>AI_ISSUE[i]||i).join(', ')}.` : 'No camera problems right now.');
    return;
  }
  if (/\b(latest alerts?|last alerts?|recent alerts?|kya hua|what happened|alerts? batao|new alerts?)\b/.test(t)) {
    const ev = events.filter(e=>String(e.id).startsWith('AI-') && e.severity!=='INFO').slice(0,3);
    reply(ev.length ? ['Latest alerts:'].concat(ev.map(e=>`• ${e.time} — ${e.title} — ${e.site}`)).join('\n') : 'No alerts yet.',
          ev.length ? 'Latest alert: ' + ev[0].title.split(' — ')[0] + ' at ' + ev[0].site : 'No alerts yet.');
    return;
  }
  if (/\b(check all|scan|check cameras|camera check)\b/.test(t)) { aiScan('health'); reply('Checking all cameras now. Results come in shortly.'); return; }
  if (/\b(status|health|haal|report status|current status)\b/.test(t)) {
    reply(buildStatusAnswer(), aiSpokenStatus()); return;
  }
  if (/\b(ai camera|camera health|ai monitor)\b/.test(t)) { go('aimon'); reply('Opened AI Camera Health.'); return; }
  return handleVoiceCommandBase(raw);
}

/* ---------- live video + live face recognition ---------- */
function setFeeds(id, list, empty){
  const key = JSON.stringify(list.map(c => [c.id, c.ch, c.status, c.snap, c.name, c.site, c.angle, !!c.face, c.devId, c.rtspSub, !!c.manualOff]));
  if (FEED_KEYS[id] === key) return;           // same cameras => keep the running video
  FEED_KEYS[id] = key;
  document.getElementById(id).innerHTML = list.map(camCard).join('') || empty;
  syncLiveImgs(); paintInView();
}
function liveVisible(img){
  if (img.id === 'imgModalImg') return document.getElementById('imgModal').style.display === 'grid';
  if (img.closest('details:not([open])')) return false;
  const pg = img.closest('.page'); return !!(pg && pg.classList.contains('active'));
}
function syncLiveImgs(){ liveTick(); }
function setTileMsg(img, text, small){
  const m = img.parentElement && img.parentElement.querySelector('.livemsg');
  if (m) { m.textContent = text; m.style.display = text ? 'block' : 'none'; m.classList.toggle('small', !!small); }
}
async function fetchFrame(img){
  const st = img._live || (img._live = {seq:-1, last:0, ok:0, busy:false, obj:''});
  st.busy = true; st.last = Date.now();
  try {
    const r = await fetch(img.dataset.src + '&after=' + st.seq + '&t=' + Date.now(), {cache:'no-store'});
    if (r.status === 401) { location.href = '/login'; return; }
    if (r.status === 200) {
      const blob = await r.blob(), url = URL.createObjectURL(blob), old = st.obj;
      st.obj = url; img.src = url;
      if (r.headers.get('X-State') !== 'snapshot') st.ok = Date.now(); else st.snapOk = Date.now();
      st.seq = parseInt(r.headers.get('X-Seq') || '-1', 10);
      if (old) setTimeout(() => URL.revokeObjectURL(old), 2000);
      if (r.headers.get('X-State') === 'snapshot') { setTileMsg(img, 'Snapshot mode (1 picture/sec). ' + (r.headers.get('X-Error') || ''), true); setLiveBadge(img, 'snap'); }
      else { setTileMsg(img, ''); setLiveBadge(img, 'on'); }
      markTileOnline(img);
    } else if (r.status === 204) {
      const state = r.headers.get('X-State') || '', err = r.headers.get('X-Error') || '';
      if (state === 'error') { setTileMsg(img, 'No video from this camera. ' + err); setLiveBadge(img, 'off'); }
      else if (!st.ok) setTileMsg(img, 'Connecting to camera…');
      else if (Date.now() - st.ok > 8000) setTileMsg(img, 'Video paused — reconnecting…');
    } else {
      setTileMsg(img, (await r.text()).replace(/<[^>]*>/g, ' ').trim().slice(0, 200) || ('Error ' + r.status));
    }
  } catch (e) { setTileMsg(img, 'Cannot reach the IDP i server.'); }
  finally { st.busy = false; }
}
function setLiveBadge(img, state){
  const b = img.parentElement && img.parentElement.querySelector('.sd-live');
  if (b) { b.className = 'sd-live ' + state; b.innerHTML = '<i></i>' + (state === 'snap' ? 'SNAP' : state === 'off' ? 'OFFLINE' : 'LIVE'); }
}
function markTileOnline(img){
  const ch = parseInt(img.dataset.ch || '0', 10);
  const cam = cameras.find(c => c.ch === ch && c.snap && c.devId && img.dataset.src && img.dataset.src.includes('dev=' + c.devId + '&') && img.dataset.src.includes('ch=' + ch));
  if (cam && cam.manualOff) return;
  if (cam && cam.status !== 'Online') { cam.status = 'Online'; }
  const lp = document.getElementById('livePill'); if (lp && lp.textContent !== 'LIVE') { lp.textContent = 'LIVE'; lp.className = 'pill online'; }
  const pillEl = img.closest('.feed') && img.closest('.feed').querySelector('.feed-state');
  if (pillEl && !pillEl.textContent.includes('ONLINE')) pillEl.innerHTML = pill('Online');
}
function tileHasLive(ch){
  return [...document.querySelectorAll('img.live-snap[data-ch="' + ch + '"]')].some(i => i._live && Date.now() - (i._live.ok || 0) < 15000);
}
function goDirect(img){
  if (img._direct) return;
  img._direct = true;
  setTileMsg(img, 'Switching to direct video (Sudarshan mode)…', true);
  img.onload = () => { setTileMsg(img, 'Direct video', true); setLiveBadge(img, 'on'); markTileOnline(img); if (img._live) img._live.ok = Date.now(); };
  img.onerror = () => {             // direct failed too => back to the normal player (snapshot mode if possible)
    img._direct = false; img._directFailed = true; img.onload = img.onerror = null;
    if (img._live) img._live.last = 0;
    setTileMsg(img, 'Live video failed (normal + direct). Press 🩺 Diagnose above and send the result.');
  };
  img.src = img.dataset.src.replace('/api/frame', '/api/live-direct') + '&t=' + Date.now();
}
function liveTick(){
  document.querySelectorAll('img.live-snap[data-src]').forEach(img => {   // hidden page => close direct streams
    if (img._direct && !liveVisible(img)) { img._direct = false; img.onload = img.onerror = null; img.src = BLANK_IMG; img._live = null; }
  });
  const imgs = [...document.querySelectorAll('img.live-snap[data-src]')].filter(i => liveVisible(i) && !i._direct);
  const modal = document.getElementById('imgModalImg');
  const grid = imgs.filter(i => i !== modal).length;
  const every = grid <= 4 ? 120 : grid <= 9 ? 180 : 250;        // ms between frames per tile
  const now = Date.now();
  imgs.forEach(img => {
    const st = img._live || (img._live = {seq:-1, last:0, ok:0, busy:false, obj:'', start:Date.now()});
    if (!st.start) st.start = Date.now();
    if (!st.ok && !img._directFailed && Date.now() - st.start > 12000 && img !== modal) { goDirect(img); return; }
    const gap = img === modal ? 90 : every;
    if (!st.busy && now - (st.last || 0) >= gap) fetchFrame(img);
  });
}
setInterval(liveTick, 60);
function openLive(src){
  const m = document.getElementById('imgModalImg');
  m.classList.add('live-snap'); m.dataset.src = src; m._live = null; m.src = BLANK_IMG;
  document.getElementById('imgModal').style.display = 'grid';
}
async function toggleFaceAI(dev, ch, on){
  const j = await aiPost('/api/ai/camera', {dev, ch, face: !!on});
  showToast('Face AI', j.message || '', j.ok ? 'INFO' : 'WARNING');
  await loadAiStatus(); pollLiveFaces();
}
const CAT_LABEL = {known:'STAFF', vip:'VIP', watchlist:'WATCHLIST', unknown:'UNKNOWN'};
const CAT_PILL = {known:'online', vip:'warn', watchlist:'offline', unknown:''};
function paintInView(){
  document.querySelectorAll('.inview').forEach(el => {
    const ppl = (LIVE_FACES.people||[]).filter(p => p.dev === el.dataset.dev && String(p.ch) === el.dataset.ch);
    el.innerHTML = ppl.map(p => `<span class="${p.category}">${p.category==='watchlist'?'⛔ ':p.category==='vip'?'⭐ ':'🙂 '}${esc(p.name)}${p.category!=='unknown'?' '+Math.round(p.match*100)+'%':''}</span>`).join('');
  });
}
function personCard(p){
  const img = p.thumb ? `<img src="${p.thumb}" alt="">` : '<div class="noimg">🙂</div>';
  return `<div class="person ${p.category}">${img}<div style="min-width:0">
    <div><b>${esc(p.name)}</b> <span class="pill ${CAT_PILL[p.category]||''}">${CAT_LABEL[p.category]||p.category}</span></div>
    <div class="muted" style="font-size:10px">${esc(p.site)} · ${esc(p.camera||'')} (CH${p.ch})</div>
    <div class="muted" style="font-size:10px">${p.category!=='unknown'?'match '+Math.round(p.match*100)+'% · ':''}in view for ${aiAgo(p.since).replace(' ago','')}</div></div></div>`;
}
function renderLivePeople(){
  const ppl = LIVE_FACES.people || [], st = LIVE_FACES.streams || [];
  const faceCams = Math.max(st.filter(x => x.face_ai).length, ((typeof AI_STATUS !== 'undefined' && AI_STATUS && AI_STATUS.cameras) || []).filter(c => c.face).length);
  let empty = faceCams ? 'Nobody in front of the face cameras right now.' : 'No camera has Face AI on yet — press 🙂 Face AI on a camera below.';
  if (LIVE_FACES.ffmpeg === false) empty = 'ffmpeg is not installed on the server: sudo apt install ffmpeg';
  else if (LIVE_FACES.cv_ok === false) empty = 'OpenCV is not installed: sudo apt install python3-opencv python3-numpy';
  else if (LIVE_FACES.face_error) empty = LIVE_FACES.face_error;
  const html = ppl.length ? ppl.map(personCard).join('') : `<div class="muted">${esc(empty)}</div>`;
  ['livePeople','livePeopleFaces'].forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = html; });
  const pill = document.getElementById('liveFaceState');
  if (pill) { pill.textContent = faceCams ? `${faceCams} FACE CAM${faceCams>1?'S':''} · ${ppl.length} IN VIEW` : 'FACE AI OFF'; pill.className = 'pill ' + (faceCams ? 'online' : ''); }
}
async function pollLiveFaces(){
  const pg = document.querySelector('.page.active')?.id;
  if (!['cctv','overview','faces'].includes(pg)) return;
  const j = await aiGet('/api/ai/live-faces'); if (!j || !j.ok) return;
  LIVE_FACES = j; paintInView(); renderLivePeople();
}
setInterval(pollLiveFaces, 1000);

async function runDiagnose(){
  const card = document.getElementById('diagCard'), out = document.getElementById('diagOut');
  card.classList.remove('hidden');
  out.textContent = 'Testing the DVR step by step… (takes up to a minute)';
  const j = await aiPost('/api/ai/diagnose', {dev: profile.deviceId || ''});
  out.textContent = j.ok ? j.report : ('Diagnose failed: ' + (j.message || ''));
}

/* ---------- dashboard (picture layout) ---------- */
function sdAi(){ try { return AI_STATUS; } catch (e) { return null; } }
function sdType(d){ return (d && d.type === 'NVR') ? 'NVR' : 'DVR'; }
function sdDevOf(e){ return SD.devices.find(d => d.id === e.dvr_id); }
function sdTime(ts){ return ts ? new Date(ts*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—'; }
function sdTitle(t){ return String(t||'').toLowerCase().replace(/\b\w/g, m => m.toUpperCase()).replace(/\bDvr\b/g,'DVR').replace(/\bNvr\b/g,'NVR').replace(/\bVip\b/g,'VIP'); }
function sdSev(e){ return e.severity === 'CRITICAL' ? 'sos' : e.severity === 'WARNING' ? 'warn' : 'ok'; }
function sdSevText(e){ return e.severity === 'CRITICAL' ? 'SOS' : e.severity === 'WARNING' ? 'Warning' : 'Normal'; }
function sdChans(d){ return (d.detected && d.detected.length) ? d.detected : Array.from({length: d.channels || 0}, (_, i) => i + 1); }
function sdCamName(devId, ch){
  const st = sdAi(), c = st && (st.cameras || []).find(x => x.dev === devId && x.ch === ch);
  if (!c) return '';
  if (c.location) return c.location;
  return (c.name && !/^Channel \d+$/.test(c.name)) ? c.name : '';
}
function sdTile(d, ch){
  const src = `/api/frame?dev=${encodeURIComponent(d.id)}&ch=${ch}`, nm = sdCamName(d.id, ch);
  return `<div class="sd-tile" onclick="openLive('${src}')"><img class="live-snap" data-live="1" data-ch="${ch}" data-src="${src}" src="${BLANK_IMG}" alt="">`
    + `<div class="livemsg">Connecting to camera…</div><div class="inview" data-dev="${esc(d.id)}" data-ch="${ch}"></div>`
    + `<span class="sd-tlabel">${sdType(d)} - CH${ch}${nm ? ' (' + esc(nm) + ')' : ''}${SD.devices.filter(x => sdType(x) === sdType(d)).length > 1 ? ' · ' + esc(d.name || d.ip) : ''}</span>`
    + `<span class="sd-live"><i></i>LIVE</span><span class="sd-wm">CP PLUS</span></div>`;
}
function sdGroup(type, limit, wide){
  const tiles = [];
  SD.devices.filter(d => sdType(d) === type).forEach(d => sdChans(d).forEach(ch => tiles.push([d, ch])));
  const head = `<div class="sd-ghead"><span class="sd-gico ${type === 'DVR' ? 'red' : 'blue'}">${type === 'DVR' ? '🖴' : '🖧'}</span><b>${type} - Live Feed (CP Plus)</b>`
    + `<span class="muted" style="margin-left:auto;font-size:11px">${tiles.length ? Math.min(limit, tiles.length) + ' of ' + tiles.length + ' cameras' : ''}</span></div>`;
  const body = tiles.length
    ? `<div class="sd-grid${wide ? ' wide' : ''}">${tiles.slice(0, limit).map(t => sdTile(t[0], t[1])).join('')}</div>`
      + (tiles.length > limit ? `<div style="text-align:right;margin-top:6px"><button class="ghost" onclick="${wide ? "go('cctv')" : "sdSetTab('" + type + "')"}">View all ${type} cameras →</button></div>` : '')
    : `<div class="sd-empty">No ${type} added yet.<br><button onclick="go('devices')">+ Add ${type} in Devices</button></div>`;
  return `<div class="sd-group">${head}${body}</div>`;
}
function sdSetTab(t){
  SD.tab = t;
  document.querySelectorAll('.sd-tabs button[data-sdtab]').forEach(b => b.classList.toggle('active', b.dataset.sdtab === t));
  renderSdFeeds();
}
function renderSdFeeds(){
  const box = document.getElementById('sdFeeds'); if (!box) return;
  const html = SD.tab === 'live' ? `<div class="sd-split">${sdGroup('DVR', 4)}${sdGroup('NVR', 4)}</div>` : sdGroup(SD.tab, 16, true);
  if (html === SD.key) return;                  // same cameras => keep the running video
  SD.key = html; box.innerHTML = html; paintInView(); liveTick();
}
function renderSdTop(){
  const st = sdAi(), c = st && st.counts, devs = SD.devices;
  const nD = devs.filter(d => sdType(d) === 'DVR').length, nN = devs.filter(d => sdType(d) === 'NVR').length;
  const onl = devs.filter(d => d.status !== 'offline').length;
  const r = document.getElementById('sdRemote');
  if (r) { if (!devs.length) { r.className = 'sd-state warn'; r.textContent = '● No device added'; }
    else if (onl) { r.className = 'sd-state ok'; r.textContent = `● Online (${onl}/${devs.length})`; }
    else { r.className = 'sd-state bad'; r.textContent = '● Offline'; } }
  const dc = document.getElementById('sdDevCount'); if (dc) dc.textContent = `${nD} DVR · ${nN} NVR`;
  const sec = document.getElementById('sdSecurity');
  if (sec) {
    const issues = c ? (c.dvr_offline + c.cam_offline + c.cam_faulty + c.blur + c.angle + c.frozen) : 0;
    if (!devs.length) { sec.className = 'sd-state warn'; sec.textContent = '● Add a device to start'; }
    else if (issues) { sec.className = 'sd-state warn'; sec.textContent = `● ${issues} issue${issues > 1 ? 's' : ''} need attention`; }
    else { sec.className = 'sd-state ok'; sec.textContent = '● All Systems OK'; }
  }
  ['DVR', 'NVR'].forEach(t => {
    const list = devs.filter(d => sdType(d) === t), off = list.filter(d => d.status === 'offline').length;
    const el = document.getElementById('sdNav' + t);
    if (el) { el.classList.toggle('off', !!off || !list.length);
      el.innerHTML = `<span class="sd-chk">${list.length && !off ? '✓' : '!'}</span> ${t} <span class="muted">${!list.length ? 'Not added' : off ? off + ' offline' : 'Connected'}</span>`; }
    const dot = document.getElementById('sdDot' + t); if (dot) dot.classList.toggle('hidden', !off);
  });
}
function renderSdEvents(){
  const tb = document.getElementById('sdEvents'); if (!tb) return;
  const ev = SD.events.slice(-6).reverse();
  tb.innerHTML = ev.length ? ev.map(e => `<tr><td style="white-space:nowrap"><span class="sd-sevdot ${sdSev(e)}">!</span>${sdTime(e.ts)}</td>`
    + `<td>${e.dvr_id ? sdType(sdDevOf(e)) : 'System'}</td><td>${e.ch ? 'CH' + e.ch + (e.cam_location || (e.camera && !/^Channel \d+$/.test(e.camera)) ? ' (' + esc(e.cam_location || e.camera) + ')' : '') : '—'}</td>`
    + `<td>${esc(sdTitle(e.title))}</td><td><span class="sd-pill ${sdSev(e)}">${sdSevText(e)}</span></td></tr>`).join('')
    : '<tr><td colspan="5" class="muted">No events yet.</td></tr>';
}
function renderSdSos(){
  const box = document.getElementById('sdSos'); if (!box) return;
  const day = Date.now()/1000 - 86400;
  const ev = SD.events.filter(e => e.severity !== 'INFO' && e.ts > day).reverse();
  const n = ev.length;
  const cnt = document.getElementById('sdSosCount'); if (cnt) cnt.textContent = n;
  const nb = document.getElementById('sdNavSos'); if (nb) { nb.textContent = n; nb.classList.toggle('hidden', !n); }
  box.innerHTML = n ? ev.slice(0, 3).map(e => {
    const crit = e.severity === 'CRITICAL';
    const btn = crit ? `<button class="danger" onclick="go('alerts')">SOS</button>` : `<button onclick="${e.image ? `openImg(aiImg('${esc(e.image)}'))` : "go('logs')"}">View</button>`;
    return `<div class="sd-sos-item ${crit ? '' : 'warn'}"><div class="t"><span class="c">${crit ? '⛔' : '⚠'} ${esc(sdTitle(e.title))}</span><span class="muted" style="font-weight:400">${sdTime(e.ts)}</span></div>`
      + `<div class="d">${esc(e.where || e.site || '')}<br>${esc(String(e.details || '').split('\n')[0]).slice(0, 140)}</div><div class="a">${btn}</div></div>`;
  }).join('') + (n > 3 ? `<div style="text-align:right"><a style="color:#3aa0ff;font-size:12px;cursor:pointer" onclick="go('logs')">+${n - 3} more</a></div>` : '')
  : '<div class="muted">No open alerts in the last 24 hours. All good.</div>';
}
function renderSdDevices(){
  const box = document.getElementById('sdDevices'); if (!box) return;
  const st = sdAi(), cams = (st && st.cameras) || [];
  if (!SD.devices.length) { box.innerHTML = '<div class="muted">No device added yet. <a style="color:#3aa0ff;cursor:pointer" onclick="go(\'devices\')">Add one</a></div>'; return; }
  box.innerHTML = SD.devices.slice(0, 4).map(d => {
    const mine = cams.filter(c => c.dev === d.id), tot = mine.length || sdChans(d).length;
    const on = mine.length ? mine.filter(c => !c.dvr_offline && c.status !== 'offline').length : tot;
    const off = d.status === 'offline';
    return `<div class="sd-dev"><div class="logo2 sd-brand">CP PLUS</div><div><b>${sdType(d)} · ${esc(d.name || d.ip)}</b><div class="muted">IP: ${esc(d.ip)}</div>`
      + `<div>Status: <span style="color:${off ? '#ff5468' : '#2ee07e'}">● ${off ? 'Offline' : 'Online'}</span> · Channels: ${on} / ${tot}</div></div></div>`;
  }).join('') + (SD.devices.length > 4 ? `<div class="muted" style="font-size:11px">+${SD.devices.length - 4} more devices</div>` : '');
}
function renderSdHealth(){
  const box = document.getElementById('sdHealth'); if (!box) return;
  const st = sdAi(), c = st && st.counts;
  const total = c ? c.cam_total : 0, offline = c ? c.cam_offline : 0, online = Math.max(0, total - offline);
  const tamper = c ? (c.cam_faulty + c.blur + c.frozen) : 0, angle = c ? c.angle : 0;
  const R = 34, L = 2 * Math.PI * R, frac = total ? online / total : 0;
  box.innerHTML = `<svg width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="${online} of ${total} cameras online"><circle cx="48" cy="48" r="${R}" fill="none" stroke="#173d61" stroke-width="10"/>`
    + `<circle cx="48" cy="48" r="${R}" fill="none" stroke="#1fd36f" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(L * frac).toFixed(1)} ${L.toFixed(1)}" transform="rotate(-90 48 48)"/>`
    + `<text x="48" y="47" text-anchor="middle" fill="#fff" font-size="15" font-weight="700">${online}/${total}</text><text x="48" y="62" text-anchor="middle" fill="#9bb6cf" font-size="10">Online</text></svg>`
    + `<div class="sd-legend"><div><span><i style="background:#1fd36f"></i>Online</span><b>${online}</b></div><div><span><i style="background:#ff4255"></i>Offline</span><b>${offline}</b></div>`
    + `<div><span><i style="background:#ffb52e"></i>Tampered</span><b>${tamper}</b></div><div><span><i style="background:#8aa0b8"></i>Angle Changed</span><b>${angle}</b></div></div>`;
}
const SD_REPORTS = [
  {name:'Tamper Attempt Report', icon:'⚠', types:['NO_VIDEO','BLUR','FROZEN','TOO_DARK','OVEREXPOSED']},
  {name:'Camera Offline Report', icon:'📷', types:['CAMERA_OFFLINE','DVR_OFFLINE','DVR_AUTH']},
  {name:'Angle Change Report', icon:'⌖', types:['ANGLE_CHANGE']},
  {name:'People / Face Detection Report', icon:'🙂', types:['FACE_']},
  {name:'Gate Activity Report', icon:'🚪', types:['GATE_']},
  {name:'System Activity Log', icon:'🗎', types:null},
];
function sdMatch(e, types){ return !types || types.some(t => t.endsWith('_') ? String(e.type).startsWith(t) : e.type === t); }
function sdInRange(e){ return e.ts >= Date.now()/1000 - SD.range * 86400; }
function sdSetRange(n){ SD.range = n; document.querySelectorAll('.sd-tabs button[data-sdrange]').forEach(b => b.classList.toggle('active', +b.dataset.sdrange === n)); renderSdReports(); }
function renderSdReports(){
  const box = document.getElementById('sdReports'); if (!box) return;
  box.innerHTML = SD_REPORTS.map((r, i) => {
    const n = SD.events.filter(e => sdInRange(e) && sdMatch(e, r.types)).length;
    return `<div class="sd-rep"><div class="i">${r.icon}</div><div class="n">${r.name}<div>${n} event${n === 1 ? '' : 's'}</div></div><button onclick="sdDownloadReport(${i})">Download</button></div>`;
  }).join('');
}
function sdDownloadReport(i){
  const r = SD_REPORTS[i], rows = SD.events.filter(e => sdInRange(e) && sdMatch(e, r.types)).reverse();
  sdCsv(rows, r.name.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + (SD.range === 1 ? 'today' : SD.range + 'days') + '.csv');
}
function sdCsv(rows, name){
  const head = ['Time', 'Status', 'Event', 'Device', 'Site', 'Camera', 'Channel', 'Details'];
  const lines = [head].concat(rows.map(e => [e.time, sdSevText(e), sdTitle(e.title), e.dvr_id ? sdType(sdDevOf(e)) + ' ' + (e.dvr || '') : 'System', e.site || '', e.camera || '', e.ch || '', String(e.details || '').replace(/\s+/g, ' ')]));
  const csv = lines.map(r => r.map(v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"').join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['\ufeff' + csv], {type:'text/csv'}));
  a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function sdLogRows(){ const f = (document.getElementById('logFilter') || {}).value || ''; return SD.events.filter(e => !f || e.severity === f).reverse(); }
function renderLogs(){
  const tb = document.getElementById('logRows'); if (!tb) return;
  const rows = sdLogRows();
  tb.innerHTML = rows.length ? rows.map(e => `<tr><td style="white-space:nowrap">${esc(e.time)}</td><td>${e.dvr_id ? sdType(sdDevOf(e)) : 'System'}</td><td>${esc(e.site || '')}</td>`
    + `<td>${e.ch ? 'CH' + e.ch + ' ' + esc(e.camera || '') : '—'}</td><td>${esc(sdTitle(e.title))}</td><td class="muted" style="max-width:380px">${esc(String(e.details || '').split('\n')[0])}</td>`
    + `<td><span class="sd-pill ${sdSev(e)}">${sdSevText(e)}</span>${e.image ? ` <button style="font-size:10px;padding:2px 7px" onclick="openImg(aiImg('${esc(e.image)}'))">📷</button>` : ''}</td></tr>`).join('')
    : '<tr><td colspan="7" class="muted">No events yet.</td></tr>';
}
async function setDevType(id, type){
  const j = await aiPost('/api/ai/device-type', {id, type});
  showToast('Device type', j.message || '', j.ok ? 'INFO' : 'WARNING');
  await refreshDeviceList(); sdRefresh(true);
}
async function sdRefresh(force){
  const pg = document.querySelector('.page.active')?.id;
  if (!force && pg !== 'overview' && pg !== 'logs') { renderSdTopOnly(); return; }
  if (SD.busy) return; SD.busy = true;
  try {
    const [d, ev] = await Promise.all([fetch('/api/devices').then(r => r.json()).catch(() => null), aiGet('/api/ai/events?since=0')]);
    if (d && d.devices) SD.devices = d.devices;
    if (ev && ev.events) SD.events = ev.events;
  } finally { SD.busy = false; }
  renderSdTop(); renderSdFeeds(); renderSdEvents(); renderSdSos(); renderSdDevices(); renderSdHealth(); renderSdReports();
  if (pg === 'logs') renderLogs();
}
async function renderSdTopOnly(){       // keep the sidebar badges fresh on other pages
  try {
    const [d, ev] = await Promise.all([fetch('/api/devices').then(r => r.json()), aiGet('/api/ai/events?since=0')]);
    if (d && d.devices) SD.devices = d.devices; if (ev && ev.events) SD.events = ev.events;
    renderSdTop(); renderSdSos();
  } catch (e) {}
}
setInterval(sdRefresh, 5000);
setTimeout(() => sdRefresh(true), 300);


/* ---------- current user / RBAC UI ---------- */
let ME = {role: 'admin', username: ''};
async function loadMe(){
  try {
    const r = await fetch('/api/me'); const j = await r.json();
    if (j && j.ok) {
      ME = j;
      applyRoleUI();
      const el = document.getElementById('meBadge');
      if (el) el.textContent = (j.display_name || j.username || '') + ' · ' + (j.role || '');
    }
  } catch (e) {}
}
function applyRoleUI(){
  const admin = (ME.role || '') === 'admin';
  document.querySelectorAll('.admin-only').forEach(el => {
    el.style.display = admin ? '' : 'none';
  });
  if (!admin) {
    const active = document.querySelector('.page.active');
    const allowed = {overview:1, cctv:1, playback:1};
    if (active && !allowed[active.id]) go('cctv');
  }
}
let DEVICE_LIST = [], USER_ROWS = [];
function devName(id){ const d = DEVICE_LIST.find(x => x.id === id); return d ? (d.name || d.id) : id; }
function deviceCheck(cls, d){
  return `<label style="display:flex;gap:8px;align-items:center;margin:4px 0;font-size:12px"><input type="checkbox" class="${cls}" value="${esc(d.id)}" style="width:auto;margin:0"><span>${esc(d.name||d.id)}</span><span class="muted">· ${esc(d.type||'DVR')} · ${esc(d.location||'no location')}</span></label>`;
}
async function loadDevicesForUsers(){
  try { const r = await fetch('/api/devices'); const j = await r.json(); DEVICE_LIST = j.devices || []; }
  catch (e) { DEVICE_LIST = []; }
  const nb = document.getElementById('newUserDevices');
  if (nb) nb.innerHTML = DEVICE_LIST.length ? DEVICE_LIST.map(d => deviceCheck('nud', d)).join('')
                                            : '<span class="muted">No DVR/NVR registered yet. Add one in DVR Setup first.</span>';
}
async function loadUsers(){
  const tb = document.getElementById('userRows'); if (!tb) return;
  await loadDevicesForUsers();
  const r = await fetch('/api/users'); const j = await r.json();
  if (!j.ok) { tb.innerHTML = '<tr><td colspan="4" class="muted">'+(j.message||'Not allowed')+'</td></tr>'; return; }
  USER_ROWS = j.users || [];
  tb.innerHTML = USER_ROWS.map(u => `<tr>
    <td><b>${esc(u.display_name||u.username)}</b><div class="muted" style="font-size:11px">${esc(u.username)}${u.role==='admin'?' · all devices':' · devices: '+esc((u.devices||[]).map(devName).join(', ')||'none')}${u.location?' · '+esc(u.location):''}</div></td>
    <td>${u.role==='admin'?'<span class="pill warn">ADMIN</span>':'<span class="pill">VIEWER</span>'}</td>
    <td>${u.enabled===false?'<span class="pill offline">DISABLED</span>':'<span class="pill online">ACTIVE</span>'}</td>
    <td>
      <button style="font-size:10px;padding:4px 8px" onclick="pickAccount('${esc(u.username)}')">Access</button>
      <button style="font-size:10px;padding:4px 8px" onclick="toggleUser('${esc(u.username)}',${u.enabled===false})">${u.enabled===false?'Enable':'Disable'}</button>
      <button style="font-size:10px;padding:4px 8px" onclick="resetUserPass('${esc(u.username)}')">Password</button>
      <button style="font-size:10px;padding:4px 8px" onclick="deleteUser('${esc(u.username)}')">Delete</button>
    </td>
  </tr>`).join('') || '<tr><td colspan="4" class="muted">No users</td></tr>';
  refreshAccessEditor();
}
function refreshAccessEditor(){
  const sel = document.getElementById('accUser'); if (!sel) return;
  const keep = sel.value;
  sel.innerHTML = USER_ROWS.map(u => `<option value="${esc(u.username)}">${esc(u.display_name||u.username)} (${esc(u.username)})${u.role==='admin'?' · admin':''}</option>`).join('');
  if (keep && USER_ROWS.some(u => u.username === keep)) sel.value = keep;
  accUserChanged();
}
function accUserChanged(){
  const sel = document.getElementById('accUser'), box = document.getElementById('accDevices'), loc = document.getElementById('accLoc');
  if (!sel || !box) return;
  const u = USER_ROWS.find(x => x.username === sel.value);
  if (!u) { box.innerHTML = ''; return; }
  loc.value = u.location || '';
  if (u.role === 'admin') { box.innerHTML = '<span class="muted">Administrators always have access to every DVR/NVR.</span>'; return; }
  box.innerHTML = DEVICE_LIST.length ? DEVICE_LIST.map(d => deviceCheck('accdev', d)).join('')
                                     : '<span class="muted">No DVR/NVR registered yet.</span>';
  const mine = new Set(u.devices || []);
  box.querySelectorAll('.accdev').forEach(cb => { cb.checked = mine.has(cb.value); });
}
function pickAccount(un){
  const sel = document.getElementById('accUser'); if (!sel) return;
  sel.value = un; accUserChanged();
  document.getElementById('accessCard').scrollIntoView({behavior:'smooth', block:'start'});
}
async function saveAccess(){
  const un = document.getElementById('accUser').value;
  const u = USER_ROWS.find(x => x.username === un);
  const msg = document.getElementById('accMsg');
  if (!u) { msg.textContent = 'Choose an account first.'; return; }
  const body = {username: un, location: document.getElementById('accLoc').value.trim()};
  if (u.role !== 'admin') body.devices = [...document.querySelectorAll('.accdev:checked')].map(x => x.value);
  const r = await fetch('/api/users/update', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const j = await r.json(); msg.textContent = j.message || '';
  loadUsers();
}
async function createUser(){
  const body = {
    username: document.getElementById('newUserName').value.trim(),
    display_name: document.getElementById('newUserDisplay').value.trim(),
    password: document.getElementById('newUserPass').value,
    role: document.getElementById('newUserRole').value,
    location: document.getElementById('newUserLoc').value.trim(),
    devices: [...document.querySelectorAll('.nud:checked')].map(x => x.value),
  };
  const r = await fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const j = await r.json();
  document.getElementById('userMsg').textContent = j.message || '';
  if (j.ok) {
    document.getElementById('newUserPass').value='';
    document.getElementById('newUserLoc').value='';
    document.querySelectorAll('.nud:checked').forEach(x => x.checked = false);
    loadUsers();
  }
}
async function toggleUser(username, enable){
  const r = await fetch('/api/users/update', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, enabled: !!enable})});
  const j = await r.json(); alert(j.message||''); loadUsers();
}
async function resetUserPass(username){
  const pw = prompt('New password for '+username+' (min 10 characters)');
  if (!pw) return;
  const r = await fetch('/api/users/update', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, password: pw})});
  const j = await r.json(); alert(j.message||'');
}
async function deleteUser(username){
  if (!confirm('Delete user '+username+'?')) return;
  const r = await fetch('/api/users/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username})});
  const j = await r.json(); alert(j.message||''); loadUsers();
}
function pbCtl(cmd){
  const v = document.getElementById('pbPlayer'); if (!v) return;
  if (cmd==='play') v.play();
  else if (cmd==='pause') v.pause();
  else if (cmd==='back') v.currentTime = Math.max(0, v.currentTime - 10);
  else if (cmd==='fwd') v.currentTime = Math.min(v.duration||0, v.currentTime + 10);
  else if (cmd==='slow') v.playbackRate = 0.5;
  else if (cmd==='norm') v.playbackRate = 1;
  else if (cmd==='fast') v.playbackRate = 2;
}


/* ---------- boot ---------- */
updateVoiceAlertBtn();
loadAiStatus(); pollAiEvents();
setInterval(loadAiStatus, 10000);
setInterval(pollAiEvents, 4000);

function buildStatusAnswer(){ return buildStatusAnswerBase() + aiStatusLines(); }
</script></body></html>
'''


class Handler(BaseHTTPRequestHandler):
    # ---------- login session ----------
    def _session_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "idpi_session":
                return v
        return ""

    def _authed(self):
        return session_valid(self._session_token())

    def _me(self):
        return session_info(self._session_token()) or {}

    def _role(self):
        return (self._me().get("role") or "viewer")

    def _user(self):
        """The current, live account for this request (None when not signed in)."""
        return session_user(self._session_token())

    def _guard_device(self, dev_id):
        """True (and a 403 sent) when this account is not assigned to the device."""
        if device_allowed_for(self._user(), dev_id):
            return False
        self._send_bytes(403, b"This account is not assigned to that DVR/NVR.", "text/plain; charset=utf-8")
        return True

    def _require_admin(self):
        if self._role() != "admin":
            self._json(403, {"ok": False, "message": "Administrator access required."})
            return False
        return True

    def _require_role_path(self, method, path):
        if not role_allows(self._role(), method, path):
            self._json(403, {"ok": False, "message": "Your account is not allowed to use this feature."})
            return False
        return True

    def _send_bytes(self, status, body, ctype, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = min(int(self.headers.get("Content-Length", "0") or 0), 20000)
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8") or "{}")

    def _telegram_send(self, message):
        token = TELEGRAM_CONFIG.get("bot_token", "")
        chat_id = TELEGRAM_CONFIG.get("chat_id", "")
        if not token or not chat_id:
            return False, "Telegram not configured. Save bot token and chat ID first."
        url = "https://api.telegram.org/bot" + token + "/sendMessage"
        data = json.dumps({"chat_id": chat_id, "text": message, "disable_web_page_preview": True}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
            if result.get("ok"):
                return True, "Telegram alert sent. Check phone."
            return False, "Telegram rejected request. Check token and chat ID."
        except urllib.error.HTTPError as exc:
            return False, f"Telegram failed (HTTP {exc.code})."
        except Exception:
            return False, "Could not reach Telegram."

    def _build_rtsp_urls(self, ip, port, username, password, channel_list):
        streams = []
        # Credential-free URLs: the DVR/NVR username and password never leave the server.
        for ch in channel_list:
            main = f"rtsp://{ip}:{port}{RTSP_PATH_MAIN.format(ch=ch)}"
            sub = f"rtsp://{ip}:{port}{RTSP_PATH_SUB.format(ch=ch)}"
            streams.append({"ch": ch, "main": main, "sub": sub, "snap": None})
        return streams

    def _quick_tcp_check(self, ip, port, timeout=2.0):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _auth_header(self, username, password):
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": "Basic " + token}

    def _fetch_snapshot(self, ip, http_port, username, password, ch, timeout=4, rtsp_port=554, rtsp_fallback=True):
        """CP PLUS / Dahua-style snapshot (web first, then RTSP). Returns JPEG bytes or None."""
        try:
            return ai_snapshot({"id": f"{ip}:{http_port}", "ip": ip, "http_port": http_port, "port": rtsp_port,
                                "username": username, "password": password}, ch, timeout=timeout,
                               rtsp_fallback=rtsp_fallback)
        except AuthError:
            return None

    def _detect_channels(self, ip, http_port, rtsp_port, username, password, max_ch=16):
        """Find the channels that give a picture: web snapshot first, then RTSP (both in parallel)."""
        chans = list(range(1, max_ch + 1))
        with ThreadPoolExecutor(max_workers=8) as ex:
            ok = list(ex.map(lambda c: self._fetch_snapshot(ip, http_port, username, password, c, 2.5,
                                                            rtsp_port, rtsp_fallback=False), chans))
        found = [c for c, d in zip(chans, ok) if d]
        if found:
            return found, "snapshot"
        if self._quick_tcp_check(ip, rtsp_port, timeout=2) and shutil.which("ffmpeg"):
            dev = {"id": f"probe-{ip}", "ip": ip, "port": rtsp_port, "username": username, "password": password}
            with ThreadPoolExecutor(max_workers=4) as ex:
                ok = list(ex.map(lambda c: rtsp_grab(dev, c, timeout=7), chans))
            found = [c for c, d in zip(chans, ok) if d]
            if found:
                return found, "rtsp"
        return [], "none"

    def _stop_ffmpeg(self):
        global FFMPEG_PROCS
        for ch, proc in list(FFMPEG_PROCS.items()):
            try:
                proc.terminate()
            except Exception:
                pass
        FFMPEG_PROCS = {}

    def _rtsp_url_for(self, dev, ch, sub=True):
        user = urllib.parse.quote(dev.get("username") or "", safe="")
        pw = urllib.parse.quote(dev.get("password") or "", safe="")
        tpl = RTSP_PATH_SUB if sub else RTSP_PATH_MAIN
        return f"rtsp://{user}:{pw}@{dev.get('ip')}:{int(dev.get('port') or 554)}{tpl.format(ch=ch)}"

    def _serve_live_direct(self, qs):
        """Sudarshan's live code, unchanged: one ffmpeg per viewer, RTSP -> MJPEG straight to the <img>."""
        if not shutil.which("ffmpeg"):
            self.send_error(500, "ffmpeg not installed (sudo apt install ffmpeg)")
            return
        try:
            ch = int((qs.get("ch") or ["1"])[0])
        except ValueError:
            self.send_error(400, "bad channel")
            return
        dev_id = (qs.get("dev") or [ACTIVE_DEVICE_ID or ""])[0]
        dev = DEVICES.get(dev_id) if dev_id else None
        if self._guard_device(dev_id):
            return
        if not dev:
            self.send_error(400, "Unknown device")
            return
        use_main = (qs.get("sub") or ["1"])[0] == "0"
        try:
            fps = max(1, min(25, int((qs.get("fps") or ["10"])[0])))
            width = max(160, min(1920, int((qs.get("w") or ["640"])[0])))
        except ValueError:
            fps, width = 10, 640
        if len(FFMPEG_PROCS) >= MAX_LIVE_PREVIEW:
            self.send_error(503, "Too many live streams open")
            return
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "error",
            "-rtsp_transport", "tcp", "-timeout", "8000000",
            "-fflags", "nobuffer", "-flags", "low_delay",
            "-i", self._rtsp_url_for(dev, ch, sub=not use_main),
            "-an", "-vf", f"fps={fps},scale={width}:-2",
            "-c:v", "mjpeg", "-q:v", "6",
            "-f", "mpjpeg", "-boundary_tag", "sudarshan", "pipe:1",
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.send_error(500, f"ffmpeg start failed: {exc}")
            return
        key = f"live-{id(proc)}"
        FFMPEG_PROCS[key] = proc
        try:
            first = proc.stdout.read(4096)
            if not first:
                self.send_error(502, "No video from DVR (check IP, user/pass, RTSP port)")
                return
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace;boundary=sudarshan")
            self.send_header("Cache-Control", "no-store, no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(first)
            while True:
                chunk = proc.stdout.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            FFMPEG_PROCS.pop(key, None)
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

    def _serve_live_mjpeg(self, qs):
        """Shared live stream (one ffmpeg per camera for all viewers) with face boxes drawn on the video."""
        if not shutil.which("ffmpeg"):
            self.send_error(500, "ffmpeg not installed (sudo apt install ffmpeg)")
            return
        try:
            ch = int((qs.get("ch") or ["1"])[0])
        except ValueError:
            self.send_error(400, "bad channel")
            return
        dev_id = (qs.get("dev") or [ACTIVE_DEVICE_ID or ""])[0]
        dev = DEVICES.get(dev_id) if dev_id else None
        if self._guard_device(dev_id):
            return
        if not dev:
            self.send_error(400, "Unknown device")
            return
        try:
            stream = LIVE.get(dev["id"], ch)
        except RuntimeError as exc:
            self.send_error(503, str(exc))
            return
        if not stream.wait_frame(12):
            self.send_error(502, (stream.error or "No video from DVR (check IP, user/pass, RTSP port)")[:200])
            return
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace;boundary=idpi")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.end_headers()
        try:
            stream.serve(self.wfile)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # browser tab closed / page changed

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon")
            return
        if path == "/login":
            if self._authed():
                self._send_bytes(302, b"", "text/plain", {"Location": "/"})
                return
            page = SETUP_HTML if setup_pending() else LOGIN_HTML
            self._send_bytes(200, page.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/reset":
            if self._authed():
                self._send_bytes(302, b"", "text/plain", {"Location": "/"})
                return
            self._send_bytes(200, RESET_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self._authed():
            if path in ("/", "/index.html"):
                self._send_bytes(302, b"", "text/plain", {"Location": "/login"})
            else:
                self._json(401, {"ok": False, "message": "Please sign in."})
            return

        if path.startswith("/api") or path.startswith("/downloads"):
            if not self._require_role_path("GET", path):
                return

        if path.startswith("/api/ai/"):
            try:
                res = ai_api_get(path, qs, self._user())
            except Exception as exc:
                self._json(500, {"ok": False, "message": f"AI error: {exc}"})
                return
            if res is None:
                self.send_error(404)
            elif isinstance(res, tuple):
                self._send_bytes(200, res[1], res[0])
            else:
                self._json(200, res)
            return

        # Latest live frame of one camera (the dashboard polls this; short requests, so 16+
        # cameras work at once — a browser allows only ~6 long-running streams per server)
        if path == "/api/frame":
            def snap_reply(dev, ch, after, why):
                key = (dev["id"], ch)
                c = _SNAP_FRAMES.get(key)
                if not c or time.time() - c[0] >= 1.0:       # at most 1 snapshot / second / camera
                    try:
                        data = ai_snapshot(dev, ch, timeout=3, rtsp_fallback=False)
                    except AuthError:
                        data = None
                    c = _SNAP_FRAMES[key] = (time.time(), data or (c[1] if c else None),
                                             (c[2] + 1 if c else 1) if data else (c[2] if c else 0))
                hdr = {"X-Seq": str(c[2]), "X-State": "snapshot", "X-Error": re.sub(r"[^\x20-\x7e]", " ", why)[:200]}
                if c[1] is None:
                    return False
                if c[2] == after:
                    self._send_bytes(204, b"", "text/plain", hdr)
                else:
                    self._send_bytes(200, c[1], "image/jpeg", hdr)
                return True
            try:
                ch = int((qs.get("ch") or ["1"])[0])
                after = int((qs.get("after") or ["-1"])[0])
            except ValueError:
                self._send_bytes(400, b"bad channel", "text/plain")
                return
            dev_id = (qs.get("dev") or [ACTIVE_DEVICE_ID or ""])[0]
            dev = DEVICES.get(dev_id) if dev_id else None
            if self._guard_device(dev_id):
                return
            if not dev:
                self._send_bytes(404, b"This DVR is not registered any more. Add it again in DVR Setup.", "text/plain")
                return
            if not shutil.which("ffmpeg"):
                if not snap_reply(dev, ch, after, "ffmpeg is not installed - showing DVR snapshots (sudo apt install ffmpeg)"):
                    self._send_bytes(500, b"ffmpeg is not installed on the server (sudo apt install ffmpeg) and the DVR web snapshot is not answering.", "text/plain")
                return
            try:
                st = LIVE.get(dev["id"], ch)
            except RuntimeError as exc:
                if not snap_reply(dev, ch, after, str(exc)):
                    self._send_bytes(503, str(exc).encode(), "text/plain")
                return
            st.last_view = time.time()
            with st.cond:
                if st.seq == after and not st.stop_ev.is_set():
                    st.cond.wait(0.4)      # brief wait for the next frame
                seq, out = st.seq, st.out
            hdr = {"X-Seq": str(seq), "X-State": st.state,
                   "X-Error": re.sub(r"[^\x20-\x7e]", " ", st.error or "")[:200]}
            if out is None and st.state == "error" and snap_reply(dev, ch, after, "Live video failed: " + (st.error or "")):
                return
            try:
                if out is None or seq == after:
                    self._send_bytes(204, b"", "text/plain", hdr)
                else:
                    self._send_bytes(200, out, "image/jpeg", hdr)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        if path == "/api/live-direct":
            self._serve_live_direct(qs)
            return

        # Real live video (ffmpeg -> MJPEG) — for VLC / a single full-screen tab
        if path == "/api/live":
            self._serve_live_mjpeg(qs)
            return

        # Live JPEG proxy — requires device id (multi-DVR)
        if path == "/api/snapshot":
            ch = int((qs.get("ch") or ["1"])[0])
            dev_id = (qs.get("dev") or [ACTIVE_DEVICE_ID or ""])[0]
            dev = DEVICES.get(dev_id) if dev_id else None
            if self._guard_device(dev_id):
                return
            if not dev:
                self.send_error(400, "Unknown device")
                return
            try:
                data = ai_snapshot(dev, ch, timeout=4)
            except AuthError:
                data = None
            if not data:
                self.send_error(502, "No snapshot")
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/telegram-status":
            configured = bool(TELEGRAM_CONFIG.get("bot_token") and TELEGRAM_CONFIG.get("chat_id"))
            self._json(200, {"ok": True, "configured": configured, "chat_id": TELEGRAM_CONFIG.get("chat_id") or "",
                             "message": "Telegram ready (saved on disk)." if configured else "Not configured."})
            return

        if path == "/api/users":
            self._handle_users("GET", path)
            return

        if path == "/api/me":
            me = self._me()
            self._json(200, {"ok": True, "username": me.get("username"), "role": me.get("role"),
                             "display_name": me.get("display_name") or me.get("username")})
            return

        if path == "/api/devices":
            rows = []
            me_u = self._user() or {}
            for did, d in DEVICES.items():
                if not device_allowed_for(me_u, did):
                    continue
                rows.append({
                    "id": did,
                    "name": d.get("name") or d.get("ip"),
                    "ip": d.get("ip"),
                    "port": d.get("port"),
                    "http_port": d.get("http_port"),
                    "username": d.get("username") if me_u.get("role") == "admin" else None,
                    "channels": d.get("channels"),
                    "detected": d.get("detected") or [],
                    "connected": d.get("connected"),
                    "active": did == ACTIVE_DEVICE_ID,
                    "type": d.get("type") or "DVR",
                    "location": d.get("location") or "",
                    "status": AI_MON.dvr_state.get(did, "unknown"),
                })
            body = json.dumps({"ok": True, "devices": rows, "active": ACTIVE_DEVICE_ID if device_allowed_for(me_u, ACTIVE_DEVICE_ID) else None, "count": len(rows)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/export-status":
            me_u = self._user() or {}
            jid = (urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("id") or [""])[0]
            job = EXPORT_JOBS.get(jid)
            if not job or not me_u.get("id") or job["uid"] != me_u.get("id"):
                self._json(404, {"ok": False, "message": "Export not found. It may have expired; start it again."})
                return
            if not device_allowed_for(me_u, job["dev"]):
                self._json(403, {"ok": False, "message": "This DVR/NVR is no longer assigned to your account."})
                return
            self._json(200, {"ok": True, "job": _export_public(job)})
            return

        if path.startswith("/downloads/"):
            tok = path.split("/downloads/", 1)[-1]
            me_u = self._user() or {}
            with EXPORT_LOCK:
                _export_sweep_locked()
                rec = EXPORT_TOKENS.get(tok)
            if not rec or not rec["path"].is_file():
                self._send_bytes(404, b"This download link has expired or does not exist. Create the clip again.", "text/plain; charset=utf-8")
                return
            if not me_u.get("id") or rec["uid"] != me_u.get("id"):
                self._send_bytes(403, b"This download link belongs to another account.", "text/plain; charset=utf-8")
                return
            if not device_allowed_for(me_u, rec["dev"]):
                self._send_bytes(403, b"This DVR/NVR is no longer assigned to your account, so the download was refused.", "text/plain; charset=utf-8")
                return
            _send_file_ranged(self, rec["path"], rec["name"])
            return

        if path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404)

    def do_POST(self):
        global ACTIVE_DEVICE_ID, SETUP_CODE
        path = self.path.split("?")[0]

        if path == "/api/login":
            ip = self.client_address[0]
            wait = login_blocked(ip)
            if wait:
                self._json(429, {"ok": False, "message": f"Too many wrong attempts. Try again in {wait} seconds."})
                return
            try:
                data = self._read_json()
            except Exception:
                data = {}
            if setup_pending():
                self._json(409, {"ok": False, "message": "First-time setup is not finished. Open this page in the browser and create the password first."})
                return
            user = user_authenticate(data.get("username", ""), data.get("password", ""))
            if not user:
                login_failed(ip)
                print(f"[IDP i AI] failed login from {ip}")
                self._json(401, {"ok": False, "message": "Wrong login ID or password."})
                return
            LOGIN_FAILS.pop(ip, None)
            tok = session_new(user)
            body = json.dumps({
                "ok": True,
                "username": user.get("username"),
                "role": user.get("role"),
                "display_name": user.get("display_name") or user.get("username"),
            }).encode()
            self._send_bytes(200, body, "application/json; charset=utf-8", {
                "Set-Cookie": f"idpi_session={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS * 3600}"})
            print(f"[IDP i AI] login OK from {ip} user={user.get('username')} role={user.get('role')}")
            return
        # ---- first-time setup: works only while no administrator password exists yet
        if path == "/api/setup":
            ip = self.client_address[0]
            wait = login_blocked(ip)
            if wait:
                self._json(429, {"ok": False, "message": f"Too many wrong attempts. Try again in {wait} seconds."})
                return
            try:
                data = self._read_json()
            except Exception:
                data = {}
            pw = str(data.get("password", ""))
            confirm = str(data.get("confirm", ""))
            with USERS_LOCK:
                admin = next((u for u in USERS.values() if u.get("setup_pending")), None)
                if not admin:
                    self._json(403, {"ok": False, "message": "Setup is already complete. Sign in instead."})
                    return
                if not SETUP_CODE or not _same(_norm_code(data.get("code")), _norm_code(SETUP_CODE)):
                    login_failed(ip)
                    self._json(401, {"ok": False, "message": "The setup code is wrong. It is printed on the IDP i server console when it starts."})
                    return
                if pw != confirm:
                    self._json(400, {"ok": False, "message": "The two passwords do not match."})
                    return
                prob = _password_problem(pw)
                if prob:
                    self._json(400, {"ok": False, "message": prob})
                    return
                admin["password"] = _hash_password(pw)
                admin.pop("setup_pending", None)
                SETUP_CODE = None
                uname = admin["username"]
            LOGIN_FAILS.pop(ip, None)
            users_save()
            audit("setup.complete", uname, ip, "administrator password created")
            self._json(200, {"ok": True, "message": "Password created. Sign in with it now."})
            return

        # ---- password reset: a one-time code shown on the server console proves who is asking
        if path == "/api/reset/request":
            ip = self.client_address[0]
            if not rate_ok("reset-request:" + ip, 5, 600):
                self._json(429, {"ok": False, "message": "Too many reset requests. Wait ten minutes and try again."})
                return
            try:
                data = self._read_json()
            except Exception:
                data = {}
            username = str(data.get("username", "")).strip()
            with USERS_LOCK:
                u = USERS.get(username)
                eligible = bool(u) and u.get("enabled", True) and not u.get("setup_pending")
            if eligible:
                code = _new_code()
                with RESET_LOCK:
                    RESET_CODES[username] = {"hash": _sha(_norm_code(code)), "exp": time.time() + RESET_TTL, "tries": 0}
                print(f"[IDP i AI] PASSWORD RESET CODE for '{username}': {code}  (valid 10 minutes, one use)", flush=True)
                audit("password.reset_requested", username, ip, "code shown on server console")
            # Same answer whether or not the account exists, so the page cannot be used to find accounts.
            self._json(200, {"ok": True, "message": "If that account exists, a reset code has been shown on the IDP i server console (or in its service log). Enter it below. It expires in 10 minutes."})
            return
        if path == "/api/reset/confirm":
            ip = self.client_address[0]
            if not rate_ok("reset-confirm:" + ip, 20, 600):
                self._json(429, {"ok": False, "message": "Too many attempts. Wait ten minutes and try again."})
                return
            try:
                data = self._read_json()
            except Exception:
                data = {}
            username = str(data.get("username", "")).strip()
            pw = str(data.get("password", ""))
            confirm = str(data.get("confirm", ""))
            with RESET_LOCK:
                rec = RESET_CODES.get(username)
                if not rec or rec["exp"] < time.time():
                    RESET_CODES.pop(username, None)
                    self._json(400, {"ok": False, "message": "This reset code has expired or was never requested. Ask for a new code."})
                    return
                if not _same(_sha(_norm_code(data.get("code"))), rec["hash"]):
                    rec["tries"] += 1
                    if rec["tries"] >= RESET_MAX_TRIES:
                        RESET_CODES.pop(username, None)
                        msg = "Too many wrong codes. Ask for a new code."
                    else:
                        msg = f"The reset code is wrong. {RESET_MAX_TRIES - rec['tries']} tries left."
                    self._json(401, {"ok": False, "message": msg})
                    return
                if pw != confirm:
                    self._json(400, {"ok": False, "message": "The two passwords do not match."})
                    return
                prob = _password_problem(pw)
                if prob:
                    self._json(400, {"ok": False, "message": prob})
                    return
                RESET_CODES.pop(username, None)          # single use: consumed only on success
            with USERS_LOCK:
                u = USERS.get(username)
                if not u:
                    self._json(400, {"ok": False, "message": "Account not found."})
                    return
                u["password"] = _hash_password(pw)
            kill_user_sessions(username)                 # every existing session of the account ends
            users_save()
            audit("password.reset", username, ip, "password reset with reset code")
            self._json(200, {"ok": True, "message": "Password changed. Sign in with the new password."})
            return
        if path == "/api/logout":
            session_end(self._session_token())
            self._send_bytes(200, b'{"ok": true}', "application/json", {
                "Set-Cookie": "idpi_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            return
        if not self._authed():
            self._json(401, {"ok": False, "message": "Please sign in."})
            return

        if path.startswith("/api"):
            if not self._require_role_path("POST", path):
                return

        if path.startswith("/api/ai/"):
            try:
                length = min(int(self.headers.get("Content-Length", "0") or 0), 15 * 1024 * 1024)
                data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except Exception:
                self._json(400, {"ok": False, "message": "Invalid request."})
                return
            try:
                self._json(200, ai_api_post(path, data))
            except ValueError as exc:
                self._json(400, {"ok": False, "message": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "message": f"AI error: {exc}"})
            return
        if path in ("/api/users", "/api/users/update", "/api/users/delete"):
            try:
                data = self._read_json()
            except Exception:
                data = {}
            self._handle_users("POST", path, data)
            return

        if path not in (
            "/api/telegram-config", "/api/telegram-test", "/api/notify",
            "/api/connect-rtsp", "/api/detect-channels",
            "/api/device-select", "/api/device-remove",
            "/api/playback-url", "/api/playback-export", "/api/export-cancel", "/api/telegram-status",
        ):
            self._json(404, {"ok": False, "message": "Unknown endpoint."})
            return
        try:
            data = self._read_json()
        except Exception:
            self._json(400, {"ok": False, "message": "Invalid request."})
            return

        if path == "/api/telegram-status":
            configured = bool(TELEGRAM_CONFIG.get("bot_token") and TELEGRAM_CONFIG.get("chat_id"))
            self._json(200, {
                "ok": True,
                "configured": configured,
                "chat_id": TELEGRAM_CONFIG.get("chat_id") or "",
                "message": "Telegram ready (saved on disk)." if configured else "Not configured.",
            })
            return

        if path == "/api/telegram-config":
            token = str(data.get("bot_token", "")).strip()
            chat_id = str(data.get("chat_id", "")).strip()
            if not token or not chat_id or len(token) > 300 or len(chat_id) > 100:
                self._json(400, {"ok": False, "message": "Valid bot token and chat ID required."})
                return
            TELEGRAM_CONFIG["bot_token"] = token
            TELEGRAM_CONFIG["chat_id"] = chat_id
            save_config()
            self._json(200, {"ok": True, "message": "Saved permanently on this PC. Alerts will keep working after restart."})
            return

        if path == "/api/telegram-test":
            ok, msg = self._telegram_send(
                "IDP i AI TEST\nCP-UVR-1601E2-I notifications OK.\nAI monitor active."
            )
            self._json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        if path == "/api/notify":
            severity = str(data.get("severity", "INFO")).upper()
            if severity not in ("WARNING", "CRITICAL"):
                self._json(200, {"ok": True, "message": "No phone alert for this severity."})
                return
            fields = [
                ("IDP i AI SECURITY ALERT",),
                ("Model", "CP-UVR-1601E2-I"),
                ("Event", str(data.get("id", ""))),
                ("Type", str(data.get("type", ""))),
                ("Severity", severity),
                ("Details", str(data.get("title", ""))),
                ("Location", str(data.get("site", ""))),
                ("Time", str(data.get("time", ""))),
            ]
            message = "\n".join(x[0] if len(x) == 1 else f"{x[0]}: {x[1]}" for x in fields)
            ok, msg = self._telegram_send(message[:3500])
            self._json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        if path == "/api/detect-channels":
            ip = str(data.get("ip", "")).strip()
            port = int(data.get("port") or 554)
            http_port = int(data.get("http_port") or 80)
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            max_ch = max(1, min(16, int(data.get("max_ch") or 16)))
            if not ip or not username or not password:
                self._json(400, {"ok": False, "message": "IP, username and password required."})
                return
            found, method = self._detect_channels(ip, http_port, port, username, password, max_ch)
            self._json(200, {
                "ok": True,
                "channels": found,
                "count": len(found),
                "method": method,
                "message": (
                    f"Detected {len(found)} channel(s) via {method}: {found}"
                    if found else
                    "No channels detected. Check IP, HTTP port (80), username/password, and that DVR web is enabled."
                ),
            })
            return

        if path == "/api/device-select":
            did = str(data.get("id", "")).strip()
            if not device_allowed_for(self._user(), did):
                self._json(403, {"ok": False, "message": "This account is not assigned to that DVR/NVR."})
                return
            if did not in DEVICES:
                self._json(404, {"ok": False, "message": "Device not found."})
                return
            ACTIVE_DEVICE_ID = did
            save_config()
            dev = DEVICES[did]
            chans = dev.get("detected") or list(range(1, int(dev.get("channels") or 4) + 1))
            streams = self._build_rtsp_urls(dev["ip"], int(dev.get("port") or 554), dev.get("username") or "", dev.get("password") or "", chans)
            for s in streams:
                s["snap"] = f"/api/snapshot?dev={did}&ch={s['ch']}"
            dev["rtsp_urls"] = streams
            self._json(200, {
                "ok": True,
                "active": did,
                "message": "Active device set.",
                "device_id": did,
                "detected": chans,
                "streams": streams,
                "http_up": self._quick_tcp_check(dev["ip"], int(dev.get("http_port") or 80)),
            })
            return

        if path == "/api/device-remove":
            did = str(data.get("id", "")).strip()
            if did in DEVICES:
                DEVICES.pop(did, None)
                with USERS_LOCK:
                    for _u in USERS.values():
                        _u["devices"] = [x for x in (_u.get("devices") or []) if x != did]
                users_save()
                audit("device.remove", self._me().get("username"), did)
                LIVE.stop(did)
                if ACTIVE_DEVICE_ID == did:
                    ACTIVE_DEVICE_ID = next(iter(DEVICES), None)
            save_config()
            self._json(200, {"ok": True, "count": len(DEVICES), "active": ACTIVE_DEVICE_ID})
            return

        if path == "/api/connect-rtsp":
            ip = str(data.get("ip", "")).strip()
            port = int(data.get("port") or 554)
            http_port = int(data.get("http_port") or 80)
            username = str(data.get("username", "")).strip()
            password = str(data.get("password", ""))
            name = str(data.get("name", "")).strip() or ip
            dtype = "NVR" if str(data.get("device_type") or "DVR").upper() == "NVR" else "DVR"
            auto = bool(data.get("auto_detect", True))
            channels_req = max(1, min(16, int(data.get("channels") or 16)))
            if not ip or not username or not password:
                self._json(400, {"ok": False, "message": "IP, username and password required."})
                return
            if len(DEVICES) >= MAX_DEVICES:
                self._json(400, {"ok": False, "message": f"Device limit reached ({MAX_DEVICES}). Remove unused DVRs first."})
                return

            # Reuse existing device with same IP if present
            existing_id = None
            for did, d in DEVICES.items():
                if d.get("ip") == ip and int(d.get("port") or 554) == port:
                    existing_id = did
                    break
            dev_id = existing_id or _new_device_id()

            reachable = self._quick_tcp_check(ip, port)
            http_up = self._quick_tcp_check(ip, http_port)

            if auto:
                found, method = self._detect_channels(ip, http_port, port, username, password, 16)
                channel_list = found if found else list(range(1, channels_req + 1))
            else:
                channel_list = list(range(1, channels_req + 1))
                method = "manual"

            streams = self._build_rtsp_urls(ip, port, username, password, channel_list)
            for s in streams:
                s["snap"] = f"/api/snapshot?dev={dev_id}&ch={s['ch']}"

            old_loc = (DEVICES.get(dev_id) or {}).get("location", "")
            DEVICES[dev_id] = {
                "id": dev_id,
                "location": old_loc,
                "name": name,
                "type": dtype,
                "mode": "rtsp",
                "ip": ip,
                "port": port,
                "http_port": http_port,
                "username": username,
                "password": password,
                "channels": len(channel_list),
                "connected": True,
                "detected": channel_list,
                "last_error": "" if reachable else f"TCP {ip}:{port} not reachable.",
                "rtsp_urls": streams,
            }
            ACTIVE_DEVICE_ID = dev_id
            save_config()
            LIVE.stop(dev_id)             # new IP / password => reopen live streams with the new details
            AI_MON.wake["dvr"].set()      # AI checks the new DVR and its cameras right away
            AI_MON.wake["health"].set()

            msg = (
                f"Device saved ({len(DEVICES)} total). {name} @ {ip}. Channels: {channel_list} ({method}). "
                + ("RTSP OK. " if reachable else "RTSP port issue. ")
                + ("HTTP OK — live snapshots on." if http_up else "HTTP closed — enable DVR web for live preview.")
            )
            self._json(200, {
                "ok": True,
                "message": msg,
                "device_id": dev_id,
                "device_count": len(DEVICES),
                "reachable": reachable,
                "http_up": http_up,
                "detected": channel_list,
                "method": method,
                "streams": streams,
            })
            return


        if path == "/api/playback-url":
            me_u = self._user() or {}
            did = pick_device(me_u, data.get("dev"))
            if not did or did not in DEVICES or not device_allowed_for(me_u, did):
                self._json(403, {"ok": False, "message": "This DVR/NVR is not assigned to your account."})
                return
            start = str(data.get("start", "")).strip()
            end = str(data.get("end", "")).strip()
            if not start or not end:
                self._json(400, {"ok": False, "message": "Start and end time required (YYYY_MM_DD_HH_MM_SS)."})
                return
            if not (re.fullmatch(r"\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}", start) and re.fullmatch(r"\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}", end)):
                self._json(400, {"ok": False, "message": "Time must look like YYYY_MM_DD_HH_MM_SS."})
                return
            # The DVR/NVR login stays on the server. Recordings are delivered by Download MP4 only.
            self._json(200, {"ok": True, "message": "Recording request accepted. Use Download MP4 to save it; the device login stays on the server."})
            return

        if path == "/api/playback-export":
            me_u = self._user() or {}
            did = pick_device(me_u, data.get("dev"))
            if not did or did not in DEVICES or not device_allowed_for(me_u, did):
                self._json(403, {"ok": False, "message": "This DVR/NVR is not assigned to your account."})
                return
            if not shutil.which("ffmpeg"):
                self._json(400, {"ok": False, "message": "ffmpeg not found on this computer. Install ffmpeg to export clips."})
                return
            status, payload = _export_start(me_u, did, data)
            self._json(status, payload)
            return

        if path == "/api/export-cancel":
            me_u = self._user() or {}
            job = EXPORT_JOBS.get(str(data.get("job_id") or ""))
            if not job or not me_u.get("id") or job["uid"] != me_u.get("id"):
                self._json(404, {"ok": False, "message": "Export not found."})
                return
            if job["state"] in ("done", "error", "cancelled"):
                self._json(200, {"ok": True, "message": "This export has already finished."})
                return
            job["_cancel"] = True
            proc = job.get("_proc")
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            self._json(200, {"ok": True, "message": "Cancelling export…"})
            return

    def _handle_users(self, method, path, data=None):

        """Admin-only user management."""
        if not self._require_admin():
            return
        if method == "GET" and path == "/api/users":
            with USERS_LOCK:
                rows = [{k: v for k, v in u.items() if k != "password"} for u in USERS.values()]
            rows.sort(key=lambda x: (0 if x.get("role") == "admin" else 1, x.get("username") or ""))
            self._json(200, {"ok": True, "users": rows})
            return
        if method == "POST" and path == "/api/users":
            data = data or {}
            un = str(data.get("username") or "").strip()
            pw = str(data.get("password") or "")
            role = "admin" if str(data.get("role") or "").lower() == "admin" else "viewer"
            dn = str(data.get("display_name") or un).strip()[:80]
            if not un or len(un) < 2 or len(un) > 40:
                self._json(400, {"ok": False, "message": "Username must be 2–40 characters."})
                return
            if not re.match(r"^[\w.@+-]+$", un):
                self._json(400, {"ok": False, "message": "Username has invalid characters."})
                return
            if _password_problem(pw):
                self._json(400, {"ok": False, "message": _password_problem(pw)})
                return
            with USERS_LOCK:
                if un in USERS:
                    self._json(400, {"ok": False, "message": "Username already exists."})
                    return
                USERS[un] = {
                    "id": "u-" + uuid.uuid4().hex[:10],
                    "username": un,
                    "password": _hash_password(pw),
                    "role": role,
                    "enabled": True,
                    "created": time.time(),
                    "display_name": dn or un,
                    "location": str(data.get("location") or "").strip()[:80],
                    "devices": [] if role == "admin" else _valid_device_ids(data.get("devices")),
                }
            users_save()
            audit("user.create", self._me().get("username"), un,
                  f"role={role} devices={','.join(_valid_device_ids(data.get('devices')) if role != 'admin' else [])}")
            self._json(200, {"ok": True, "message": f"User {un} created ({role})."})
            return
        if method == "POST" and path == "/api/users/update":
            data = data or {}
            un = str(data.get("username") or "").strip()
            with USERS_LOCK:
                u = USERS.get(un)
                if not u:
                    self._json(404, {"ok": False, "message": "User not found."})
                    return
                if "devices" in data:
                    u["devices"] = [] if u.get("role") == "admin" else _valid_device_ids(data.get("devices"))
                if "location" in data:
                    u["location"] = str(data.get("location") or "").strip()[:80]
                if "display_name" in data:
                    u["display_name"] = str(data.get("display_name") or un).strip()[:80]
                if "role" in data:
                    role = "admin" if str(data.get("role") or "").lower() == "admin" else "viewer"
                    # keep at least one admin
                    if u.get("role") == "admin" and role != "admin":
                        admins = sum(1 for x in USERS.values() if x.get("role") == "admin" and x.get("enabled", True))
                        if admins <= 1:
                            self._json(400, {"ok": False, "message": "Cannot demote the last administrator."})
                            return
                    u["role"] = role
                if "enabled" in data:
                    en = bool(data.get("enabled"))
                    if u.get("role") == "admin" and not en:
                        admins = sum(1 for x in USERS.values() if x.get("role") == "admin" and x.get("enabled", True) and x.get("username") != un)
                        if admins < 1:
                            self._json(400, {"ok": False, "message": "Cannot disable the last administrator."})
                            return
                    u["enabled"] = en
                if data.get("password"):
                    pw = str(data.get("password"))
                    if _password_problem(pw):
                        self._json(400, {"ok": False, "message": _password_problem(pw)})
                        return
                    u["password"] = _hash_password(pw)
            if ("enabled" in data and not data.get("enabled")) or data.get("password"):
                kill_user_sessions(un)
            users_save()
            changed = sorted(k for k in data if k not in ("username", "password"))
            audit("user.update", self._me().get("username"), un,
                  ",".join(changed) + (" +password" if data.get("password") else ""))
            self._json(200, {"ok": True, "message": "User updated."})
            return
        if method == "POST" and path == "/api/users/delete":
            data = data or {}
            un = str(data.get("username") or "").strip()
            with USERS_LOCK:
                u = USERS.get(un)
                if not u:
                    self._json(404, {"ok": False, "message": "User not found."})
                    return
                if u.get("role") == "admin":
                    admins = sum(1 for x in USERS.values() if x.get("role") == "admin" and x.get("enabled", True))
                    if admins <= 1:
                        self._json(400, {"ok": False, "message": "Cannot delete the last administrator."})
                        return
                USERS.pop(un, None)
            kill_user_sessions(un)
            users_save()
            audit("user.delete", self._me().get("username"), un)
            self._json(200, {"ok": True, "message": "User deleted."})
            return
        self._json(404, {"ok": False, "message": "Unknown users endpoint."})


    def log_message(self, fmt, *args):
        print("[IDP i AI] " + (fmt % args))


def play_ffplay(ip, username, password, channel=1, port=554, main=False):
    """Play the live feed directly in a desktop window with ffplay (lowest latency)."""
    if not shutil.which("ffplay"):
        raise SystemExit("ffplay not found: sudo apt install ffmpeg")
    dev = {"ip": ip, "port": port, "username": username, "password": password}
    url = Handler._rtsp_url_for(None, dev, channel, sub=not main)
    cmd = ["ffplay", "-hide_banner", "-loglevel", "warning",
           "-rtsp_transport", "tcp", "-fflags", "nobuffer", "-flags", "low_delay",
           "-framedrop", "-window_title", f"IDP i CH{channel}", url]
    return subprocess.call(cmd)


def run_server(host=HOST, port=PORT, block=True):
    """Start the IDP i server.

    host  : "127.0.0.1" (this machine only) or "0.0.0.0" (whole LAN)
    port  : default 8765
    block : True  -> runs until Ctrl+C
            False -> starts in a background thread and returns the server object
    """
    print()
    print("=" * 60)
    print("  IDP i AI · CP-UVR-1601E2-I")
    print("=" * 60)
    print(f"  Open: http://{host}:{port}")
    print("  AI: continuous monitor + auto message fill + help chat")
    print("  Live: Local RTSP -> VLC")
    print("=" * 60)
    print()
    if setup_pending():
        print("  FIRST START: create the administrator password in the browser.")
        print(f"  Setup code: {SETUP_CODE}   (asked for on the setup screen; a new code is made on each start until setup is done)")
    else:
        print(f"  Login ID: {LOGIN_ID} · password: set (stored as a scrypt hash). Forgot it? Use the Forgot password link.")
    print(f"  24/7 AI engine: ON · OpenCV AI (blur/angle/gate/face): {'ON' if CV_OK else 'OFF — sudo apt install python3-opencv python3-numpy'}")
    print(f"  Telegram: {'ON' if TELEGRAM_CONFIG.get('bot_token') and TELEGRAM_CONFIG.get('chat_id') else 'OFF — set it on the Alerts & SOS page'}")
    print()
    AI_MON.start()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    if not block:
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nIDP i AI stopped.")
        ai_save()
    finally:
        server.server_close()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="IDP i DVR monitoring")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--play", metavar="DVR_IP", help="watch live in an ffplay window without the web UI")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="")
    ap.add_argument("--ch", type=int, default=1)
    ap.add_argument("--rtsp-port", type=int, default=554)
    ap.add_argument("--main", action="store_true", help="use the main (HD) stream instead of the sub stream")
    ap.add_argument("--diagnose", metavar="DVR_IP", help="test live video from this DVR and print the result")
    ap.add_argument("--http-port", type=int, default=80)
    a = ap.parse_args()
    if a.diagnose:
        dev = {"id": "diag", "name": "DVR", "ip": a.diagnose, "port": a.rtsp_port, "http_port": a.http_port,
               "username": a.user, "password": a.password}
        print("\n".join(["", "=== IDP i DIAGNOSE ==="] + run_diagnose(dev, a.ch) + [""]))
        return
    if a.play:
        play_ffplay(a.play, a.user, a.password, a.ch, a.rtsp_port, a.main)
        return
    run_server(a.host, a.port)


if __name__ == "__main__":
    main()
