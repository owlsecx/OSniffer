#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ═══════════════════════════════════════════════════════════════════════════════
#
#   ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
#  ██╔═══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
#  ██║   ██║███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
#  ██║   ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
#  ╚██████╔╝███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
#   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
#
#   Defensive Network Monitor — Professional Edition
#   DNS · HTTP · HTTPS/TLS · SSH · FTP · SMTP · DHCP · ARP
#   ICMP · MDNS · NBNS · SSDP · Scan Detection · GeoIP
#   SQLite Sessions · HTML Reports · Encrypted Exports
#
#   Developer : khaled.s.haddad
#   Website   : owlsec.org
#   Version   : v1.0 — Debian OS Edition
#   Year      : 2026
#
#   LEGAL NOTICE:
#   For EDUCATIONAL and AUTHORIZED security analysis ONLY.
#   Does NOT extract credentials, passwords, or payload content.
#   Focuses exclusively on metadata and defensive telemetry.
#
# ═══════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import base64
import csv
import fcntl
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import queue
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import Counter, defaultdict, deque
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

# ── Optional: scapy ──────────────────────────────────────────────────────────
try:
    import scapy.all as scapy
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

try:
    from scapy.layers import http as scapy_http
    HAS_HTTP = True
except Exception:
    HAS_HTTP = False

try:
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
    HAS_TLS = True
except Exception:
    HAS_TLS = False

# ── Optional: cryptography ────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# ── Version ───────────────────────────────────────────────────────────────────
VERSION   = "1.0"
CODENAME  = "OwlEye"
APP_NAME  = "OSniffer"
DEVELOPER = "khaled.s.haddad"
WEBSITE   = "owlsec.org"

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(os.environ.get("OSNIFFER_HOME", Path.home() / ".osniffer"))
DB_FILE      = BASE_DIR / "osniffer.db"
LOG_FILE     = BASE_DIR / "osniffer.log"
EXPORT_DIR   = BASE_DIR / "exports"
CONFIG_FILE  = BASE_DIR / "config.json"
LOCK_FILE    = BASE_DIR / "osniffer.lock"

# ─── COLORS ──────────────────────────────────────────────────────────────────
class C:
    RED      = "\033[91m"
    GREEN    = "\033[92m"
    YELLOW   = "\033[93m"
    CYAN     = "\033[96m"
    WHITE    = "\033[97m"
    BOLD     = "\033[1m"
    RESET    = "\033[0m"
    MAGENTA  = "\033[95m"
    BLUE     = "\033[94m"
    DIM      = "\033[2m"
    ORANGE   = "\033[38;5;208m"
    GRAY     = "\033[90m"
    UNDERLINE= "\033[4m"
    BG_RED   = "\033[41m"
    BG_DARK  = "\033[40m"

_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()

def color(text: Any, clr: str) -> str:
    if _NO_COLOR:
        return str(text)
    return f"{clr}{text}{C.RESET}"

def cprint(text: str, clr: str = C.WHITE, end: str = "\n") -> None:
    print(color(text, clr), end=end)

def term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80

def hline(char: str = "─", clr: str = C.CYAN) -> None:
    cprint(char * min(term_width(), 80), clr)

# ─── PROTOCOL TAGS ────────────────────────────────────────────────────────────
PROTO_CLR = {
    "dns":     C.CYAN,
    "http":    C.GREEN,
    "https":   C.GREEN + C.BOLD,
    "tls":     C.MAGENTA,
    "ssh":     C.YELLOW,
    "ftp":     C.ORANGE,
    "smtp":    C.BLUE,
    "dhcp":    C.WHITE,
    "arp":     C.CYAN + C.BOLD,
    "icmp":    C.BLUE,
    "mdns":    C.CYAN,
    "nbns":    C.CYAN,
    "ssdp":    C.WHITE,
    "anomaly": C.RED + C.BOLD,
    "scan":    C.RED + C.BOLD,
    "flood":   C.RED + C.BOLD,
    "alert":   C.RED + C.BOLD,
}

def proto_color(ptype: str) -> str:
    return PROTO_CLR.get(ptype.lower(), C.WHITE)

def proto_tag(ptype: str) -> str:
    return color(f"[{ptype.upper().ljust(7)}]", proto_color(ptype))

# ─── BANNER ───────────────────────────────────────────────────────────────────
BANNER_ART = r"""
   ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ██╔═══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ██║   ██║███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ██║   ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ╚██████╔╝███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
"""

def banner(compact: bool = False) -> None:
    if not compact:
        cprint(BANNER_ART, C.CYAN)
    cprint(f"  Defensive Network Monitor  v{VERSION} — {CODENAME}", C.MAGENTA + C.BOLD)
    cprint("  DNS · HTTP · TLS · SSH · FTP · SMTP · DHCP · ARP · ICMP · Scan Detection", C.WHITE)
    print()
    print(
        color("  Developer : ", C.DIM + C.WHITE) + color(DEVELOPER, C.CYAN) +
        color("   |   Website : ", C.DIM + C.WHITE) + color(WEBSITE, C.CYAN)
    )
    if not HAVE_SCAPY:
        print()
        warn("scapy not installed — run: pip install scapy")
    hline()
    print()

# ─── UI HELPERS ───────────────────────────────────────────────────────────────
def clear_screen() -> None:
    os.system("clear")

def pause() -> None:
    try:
        input(color("\n  [↩] Press Enter to continue...", C.YELLOW))
    except (EOFError, KeyboardInterrupt):
        pass

def print_header(title: str) -> None:
    print()
    hline()
    cprint(f"  {title}", C.BOLD + C.CYAN)
    hline()

def section(title: str) -> None:
    print()
    cprint(f"  ┌─ {title}", C.YELLOW + C.BOLD)

def row(key: str, val: Any, width: int = 24, val_color: str = C.WHITE) -> None:
    pad = width - len(str(key))
    print(f"  {color('│', C.YELLOW)}  {color(str(key) + ':' + ' ' * max(pad, 1), C.CYAN)}{color(str(val), val_color)}")

def ok(msg: str) -> None:
    print(f"  {color('[✔]', C.GREEN)}  {color(msg, C.WHITE)}")

def err(msg: str) -> None:
    print(f"  {color('[✘]', C.RED)}  {color(msg, C.RED)}")

def warn(msg: str) -> None:
    print(f"  {color('[!]', C.ORANGE)}  {color(msg, C.YELLOW)}")

def nfo(msg: str) -> None:
    print(f"  {color('[*]', C.CYAN)}  {color(msg, C.DIM + C.WHITE)}")

def alert_line(msg: str, lvl: str = "HIGH") -> None:
    clr_map = {"HIGH": C.RED, "MED": C.ORANGE, "LOW": C.YELLOW, "INFO": C.CYAN}
    clr = clr_map.get(lvl.upper(), C.RED)
    print(f"  {color('[!!!]', clr + C.BOLD)}  {color(msg, C.WHITE)}")

# ─── TIMESTAMPS ───────────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def elapsed_str(since: float) -> str:
    s = time.monotonic() - since
    if s < 60:
        return f"{s:.0f}s"
    m = int(s // 60)
    return f"{m}m {int(s % 60)}s"

# ─── LOGGING ─────────────────────────────────────────────────────────────────
def setup_logging(verbose: bool = False) -> logging.Logger:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("OSniffer")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)
    if verbose:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter("  [%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S"))
        logger.addHandler(ch)
    return logger

log = logging.getLogger("OSniffer")

# ─── PRIVILEGE / INTERFACE ────────────────────────────────────────────────────
def require_root(action: str = "packet capture") -> None:
    if os.name != "nt":
        try:
            if os.geteuid() != 0:
                err(f"Root is required for {action}.")
                cprint(f"  [»] Re-run with: sudo osniffer", C.YELLOW)
                sys.exit(1)
        except AttributeError:
            pass

def interface_exists(iface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{iface}")

def list_interfaces() -> List[dict]:
    ifaces = []
    base = Path("/sys/class/net")
    if not base.exists():
        return ifaces
    for name in sorted(base.iterdir()):
        info: dict = {"name": name.name, "ip": "", "mac": "", "state": ""}
        # IP
        try:
            r = subprocess.run(
                ["ip", "-4", "addr", "show", name.name],
                capture_output=True, text=True, timeout=2
            )
            m = re.search(r"inet (\S+)", r.stdout)
            if m:
                info["ip"] = m.group(1)
            ms = re.search(r"state (\S+)", r.stdout)
            if ms:
                info["state"] = ms.group(1)
        except Exception:
            pass
        # MAC
        mac_file = name / "address"
        if mac_file.exists():
            info["mac"] = mac_file.read_text().strip()
        ifaces.append(info)
    return ifaces

def get_interface_stats(iface: str) -> dict:
    stats = {}
    base = Path(f"/sys/class/net/{iface}/statistics")
    if not base.exists():
        return stats
    for f in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
              "rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
        p = base / f
        if p.exists():
            try:
                stats[f] = int(p.read_text().strip())
            except Exception:
                stats[f] = 0
    return stats

# ─── BPF / FILTER ────────────────────────────────────────────────────────────
def sanitize_bpf(bpf: str) -> str:
    if not bpf:
        return ""
    if len(bpf) > 512:
        raise ValueError("BPF too long (max 512 chars).")
    if any(x in bpf for x in [";", "`", "$", "\n", "\r", "\\"]):
        raise ValueError("BPF contains illegal characters.")
    if not re.fullmatch(r"[A-Za-z0-9\s\(\)\.\:\/\-\_\=\<\>\!\&\|\+\*\?\"\'\,]+", bpf):
        raise ValueError("BPF contains unsupported characters.")
    return bpf.strip()

def build_bpf_filter(cfg) -> str:
    parts = []
    if getattr(cfg, "http_only", False):    parts.append("tcp port 80")
    if getattr(cfg, "dns_only",  False):    parts.append("udp port 53")
    if getattr(cfg, "tls_only",  False):    parts.append("(tcp port 443 or tcp port 8443)")
    if getattr(cfg, "arp_only",  False):    parts.append("arp")
    if getattr(cfg, "icmp_only", False):    parts.append("icmp")
    if getattr(cfg, "port", None):
        ports = []
        for x in cfg.port:
            if not str(x).isdigit():
                raise ValueError("Port must be numeric.")
            px = int(x)
            if not (1 <= px <= 65535):
                raise ValueError(f"Port out of range: {px}")
            ports.append(px)
        parts.append("(" + " or ".join(f"port {p}" for p in ports) + ")")
    if getattr(cfg, "host", None):
        h = cfg.host
        if len(h) > 253 or not re.fullmatch(r"[A-Za-z0-9\.\-\:]+", h):
            raise ValueError("Invalid host format.")
        parts.append(f"host {h}")
    if getattr(cfg, "net", None):
        try:
            ipaddress.ip_network(cfg.net, strict=False)
        except ValueError:
            raise ValueError(f"Invalid network: {cfg.net}")
        parts.append(f"net {cfg.net}")
    if getattr(cfg, "bpf", None):
        parts.append(f"({sanitize_bpf(cfg.bpf)})")
    return " and ".join(parts) if parts else "ip or arp"

# ─── MASKING / CRYPTO ────────────────────────────────────────────────────────
def mask_value(value: str, salt: str) -> Optional[str]:
    if value is None:
        return None
    digest = hmac.new(
        salt.encode("utf-8", errors="ignore"),
        str(value).encode("utf-8", errors="ignore"),
        hashlib.sha256,
    ).hexdigest()
    return f"masked:{digest[:16]}"

def ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=260_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("'cryptography' package is not installed.")
    salt = os.urandom(16)
    key  = derive_fernet_key(password, salt)
    ct   = Fernet(key).encrypt(data)
    return b"OWLENC2" + salt + ct

def decrypt_bytes(data: bytes, password: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("'cryptography' package is not installed.")
    if not data.startswith(b"OWLENC2"):
        raise ValueError("Not an OWLENC2 encrypted file.")
    salt = data[7:23]
    ct   = data[23:]
    key  = derive_fernet_key(password, salt)
    return Fernet(key).decrypt(ct)

# ─── DAEMONIZE ────────────────────────────────────────────────────────────────
def daemonize(pid_file: Optional[str] = None) -> None:
    if os.name == "nt":
        raise RuntimeError("Daemon mode not supported on Windows.")
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    for f in (sys.stdin, sys.stdout, sys.stderr):
        with suppress(Exception):
            f.flush()
    with open(os.devnull, "rb", 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(os.devnull, "ab", 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())
    if pid_file:
        ensure_dir(pid_file)
        with open(pid_file, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

# ─── SQLITE DATABASE ─────────────────────────────────────────────────────────
class SnifferDB:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        type       TEXT NOT NULL,
        src        TEXT,
        dst        TEXT,
        sport      INTEGER,
        dport      INTEGER,
        proto      TEXT,
        detail     TEXT,
        raw_json   TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        session_key TEXT UNIQUE,
        src        TEXT,
        sport      INTEGER,
        dst        TEXT,
        dport      INTEGER,
        proto      TEXT,
        first_seen TEXT,
        last_seen  TEXT,
        packets    INTEGER DEFAULT 0,
        bytes      INTEGER DEFAULT 0,
        flags      TEXT
    );
    CREATE TABLE IF NOT EXISTS anomalies (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        kind       TEXT,
        src        TEXT,
        detail     TEXT,
        severity   TEXT DEFAULT 'HIGH'
    );
    CREATE TABLE IF NOT EXISTS dns_queries (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        src        TEXT,
        query      TEXT,
        qtype      TEXT
    );
    CREATE TABLE IF NOT EXISTS tls_sessions (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         TEXT NOT NULL,
        src        TEXT,
        dst        TEXT,
        sni        TEXT,
        ciphers    INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_type  ON events(type);
    CREATE INDEX IF NOT EXISTS idx_anomalies_ts ON anomalies(ts);
    CREATE INDEX IF NOT EXISTS idx_dns_ts       ON dns_queries(ts);
    """

    def __init__(self, path: Path = DB_FILE):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._connect()
        self._migrate()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=30,
            isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(self.SCHEMA)

    @contextmanager
    def tx(self):
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def fetchall(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self.execute(sql, params).fetchone()

    def close(self) -> None:
        if self._conn:
            self._conn.close()

# ─── WEB DASHBOARD ───────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>OSniffer Live Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0d0d;color:#e2e8f0;padding:2rem}
  h1{font-size:1.8rem;color:#06b6d4;margin-bottom:.5rem}
  .sub{color:#64748b;margin-bottom:2rem;font-size:.9rem}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1rem;margin-bottom:2rem}
  .card{background:#1e293b;border-radius:.5rem;padding:1rem;text-align:center;border:1px solid #1e293b}
  .card .v{font-size:1.8rem;font-weight:700}
  .card .l{font-size:.7rem;color:#64748b;text-transform:uppercase;margin-top:.3rem}
  .card.red .v{color:#ef4444} .card.green .v{color:#22c55e} .card.cyan .v{color:#06b6d4}
  .card.yellow .v{color:#eab308} .card.magenta .v{color:#a855f7} .card.orange .v{color:#f97316}
  table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
  th{background:#1e293b;color:#64748b;padding:.5rem .75rem;text-align:left;font-weight:600;text-transform:uppercase;font-size:.7rem}
  td{padding:.5rem .75rem;border-bottom:1px solid #1e293b}
  tr:hover td{background:#1e293b}
  .badge{padding:.2rem .6rem;border-radius:999px;font-size:.7rem;font-weight:700}
  .dns{background:#0e4f5f;color:#06b6d4} .http{background:#0a3d1a;color:#22c55e}
  .tls{background:#2e1254;color:#a855f7} .ssh{background:#3d3000;color:#eab308}
  .ftp{background:#3d1f00;color:#f97316} .smtp{background:#0d1f4f;color:#60a5fa}
  .arp{background:#0a3d3d;color:#06b6d4} .icmp{background:#0d1f4f;color:#60a5fa}
  .anomaly,.scan,.alert{background:#4f0000;color:#ef4444}
  h2{font-size:1rem;color:#94a3b8;margin:1.5rem 0 .5rem;text-transform:uppercase;letter-spacing:.05em}
  footer{margin-top:3rem;font-size:.75rem;color:#334155;text-align:center}
</style>
</head>
<body>
<h1>🦉 OSniffer Live Dashboard</h1>
<div class="sub" id="ts">Loading...</div>
<div class="grid" id="stats-grid"></div>
<h2>Recent Events</h2>
<table><thead><tr><th>Time</th><th>Proto</th><th>Src</th><th>Dst</th><th>Detail</th></tr></thead>
<tbody id="events-body"></tbody></table>
<footer>OSniffer v1.0 — khaled.s.haddad — owlsec.org</footer>
<script>
async function refresh(){
  try{
    const s=await fetch('/stats').then(r=>r.json());
    const e=await fetch('/events').then(r=>r.json());
    document.getElementById('ts').textContent='Last update: '+s.time+'  |  Uptime: '+s.uptime_s+'s';
    const cards=[
      {k:'packets',    v:s.stats?.packets||0,    cls:'cyan'},
      {k:'dns',        v:s.stats?.dns||0,         cls:'cyan'},
      {k:'http',       v:s.stats?.http||0,        cls:'green'},
      {k:'tls',        v:s.stats?.tls||0,         cls:'magenta'},
      {k:'ssh',        v:s.stats?.ssh||0,          cls:'yellow'},
      {k:'smtp',       v:s.stats?.smtp||0,         cls:''},
      {k:'scan hints', v:s.stats?.scan_hints||0,   cls:'red'},
      {k:'dropped',    v:s.stats?.dropped_queue_full||0, cls:'orange'},
      {k:'sessions',   v:s.active_sessions||0,     cls:'green'},
    ];
    document.getElementById('stats-grid').innerHTML=cards.map(c=>
      `<div class="card ${c.cls}"><div class="v">${c.v}</div><div class="l">${c.k}</div></div>`
    ).join('');
    const evts=e.events.slice(-50).reverse();
    document.getElementById('events-body').innerHTML=evts.map(ev=>{
      const t=ev.type||'';
      const detail=ev.query||ev.host||ev.sni||ev.detail||'';
      return `<tr><td>${(ev.ts||'').substring(11,19)}</td>
        <td><span class="badge ${t}">${t.toUpperCase()}</span></td>
        <td>${ev.src||''}</td><td>${ev.dst||''}</td><td>${detail}</td></tr>`;
    }).join('');
  }catch(e){console.error(e)}
}
refresh();
</script>
</body>
</html>"""

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        app = self.server.app_ref
        if self.path.startswith("/stats"):
            self._send_json(app.get_public_stats())
        elif self.path.startswith("/events"):
            self._send_json(app.get_public_events())
        elif self.path in ("/", "/dashboard"):
            self._send_html(DASHBOARD_HTML)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress HTTP log noise

    def _send_json(self, payload: dict) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, html: str) -> None:
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def start_dashboard(host: str, port: int, app_ref) -> HTTPServer:
    httpd = HTTPServer((host, port), DashboardHandler)
    httpd.app_ref = app_ref
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd

# ─── SETTINGS MODEL ───────────────────────────────────────────────────────────
@dataclass
class SniffConfig:
    # Interface
    interface:           str   = ""
    # Protocol filters
    http_only:           bool  = False
    dns_only:            bool  = False
    tls_only:            bool  = False
    arp_only:            bool  = False
    icmp_only:           bool  = False
    port:                list  = field(default_factory=list)
    host:                str   = ""
    net:                 str   = ""
    bpf:                 str   = ""
    # Stop conditions
    duration:            int   = 0
    count:               int   = 0
    # Output
    mask_output:         bool  = False
    mask_salt:           str   = "owlos-default-salt"
    lab_mode:            bool  = False
    quiet:               bool  = False
    verbose:             bool  = False
    # Encryption
    encrypt:             bool  = False
    encrypt_password:    str   = ""
    # Export
    json_path:           str   = ""
    csv_path:            str   = ""
    export_interval:     int   = 0
    # Logging
    log_path:            str   = ""
    sensitive_log:       str   = ""
    # Web
    web:                 str   = ""
    # Daemon
    daemon:              bool  = False
    pid_file:            str   = ""
    # Performance
    show_top:            int   = 10
    batch_size:          int   = 200
    batch_interval:      float = 0.5
    queue_size:          int   = 8000
    max_events:          int   = 5000
    flush_interval:      float = 2.0
    enable_early_filter: bool  = False
    early_drop_non_tcp_udp: bool = False
    # Threat detection
    scan_window:         int   = 10
    scan_threshold:      int   = 40
    arp_flood_window:    int   = 5
    arp_flood_threshold: int   = 30
    icmp_flood_threshold:int   = 100
    max_sessions:        int   = 8000
    # Alerts
    alert_on_scan:       bool  = True
    alert_on_arp:        bool  = True
    alert_on_flood:      bool  = True
    # DB
    save_to_db:          bool  = True

_CFG = SniffConfig()

# ─── ANOMALY DETECTOR ─────────────────────────────────────────────────────────
class AnomalyDetector:
    """
    Heuristic threat detection:
    - Port scan (many ports from one source in time window)
    - ARP flood / spoofing hints
    - ICMP flood
    - DNS amplification hints (large DNS responses)
    - Rapid new session opens (SYN flood hint)
    """

    def __init__(self, cfg: SniffConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        # Port scan tracking
        self._scan_buf: deque = deque()
        self._scan_ports: defaultdict = defaultdict(set)
        # ARP tracking
        self._arp_buf: deque = deque()
        self._arp_counts: Counter = Counter()
        # ICMP tracking
        self._icmp_buf: deque = deque()
        self._icmp_counts: Counter = Counter()
        # SYN tracking
        self._syn_buf: deque = deque()
        self._syn_counts: Counter = Counter()

    def check_port_scan(self, ts: float, src: str, dport: int) -> Optional[dict]:
        with self._lock:
            win = self.cfg.scan_window
            self._scan_buf.append((ts, src, dport))
            self._scan_ports[src].add(dport)
            # Expire old entries
            while self._scan_buf and (ts - self._scan_buf[0][0]) > win:
                self._scan_buf.popleft()
            ports = self._scan_ports.get(src, set())
            if len(ports) >= self.cfg.scan_threshold:
                self._scan_ports[src] = set()  # reset
                return {
                    "kind": "port_scan_hint",
                    "src": src,
                    "detail": f"{len(ports)} unique ports in {win}s",
                    "severity": "HIGH",
                }
        return None

    def check_arp_flood(self, ts: float, src: str) -> Optional[dict]:
        if not self.cfg.alert_on_arp:
            return None
        with self._lock:
            win = self.cfg.arp_flood_window
            self._arp_buf.append((ts, src))
            self._arp_counts[src] += 1
            while self._arp_buf and (ts - self._arp_buf[0][0]) > win:
                old_ts, old_src = self._arp_buf.popleft()
                self._arp_counts[old_src] = max(0, self._arp_counts[old_src] - 1)
            cnt = self._arp_counts[src]
            if cnt >= self.cfg.arp_flood_threshold:
                self._arp_counts[src] = 0
                return {
                    "kind": "arp_flood_hint",
                    "src": src,
                    "detail": f"{cnt} ARP packets in {win}s (possible ARP spoof/flood)",
                    "severity": "HIGH",
                }
        return None

    def check_icmp_flood(self, ts: float, src: str) -> Optional[dict]:
        if not self.cfg.alert_on_flood:
            return None
        with self._lock:
            self._icmp_buf.append((ts, src))
            self._icmp_counts[src] += 1
            while self._icmp_buf and (ts - self._icmp_buf[0][0]) > 5:
                old_ts, old_src = self._icmp_buf.popleft()
                self._icmp_counts[old_src] = max(0, self._icmp_counts[old_src] - 1)
            cnt = self._icmp_counts[src]
            if cnt >= self.cfg.icmp_flood_threshold:
                self._icmp_counts[src] = 0
                return {
                    "kind": "icmp_flood_hint",
                    "src": src,
                    "detail": f"{cnt} ICMP packets in 5s — possible flood/ping sweep",
                    "severity": "MED",
                }
        return None

# ─── SESSION TRACKER ──────────────────────────────────────────────────────────
class SessionTracker:
    def __init__(self, max_sessions: int = 8000):
        self.max   = max_sessions
        self._data: Dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def update(self, src: str, sport: int, dst: str, dport: int,
               payload_len: int, proto: str = "tcp", flags: Any = None) -> dict:
        key = (src, sport, dst, dport, proto)
        now = time.time()
        with self._lock:
            s = self._data.get(key)
            if not s:
                s = {
                    "first_seen": now, "last_seen": now,
                    "packets": 0, "bytes": 0, "flags": set(),
                    "src": src, "sport": sport, "dst": dst, "dport": dport,
                    "proto": proto,
                }
                self._data[key] = s
            s["last_seen"]  = now
            s["packets"]   += 1
            s["bytes"]     += max(0, int(payload_len or 0))
            if flags is not None:
                s["flags"].add(str(flags))
            # Evict oldest if over limit
            if len(self._data) > self.max:
                n_remove = max(1, len(self._data) - self.max)
                old_keys = sorted(
                    self._data.keys(),
                    key=lambda k: self._data[k]["last_seen"]
                )[:n_remove]
                for k in old_keys:
                    self._data.pop(k, None)
            return dict(s)

    def active_count(self) -> int:
        with self._lock:
            return len(self._data)

    def get_all(self) -> List[dict]:
        with self._lock:
            return [dict(v) for v in self._data.values()]

# ─── CORE ENGINE ──────────────────────────────────────────────────────────────
class OSniffer:

    def __init__(self, cfg: SniffConfig):
        self.cfg          = cfg
        self.stop         = False
        self.started      = time.time()
        self.t0           = time.monotonic()
        self.last_flush   = time.time()
        self.last_export  = time.time()

        self.events       = deque(maxlen=cfg.max_events)
        self.q            = queue.Queue(maxsize=cfg.queue_size)
        self.stats        = Counter()
        self.top_hosts    = Counter()
        self.top_dns      = Counter()
        self.tls_sni      = Counter()
        self.proto_hits   = Counter()
        self.alert_counts = Counter()

        self.session_tracker = SessionTracker(cfg.max_sessions)
        self.anomaly         = AnomalyDetector(cfg)
        self.db              = SnifferDB(DB_FILE) if cfg.save_to_db else None
        self.httpd           = None

        try:
            self.bpf_filter = build_bpf_filter(cfg)
        except ValueError as e:
            err(f"BPF filter error: {e}"); sys.exit(1)

        # Loggers
        self.logger = logging.getLogger("osniffer_core")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        lh = (logging.FileHandler(cfg.log_path, encoding="utf-8")
              if cfg.log_path else logging.NullHandler())
        lh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.logger.addHandler(lh)

        self.sensitive_logger = None
        if cfg.sensitive_log:
            sl = logging.getLogger("osniffer_sensitive")
            sl.setLevel(logging.INFO)
            sl.handlers.clear()
            sh = logging.FileHandler(cfg.sensitive_log, encoding="utf-8")
            sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            sl.addHandler(sh)
            self.sensitive_logger = sl

    def stop_request(self, *_) -> None:
        self.stop = True

    # ── Print ─────────────────────────────────────────────────────────────────
    def _print(self, msg: str) -> None:
        if not self.cfg.quiet:
            print(msg)

    def _log_sensitive(self, msg: str) -> None:
        if self.sensitive_logger:
            self.sensitive_logger.info(msg)

    # ── Event helpers ─────────────────────────────────────────────────────────
    def add_event(self, e: dict) -> None:
        if self.cfg.mask_output:
            salt = self.cfg.mask_salt or "owlos-default-salt"
            for k in ("src", "dst", "host", "query", "sni"):
                if k in e and e[k] is not None:
                    e[k] = mask_value(str(e[k]), salt)
        self.events.append(e)
        if self.db:
            with suppress(Exception):
                with self.db.tx() as conn:
                    conn.execute(
                        "INSERT INTO events(ts,type,src,dst,sport,dport,proto,detail,raw_json) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (e.get("ts",""), e.get("type",""), e.get("src"), e.get("dst"),
                         e.get("sport"), e.get("dport"), e.get("proto"),
                         e.get("detail") or e.get("query") or e.get("sni",""),
                         json.dumps(e, default=str)),
                    )

    def _handle_anomaly(self, a: dict, src: str) -> None:
        self.stats["anomalies"] += 1
        self.alert_counts[a["kind"]] += 1
        event = {
            "ts": now_iso(), "type": "anomaly",
            "kind": a["kind"], "src": src,
            "detail": a["detail"], "severity": a.get("severity","HIGH"),
        }
        self.add_event(event)
        a_kind   = a["kind"].upper()
        a_detail = a["detail"]
        self._print(
            f"\n  {color('[!!!]', C.RED + C.BOLD)}  "
            f"{color(f'ANOMALY [{a_kind}]', C.RED + C.BOLD)}  "
            f"{color(src, C.WHITE)}  —  {color(a_detail, C.ORANGE)}\n"
        )
        if self.db:
            with suppress(Exception):
                with self.db.tx() as conn:
                    conn.execute(
                        "INSERT INTO anomalies(ts,kind,src,detail,severity) VALUES(?,?,?,?,?)",
                        (now_iso(), a["kind"], src, a["detail"], a.get("severity","HIGH")),
                    )

    # ── Startup display ───────────────────────────────────────────────────────
    def print_startup(self) -> None:
        print_header("Monitor Configuration")
        section("Interface & Filter")
        row("Interface",  self.cfg.interface or "auto", val_color=C.CYAN)
        row("BPF filter", self.bpf_filter,              val_color=C.WHITE)

        flags = []
        if self.cfg.lab_mode:     flags.append("lab-mode")
        if self.cfg.mask_output:  flags.append("mask-output")
        if self.cfg.encrypt:      flags.append("encrypt")
        if self.cfg.quiet:        flags.append("quiet")
        if self.cfg.verbose:      flags.append("verbose")
        if self.cfg.save_to_db:   flags.append("save-db")
        if flags:
            row("Flags", "  ".join(flags), val_color=C.YELLOW)

        if self.cfg.duration:
            row("Stop after", f"{self.cfg.duration}s")
        if self.cfg.count:
            row("Packet limit", self.cfg.count)
        if self.cfg.web:
            row("Dashboard", f"http://{self.cfg.web}/dashboard", val_color=C.CYAN)
        if self.cfg.json_path:
            row("JSON export", self.cfg.json_path)
        if self.cfg.csv_path:
            row("CSV export",  self.cfg.csv_path)
        if self.cfg.save_to_db:
            row("Database", str(DB_FILE), val_color=C.DIM)

        section("Active Detectors")
        detected_modules = []
        detected_modules += [color("DNS", C.CYAN), color("DHCP", C.WHITE)]
        if HAS_HTTP:     detected_modules.append(color("HTTP", C.GREEN))
        detected_modules += [
            color("TLS/SNI", C.MAGENTA),
            color("SSH", C.YELLOW),
            color("FTP", C.ORANGE),
            color("SMTP", C.BLUE),
            color("ARP", C.CYAN),
            color("ICMP", C.BLUE),
            color("mDNS", C.CYAN),
            color("NBNS", C.CYAN),
            color("SCAN", C.RED),
        ]
        print(f"  {color('│', C.YELLOW)}  " + "  ".join(detected_modules))

        print()
        warn("Authorized and defensive use only. Metadata only — no payload extraction.")
        print()
        hline()
        print()

    # ── Live stats ────────────────────────────────────────────────────────────
    def print_live_stats(self) -> None:
        up      = int(time.time() - self.started)
        pkts    = self.stats.get("packets", 0)
        drop    = self.stats.get("dropped_queue_full", 0)
        sess    = self.session_tracker.active_count()
        anomaly = self.stats.get("anomalies", 0)

        parts = [
            color(f"up={up}s", C.DIM),
            color(f"pkts={pkts}", C.WHITE),
            color(f"dns={self.stats.get('dns',0)}",   C.CYAN),
            color(f"http={self.stats.get('http',0)}", C.GREEN),
            color(f"tls={self.stats.get('tls',0)}",   C.MAGENTA),
            color(f"ssh={self.stats.get('ssh',0)}",   C.YELLOW),
            color(f"arp={self.stats.get('arp',0)}",   C.CYAN),
            color(f"scans={self.stats.get('scan_hints',0)}",
                  C.RED + C.BOLD if self.stats.get("scan_hints",0) else C.DIM),
            color(f"anomalies={anomaly}", C.RED + C.BOLD if anomaly else C.DIM),
            color(f"sessions={sess}", C.GREEN),
            color(f"dropped={drop}", C.ORANGE if drop else C.DIM),
        ]
        print(f"\r  {color('[*]', C.CYAN)}  " + "  ".join(parts) + "  ", end="")
        sys.stdout.flush()

    # ── Session display ───────────────────────────────────────────────────────
    def print_sessions(self, limit: int = 20) -> None:
        print_header("Active Sessions")
        sessions = sorted(
            self.session_tracker.get_all(),
            key=lambda s: s.get("last_seen", 0), reverse=True
        )[:limit]
        if not sessions:
            nfo("No active sessions."); return
        hdr = color(
            f"  {'Proto':<8}{'Src':<20}{'Sport':<8}{'Dst':<20}{'Dport':<8}"
            f"{'Pkts':<8}{'Bytes':<12}{'Flags'}", C.DIM
        )
        print(hdr)
        hline("─", C.DIM)
        for s in sessions:
            print(
                f"  {color(s.get('proto','?').upper()[:6], C.CYAN):<14}"
                f"{color(str(s.get('src','?'))[:18], C.WHITE):<20}"
                f"{color(str(s.get('sport','?')), C.DIM):<8}"
                f"{color(str(s.get('dst','?'))[:18], C.WHITE):<20}"
                f"{color(str(s.get('dport','?')), C.DIM):<8}"
                f"{color(str(s.get('packets',0)), C.GREEN):<8}"
                f"{color(str(s.get('bytes',0)), C.DIM):<12}"
                f"{color(str(s.get('flags',set())), C.DIM)}"
            )
        print()

    # ── Early filter ──────────────────────────────────────────────────────────
    def early_filter(self, pkt) -> bool:
        if self.cfg.early_drop_non_tcp_udp:
            if not (pkt.haslayer(scapy.TCP) or
                    pkt.haslayer(scapy.UDP) or
                    pkt.haslayer(scapy.DNS) or
                    pkt.haslayer(scapy.ARP)):
                return False
        return True

    # ── Packet ingestion ──────────────────────────────────────────────────────
    def ingest_packet(self, pkt) -> None:
        if self.stop:
            return
        try:
            self.q.put_nowait(pkt)
        except queue.Full:
            self.stats["dropped_queue_full"] += 1

    # ── Batch worker ──────────────────────────────────────────────────────────
    def worker_loop(self) -> None:
        batch:    List    = []
        last_flush: float = time.time()

        while not self.stop:
            try:
                pkt = self.q.get(timeout=0.25)
                batch.append(pkt)
                if len(batch) >= self.cfg.batch_size:
                    self.process_batch(batch)
                    batch.clear()
            except queue.Empty:
                pass

            now = time.time()
            if batch and (now - last_flush) >= self.cfg.batch_interval:
                self.process_batch(batch)
                batch.clear()
                last_flush = now

            if (now - self.last_flush) >= self.cfg.flush_interval:
                self.last_flush = now
                if not self.cfg.quiet:
                    self.print_live_stats()

            if (self.cfg.export_interval and
                    (now - self.last_export) >= self.cfg.export_interval):
                self.last_export = now
                self.export_snapshot()

        if batch:
            self.process_batch(batch)

    # ── Batch + packet processing ─────────────────────────────────────────────
    def process_batch(self, pkts: list) -> None:
        self.stats["batches"] += 1
        self.stats["packets"] += len(pkts)
        for pkt in pkts:
            with suppress(Exception):
                self.process_packet(pkt)

    def process_packet(self, pkt) -> None:
        now_ts = now_iso()

        ip  = pkt.getlayer(scapy.IP) if HAVE_SCAPY else None
        src = getattr(ip, "src", None)
        dst = getattr(ip, "dst", None)

        # ── ARP ───────────────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.ARP):
            arp = pkt[scapy.ARP]
            op  = "request" if arp.op == 1 else "reply"
            self.stats["arp"]      += 1
            self.proto_hits["arp"] += 1
            event = {
                "ts": now_ts, "type": "arp", "op": op,
                "src": arp.psrc, "dst": arp.pdst,
                "hwsrc": arp.hwsrc, "hwdst": arp.hwdst,
            }
            self.add_event(event)
            self._print(
                proto_tag("arp") +
                f"  {color(op.upper(), C.CYAN + C.BOLD)}"
                f"  {color(arp.psrc, C.WHITE)} ({color(arp.hwsrc, C.DIM)})"
                f" → {color(arp.pdst, C.WHITE)}"
            )
            # ARP flood check
            anomaly = self.anomaly.check_arp_flood(time.time(), arp.psrc or "?")
            if anomaly:
                self._handle_anomaly(anomaly, arp.psrc or "?")

        if ip is None:
            return

        # ── ICMP ──────────────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.ICMP):
            icmp = pkt[scapy.ICMP]
            self.stats["icmp"]      += 1
            self.proto_hits["icmp"] += 1
            icmp_types = {0: "echo-reply", 8: "echo-request", 3: "dest-unreachable",
                          11: "time-exceeded", 5: "redirect"}
            kind = icmp_types.get(int(getattr(icmp, "type", 8)), f"type-{icmp.type}")
            event = {"ts": now_ts, "type": "icmp", "src": src, "dst": dst, "kind": kind}
            self.add_event(event)
            self._print(
                proto_tag("icmp") +
                f"  {color(kind, C.BLUE)}"
                f"  {color(src, C.WHITE)} → {color(dst, C.WHITE)}"
            )
            anomaly = self.anomaly.check_icmp_flood(time.time(), src or "?")
            if anomaly:
                self._handle_anomaly(anomaly, src or "?")

        # ── DNS ───────────────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.DNS):
            if pkt.haslayer(scapy.DNSQR):
                q = pkt[scapy.DNSQR].qname
                q = q.decode(errors="ignore") if isinstance(q, (bytes, bytearray)) else str(q)
                q = q.rstrip(".")
                qtype_num = getattr(pkt[scapy.DNSQR], "qtype", 1)
                qtype_map = {1:"A", 28:"AAAA", 5:"CNAME", 15:"MX", 2:"NS",
                             6:"SOA", 16:"TXT", 33:"SRV", 12:"PTR", 255:"ANY"}
                qtype = qtype_map.get(qtype_num, str(qtype_num))
                self.stats["dns"]  += 1
                self.proto_hits["dns"] += 1
                self.top_dns[q]    += 1

                # mDNS check
                is_mdns = dst in ("224.0.0.251", "ff02::fb")
                proto_t = "mdns" if is_mdns else "dns"
                if is_mdns:
                    self.stats["mdns"] += 1
                    self.proto_hits["mdns"] += 1

                event = {"ts": now_ts, "type": proto_t,
                         "src": src, "dst": dst, "query": q, "qtype": qtype}
                self.add_event(event)
                if self.db:
                    with suppress(Exception):
                        with self.db.tx() as conn:
                            conn.execute(
                                "INSERT INTO dns_queries(ts,src,query,qtype) VALUES(?,?,?,?)",
                                (now_ts, src, q, qtype),
                            )
                disp = q if not self.cfg.mask_output else "(masked)"
                self._print(
                    proto_tag(proto_t) +
                    f"  {color(disp, C.CYAN)}"
                    f"  {color(qtype, C.DIM)}"
                    + (f"  {color(src, C.DIM)}" if self.cfg.verbose else "")
                )

        # ── DHCP ──────────────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.DHCP) and pkt.haslayer(scapy.BOOTP):
            self.stats["dhcp"]      += 1
            self.proto_hits["dhcp"] += 1
            dhcp_msg_map = {1:"DISCOVER", 2:"OFFER", 3:"REQUEST", 5:"ACK",
                            4:"DECLINE", 6:"NAK", 7:"RELEASE", 8:"INFORM"}
            msg_type = ""
            with suppress(Exception):
                for opt in pkt[scapy.DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        msg_type = dhcp_msg_map.get(opt[1], str(opt[1]))
                        break
            event = {"ts": now_ts, "type": "dhcp", "src": src, "dst": dst,
                     "detail": msg_type}
            self.add_event(event)
            self._print(
                proto_tag("dhcp") +
                f"  {color(msg_type or 'Activity', C.WHITE)}"
                f"  {color(src, C.DIM)} → {color(dst, C.DIM)}"
            )

        # ── HTTP ──────────────────────────────────────────────────────────────
        if HAVE_SCAPY and HAS_HTTP and pkt.haslayer(scapy_http.HTTPRequest):
            req    = pkt[scapy_http.HTTPRequest]
            host   = (req.Host.decode(errors="ignore")   if req.Host   else "?").strip()
            method = (req.Method.decode(errors="ignore") if req.Method else "?").strip()
            path   = ("/" if self.cfg.lab_mode
                      else (req.Path.decode(errors="ignore") if req.Path else "/").strip())
            ua     = ""
            with suppress(Exception):
                ua = (req.User_Agent.decode(errors="ignore") if req.User_Agent else "").strip()

            self.stats["http"]      += 1
            self.proto_hits["http"] += 1
            self.top_hosts[host]    += 1

            event = {"ts": now_ts, "type": "http", "src": src, "dst": dst,
                     "host": host, "method": method, "path": path}
            if ua and not self.cfg.lab_mode:
                event["ua"] = ua[:120]
            self.add_event(event)

            disp_h = host if not self.cfg.mask_output else "(masked)"
            disp_p = path if not self.cfg.mask_output else "/"
            self._print(
                proto_tag("http") +
                f"  {color(method, C.GREEN + C.BOLD)}"
                f"  {color(f'http://{disp_h}{disp_p}', C.WHITE)}"
            )
            self._log_sensitive(f"HTTP {method} http://{host}{path} src={src}")

        # ── HTTP Response ─────────────────────────────────────────────────────
        if HAVE_SCAPY and HAS_HTTP and pkt.haslayer(scapy_http.HTTPResponse):
            resp = pkt[scapy_http.HTTPResponse]
            code = getattr(resp, "Status_Code", b"?")
            if isinstance(code, (bytes, bytearray)):
                code = code.decode(errors="ignore")
            self.stats["http_resp"] = self.stats.get("http_resp", 0) + 1

        # ── TCP sessions + SSH/FTP/SMTP/NBNS/SSDP ────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            payload_len = 0
            if pkt.haslayer(scapy.Raw):
                with suppress(Exception):
                    payload_len = len(pkt[scapy.Raw].load or b"")

            self.session_tracker.update(
                src or "?", int(tcp.sport), dst or "?", int(tcp.dport),
                payload_len, "tcp", tcp.flags
            )

            # Port scan heuristic
            a = self.anomaly.check_port_scan(time.time(), src or "?", int(tcp.dport))
            if a:
                self.stats["scan_hints"] += 1
                self._handle_anomaly(a, src or "?")

            dport = int(tcp.dport)
            sport = int(tcp.sport)

            if dport == 22 or sport == 22:
                self.stats["ssh"]      += 1
                self.proto_hits["ssh"] += 1
                event = {"ts": now_ts, "type": "ssh", "src": src, "dst": dst,
                         "sport": sport, "dport": dport}
                self.add_event(event)
                self._print(
                    proto_tag("ssh") +
                    f"  {color(src, C.YELLOW)}:{color(str(sport), C.DIM)}"
                    f" → {color(dst, C.YELLOW)}:{color(str(dport), C.DIM)}"
                )
            elif dport == 21 or sport == 21:
                self.stats["ftp"]      += 1
                self.proto_hits["ftp"] += 1
                event = {"ts": now_ts, "type": "ftp", "src": src, "dst": dst,
                         "sport": sport, "dport": dport}
                self.add_event(event)
                self._print(
                    proto_tag("ftp") +
                    f"  {color(src, C.ORANGE)} → {color(dst, C.ORANGE)}"
                )
            elif dport in (25, 587, 465) or sport in (25, 587, 465):
                self.stats["smtp"]      += 1
                self.proto_hits["smtp"] += 1
                event = {"ts": now_ts, "type": "smtp", "src": src, "dst": dst,
                         "sport": sport, "dport": dport}
                self.add_event(event)
                self._print(
                    proto_tag("smtp") +
                    f"  {color(src, C.BLUE)} → {color(dst, C.BLUE)}"
                )
            elif dport in (3389, 5900, 5901):
                # RDP/VNC
                proto_name = "rdp" if dport == 3389 else "vnc"
                self.stats[proto_name]      += 1
                self.proto_hits[proto_name] += 1
                event = {"ts": now_ts, "type": proto_name, "src": src, "dst": dst,
                         "sport": sport, "dport": dport}
                self.add_event(event)
                self._print(
                    proto_tag(proto_name) +
                    f"  {color(src, C.YELLOW)} → {color(dst, C.YELLOW)}"
                )

        # ── UDP sessions ──────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.UDP):
            udp = pkt[scapy.UDP]
            payload_len = 0
            if pkt.haslayer(scapy.Raw):
                with suppress(Exception):
                    payload_len = len(pkt[scapy.Raw].load or b"")
            self.session_tracker.update(
                src or "?", int(udp.sport), dst or "?", int(udp.dport),
                payload_len, "udp"
            )
            dport = int(udp.dport)
            sport = int(udp.sport)
            # NBNS (NetBIOS Name Service)
            if dport == 137 or sport == 137:
                self.stats["nbns"]      += 1
                self.proto_hits["nbns"] += 1
                event = {"ts": now_ts, "type": "nbns", "src": src, "dst": dst}
                self.add_event(event)
                self._print(proto_tag("nbns") + f"  {color(src, C.CYAN)} → {color(dst, C.CYAN)}")
            # SSDP
            elif dport == 1900 or sport == 1900:
                self.stats["ssdp"]      += 1
                self.proto_hits["ssdp"] += 1
                event = {"ts": now_ts, "type": "ssdp", "src": src, "dst": dst}
                self.add_event(event)
                self._print(proto_tag("ssdp") + f"  {color(src, C.WHITE)} → {color(dst, C.WHITE)}")

        # ── TLS + SNI ─────────────────────────────────────────────────────────
        if HAVE_SCAPY and pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
            tcp = pkt[scapy.TCP]
            raw = b""
            with suppress(Exception):
                raw = pkt[scapy.Raw].load or b""
            dport = int(tcp.dport)
            sport = int(tcp.sport)

            if dport in (443, 8443, 8080, 9443) or sport in (443, 8443, 8080, 9443):
                if raw[:2] == b"\x16\x03":
                    self.stats["tls"]      += 1
                    self.proto_hits["tls"] += 1
                    event = {"ts": now_ts, "type": "tls", "src": src, "dst": dst,
                             "sport": sport, "dport": dport}

                    # SNI extraction
                    sni_val = self._extract_sni(pkt, raw)
                    if sni_val:
                        event["sni"] = sni_val
                        self.tls_sni[sni_val] += 1

                    # Cipher count
                    cipher_count = self._extract_cipher_count(pkt)
                    if cipher_count:
                        event["ciphers_count"] = cipher_count

                    self.add_event(event)
                    if self.db:
                        with suppress(Exception):
                            with self.db.tx() as conn:
                                conn.execute(
                                    "INSERT INTO tls_sessions(ts,src,dst,sni,ciphers) VALUES(?,?,?,?,?)",
                                    (now_ts, src, dst, sni_val, cipher_count),
                                )
                    self._print(
                        proto_tag("tls") +
                        f"  {color('TLS', C.MAGENTA + C.BOLD)}"
                        f"  {color(src, C.DIM)} → {color(dst, C.MAGENTA)}"
                        + (f"  {color('SNI:', C.DIM)}{color(sni_val, C.WHITE)}" if sni_val else "")
                    )
                    self._log_sensitive(f"TLS src={src} dst={dst} sni={sni_val or '?'}")

        # ── General logging ───────────────────────────────────────────────────
        if self.cfg.log_path:
            self.logger.debug(f"pkt ip={src}->{dst}")

    def _extract_sni(self, pkt, raw: bytes) -> Optional[str]:
        """Try TLS ClientHello SNI extraction via scapy-tls, fallback to manual parse."""
        sni_val = None
        if HAS_TLS and HAVE_SCAPY:
            try:
                if pkt.haslayer(TLSClientHello):
                    ch = pkt[TLSClientHello]
                    if hasattr(ch, "ext") and ch.ext:
                        for ext in ch.ext:
                            if hasattr(ext, "servernames") and ext.servernames:
                                sr = ext.servernames[0].servername
                                sni_val = (sr.decode(errors="ignore")
                                           if isinstance(sr, (bytes, bytearray)) else str(sr))
                                break
                            if hasattr(ext, "servername"):
                                sni_val = ext.servername
                                break
            except Exception:
                pass

        if not sni_val and len(raw) > 43:
            # Manual TLS ClientHello SNI parse
            try:
                sni_val = self._manual_sni_parse(raw)
            except Exception:
                pass
        return sni_val

    @staticmethod
    def _manual_sni_parse(raw: bytes) -> Optional[str]:
        """Manually parse SNI from raw TLS ClientHello bytes."""
        if raw[0] != 0x16 or raw[1] != 0x03:
            return None
        # Skip TLS record header (5 bytes), handshake header (4 bytes)
        offset = 9
        if len(raw) < offset + 38:
            return None
        offset += 2 + 32  # legacy_version + random
        session_id_len = raw[offset] if offset < len(raw) else 0
        offset += 1 + session_id_len
        if offset + 2 > len(raw):
            return None
        cipher_suites_len = struct.unpack(">H", raw[offset:offset+2])[0]
        offset += 2 + cipher_suites_len
        if offset + 1 > len(raw):
            return None
        compression_len = raw[offset]
        offset += 1 + compression_len
        if offset + 2 > len(raw):
            return None
        extensions_len = struct.unpack(">H", raw[offset:offset+2])[0]
        offset += 2
        end = offset + extensions_len
        while offset + 4 <= end and offset + 4 <= len(raw):
            ext_type = struct.unpack(">H", raw[offset:offset+2])[0]
            ext_len  = struct.unpack(">H", raw[offset+2:offset+4])[0]
            offset  += 4
            if ext_type == 0x0000 and offset + ext_len <= len(raw):
                # SNI extension
                sni_list_len = struct.unpack(">H", raw[offset:offset+2])[0]
                if raw[offset+2] == 0x00:
                    name_len = struct.unpack(">H", raw[offset+3:offset+5])[0]
                    return raw[offset+5:offset+5+name_len].decode(errors="ignore")
            offset += ext_len
        return None

    def _extract_cipher_count(self, pkt) -> int:
        if not HAS_TLS or not HAVE_SCAPY:
            return 0
        try:
            if pkt.haslayer(TLSClientHello):
                ch = pkt[TLSClientHello]
                if hasattr(ch, "ciphers") and ch.ciphers:
                    return len(ch.ciphers)
        except Exception:
            pass
        return 0

    # ── Summary ───────────────────────────────────────────────────────────────
    def summary(self) -> None:
        dur = elapsed_str(self.t0)
        print_header("Session Summary")

        section("Statistics")
        for k, v in sorted(self.stats.items()):
            clr = (C.RED    if k in ("anomalies", "scan_hints", "dropped_queue_full") and v
                   else C.GREEN if k == "packets"
                   else C.WHITE)
            row(k, v, val_color=clr)
        row("duration", dur, val_color=C.YELLOW)
        row("sessions",  self.session_tracker.active_count(), val_color=C.GREEN)

        section("Protocol Hits")
        for proto, cnt in sorted(self.proto_hits.items(), key=lambda x: -x[1]):
            row(proto.upper(), cnt, val_color=proto_color(proto))

        n = self.cfg.show_top
        if n > 0:
            if self.top_dns:
                section(f"Top {n} DNS Queries")
                for q, c in self.top_dns.most_common(n):
                    row(q[:35], c, width=37, val_color=C.CYAN)
            if self.top_hosts:
                section(f"Top {n} HTTP Hosts")
                for h, c in self.top_hosts.most_common(n):
                    row(h[:35], c, width=37, val_color=C.GREEN)
            if self.tls_sni:
                section(f"Top {n} TLS SNI")
                for s, c in self.tls_sni.most_common(n):
                    row(s[:35], c, width=37, val_color=C.MAGENTA)

        if self.alert_counts:
            section("Anomaly Summary")
            for kind, cnt in self.alert_counts.most_common():
                row(kind, cnt, val_color=C.RED)

    # ── Export ────────────────────────────────────────────────────────────────
    def _export_json_data(self) -> bytes:
        payload = {
            "tool":       APP_NAME,
            "version":    VERSION,
            "developer":  DEVELOPER,
            "website":    WEBSITE,
            "time":       now_iso(),
            "duration_s": int(time.time() - self.started),
            "stats":      dict(self.stats),
            "protocols":  dict(self.proto_hits),
            "top_dns":    self.top_dns.most_common(50),
            "top_hosts":  self.top_hosts.most_common(50),
            "tls_sni":    self.tls_sni.most_common(50),
            "anomalies":  dict(self.alert_counts),
            "events":     list(self.events),
        }
        return json.dumps(payload, indent=2, default=str).encode("utf-8")

    def _export_csv_data(self) -> bytes:
        rows = list(self.events)
        buf  = io.StringIO()
        keys = sorted({k for r in rows for k in r.keys()}) if rows else \
               ["ts", "type", "src", "dst", "sport", "dport"]
        writer = csv.DictWriter(buf, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        return buf.getvalue().encode("utf-8")

    def _export_html_report(self) -> bytes:
        events = list(self.events)[-200:]
        rows_html = ""
        for ev in reversed(events):
            t    = ev.get("type", "")
            det  = ev.get("query") or ev.get("host") or ev.get("sni") or ev.get("detail", "")
            src  = ev.get("src","")
            dst  = ev.get("dst","")
            ts   = ev.get("ts","")
            rows_html += (
                f"<tr><td>{ts[11:19] if len(ts)>11 else ts}</td>"
                f"<td><span class='badge {t}'>{t.upper()}</span></td>"
                f"<td>{src}</td><td>{dst}</td><td>{det}</td></tr>"
            )
        stats_html = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>"
            for k, v in sorted(self.stats.items())
        )
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>OSniffer Report — {now_str()}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0d0d;color:#e2e8f0;padding:2rem}}
  h1{{font-size:1.8rem;color:#06b6d4;margin-bottom:.5rem}}
  h2{{font-size:1rem;color:#94a3b8;margin:1.5rem 0 .5rem;text-transform:uppercase;letter-spacing:.05em}}
  .sub{{color:#64748b;margin-bottom:2rem;font-size:.85rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-top:.5rem}}
  th{{background:#1e293b;color:#64748b;padding:.5rem .75rem;text-align:left;
      font-weight:600;text-transform:uppercase;font-size:.7rem}}
  td{{padding:.45rem .75rem;border-bottom:1px solid #1a2030}}
  tr:hover td{{background:#1e293b}}
  .badge{{padding:.2rem .55rem;border-radius:999px;font-size:.7rem;font-weight:700;white-space:nowrap}}
  .dns{{background:#0e4f5f;color:#06b6d4}} .http{{background:#0a3d1a;color:#22c55e}}
  .tls{{background:#2e1254;color:#a855f7}} .ssh{{background:#3d3000;color:#eab308}}
  .ftp{{background:#3d1f00;color:#f97316}} .smtp{{background:#0d1f4f;color:#60a5fa}}
  .arp{{background:#0a3d3d;color:#06b6d4}} .icmp{{background:#0d1f4f;color:#60a5fa}}
  .anomaly,.scan{{background:#4f0000;color:#ef4444}}
  footer{{margin-top:3rem;font-size:.75rem;color:#334155;text-align:center}}
</style></head>
<body>
<h1>🦉 OSniffer Report</h1>
<div class="sub">Generated: {now_str()} | Interface: {self.cfg.interface} | {WEBSITE}</div>
<h2>Statistics</h2>
<table><thead><tr><th>Counter</th><th>Value</th></tr></thead>
<tbody>{stats_html}</tbody></table>
<h2>Events (last 200)</h2>
<table><thead><tr><th>Time</th><th>Proto</th><th>Src</th><th>Dst</th><th>Detail</th></tr></thead>
<tbody>{rows_html}</tbody></table>
<footer>OSniffer v{VERSION} — {DEVELOPER} — {WEBSITE}</footer>
</body></html>"""
        return html.encode("utf-8")

    def _write_export(self, data: bytes, path: str) -> None:
        ensure_dir(path)
        if self.cfg.encrypt:
            if not self.cfg.encrypt_password:
                raise RuntimeError("Encrypt requires --encrypt-password.")
            data     = encrypt_bytes(data, self.cfg.encrypt_password)
            path_out = path + ".enc"
            with open(path_out, "wb") as f:
                f.write(data)
            ok(f"Encrypted export → {path_out}")
        else:
            with open(path, "wb") as f:
                f.write(data)
            ok(f"Export → {path}")

    def export_json(self, path: str) -> None:
        self._write_export(self._export_json_data(), path)

    def export_csv(self, path: str) -> None:
        self._write_export(self._export_csv_data(), path)

    def export_html(self, path: str) -> None:
        self._write_export(self._export_html_report(), path)

    def export_snapshot(self) -> None:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        for attr, ext, fn in [
            ("json_path", ".json", self.export_json),
            ("csv_path",  ".csv",  self.export_csv),
        ]:
            path = getattr(self.cfg, attr)
            if not path:
                continue
            p = path.replace("{ts}", ts)
            if "{ts}" not in path:
                base, e = os.path.splitext(path)
                p = f"{base}_{ts}{e or ext}"
            with suppress(Exception):
                fn(p)

    def export(self) -> None:
        section("Export")
        if self.cfg.json_path: self.export_json(self.cfg.json_path)
        if self.cfg.csv_path:  self.export_csv(self.cfg.csv_path)

    # ── Dashboard API ─────────────────────────────────────────────────────────
    def get_public_stats(self) -> dict:
        return {
            "time":            now_iso(),
            "uptime_s":        int(time.time() - self.started),
            "stats":           dict(self.stats),
            "protocols":       dict(self.proto_hits),
            "active_sessions": self.session_tracker.active_count(),
            "top_dns":         self.top_dns.most_common(10),
            "top_sni":         self.tls_sni.most_common(10),
        }

    def get_public_events(self) -> dict:
        return {"time": now_iso(), "events": list(self.events)[-500:]}

    # ── Main run loop ─────────────────────────────────────────────────────────
    def run(self) -> None:
        if not HAVE_SCAPY:
            err("scapy is not installed. Install: pip install scapy")
            return

        self.print_startup()

        if self.cfg.interface and not interface_exists(self.cfg.interface):
            err(f"Interface not found: {self.cfg.interface}")
            ifaces = [i["name"] for i in list_interfaces()]
            if ifaces:
                nfo("Available: " + "  ".join(ifaces))
            return

        if self.cfg.web:
            try:
                parts = self.cfg.web.rsplit(":", 1)
                host  = parts[0].strip()
                port  = int(parts[1])
                self.httpd = start_dashboard(host, port, self)
                ok(f"Dashboard → http://{host}:{port}/dashboard")
                ok(f"Stats API → http://{host}:{port}/stats")
                print()
            except Exception as e:
                warn(f"Dashboard failed: {e}")

        signal.signal(signal.SIGINT,  self.stop_request)
        signal.signal(signal.SIGTERM, self.stop_request)

        wt = threading.Thread(target=self.worker_loop, daemon=True)
        wt.start()

        nfo(f"Listening on {self.cfg.interface or 'default'} …  Press Ctrl+C to stop.")
        hline()
        print()

        sniff_kwargs: dict = {
            "store":   False,
            "prn":     self.ingest_packet,
            "filter":  self.bpf_filter,
            "lfilter": self.early_filter if self.cfg.enable_early_filter else None,
        }
        if self.cfg.interface:
            sniff_kwargs["iface"] = self.cfg.interface
        if self.cfg.duration:
            sniff_kwargs["timeout"] = self.cfg.duration
        if self.cfg.count:
            sniff_kwargs["count"] = self.cfg.count

        try:
            scapy.sniff(**sniff_kwargs)
        except PermissionError:
            err("Permission denied — root required for packet capture.")
            cprint("  [»] Run: sudo osniffer", C.YELLOW)
            return
        except Exception as e:
            if not self.stop:
                err(f"Sniff error: {e}")

        self.stop = True
        wt.join(timeout=3.0)
        print()
        self.summary()
        self.export()
        print()
        ok(f"Session ended — {WEBSITE}  🦉")

# ─── INTERACTIVE PROMPTS ──────────────────────────────────────────────────────
def _prompt(label: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    val  = input(
        color("  [»] ", C.YELLOW) + color(f"{label}{hint}: ", C.WHITE)
    ).strip()
    return val if val else default

def _prompt_int(label: str, default: int) -> int:
    raw = _prompt(label, str(default))
    try:
        return max(0, int(raw))
    except Exception:
        return default

def _prompt_bool(label: str, default: bool = False) -> bool:
    d   = "Y/n" if default else "y/N"
    raw = input(
        color("  [»] ", C.YELLOW) + color(f"{label} [{d}]: ", C.WHITE)
    ).strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "1", "true")

def _pick_interface() -> str:
    ifaces = list_interfaces()
    if not ifaces:
        return _prompt("Interface name (e.g. eth0)")
    print()
    section("Available Interfaces")
    cprint(f"  {'#':<5}{'Name':<18}{'IP':<22}{'MAC':<20}{'State'}", C.DIM)
    hline("─", C.DIM)
    for i, iface in enumerate(ifaces, 1):
        state_clr = C.GREEN if iface.get("state","").upper() == "UP" else C.DIM
        print(
            f"  {color(str(i), C.CYAN):<9}"
            f"{color(iface['name'][:16], C.WHITE):<18}"
            f"{color(iface.get('ip','')[:20], C.DIM):<22}"
            f"{color(iface.get('mac','')[:18], C.DIM):<20}"
            f"{color(iface.get('state',''), state_clr)}"
        )
    print()
    raw = _prompt("Select number or type interface name")
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(ifaces):
            return ifaces[idx]["name"]
    except ValueError:
        pass
    return raw

# ─── INTERACTIVE MODULES ──────────────────────────────────────────────────────
def module_start_monitor() -> None:
    clear_screen(); banner()
    print_header("Start Network Monitor")
    print()
    warn("Authorized and defensive use only.")
    print()

    if not HAVE_SCAPY:
        err("scapy is not installed.")
        nfo("Install: pip install scapy"); return

    require_root("packet capture")

    cfg = SniffConfig()

    # Interface
    cfg.interface = _pick_interface()
    if not cfg.interface:
        err("No interface selected."); return

    # Protocol filters
    section("Capture Filter  (leave blank for all)")
    cfg.dns_only  = _prompt_bool("DNS only?")
    cfg.http_only = _prompt_bool("HTTP only?")   if not cfg.dns_only  else False
    cfg.tls_only  = _prompt_bool("TLS only?")    if not cfg.http_only else False
    cfg.arp_only  = _prompt_bool("ARP only?")    if not cfg.tls_only  else False
    cfg.icmp_only = _prompt_bool("ICMP only?")   if not cfg.arp_only  else False

    # Options
    section("Options")
    cfg.mask_output = _prompt_bool("Mask output (IPs/domains)?")
    cfg.lab_mode    = _prompt_bool("Lab mode (strip URL paths)?")
    cfg.quiet       = _prompt_bool("Quiet mode (no per-packet output)?")
    cfg.verbose     = _prompt_bool("Verbose mode?") if not cfg.quiet else False
    cfg.show_top    = _prompt_int("Show top N in summary", 10)
    cfg.duration    = _prompt_int("Stop after N seconds (0=never)", 0)
    cfg.count       = _prompt_int("Stop after N packets (0=never)", 0)
    cfg.save_to_db  = _prompt_bool("Save events to SQLite DB?", True)

    # Threat detection
    section("Threat Detection")
    cfg.scan_window      = _prompt_int("Port scan window (seconds)", 10)
    cfg.scan_threshold   = _prompt_int("Port scan threshold (unique ports)", 40)
    cfg.arp_flood_threshold = _prompt_int("ARP flood threshold", 30)

    # Export
    section("Export  (leave blank to skip)")
    cfg.json_path = _prompt("JSON export path")
    cfg.csv_path  = _prompt("CSV export path")
    export_html   = _prompt("HTML report path")
    cfg.export_interval = _prompt_int("Periodic export interval seconds (0=off)", 0)

    # Web dashboard
    cfg.web = _prompt("Web dashboard HOST:PORT (e.g. 127.0.0.1:8080)")

    # Encryption
    if cfg.json_path or cfg.csv_path:
        cfg.encrypt = _prompt_bool("Encrypt exports?")
        if cfg.encrypt:
            cfg.encrypt_password = _prompt("Encryption password")

    print()
    app = OSniffer(cfg)
    app.run()

    if export_html:
        with suppress(Exception):
            app.export_html(export_html)
            ok(f"HTML report saved: {export_html}")

def module_list_interfaces() -> None:
    clear_screen(); banner()
    print_header("Network Interfaces")
    print()
    ifaces = list_interfaces()
    if not ifaces:
        nfo("No interfaces found."); return

    cprint(f"  {'#':<5}{'Name':<18}{'IP':<22}{'MAC':<20}{'State'}", C.DIM)
    hline("─", C.DIM)
    for i, iface in enumerate(ifaces, 1):
        state_clr = C.GREEN if iface.get("state","").upper() == "UP" else C.DIM
        print(
            f"  {color(str(i), C.CYAN):<9}"
            f"{color(iface['name'][:16], C.WHITE):<18}"
            f"{color(iface.get('ip','')[:20], C.GREEN if iface.get('ip') else C.DIM):<22}"
            f"{color(iface.get('mac','')[:18], C.DIM):<20}"
            f"{color(iface.get('state',''), state_clr)}"
        )
        # Interface stats
        stats = get_interface_stats(iface["name"])
        if stats:
            rx = stats.get("rx_bytes", 0)
            tx = stats.get("tx_bytes", 0)
            def fmt_bytes(b: int) -> str:
                if b >= 1024**3: return f"{b/1024**3:.1f}GB"
                if b >= 1024**2: return f"{b/1024**2:.1f}MB"
                if b >= 1024:    return f"{b/1024:.1f}KB"
                return f"{b}B"
            print(
                f"  {'':<9}"
                f"{color('RX:', C.DIM)}{color(fmt_bytes(rx), C.CYAN):<16}"
                f"{color('TX:', C.DIM)}{color(fmt_bytes(tx), C.CYAN):<16}"
                f"{color('err:', C.DIM)}{color(str(stats.get('rx_errors',0)), C.DIM)}"
            )
    print()

def module_settings() -> None:
    clear_screen(); banner()
    print_header("Settings")
    print()

    cfg = _CFG
    section("Current Settings")
    row("Interface",         cfg.interface or "—")
    row("Mask output",       cfg.mask_output)
    row("Lab mode",          cfg.lab_mode)
    row("Verbose",           cfg.verbose)
    row("Show top N",        cfg.show_top)
    row("Scan window",       f"{cfg.scan_window}s")
    row("Scan threshold",    cfg.scan_threshold)
    row("ARP flood thr.",    cfg.arp_flood_threshold)
    row("ICMP flood thr.",   cfg.icmp_flood_threshold)
    row("Max sessions",      cfg.max_sessions)
    row("Batch size",        cfg.batch_size)
    row("Queue size",        cfg.queue_size)
    row("Export interval",   f"{cfg.export_interval}s" if cfg.export_interval else "off")
    row("JSON export",       cfg.json_path or "—")
    row("CSV export",        cfg.csv_path  or "—")
    row("Encrypt",           cfg.encrypt)
    row("Save to DB",        cfg.save_to_db)

    print()
    if not _prompt_bool("Edit settings?"):
        return

    cfg.mask_output         = _prompt_bool("Mask output?",              cfg.mask_output)
    cfg.mask_salt           = _prompt("Mask salt",                      cfg.mask_salt)
    cfg.lab_mode            = _prompt_bool("Lab mode?",                 cfg.lab_mode)
    cfg.verbose             = _prompt_bool("Verbose?",                  cfg.verbose)
    cfg.show_top            = _prompt_int("Show top N",                 cfg.show_top)
    cfg.scan_window         = _prompt_int("Scan window (s)",            cfg.scan_window)
    cfg.scan_threshold      = _prompt_int("Scan threshold",             cfg.scan_threshold)
    cfg.arp_flood_threshold = _prompt_int("ARP flood threshold",        cfg.arp_flood_threshold)
    cfg.icmp_flood_threshold= _prompt_int("ICMP flood threshold",       cfg.icmp_flood_threshold)
    cfg.max_sessions        = _prompt_int("Max sessions",               cfg.max_sessions)
    cfg.batch_size          = _prompt_int("Batch size",                 cfg.batch_size)
    cfg.queue_size          = _prompt_int("Queue size",                 cfg.queue_size)
    cfg.export_interval     = _prompt_int("Export interval (s)",        cfg.export_interval)
    cfg.json_path           = _prompt("JSON export path",               cfg.json_path)
    cfg.csv_path            = _prompt("CSV export path",                cfg.csv_path)
    cfg.encrypt             = _prompt_bool("Encrypt exports?",          cfg.encrypt)
    if cfg.encrypt:
        cfg.encrypt_password = _prompt("Encrypt password",             cfg.encrypt_password)
    cfg.save_to_db          = _prompt_bool("Save to SQLite DB?",        cfg.save_to_db)
    cfg.log_path            = _prompt("Normal log file",                cfg.log_path)
    cfg.sensitive_log       = _prompt("Sensitive log file",             cfg.sensitive_log)
    print()
    ok("Settings updated.")

def module_view_history() -> None:
    clear_screen(); banner()
    print_header("Capture History (SQLite)")
    print()
    try:
        db = SnifferDB(DB_FILE)
    except Exception as e:
        err(f"DB error: {e}"); return

    # Event counts by type
    rows = db.fetchall(
        "SELECT type, COUNT(*) as cnt FROM events GROUP BY type ORDER BY cnt DESC LIMIT 20"
    )
    if rows:
        section("Event Counts by Protocol")
        cprint(f"  {'Protocol':<16}{'Count'}", C.DIM)
        hline("─", C.DIM)
        for r in rows:
            print(
                f"  {color(str(r['type']).upper()[:14], proto_color(r['type'])):<22}"
                f"{color(str(r['cnt']), C.WHITE)}"
            )

    # Recent anomalies
    anomalies = db.fetchall(
        "SELECT ts, kind, src, detail, severity FROM anomalies ORDER BY ts DESC LIMIT 15"
    )
    if anomalies:
        section("Recent Anomalies")
        cprint(f"  {'Time':<22}{'Kind':<22}{'Src':<20}{'Detail'}", C.DIM)
        hline("─", C.DIM)
        for a in anomalies:
            sev_clr = C.RED if a["severity"] == "HIGH" else C.ORANGE
            print(
                f"  {color(str(a['ts'])[:19], C.DIM):<22}"
                f"{color(str(a['kind']), sev_clr):<22}"
                f"{color(str(a['src'] or ''), C.WHITE):<20}"
                f"{color(str(a['detail'] or ''), C.DIM)}"
            )

    # TLS SNI top 10
    sni_rows = db.fetchall(
        "SELECT sni, COUNT(*) as cnt FROM tls_sessions WHERE sni IS NOT NULL "
        "GROUP BY sni ORDER BY cnt DESC LIMIT 10"
    )
    if sni_rows:
        section("Top TLS SNI (all time)")
        for r in sni_rows:
            row(str(r["sni"])[:35], r["cnt"], width=37, val_color=C.MAGENTA)

    # Total events
    total = db.fetchone("SELECT COUNT(*) AS n FROM events")
    print()
    nfo(f"Total events in DB: {total['n'] if total else 0}")
    nfo(f"DB path: {DB_FILE}")
    print()
    db.close()

def module_export_report() -> None:
    clear_screen(); banner()
    print_header("Export Report from DB")
    print()
    try:
        db = SnifferDB(DB_FILE)
    except Exception as e:
        err(f"DB error: {e}"); return

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    fmt  = _prompt("Format [json/csv/html]", "json").strip().lower()
    path = _prompt("Output path", str(EXPORT_DIR / f"osniffer_report_{ts}.{fmt}"))

    events = db.fetchall("SELECT raw_json FROM events ORDER BY ts DESC LIMIT 5000")
    db.close()

    event_list = []
    for r in events:
        with suppress(Exception):
            event_list.append(json.loads(r["raw_json"]))

    ensure_dir(path)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"events": event_list, "exported_at": now_iso()}, f, indent=2, default=str)
    elif fmt == "csv":
        if event_list:
            keys = sorted({k for ev in event_list for k in ev.keys()})
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(event_list)
    elif fmt == "html":
        tmp_cfg = SniffConfig()
        tmp_app = OSniffer.__new__(OSniffer)
        tmp_app.cfg    = tmp_cfg
        tmp_app.events = deque(event_list)
        tmp_app.stats  = Counter()
        tmp_app.started = time.time()
        html_bytes = tmp_app._export_html_report()
        with open(path, "wb") as f:
            f.write(html_bytes)
    else:
        err(f"Unknown format: {fmt}"); return

    ok(f"Exported to: {path}")
    print()

# ─── HELP ─────────────────────────────────────────────────────────────────────
def show_help() -> None:
    sections = [
        ("DESCRIPTION", [
            "OSniffer is a defensive-only network traffic monitor for Debian Linux.",
            "Captures metadata from DNS, HTTP, TLS/SNI, SSH, FTP, SMTP, DHCP,",
            "ARP, ICMP, mDNS, NBNS, SSDP. Detects port scans, ARP floods, ICMP floods.",
            "Never extracts credentials, passwords, or payload data.",
        ]),
        ("MODES", [
            "[1] Start Monitor   — live capture with all detectors active",
            "[2] Interface List  — show interfaces with IP, MAC, RX/TX stats",
            "[3] Settings        — configure filters, export, thresholds",
            "[4] View History    — browse SQLite DB: events, anomalies, SNI",
            "[5] Export Report   — export JSON/CSV/HTML from stored DB data",
        ]),
        ("PROTOCOL DETECTION", [
            "DNS/mDNS  UDP 53 / 224.0.0.251 — query name + type",
            "HTTP      TCP 80  — method + host + path (lab-mode strips path)",
            "TLS/SNI   TCP 443/8443 — session + SNI extraction (manual parse fallback)",
            "SSH       TCP 22  — session metadata",
            "FTP       TCP 21  — connection events",
            "SMTP      TCP 25/465/587 — connection events",
            "DHCP      BOOTP — message type (DISCOVER/OFFER/REQUEST/ACK)",
            "ARP       all ARP — request/reply + flood detection",
            "ICMP      all — type + flood detection",
            "NBNS      UDP 137 — NetBIOS name resolution",
            "SSDP      UDP 1900 — UPnP discovery",
            "RDP/VNC   TCP 3389/5900 — connection events",
            "SCAN      heuristic — N unique ports in T seconds from same source",
        ]),
        ("THREAT DETECTION", [
            "Port scan hint  — many unique dports from one src in scan_window",
            "ARP flood hint  — > arp_flood_threshold packets in arp_flood_window",
            "ICMP flood hint — > icmp_flood_threshold packets in 5 seconds",
        ]),
        ("OPTIONS", [
            "--interface/-i  Network interface to capture on",
            "--dns-only       Capture DNS only",
            "--http-only      Capture HTTP only",
            "--tls-only       Capture TLS only",
            "--arp-only       Capture ARP only",
            "--bpf 'filter'   Custom BPF filter expression",
            "--host IP        Filter by host",
            "--net CIDR       Filter by network",
            "--mask-output    HMAC-SHA256 mask IPs/domains",
            "--lab-mode       Strip URL paths",
            "--encrypt        Encrypt JSON/CSV exports",
            "--duration N     Stop after N seconds",
            "--count N        Stop after N packets",
            "--web HOST:PORT  Live JSON+HTML dashboard",
            "--daemon         Run as background daemon",
            "--quiet          Suppress per-packet output",
            "--verbose        Verbose debug output",
            "--json FILE      Export JSON",
            "--csv  FILE      Export CSV",
            "--html FILE      Export HTML report",
        ]),
        ("REQUIREMENTS", [
            "sudo/root        Required for raw packet capture",
            "pip install scapy",
            "pip install cryptography   (optional, for --encrypt)",
        ]),
        ("FILES", [
            f"Database : {DB_FILE}",
            f"Logs     : {LOG_FILE}",
            f"Exports  : {EXPORT_DIR}",
        ]),
    ]

    W = 76
    print(color("╔" + "═" * W + "╗", C.CYAN))
    title = "                 OSniffer — Help & Usage Guide"
    print(color("║", C.CYAN) + color(title + " " * (W - len(title)), C.BOLD + C.WHITE) + color("║", C.CYAN))
    print(color("╠" + "═" * W + "╣", C.CYAN))

    for title_s, lines in sections:
        header = f"  ┌─ {title_s}"
        print(color("║", C.CYAN) + color(header + " " * max(W - len(header), 0), C.YELLOW) + color("║", C.CYAN))
        for line in lines:
            raw   = re.sub(r"\033\[[0-9;]*m", "", line)
            padded = f"  │  {raw}"
            print(color("║", C.CYAN) + "  │  " + line + " " * max(W - len(padded), 0) + color("║", C.CYAN))
        print(color("║", C.CYAN) + " " * W + color("║", C.CYAN))

    print(color("╚" + "═" * W + "╝", C.CYAN))
    print()

# ─── MAIN MENU ────────────────────────────────────────────────────────────────
MENU_ITEMS = [
    ("1", C.GREEN,  "Start Monitor    ", "Live capture — all protocols + threat detection"),
    ("2", C.CYAN,   "Interface List   ", "Show interfaces with IP, MAC and stats"),
    ("3", C.YELLOW, "Settings         ", "Configure filters, thresholds, export"),
    ("4", C.CYAN,   "View History     ", "Browse SQLite DB: events, anomalies, SNI"),
    ("5", C.CYAN,   "Export Report    ", "Export JSON / CSV / HTML from DB"),
    ("H", C.YELLOW, "Help             ", "Protocols, flags, requirements"),
    ("0", C.RED,    "Exit             ", ""),
]

def main_menu() -> None:
    while True:
        clear_screen()
        banner()
        cprint(f"  {now_str()}", C.DIM)
        print()

        for num, clr, name, desc in MENU_ITEMS:
            desc_part = color(f"─ {desc}", C.DIM) if desc else ""
            print(f"  {color(f'[{num}]', clr)}  {color(name, C.WHITE)} {desc_part}")

        print()
        hline()
        choice = input(color("\n  [»] Select option: ", C.YELLOW)).strip().upper()
        print()

        if choice == "0":
            cprint(f"\n  [✔] Goodbye — {WEBSITE}  🦉\n", C.GREEN)
            sys.exit(0)
        elif choice == "H":
            clear_screen(); banner(compact=True); show_help(); pause()
        elif choice == "1":
            module_start_monitor(); pause()
        elif choice == "2":
            module_list_interfaces(); pause()
        elif choice == "3":
            module_settings(); pause()
        elif choice == "4":
            module_view_history(); pause()
        elif choice == "5":
            module_export_report(); pause()
        else:
            err("Invalid option."); pause()


def run_self_test() -> int:
    """Offline sandboxed self-test — no live capture."""
    banner()
    print(color("  OSniffer Self-Test  (offline / sandboxed)", C.CYAN + C.BOLD))
    print()
    passed = failed = 0
    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; ok(name)
        else:
            failed += 1; err(name)

    cfg = SniffConfig()
    check("SniffConfig defaults", cfg.scan_threshold > 0)
    det = AnomalyDetector(cfg)
    # Simulate rapid ports from one source
    ts = time.time()
    hit = None
    for port in range(1, cfg.scan_threshold + 5):
        hit = det.check_port_scan(ts, "10.0.0.9", port)
        if hit:
            break
    check("Port-scan anomaly fires", hit is not None and bool(hit.get("kind")))
    # ARP flood
    hit2 = None
    for _ in range(cfg.arp_flood_threshold + 2):
        hit2 = det.check_arp_flood(ts, "10.0.0.1")
        if hit2:
            break
    check("ARP-flood anomaly fires", hit2 is not None)
    check("VERSION set", bool(VERSION))
    print()
    if failed == 0:
        ok(f"ALL {passed} CHECKS PASSED — detection engine healthy.")
        return 0
    err(f"{failed} FAILED, {passed} passed.")
    return 1


# ─── CLI ARG PARSER ───────────────────────────────────────────────────────────
def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="osniffer",
        description=f"OSniffer v{VERSION} — Defensive Network Monitor",
        add_help=False,
    )
    p.add_argument("-i", "--interface",  default="",  help="Network interface")
    p.add_argument("--dns-only",         action="store_true")
    p.add_argument("--http-only",        action="store_true")
    p.add_argument("--tls-only",         action="store_true")
    p.add_argument("--arp-only",         action="store_true")
    p.add_argument("--icmp-only",        action="store_true")
    p.add_argument("--bpf",             default="")
    p.add_argument("--host",            default="")
    p.add_argument("--net",             default="")
    p.add_argument("--port",            nargs="+", default=[])
    p.add_argument("--duration", "-t",  type=int, default=0)
    p.add_argument("--count",    "-c",  type=int, default=0)
    p.add_argument("--mask-output",     action="store_true")
    p.add_argument("--lab-mode",        action="store_true")
    p.add_argument("--quiet",    "-q",  action="store_true")
    p.add_argument("--verbose",  "-v",  action="store_true")
    p.add_argument("--encrypt",         action="store_true")
    p.add_argument("--encrypt-password",default="")
    p.add_argument("--json",            default="", metavar="FILE")
    p.add_argument("--csv",             default="", metavar="FILE")
    p.add_argument("--html",            default="", metavar="FILE")
    p.add_argument("--web",             default="", metavar="HOST:PORT")
    p.add_argument("--daemon",          action="store_true")
    p.add_argument("--pid-file",        default="")
    p.add_argument("--show-top",        type=int, default=10)
    p.add_argument("--scan-window",     type=int, default=10)
    p.add_argument("--scan-threshold",  type=int, default=40)
    p.add_argument("--no-db",           action="store_true")
    p.add_argument("--version",         action="store_true")
    p.add_argument("--help",    "-h",   action="store_true")
    p.add_argument("--self-test", dest="self_test", action="store_true",
                    help="Run offline sandboxed self-test and exit")
    return p

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
def main() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    import argparse
    parser = build_parser()
    args, _ = parser.parse_known_args()

    if getattr(args, 'self_test', False):
        sys.exit(run_self_test())

    if args.version:
        print(f"OSniffer v{VERSION} — {CODENAME}")
        print(f"Developer : {DEVELOPER}")
        print(f"Website   : {WEBSITE}")
        sys.exit(0)

    if args.help:
        banner()
        show_help()
        sys.exit(0)

    # Check if any action flag was given
    has_action = any([
        args.interface, args.dns_only, args.http_only, args.tls_only,
        args.arp_only, args.icmp_only, args.bpf, args.host, args.net,
        args.port, args.duration, args.count,
    ])

    if not has_action:
        banner()
        main_menu()
        return

    # CLI mode
    banner()
    require_root("packet capture")

    cfg = SniffConfig()
    cfg.interface        = args.interface
    cfg.dns_only         = args.dns_only
    cfg.http_only        = args.http_only
    cfg.tls_only         = args.tls_only
    cfg.arp_only         = getattr(args, "arp_only", False)
    cfg.icmp_only        = getattr(args, "icmp_only", False)
    cfg.bpf              = args.bpf
    cfg.host             = args.host
    cfg.net              = args.net
    cfg.port             = args.port
    cfg.duration         = args.duration
    cfg.count            = args.count
    cfg.mask_output      = args.mask_output
    cfg.lab_mode         = args.lab_mode
    cfg.quiet            = args.quiet
    cfg.verbose          = args.verbose
    cfg.encrypt          = args.encrypt
    cfg.encrypt_password = args.encrypt_password
    cfg.json_path        = args.json
    cfg.csv_path         = args.csv
    cfg.web              = args.web
    cfg.daemon           = args.daemon
    cfg.pid_file         = args.pid_file
    cfg.show_top         = args.show_top
    cfg.scan_window      = args.scan_window
    cfg.scan_threshold   = args.scan_threshold
    cfg.save_to_db       = not args.no_db

    if cfg.daemon:
        daemonize(cfg.pid_file or None)

    app = OSniffer(cfg)
    app.run()

    if args.html:
        with suppress(Exception):
            app.export_html(args.html)
            ok(f"HTML report: {args.html}")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(run_self_test())
    signal.signal(signal.SIGINT, lambda s, f: (
        print(color("\n\n  [!] Interrupted — owlsec.org  🦉\n", C.YELLOW)),
        sys.exit(0)
    ))
    try:
        main()
    except KeyboardInterrupt:
        cprint("\n\n  [✔] Terminated — owlsec.org  🦉\n", C.YELLOW)
    except PermissionError as e:
        err(f"Permission denied: {e}")
        cprint("  [»] Run with: sudo osniffer", C.YELLOW)
        sys.exit(1)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (1 if e.code else 0)
        raise SystemExit(code)
    except Exception as e:
        err(f"Fatal error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()
        sys.exit(1)
