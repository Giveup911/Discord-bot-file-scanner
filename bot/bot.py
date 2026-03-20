"""
Discord RAT Scanner Bot
Accepts file uploads via /giverat, runs JarAnalyzer + VirusTotal + YARA + entropy
analysis + string extraction + manifest inspection + webhook killing, returns
color-coded results with log archives.
"""

import discord
from discord.ext import commands, tasks
import asyncio
import aiohttp
import aiofiles
import copy
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

# ─── Deobfuscation ──────────────────────────────────────────────────────────
# Add tools/ to path so we can import deobfuscators
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
try:
    from deobfuscate_dasho import deobfuscate_jar as _deobfuscate_jar
    DEOBFUSCATOR_AVAILABLE = True
except ImportError:
    DEOBFUSCATOR_AVAILABLE = False
try:
    from deobfuscate_generic import deobfuscate_jar as _deobfuscate_generic
    GENERIC_DEOBFUSCATOR_AVAILABLE = True
except ImportError:
    GENERIC_DEOBFUSCATOR_AVAILABLE = False

# ─── Logging ────────────────────────────────────────────────────────────────

from logging.handlers import RotatingFileHandler

_log_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
_log_dir = Path(__file__).resolve().parent / "logs"
_log_dir.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(
            str(_log_dir / f"scanner_{_log_ts}.log"), encoding="utf-8",
            maxBytes=50 * 1024 * 1024,  # 50 MB per log file
            backupCount=5,  # keep 5 rotated files
        ),
    ],
)
log = logging.getLogger("scanner")

# ─── Config ─────────────────────────────────────────────────────────────────

BOT_DIR = Path(__file__).resolve().parent
MASTER_DIR = BOT_DIR.parent
TOOLS_DIR = MASTER_DIR / "tools"
STATS_FILE = BOT_DIR / "stats.json"
CATALOG_FILE = BOT_DIR / "catalog.json"
EXCEPTIONS_FILE = BOT_DIR / "exceptions.var"
EXCEPTIONS_MD = BOT_DIR / "exceptions.md"
DEFAULT_CFG = {
    "discord": {
        "token": "",
        "guild_id": None,
        "allow_user_install": False,
        "allow_dms": False,
        "allow_external_guilds": False,
    },
    "virustotal": {"api_key": "", "enabled": True, "upload_unknown": False},
    "malwarebazaar": {"enabled": True, "auth_key": ""},
    "hybrid_analysis": {"api_key": "", "enabled": True},
    "scanner": {
        "java_path": "java",
        "max_file_size_mb": 100,
        "scan_timeout_seconds": 300,
        "max_concurrent_scans": 3,
        "cooldown_seconds": 30,
        "auto_delete_webhooks": True,
        "auto_cleanup_days": 30,
        "save_samples": False,
        "require_tor_for_urls": True,
        "tor_proxy": "socks5://127.0.0.1:9050",
    },
    "yara": {"enabled": True, "rules_dir": "rules"},
    "alerts": {
        "user_ids": [],
        "storage_threshold_gb": 10,
        "hourly_request_threshold": 20,
    },
}


def load_config() -> dict:
    cfg = copy.deepcopy(DEFAULT_CFG)
    yml_path = BOT_DIR / "config.yml"
    if yml_path.exists():
        with open(yml_path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        _deep_merge(cfg, user)
    if os.getenv("DISCORD_TOKEN"):
        cfg["discord"]["token"] = os.getenv("DISCORD_TOKEN")
    if os.getenv("VT_API_KEY"):
        cfg["virustotal"]["api_key"] = os.getenv("VT_API_KEY")
    if os.getenv("DISCORD_GUILD_ID"):
        cfg["discord"]["guild_id"] = os.getenv("DISCORD_GUILD_ID")
    if os.getenv("HA_API_KEY"):
        cfg["hybrid_analysis"]["api_key"] = os.getenv("HA_API_KEY")
    if os.getenv("MB_AUTH_KEY"):
        cfg["malwarebazaar"]["auth_key"] = os.getenv("MB_AUTH_KEY")
    return cfg


def _ask(prompt: str, default: str = "") -> str:
    """Prompt user for input with a default value. Empty input returns default."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


def _ask_bool(prompt: str, default: bool = False) -> bool:
    """Prompt user for a yes/no with a default."""
    default_str = "Y/n" if default else "y/N"
    try:
        val = input(f"{prompt} [{default_str}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not val:
        return default
    return val in ("y", "yes", "true", "1")


def run_setup():
    """Interactive first-time setup. Creates config.yml from user input."""
    yml_path = BOT_DIR / "config.yml"
    example_path = BOT_DIR / "config.yml.example"

    print("=" * 60)
    print("  RATScanner — First-Time Setup")
    print("=" * 60)
    print()
    print("No config.yml found. Let's set one up.")
    print("Press Enter to keep the default value shown in [brackets].")
    print()

    # ── Discord ──
    print("── Discord ──")
    token = _ask("Bot token (required)")
    guild_id = _ask("Guild/server ID (optional, speeds up command registration)", "")
    allow_user_install = _ask_bool("Allow users to install bot to their profile?", False)
    allow_dms = _ask_bool("Allow bot commands in DMs?", False)
    allow_external_guilds = _ask_bool("Allow bot in servers it hasn't been added to (via user install)?", False)
    print()

    # ── VirusTotal ──
    print("── VirusTotal ──")
    print("  Get a free API key: https://www.virustotal.com")
    print("  Sign in > click the 3 lines menu > API key")
    vt_key = _ask("VirusTotal API key (optional)", "")
    vt_enabled = bool(vt_key) if vt_key else False
    upload_unknown = _ask_bool("Upload unknown files to VT for analysis?", False) if vt_key else False
    print()

    # ── MalwareBazaar ──
    print("── MalwareBazaar ──")
    print("  Get a free auth key: https://bazaar.abuse.ch")
    print("  Create account > Profile > Profile Settings > Generate Key")
    mb_key = _ask("MalwareBazaar auth key (optional)", "")
    mb_enabled = bool(mb_key) if mb_key else False
    print()

    # ── Hybrid Analysis ──
    print("── Hybrid Analysis ──")
    print("  Get a free API key: https://www.hybrid-analysis.com")
    print("  Create account > Profile > API key > Create Key")
    print("  Then: User Data > Personal Data > Show > Download API key")
    ha_key = _ask("Hybrid Analysis API key (optional)", "")
    ha_enabled = bool(ha_key) if ha_key else False
    print()

    # ── Scanner ──
    print("── Scanner Settings ──")
    max_size = _ask("Max file size in MB", "50")
    save_samples = _ask_bool("Save scanned files to disk?", False)
    require_tor = _ask_bool("Require Tor for URL downloads? (recommended)", True)
    print()

    # ── Build config ──
    # Start from example if it exists, otherwise build from scratch
    if example_path.exists():
        with open(example_path, encoding="utf-8") as f:
            config_text = f.read()
    else:
        config_text = ""

    # Build the config dict
    cfg = {
        "discord": {
            "token": token,
            "allow_user_install": allow_user_install,
            "allow_dms": allow_dms,
            "allow_external_guilds": allow_external_guilds,
        },
        "virustotal": {
            "api_key": vt_key or "YOUR_VT_API_KEY_HERE",
            "enabled": vt_enabled,
            "upload_unknown": upload_unknown,
        },
        "malwarebazaar": {
            "enabled": mb_enabled,
            "auth_key": mb_key or "YOUR_MB_AUTH_KEY_HERE",
        },
        "hybrid_analysis": {
            "api_key": ha_key or "YOUR_HA_API_KEY_HERE",
            "enabled": ha_enabled,
        },
        "scanner": {
            "java_path": "java",
            "max_file_size_mb": int(max_size) if max_size.isdigit() else 50,
            "scan_timeout_seconds": 300,
            "max_concurrent_scans": 3,
            "cooldown_seconds": 30,
            "auto_delete_webhooks": True,
            "auto_cleanup_days": 30,
            "save_samples": save_samples,
            "require_tor_for_urls": require_tor,
            "tor_proxy": "socks5://127.0.0.1:9050",
        },
        "yara": {
            "enabled": True,
            "rules_dir": "rules",
        },
    }
    if guild_id:
        cfg["discord"]["guild_id"] = guild_id

    # Write config.yml
    with open(yml_path, "w", encoding="utf-8") as f:
        f.write("# RATScanner Discord Bot - Configuration\n")
        f.write("# Generated by first-time setup. Edit as needed.\n\n")
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print("=" * 60)
    print(f"  Config saved to {yml_path.name}")
    print("  Edit config.yml anytime to change settings.")
    print("=" * 60)
    print()

    return cfg


def _deep_merge(base: dict, override: dict):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


CFG = load_config()

# ─── Path Sanitizer ─────────────────────────────────────────────────────────
# Strips local filesystem paths from any text before it reaches Discord.

_SENSITIVE_PATHS: list[str] = []


def _build_sensitive_paths():
    """Collect paths that must never appear in Discord output."""
    _SENSITIVE_PATHS.clear()
    # user home and all parent dirs
    home = Path.home()
    _SENSITIVE_PATHS.append(str(home))
    # bot working dirs
    _SENSITIVE_PATHS.append(str(BOT_DIR))
    _SENSITIVE_PATHS.append(str(MASTER_DIR))
    _SENSITIVE_PATHS.append(str(TOOLS_DIR))
    # tempdir root
    _SENSITIVE_PATHS.append(tempfile.gettempdir())
    # common Windows user paths
    for env_var in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOME"):
        val = os.environ.get(env_var)
        if val:
            _SENSITIVE_PATHS.append(val)
    # sort longest first so longer paths are replaced before shorter prefixes
    _SENSITIVE_PATHS.sort(key=len, reverse=True)


_build_sensitive_paths()


def sanitize_path(text: str) -> str:
    """Remove any local filesystem paths from text."""
    if not text:
        return text
    result = text
    # Case-insensitive replacement on Windows
    for p in _SENSITIVE_PATHS:
        fwd = p.replace("\\", "/")
        # Use case-insensitive replacement
        result = re.sub(re.escape(fwd), "[redacted]", result, flags=re.IGNORECASE)
        result = re.sub(re.escape(p), "[redacted]", result, flags=re.IGNORECASE)
    # catch any remaining Windows-style user paths: C:\Users\<name>\...
    result = re.sub(r'[A-Za-z]:\\Users\\[^\\"\s]+', "[redacted]", result, flags=re.IGNORECASE)
    # catch AppData temp paths
    result = re.sub(r'[A-Za-z]:\\Users\\[^\\]+\\AppData\\[^\\]*\\Temp\\[^\s"]*', "[redacted]", result, flags=re.IGNORECASE)
    # catch Unix home paths
    result = re.sub(r'/home/[^/"\s]+', "[redacted]", result)
    # catch temp paths with scan prefixes
    result = re.sub(r'[A-Za-z]:\\[^\\]*[Tt]emp[^\\]*\\[^\s"]*scan_[^\s"]*', "[redacted]", result, flags=re.IGNORECASE)
    result = re.sub(r'/tmp/scan_[^\s"]*', "[redacted]", result)
    return result


def _clean_class_name(marker: str, class_map: dict) -> str:
    """Replace unreadable obfuscated class names with clean labels.

    Class names with heavy Unicode (combining chars, invisible chars, Hangul fillers)
    are unreadable in Discord and look scary. Replace them with 'obfuscated_class_N'.
    """
    # Extract class name from "(in <classname>.class)" pattern
    m = re.search(r'\(in (.+?)\.class\)', marker)
    if not m:
        return marker
    raw_name = m.group(1)
    # Check if the class name has significant non-ASCII characters
    non_ascii = sum(1 for c in raw_name if ord(c) > 127)
    if non_ascii < 3:
        return marker  # Normal class name, leave it
    # Map this obfuscated name to a clean label
    if raw_name not in class_map:
        class_map[raw_name] = f"obfuscated_class_{len(class_map) + 1}"
    clean = class_map[raw_name]
    return marker.replace(f"(in {raw_name}.class)", f"(in {clean}.class)")


# ─── Stats Persistence ──────────────────────────────────────────────────────


def load_stats() -> dict:
    if STATS_FILE.exists():
        try:
            return json.loads(STATS_FILE.read_text())
        except Exception:
            pass
    return {"total_scans": 0, "detections": 0, "clean": 0, "webhooks_killed": 0,
            "files_sent_to_vt": 0, "files_sent_to_ha": 0, "mb_hits": 0}


def save_stats(stats: dict):
    try:
        fd, tmp = tempfile.mkstemp(dir=str(STATS_FILE.parent), suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(stats, f, indent=2)
        os.replace(tmp, STATS_FILE)
    except Exception as e:
        log.warning(f"Failed to save stats: {e}")


scan_stats = load_stats()
_stats_lock = asyncio.Lock()


async def update_stats(**increments):
    """Thread-safe stat update. Usage: await update_stats(total_scans=1, detections=1)"""
    async with _stats_lock:
        for key, delta in increments.items():
            scan_stats[key] = scan_stats.get(key, 0) + delta
        save_stats(scan_stats)


# ─── Alert System ──────────────────────────────────────────────────────────

_hourly_requests: list[float] = []  # timestamps of scan requests in last hour
_alert_cooldowns: dict[str, float] = {}  # alert_type -> last_sent_time (prevent spam)
ALERT_COOLDOWN_SECONDS = 600  # don't repeat same alert within 10 minutes


def _get_alert_user_ids() -> list[int]:
    """Return configured alert recipient user IDs."""
    raw = CFG.get("alerts", {}).get("user_ids", [])
    if not isinstance(raw, list):
        return []
    result = []
    for uid in raw:
        try:
            result.append(int(uid))
        except (ValueError, TypeError):
            log.warning(f"Invalid alert user_id in config: {uid!r}")
    return result


def _get_storage_usage_bytes() -> int:
    """Calculate total disk usage of scanned files, logs, and samples."""
    total = 0
    for check_dir in [MASTER_DIR / "logs", MASTER_DIR / "scanned",
                      BOT_DIR / "logs", MASTER_DIR / "PUT_JAR_HERE"]:
        if check_dir.exists():
            for entry in check_dir.rglob("*"):
                try:
                    if entry.is_file():
                        total += entry.stat().st_size
                except OSError:
                    pass
    return total


def _track_hourly_request():
    """Record a scan request timestamp and prune entries older than 1 hour."""
    now = time.time()
    _hourly_requests.append(now)
    cutoff = now - 3600
    while _hourly_requests and _hourly_requests[0] < cutoff:
        _hourly_requests.pop(0)


def _hourly_request_count() -> int:
    """Return number of scan requests in the last rolling hour."""
    now = time.time()
    cutoff = now - 3600
    while _hourly_requests and _hourly_requests[0] < cutoff:
        _hourly_requests.pop(0)
    return len(_hourly_requests)


async def send_alert(alert_type: str, title: str, description: str):
    """Send a DM alert to all configured alert user IDs. Respects cooldown."""
    now = time.time()
    last_sent = _alert_cooldowns.get(alert_type, 0)
    if now - last_sent < ALERT_COOLDOWN_SECONDS:
        return  # cooldown active, don't spam

    user_ids = _get_alert_user_ids()
    if not user_ids:
        return

    _alert_cooldowns[alert_type] = now
    log.warning(f"ALERT [{alert_type}]: {title} — {description}")

    for uid in user_ids:
        try:
            user = await bot.fetch_user(uid)
            dm = await user.create_dm()
            embed = discord.Embed(
                title=f"\u26A0\uFE0F Alert: {title}",
                description=description,
                color=0xFF6600,
                timestamp=datetime.now(tz=timezone.utc),
            )
            embed.set_footer(text=f"RATScanner Alert • {alert_type}")
            await dm.send(embed=embed)
        except Exception as e:
            log.warning(f"Failed to send alert DM to {uid}: {e}")

# ─── File Catalog ────────────────────────────────────────────────────────────


def load_catalog() -> dict:
    if CATALOG_FILE.exists():
        try:
            return json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_catalog(catalog: dict):
    try:
        fd, tmp = tempfile.mkstemp(dir=str(CATALOG_FILE.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=2)
        os.replace(tmp, CATALOG_FILE)
    except Exception as e:
        log.warning(f"Failed to save catalog: {e}")


file_catalog = load_catalog()
_catalog_lock = asyncio.Lock()
_sha256_locks: dict[str, asyncio.Lock] = {}
_sha256_locks_guard = asyncio.Lock()


async def _get_sha256_lock(sha256: str) -> asyncio.Lock:
    """Get or create a per-SHA256 lock for archive+catalog atomicity."""
    async with _sha256_locks_guard:
        if sha256 not in _sha256_locks:
            _sha256_locks[sha256] = asyncio.Lock()
        lock = _sha256_locks[sha256]
        # Evict unlocked entries to prevent unbounded growth
        if len(_sha256_locks) > 1000:
            to_remove = [k for k, v in _sha256_locks.items() if not v.locked()]
            for k in to_remove:
                del _sha256_locks[k]
            # Re-add our lock in case it was evicted
            _sha256_locks[sha256] = lock
        return lock


async def catalog_update(sha256: str, entry: dict):
    async with _catalog_lock:
        file_catalog[sha256] = entry
        save_catalog(file_catalog)


async def catalog_lookup(sha256: str) -> Optional[dict]:
    async with _catalog_lock:
        return file_catalog.get(sha256)

# ─── Exception List ──────────────────────────────────────────────────────────

def load_exceptions() -> set:
    """Load approved exception hashes from exceptions.var"""
    hashes = set()
    if EXCEPTIONS_FILE.exists():
        for line in EXCEPTIONS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Take just the hash part (before any comment)
            h = line.split()[0].strip().lower()
            if len(h) == 64:  # SHA-256 length
                hashes.add(h)
    return hashes

approved_exceptions = load_exceptions()

async def check_exception(sha256: str) -> bool:
    """Check if a file hash is in the approved exceptions list."""
    return sha256.lower() in approved_exceptions

async def write_exception_candidate(filename: str, sha256: str, file_size: int,
                                      score: int, level: str, variant: str,
                                      extracted_urls: list, url_hash_matches: list):
    """Write a candidate to exceptions.md for user review."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    entry = f"\n## {filename} — {now}\n"
    entry += f"- **SHA-256:** `{sha256}`\n"
    entry += f"- **File size:** {file_size:,} bytes\n"
    entry += f"- **Score:** {score}/100 ({level})\n"
    if variant and variant.lower() != "unknown":
        entry += f"- **Variant detected:** {variant}\n"
    if extracted_urls:
        entry += f"- **URLs found in file:**\n"
        for u in extracted_urls[:10]:
            entry += f"  - `{u}`\n"
    if url_hash_matches:
        entry += f"- **Hash verification results:**\n"
        for match in url_hash_matches:
            status = "MATCH" if match.get("matches") else "NO MATCH" if match.get("hash_found") else "No hash found on page"
            entry += f"  - `{match['url'][:80]}` — {status}\n"
            if match.get("page_hash"):
                entry += f"    Page hash: `{match['page_hash']}`\n"

    recommendation = "Unknown"
    if any(m.get("matches") for m in url_hash_matches):
        recommendation = "LIKELY SAFE — SHA-256 matches hash published on official source. Consider adding to exceptions.var"
    elif extracted_urls and not url_hash_matches:
        recommendation = "Could not verify — no hashes found on linked pages"
    else:
        recommendation = "Could not verify — hash does not match any published hash"
    entry += f"- **Recommendation:** {recommendation}\n"
    entry += f"\nTo approve, add this line to `exceptions.var`:\n```\n{sha256}  # {filename}\n```\n---\n"

    # Append to exceptions.md
    try:
        header = "# Exception Candidates\n\nFiles listed here were auto-researched by the scanner. Review and add approved hashes to `exceptions.var`.\n\n---\n"
        if EXCEPTIONS_MD.exists():
            existing = EXCEPTIONS_MD.read_text(encoding="utf-8")
        else:
            existing = header

        # Don't duplicate entries for the same hash
        if sha256 in existing:
            return

        EXCEPTIONS_MD.write_text(existing + entry, encoding="utf-8")
        log.info(f"Exception candidate written for {filename} ({sha256[:16]}...)")
    except Exception as e:
        log.warning(f"Failed to write exception candidate: {e}")


async def auto_research_urls(urls: list, sha256: str, session: aiohttp.ClientSession) -> list:
    """Try to find hash verification on download pages."""
    results = []
    # Only check URLs that look like download/release pages
    research_domains = [
        "github.com", "modrinth.com", "curseforge.com", "spigotmc.org",
        "bukkit.org", "hangar.papermc.io", "polymart.org",
        "builtbybit.com", "mc-market.org",
    ]

    candidate_urls = []
    for u in urls:
        if any(d in u for d in research_domains):
            candidate_urls.append(u)

    if not candidate_urls:
        return results

    for url in candidate_urls[:3]:  # Max 3 URLs to check
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()

                # Look for SHA-256 hashes on the page
                hash_pattern = re.compile(r'\b([a-fA-F0-9]{64})\b')
                found_hashes = hash_pattern.findall(text)

                result = {"url": url, "hash_found": False, "matches": False, "page_hash": None}
                for h in found_hashes:
                    result["hash_found"] = True
                    result["page_hash"] = h.lower()
                    if h.lower() == sha256.lower():
                        result["matches"] = True
                        break
                results.append(result)
        except Exception as e:
            log.debug(f"Auto-research failed for {url}: {e}")

    return results

# ─── YARA (optional) ────────────────────────────────────────────────────────

YARA_AVAILABLE = False
yara = None
YARA_RULES = None

try:
    import yara as _yara
    yara = _yara
    YARA_AVAILABLE = True
except ImportError:
    log.warning("yara-python not installed — YARA scanning disabled. pip install yara-python to enable.")


def load_yara_rules():
    global YARA_RULES
    if not YARA_AVAILABLE or not CFG["yara"]["enabled"]:
        return
    rules_dir = BOT_DIR / CFG["yara"]["rules_dir"]
    if not rules_dir.is_dir():
        rules_dir.mkdir(parents=True, exist_ok=True)
        log.info(f"Created YARA rules directory: {rules_dir}")
        return
    yar_files = list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
    if not yar_files:
        log.info("No YARA rule files found in rules/")
        return
    # Use relative path as namespace to avoid stem collisions across repos
    filepaths = {}
    for f in yar_files:
        ns = f.relative_to(rules_dir).as_posix().replace("/", "_").replace(".", "_")
        filepaths[ns] = str(f)
    # Compile rules one-by-one and skip broken files
    compiled_sources = {}
    skipped = 0
    for ns, path in filepaths.items():
        try:
            yara.compile(filepath=path)
            compiled_sources[ns] = path
        except Exception:
            skipped += 1
    if not compiled_sources:
        log.warning(f"All {len(filepaths)} YARA files failed to compile")
        return
    try:
        YARA_RULES = yara.compile(filepaths=compiled_sources)
        log.info(f"Loaded {len(compiled_sources)} YARA rule file(s) ({skipped} skipped due to errors)")
    except Exception as e:
        log.error(f"Failed to compile YARA rules: {e}")


def run_yara(filepath: str) -> list[dict]:
    if YARA_RULES is None:
        return []
    try:
        # Suppress stdout from YARA console module (some rules use console.log/console.hex)
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            matches = YARA_RULES.match(filepath, timeout=60)
        return [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
    except Exception as e:
        log.warning(f"YARA scan error: {e}")
        return []


# ─── VirusTotal ──────────────────────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"

# VT free tier: 4 requests/minute, 500/day. Use a lock to serialize.
_vt_rate_lock: Optional[asyncio.Lock] = None
_vt_last_request: float = 0.0


async def _vt_rate_limit():
    """Ensure at least 15 seconds between VT API calls (4/min limit)."""
    global _vt_rate_lock, _vt_last_request
    if _vt_rate_lock is None:
        _vt_rate_lock = asyncio.Lock()
    async with _vt_rate_lock:
        now = time.time()
        elapsed = now - _vt_last_request
        if elapsed < 15:
            await asyncio.sleep(15 - elapsed)
        _vt_last_request = time.time()


async def vt_lookup(sha256: str, session: aiohttp.ClientSession) -> Optional[dict]:
    log.info(f"vt_lookup called for {sha256[:16]}...")
    api_key = CFG["virustotal"]["api_key"]
    if not api_key or not CFG["virustotal"]["enabled"]:
        return None
    headers = {"x-apikey": api_key}
    await _vt_rate_limit()
    try:
        async with session.get(f"{VT_BASE}/files/{sha256}", headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                detections = {}
                for name, r in results.items():
                    if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
                        detections[name] = r.get("result", "detected")
                return {
                    "detected": stats.get("malicious", 0) + stats.get("suspicious", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "detections": detections,
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                    "meaningful_name": attrs.get("meaningful_name", ""),
                    "tags": attrs.get("tags", []),
                    "first_seen": attrs.get("first_submission_date"),
                    "status": "found",
                }
            elif resp.status == 404:
                return None
            else:
                log.warning(f"VT lookup returned {resp.status}")
                return None
    except Exception as e:
        log.warning(f"VT lookup failed: {e}")
        return None


async def vt_upload(filepath: str, sha256: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Upload file to VT, poll for completion, always return a permalink."""
    api_key = CFG["virustotal"]["api_key"]
    if not api_key or not CFG["virustotal"]["upload_unknown"]:
        return None
    headers = {"x-apikey": api_key}
    permalink = f"https://www.virustotal.com/gui/file/{sha256}"
    await _vt_rate_limit()
    try:
        file_size = os.path.getsize(filepath)
        if file_size > 32 * 1024 * 1024:
            async with session.get(f"{VT_BASE}/files/upload_url", headers=headers) as resp:
                if resp.status != 200:
                    return {"detected": 0, "total": 0, "detections": {}, "permalink": permalink,
                            "meaningful_name": "", "tags": [], "first_seen": None, "status": "upload_failed"}
                upload_url = (await resp.json())["data"]
        else:
            upload_url = f"{VT_BASE}/files"

        with open(filepath, "rb") as fh:
            data = aiohttp.FormData()
            data.add_field("file", fh, filename=os.path.basename(filepath))
            async with session.post(upload_url, headers=headers, data=data) as resp:
                if resp.status != 200:
                    log.warning(f"VT upload returned {resp.status}")
                    return {"detected": 0, "total": 0, "detections": {}, "permalink": permalink,
                            "meaningful_name": "", "tags": [], "first_seen": None, "status": "upload_failed"}
                result = await resp.json()
                analysis_id = result["data"]["id"]

        await update_stats(files_sent_to_vt=1)

        # Poll for completion with longer total wait
        for wait in [5, 10, 15, 20, 30, 40, 50, 60]:
            await asyncio.sleep(wait)
            await _vt_rate_limit()
            async with session.get(
                f"{VT_BASE}/analyses/{analysis_id}", headers=headers
            ) as resp:
                if resp.status != 200:
                    continue
                analysis = await resp.json()
                if analysis["data"]["attributes"]["status"] == "completed":
                    stats = analysis["data"]["attributes"]["stats"]
                    file_info = analysis["data"]["attributes"].get("results", {})
                    detections = {}
                    for name, r in file_info.items():
                        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
                            detections[name] = r.get("result", "")
                    return {
                        "detected": stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "total": sum(stats.values()),
                        "detections": detections,
                        "permalink": permalink,
                        "meaningful_name": "",
                        "tags": [],
                        "first_seen": None,
                        "status": "completed",
                    }

        # Timed out but still return a link — analysis is queued on VT
        log.warning("VT upload analysis timed out — returning queued permalink")
        return {
            "detected": 0, "total": 0, "detections": {},
            "permalink": permalink,
            "meaningful_name": "", "tags": [], "first_seen": None,
            "status": "queued",
        }
    except Exception as e:
        log.warning(f"VT upload failed: {e}")
        return {"detected": 0, "total": 0, "detections": {}, "permalink": permalink,
                "meaningful_name": "", "tags": [], "first_seen": None, "status": "error"}


# ─── MalwareBazaar ────────────────────────────────────────────────────────────

MB_API = "https://mb-api.abuse.ch/api/v1/"


async def mb_lookup(sha256: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Query MalwareBazaar by SHA-256 hash."""
    log.info(f"mb_lookup called for {sha256[:16]}...")
    if not CFG.get("malwarebazaar", {}).get("enabled", True):
        log.info("mb_lookup: disabled in config")
        return None
    permalink = f"https://bazaar.abuse.ch/sample/{sha256}/"
    try:
        mb_headers = {}
        mb_auth = CFG.get("malwarebazaar", {}).get("auth_key", "")
        if mb_auth and not mb_auth.startswith("YOUR_"):
            mb_headers["Auth-Key"] = mb_auth
        async with session.post(
            MB_API,
            headers=mb_headers,
            data={"query": "get_info", "hash": sha256},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 401:
                log.warning("MalwareBazaar: 401 Unauthorized — auth_key may be required or invalid")
                return {"status": "error", "permalink": permalink}
            if resp.status != 200:
                log.warning(f"MalwareBazaar returned {resp.status}")
                return {"status": "error", "permalink": permalink}
            result = await resp.json(content_type=None)
            query_status = result.get("query_status", "")
            if query_status == "hash_not_found" or query_status == "no_results":
                return {"status": "not_found", "permalink": permalink}
            if query_status != "ok":
                log.warning(f"MalwareBazaar query_status: {query_status}")
                return {"status": "not_found", "permalink": permalink}
            sample = result["data"][0]
            tags = sample.get("tags") or []
            return {
                "signature": sample.get("signature", ""),
                "file_type": sample.get("file_type", ""),
                "reporter": sample.get("reporter", ""),
                "tags": tags if isinstance(tags, list) else [],
                "first_seen": sample.get("first_seen", ""),
                "delivery_method": sample.get("delivery_method", ""),
                "downloads": sample.get("intelligence", {}).get("downloads", 0),
                "uploads": sample.get("intelligence", {}).get("uploads", 0),
                "permalink": permalink,
                "status": "found",
            }
    except Exception as e:
        log.warning(f"MalwareBazaar lookup failed: {type(e).__name__}: {e}")
        return {"status": "error", "permalink": permalink}


async def mb_upload(filepath: str, sha256: str, session: aiohttp.ClientSession,
                    tags: list[str] = None, comment: str = None) -> Optional[dict]:
    """Upload a flagged malware sample to MalwareBazaar."""
    mb_auth = CFG.get("malwarebazaar", {}).get("auth_key", "")
    if not mb_auth or mb_auth.startswith("YOUR_") or not CFG.get("malwarebazaar", {}).get("enabled", True):
        return None
    permalink = f"https://bazaar.abuse.ch/sample/{sha256}/"
    try:
        json_meta = {"anonymous": 0}
        if tags:
            json_meta["tags"] = tags[:10]
        if comment:
            json_meta["context"] = {"comment": comment[:500]}

        with open(filepath, "rb") as fh:
            data = aiohttp.FormData()
            data.add_field("json_data", json.dumps(json_meta), content_type="application/json")
            data.add_field(
                "file", fh,
                filename=os.path.basename(filepath),
                content_type="application/octet-stream",
            )
            async with session.post(
                MB_API,
                headers={"Auth-Key": mb_auth},
                data=data,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                body = await resp.text()
                if resp.status == 200:
                    try:
                        result = json.loads(body)
                    except Exception:
                        result = {}
                    status = result.get("query_status", "")
                    if status == "ok":
                        log.info(f"MalwareBazaar: sample uploaded successfully ({sha256})")
                        return {"status": "uploaded", "permalink": permalink,
                                "sha256_hash": result.get("data", [{}])[0].get("sha256_hash", sha256)}
                    elif "already" in status.lower() or "exists" in body.lower():
                        log.info(f"MalwareBazaar: sample already exists ({sha256})")
                        return {"status": "already_exists", "permalink": permalink}
                    else:
                        log.warning(f"MalwareBazaar upload query_status: {status} — {body[:200]}")
                        return {"status": "upload_failed", "permalink": permalink, "detail": status}
                else:
                    log.warning(f"MalwareBazaar upload returned {resp.status}: {body[:200]}")
                    return {"status": "upload_failed", "permalink": permalink, "detail": f"HTTP {resp.status}"}
    except Exception as e:
        log.warning(f"MalwareBazaar upload failed: {e}")
        return {"status": "upload_failed", "permalink": permalink, "detail": str(e)}


# ─── Hybrid Analysis ─────────────────────────────────────────────────────────

HA_BASE = "https://hybrid-analysis.com/api/v2"


async def ha_search(sha256: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Search Hybrid Analysis by hash."""
    log.info(f"ha_search called for {sha256[:16]}...")
    api_key = CFG.get("hybrid_analysis", {}).get("api_key", "")
    if not api_key or not CFG.get("hybrid_analysis", {}).get("enabled", True):
        log.info(f"ha_search: disabled (api_key={'set' if api_key else 'EMPTY'}, enabled={CFG.get('hybrid_analysis', {}).get('enabled', True)})")
        return None
    permalink = f"https://www.hybrid-analysis.com/sample/{sha256}"
    headers = {
        "api-key": api_key,
        "User-Agent": "Falcon",
        "accept": "application/json",
    }
    try:
        # HA v2 search/hash — GET (POST was deprecated in API v2.35.0)
        async with session.get(
            f"{HA_BASE}/search/hash",
            headers=headers,
            params={"hash": sha256},
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            body = await resp.text()
            if resp.status == 404:
                # HA returns 404 when hash is not in their database
                log.info(f"Hybrid Analysis: hash not found ({sha256[:16]}...)")
                return {"status": "not_found", "permalink": permalink}
            if resp.status == 403:
                log.warning(f"Hybrid Analysis: 403 Forbidden — API key may be invalid. Body: {body[:300]}")
                return {"status": "error", "error": "API key invalid or rate limited", "permalink": permalink}
            if resp.status == 429:
                log.warning(f"Hybrid Analysis: 429 rate limited")
                return {"status": "error", "error": "Rate limited", "permalink": permalink}
            if resp.status != 200:
                log.warning(f"Hybrid Analysis search returned {resp.status}: {body[:300]}")
                return {"status": "error", "error": f"HTTP {resp.status}", "permalink": permalink}
            try:
                data = await resp.json(content_type=None)
            except Exception:
                log.warning(f"Hybrid Analysis: failed to parse JSON: {body[:300]}")
                return {"status": "error", "error": "Invalid response", "permalink": permalink}
            # HA v2 response format: {"sha256s": [...], "reports": [...]}
            # or sometimes a flat list of report dicts
            reports = []
            if isinstance(data, dict) and "reports" in data:
                reports = data["reports"]
            elif isinstance(data, list):
                reports = data
            elif isinstance(data, dict) and data.get("sha256"):
                reports = [data]
            if not reports:
                return {"status": "not_found", "permalink": permalink}
            # Filter to completed reports with verdicts
            completed = [r for r in reports if r.get("verdict") and r.get("state") == "SUCCESS"]
            if not completed:
                # Have reports but none completed successfully
                best = reports[0]
            else:
                best = max(completed, key=lambda r: r.get("threat_score") or 0)
            return {
                "verdict": best.get("verdict", ""),
                "threat_score": best.get("threat_score"),
                "threat_level": best.get("threat_level"),
                "analysis_start_time": best.get("analysis_start_time", ""),
                "environment": best.get("environment_description", ""),
                "permalink": permalink,
                "status": "found",
            }
    except asyncio.TimeoutError:
        log.warning("Hybrid Analysis search timed out")
        return {"status": "error", "error": "Timeout", "permalink": permalink}
    except Exception as e:
        log.warning(f"Hybrid Analysis search failed: {e}")
        return {"status": "error", "error": str(e), "permalink": permalink}


async def ha_submit(filepath: str, sha256: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Submit file to Hybrid Analysis for sandbox analysis."""
    api_key = CFG.get("hybrid_analysis", {}).get("api_key", "")
    if not api_key or not CFG.get("hybrid_analysis", {}).get("enabled", True):
        return None
    headers = {"api-key": api_key, "User-Agent": "Falcon", "accept": "application/json"}
    permalink = f"https://www.hybrid-analysis.com/sample/{sha256}"
    try:
        with open(filepath, "rb") as fh:
            data = aiohttp.FormData()
            data.add_field("file", fh, filename=os.path.basename(filepath))
            data.add_field("environment_id", "160")  # Windows 10 64-bit
            async with session.post(
                f"{HA_BASE}/submit/file", headers=headers, data=data,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status in (200, 201):
                    result = await resp.json()
                    await update_stats(files_sent_to_ha=1)
                    return {
                        "verdict": "",
                        "threat_score": None,
                        "job_id": result.get("job_id", ""),
                        "environment": "Windows 10 64-bit",
                        "permalink": permalink,
                        "status": "submitted",
                    }
                else:
                    body = await resp.text()
                    log.warning(f"Hybrid Analysis submit returned {resp.status}: {body[:200]}")
                    return {"permalink": permalink, "status": "submit_failed"}
    except Exception as e:
        log.warning(f"Hybrid Analysis submit failed: {e}")
        return {"permalink": permalink, "status": "error"}


async def ha_search_or_submit(
    sha256: str, filepath: str, session: aiohttp.ClientSession
) -> Optional[dict]:
    """Search HA first; if not found, submit the file."""
    result = await ha_search(sha256, session)
    if result and result.get("status") == "found":
        return result
    # If search returned error (bad key, rate limit), don't try to submit
    if result and result.get("status") == "error":
        return result
    # Not found — submit for sandbox analysis
    submit_result = await ha_submit(filepath, sha256, session)
    return submit_result if submit_result else result


# ─── VirusTotal Sandbox/Behavior Links ───────────────────────────────────────


async def vt_get_sandbox_links(sha256: str, session: aiohttp.ClientSession) -> Optional[list]:
    """Get VT sandbox behavior report links."""
    api_key = CFG["virustotal"]["api_key"]
    if not api_key or not CFG["virustotal"]["enabled"]:
        return None
    headers = {"x-apikey": api_key}
    await _vt_rate_limit()
    try:
        async with session.get(
            f"{VT_BASE}/files/{sha256}/behaviours",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            reports = data.get("data", [])
            if not reports:
                return None
            results = []
            for report in reports[:2]:
                attrs = report.get("attributes", {})
                sandbox_name = attrs.get("sandbox_name", "Unknown Sandbox")
                analysis_date = attrs.get("analysis_date", "")
                results.append({
                    "sandbox_name": sandbox_name,
                    "analysis_date": analysis_date,
                    "link": f"https://www.virustotal.com/gui/file/{sha256}/behavior",
                })
            return results
    except Exception as e:
        log.warning(f"VT sandbox links failed: {e}")
        return None


# ─── Background Pollers (VT / HA) ────────────────────────────────────────────


def _track_poll_task(coro):
    """Create a background task and prevent GC by storing a reference."""
    task = asyncio.create_task(coro)
    _background_poll_tasks.add(task)
    task.add_done_callback(_background_poll_tasks.discard)
    return task


async def _poll_vt_completion(
    sha256: str,
    msg: "discord.Message",
    scan_id: str,
):
    """Background poller: wait for a queued VT analysis to finish, then edit the message."""
    api_key = CFG["virustotal"]["api_key"]
    if not api_key:
        return
    headers = {"x-apikey": api_key}
    permalink = f"https://www.virustotal.com/gui/file/{sha256}"
    # Use our own session so we're immune to reconnect session swaps
    async with aiohttp.ClientSession() as poll_session:
        # Poll every 30s for up to 10 minutes
        for _ in range(20):
            await asyncio.sleep(30)
            try:
                async with poll_session.get(
                    f"{VT_BASE}/files/{sha256}", headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    total = sum(stats.values())
                    if total < 10:
                        continue  # Still too early
                    results = attrs.get("last_analysis_results", {})
                    detections = {
                        name: r["result"]
                        for name, r in results.items()
                        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
                    }
                    vt_result = {
                        "detected": stats.get("malicious", 0) + stats.get("suspicious", 0),
                        "total": total,
                        "detections": detections,
                        "permalink": permalink,
                        "meaningful_name": attrs.get("meaningful_name", ""),
                        "tags": attrs.get("tags", []),
                        "first_seen": attrs.get("first_submission_date"),
                        "status": "found",
                    }
                    await msg.edit(embed=build_vt_embed(vt_result, sha256, scan_id))
                    log.info(f"[{scan_id}] VT poll: analysis complete ({vt_result['detected']}/{vt_result['total']})")
                    return
            except discord.HTTPException:
                return  # Message was deleted or we lost access
            except Exception as exc:
                log.debug(f"VT poll error: {exc}")
    # Timed out — leave the message as-is (already shows permalink)


async def _poll_ha_completion(
    sha256: str,
    msg: "discord.Message",
    scan_id: str,
):
    """Background poller: wait for a submitted HA sandbox run to finish, then edit the message."""
    api_key = CFG.get("hybrid_analysis", {}).get("api_key", "")
    if not api_key:
        return
    headers = {"api-key": api_key, "User-Agent": "Falcon", "accept": "application/json"}
    # Use our own session so we're immune to reconnect session swaps
    async with aiohttp.ClientSession() as poll_session:
        # Poll every 60s for up to 15 minutes
        for _ in range(15):
            await asyncio.sleep(60)
            try:
                async with poll_session.get(
                    f"{HA_BASE}/search/hash",
                    headers=headers,
                    params={"hash": sha256},
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json(content_type=None)
                    reports = []
                    if isinstance(data, dict) and "reports" in data:
                        reports = data["reports"]
                    elif isinstance(data, list):
                        reports = data
                    elif isinstance(data, dict) and data.get("sha256"):
                        reports = [data]
                    completed = [r for r in reports if r.get("verdict") and r.get("state") == "SUCCESS"]
                    if not completed:
                        continue
                    best = max(completed, key=lambda r: r.get("threat_score") or 0)
                    ha_result = {
                        "verdict": best.get("verdict", ""),
                        "threat_score": best.get("threat_score"),
                        "threat_level": best.get("threat_level"),
                        "analysis_start_time": best.get("analysis_start_time", ""),
                        "environment": best.get("environment_description", ""),
                        "permalink": f"https://www.hybrid-analysis.com/sample/{sha256}",
                        "status": "found",
                    }
                    await msg.edit(embed=build_ha_embed(ha_result, sha256, scan_id))
                    log.info(f"[{scan_id}] HA poll: sandbox complete (verdict={ha_result['verdict']})")
                    return
            except discord.HTTPException:
                return
            except Exception as exc:
                log.debug(f"HA poll error: {exc}")


# ─── Entropy Analysis ────────────────────────────────────────────────────────


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 - 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def analyze_entropy(filepath: str) -> dict:
    """Analyze entropy of JAR contents. High entropy = packed/encrypted."""
    results = {"overall": 0.0, "suspicious_entries": [], "max_class_entropy": 0.0}
    try:
        # Compute overall entropy from ZIP entries to avoid reading raw file twice
        all_counts = [0] * 256
        total_bytes = 0
        with zipfile.ZipFile(filepath, "r") as zf:
            for entry in zf.namelist():
                try:
                    data = zf.read(entry)
                    if not data:
                        continue
                    # Accumulate byte counts for overall entropy
                    for b in data:
                        all_counts[b] += 1
                    total_bytes += len(data)
                    if len(data) < 64:
                        continue
                    ent = shannon_entropy(data)
                    if entry.endswith(".class") and ent > results["max_class_entropy"]:
                        results["max_class_entropy"] = round(ent, 2)
                    if ent > 7.5 and len(data) > 512:
                        results["suspicious_entries"].append({
                            "name": entry,
                            "entropy": round(ent, 2),
                            "size": len(data),
                        })
                except Exception:
                    pass
        # Compute overall entropy from accumulated counts
        if total_bytes > 0:
            ent = 0.0
            for c in all_counts:
                if c > 0:
                    p = c / total_bytes
                    ent -= p * math.log2(p)
            results["overall"] = round(ent, 2)
    except Exception:
        pass
    return results


# ─── Manifest Inspection ────────────────────────────────────────────────────

SUSPICIOUS_MANIFEST_KEYS = [
    "Premain-Class",
    "Agent-Class",
    "Launcher-Agent-Class",
    "Boot-Class-Path",
    "Can-Redefine-Classes",
    "Can-Retransform-Classes",
]


def inspect_manifest(filepath: str) -> dict:
    """Parse JAR manifest for suspicious entries."""
    result = {"main_class": None, "suspicious_keys": [], "permissions": [], "raw": ""}
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            if "META-INF/MANIFEST.MF" not in zf.namelist():
                return result
            raw = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            result["raw"] = raw
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("Main-Class:"):
                    result["main_class"] = line.split(":", 1)[1].strip()
                for key in SUSPICIOUS_MANIFEST_KEYS:
                    if line.startswith(key + ":"):
                        result["suspicious_keys"].append(line)
                if "Permissions:" in line:
                    result["permissions"].append(line)
    except Exception:
        pass
    return result


# ─── Raw String Extraction ──────────────────────────────────────────────────

STRING_PATTERNS = {
    "urls": re.compile(rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,200}'),
    "discord_webhooks": re.compile(rb'https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[\w\-]+'),
    "discord_tokens": re.compile(rb'[MN][A-Za-z\d]{23,27}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,}'),
    "ipv4": re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "eth_addresses": re.compile(rb'0x[0-9a-fA-F]{40}'),
}

IGNORE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "1.0.0.0", "1.0.0.1"}


def extract_strings(filepath: str) -> dict:
    """Extract suspicious strings from raw file bytes and JAR entries."""
    found = {k: set() for k in STRING_PATTERNS}
    try:
        with open(filepath, "rb") as f:
            raw = f.read(20 * 1024 * 1024)  # Cap at 20 MB to prevent OOM
        _scan_bytes(raw, found)

        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                for entry in zf.namelist():
                    if entry.endswith((".class", ".class/", ".properties", ".json", ".yml", ".xml", ".txt", ".cfg")):
                        try:
                            data = zf.read(entry)
                            _scan_bytes(data, found)
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception:
        pass

    result = {}
    for k, v in found.items():
        cleaned = set()
        for s in v:
            s_str = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
            if k == "ipv4":
                if s_str in IGNORE_IPS:
                    continue
                try:
                    addr = ipaddress.ip_address(s_str)
                    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
                        continue
                    cleaned.add(s_str)
                except ValueError:
                    continue
            else:
                cleaned.add(s_str)
        if cleaned:
            result[k] = sorted(cleaned)
    return result


def _scan_bytes(data: bytes, found: dict):
    for key, pattern in STRING_PATTERNS.items():
        for m in pattern.finditer(data):
            found[key].add(m.group())


# ─── Webhook Killer ──────────────────────────────────────────────────────────


_WEBHOOK_PATTERN = re.compile(r'^https?://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[\w\-]+$')


async def kill_webhook(webhook_url: str, session: aiohttp.ClientSession) -> str:
    """Attempt to DELETE a malicious Discord webhook. Returns status string."""
    if not CFG["scanner"].get("auto_delete_webhooks", True):
        return "skipped (disabled)"
    if not _WEBHOOK_PATTERN.match(webhook_url):
        log.warning(f"Rejected non-Discord webhook URL: {webhook_url[:80]}")
        return "skipped (invalid URL)"
    try:
        async with session.delete(webhook_url) as resp:
            if resp.status == 204:
                await update_stats(webhooks_killed=1)
                return "KILLED"
            elif resp.status == 404:
                return "already dead"
            else:
                return f"failed ({resp.status})"
    except Exception as e:
        return f"error ({e})"


# ─── Multi-Format File Analysis ──────────────────────────────────────────────

# Optional PE analysis
PEFILE_AVAILABLE = False
pefile_mod = None
try:
    import pefile as _pefile
    pefile_mod = _pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pass

# Optional OLE analysis (for Office docs, MSI)
OLEFILE_AVAILABLE = False
olefile_mod = None
try:
    import olefile as _olefile
    olefile_mod = _olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    pass

# Magic byte signatures
MAGIC_SIGS = {
    "pe":    b"MZ",
    "pdf":   b"%PDF",
    "zip":   b"PK",
    "ole":   b"\xd0\xcf\x11\xe0",  # OLE2 (doc, xls, msi, ppt)
    "lnk":   b"\x4c\x00\x00\x00",
    "rar":   b"Rar!",
    "sevenzip": b"7z\xbc\xaf",
    "cab":   b"MSCF",
}

SCRIPT_EXTS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf"}


def detect_file_type(filepath: str) -> str:
    """Detect file type from magic bytes. Returns type string."""
    iso_sig = b""
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
            # ISO has signature at offset 0x8001
            try:
                f.seek(0x8001)
                iso_sig = f.read(5)
            except Exception:
                pass
    except Exception:
        return "unknown"

    if header[:2] == MAGIC_SIGS["pe"]:
        return "pe"
    if header[:4] == MAGIC_SIGS["pdf"]:
        return "pdf"
    if header[:2] == MAGIC_SIGS["zip"]:
        return "zip"
    if header[:4] == MAGIC_SIGS["ole"]:
        return "ole"
    if header[:4] == MAGIC_SIGS["lnk"]:
        # verify LNK CLSID
        if len(header) >= 20 and header[4:20] == b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46':
            return "lnk"
    if header[:4] == MAGIC_SIGS["rar"]:
        return "rar"
    if header[:4] == MAGIC_SIGS["sevenzip"]:
        return "7z"
    if header[:4] == MAGIC_SIGS["cab"]:
        return "cab"
    if iso_sig == b"CD001":
        return "iso"

    # check by extension for scripts (text files have no magic)
    ext = os.path.splitext(filepath)[1].lower()
    if ext in SCRIPT_EXTS:
        return "script"

    return "unknown"


# ── PE Analysis ──

SUSPICIOUS_IMPORTS = {
    "injection": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
                   "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC"],
    "keylogging": ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"],
    "persistence": ["RegSetValueEx", "CreateService", "RegCreateKeyEx"],
    "network": ["InternetOpen", "URLDownloadToFile", "HttpSendRequest",
                "WSAStartup", "InternetOpenUrl"],
    "evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "GetTickCount64"],
    "dynamic_load": ["LoadLibrary", "GetProcAddress"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext"],
    "process": ["CreateProcess", "OpenProcess", "TerminateProcess",
                "CreateToolhelp32Snapshot", "Process32First"],
}

PACKER_SECTIONS = {"UPX0", "UPX1", ".aspack", ".adata", ".nsp0", ".nsp1",
                   ".packed", ".themida", ".vmp0", ".vmp1", "MEW", ".petite",
                   ".yP", ".RLPack"}


def analyze_pe(filepath: str) -> Optional[dict]:
    """Analyze PE (exe/dll/scr) file for suspicious indicators."""
    if not PEFILE_AVAILABLE:
        # Fallback: basic string scan
        return _analyze_pe_basic(filepath)
    try:
        pe = pefile_mod.PE(filepath, fast_load=False)
    except Exception:
        return None

    result = {
        "type": "PE",
        "arch": "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "sections": [],
        "suspicious_imports": {},
        "import_count": 0,
        "packers": [],
        "warnings": [],
        "timestamp": None,
    }

    # Compile timestamp
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts and ts != 0:
        try:
            result["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    if ts == 0 or ts > time.time() + 86400 * 365:
        result["warnings"].append("Suspicious compile timestamp")

    # Sections
    for section in pe.sections:
        sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        ent = round(section.get_entropy(), 2)
        result["sections"].append({
            "name": sec_name,
            "entropy": ent,
            "vsize": section.Misc_VirtualSize,
            "rawsize": section.SizeOfRawData,
        })
        # Check for packer sections
        if sec_name.strip() in PACKER_SECTIONS:
            result["packers"].append(sec_name.strip())
        # High entropy in code/data sections
        if ent > 7.2 and section.SizeOfRawData > 1024:
            result["warnings"].append(f"High entropy section `{sec_name}` ({ent})")

    # Entry point outside .text
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    text_sections = [s for s in pe.sections if b".text" in s.Name]
    if text_sections:
        text_sec = text_sections[0]
        if ep < text_sec.VirtualAddress or ep > text_sec.VirtualAddress + text_sec.Misc_VirtualSize:
            result["warnings"].append("Entry point outside .text section")

    # Imports
    try:
        pe.parse_data_directories()
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                for imp in entry.imports:
                    total_imports += 1
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else ""
                    for category, apis in SUSPICIOUS_IMPORTS.items():
                        for api in apis:
                            if api.lower() in name.lower():
                                result["suspicious_imports"].setdefault(category, []).append(name)
        result["import_count"] = total_imports
        if total_imports < 5:
            result["warnings"].append(f"Very few imports ({total_imports}) — may dynamically resolve APIs")
    except Exception:
        pass

    # UPX check + PyInstaller/PyArmor detection
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
        if b"UPX!" in raw:
            result["packers"].append("UPX")

        # PyInstaller detection
        pyinstaller_markers = [b"PYZ-00.pyz", b"MEIPASS", b"_MEIPASS", b"_MEI", b"pyimod", b"PyInstaller"]
        pyinstaller_hits = sum(1 for m in pyinstaller_markers if m in raw)
        if pyinstaller_hits >= 2:
            result["packers"].append("PyInstaller")
            result["warnings"].append("PyInstaller-packed executable")

            # PyArmor detection inside PyInstaller bundles
            if b"__pyarmor__" in raw or b"PY000000" in raw or b"pyarmor_runtime" in raw:
                result["packers"].append("PyArmor")
                result["warnings"].append("PyArmor obfuscation — all code encrypted at rest")

            # Scan PyInstaller TOC for dangerous bundled modules
            dangerous_modules = {
                b"win32crypt": "DPAPI credential theft",
                b"pynput": "keylogger",
                b"cv2": "webcam capture",
                b"mss": "screenshot capture",
                b"psutil": "process enumeration",
                b"sqlite3": "database access",
                b"PyCryptodome": "encryption toolkit",
                b"pycryptodome": "encryption toolkit",
                b"Crypto": "encryption toolkit",
                b"aiohttp": "async HTTP (C2 capable)",
                b"socketio": "real-time C2 framework",
                b"websocket": "websocket C2",
                b"requests": "HTTP requests",
                b"win32com": "COM automation",
                b"PIL": "image processing",
            }
            found_modules = []
            for mod, desc in dangerous_modules.items():
                if mod in raw:
                    found_modules.append(f"{mod.decode()}: {desc}")
            if found_modules:
                result["bundled_modules"] = found_modules
                # Flag dangerous combos
                mod_names = {mod for mod in dangerous_modules if mod in raw}
                if b"win32crypt" in mod_names:
                    result["warnings"].append("Bundles win32crypt (DPAPI credential theft)")
                if b"pynput" in mod_names:
                    result["warnings"].append("Bundles pynput (keylogger)")
                if b"cv2" in mod_names:
                    result["warnings"].append("Bundles OpenCV (webcam capture)")
                if {b"win32crypt", b"requests"} <= mod_names or {b"win32crypt", b"aiohttp"} <= mod_names:
                    result["warnings"].append("Stealer toolkit: credential theft + exfiltration")

        # Rust zipbomb dropper detection
        if b"zipbomb" in raw or b"FATAL: copy payload" in raw:
            result["warnings"].append("Zipbomb dropper signatures detected")
            result["packers"].append("Zipbomb-Dropper")
        if b".pdb" in raw:
            # Check for suspicious PDB paths
            pdb_matches = re.findall(rb'[A-Z]:\\[^\x00]{5,80}\.pdb', raw)
            for pdb in pdb_matches:
                pdb_str = pdb.decode("utf-8", errors="replace")
                if any(s in pdb_str.lower() for s in ["zipbomb", "malware", "rat", "stealer", "dropper", "payload"]):
                    result["warnings"].append(f"Suspicious PDB path: {pdb_str}")
    except Exception:
        pass

    pe.close()
    return result


def _analyze_pe_basic(filepath: str) -> Optional[dict]:
    """Basic PE analysis without pefile — just string scanning."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None
    if data[:2] != b"MZ":
        return None

    result = {
        "type": "PE",
        "arch": "unknown",
        "is_dll": False,
        "sections": [],
        "suspicious_imports": {},
        "import_count": 0,
        "packers": [],
        "warnings": ["Install `pefile` for detailed PE analysis"],
    }

    if b"UPX!" in data:
        result["packers"].append("UPX")

    # PyInstaller/PyArmor detection (same logic as full analyze_pe)
    pyinstaller_markers = [b"PYZ-00.pyz", b"MEIPASS", b"_MEIPASS", b"_MEI", b"pyimod", b"PyInstaller"]
    pyinstaller_hits = sum(1 for m in pyinstaller_markers if m in data)
    if pyinstaller_hits >= 2:
        result["packers"].append("PyInstaller")
        result["warnings"].append("PyInstaller-packed executable")
        if b"__pyarmor__" in data or b"PY000000" in data or b"pyarmor_runtime" in data:
            result["packers"].append("PyArmor")
            result["warnings"].append("PyArmor obfuscation — all code encrypted at rest")
        dangerous_modules = {
            b"win32crypt": "DPAPI credential theft", b"pynput": "keylogger",
            b"cv2": "webcam capture", b"mss": "screenshot capture",
            b"psutil": "process enumeration", b"requests": "HTTP requests",
            b"aiohttp": "async HTTP (C2 capable)", b"socketio": "real-time C2 framework",
        }
        found_modules = []
        mod_names = set()
        for mod, desc in dangerous_modules.items():
            if mod in data:
                found_modules.append(f"{mod.decode()}: {desc}")
                mod_names.add(mod)
        if found_modules:
            result["bundled_modules"] = found_modules
            if b"win32crypt" in mod_names:
                result["warnings"].append("Bundles win32crypt (DPAPI credential theft)")
            if b"pynput" in mod_names:
                result["warnings"].append("Bundles pynput (keylogger)")
            if b"cv2" in mod_names:
                result["warnings"].append("Bundles OpenCV (webcam capture)")
            if {b"win32crypt", b"requests"} <= mod_names or {b"win32crypt", b"aiohttp"} <= mod_names:
                result["warnings"].append("Stealer toolkit: credential theft + exfiltration")

    # Rust zipbomb dropper
    if b"zipbomb" in data or b"FATAL: copy payload" in data:
        result["warnings"].append("Zipbomb dropper signatures detected")
        result["packers"].append("Zipbomb-Dropper")

    for category, apis in SUSPICIOUS_IMPORTS.items():
        for api in apis:
            if api.encode() in data:
                result["suspicious_imports"].setdefault(category, []).append(api)

    return result


# ── PDF Analysis ──

PDF_SUSPICIOUS = {
    "/JavaScript": "critical",
    "/JS": "critical",
    "/OpenAction": "high",
    "/AA": "high",
    "/Launch": "critical",
    "/EmbeddedFile": "high",
    "/AcroForm": "medium",
    "/XFA": "high",
    "/RichMedia": "medium",
    "/SubmitForm": "high",
    "/Encrypt": "medium",
    "/ObjStm": "low",
    "/JBIG2Decode": "medium",
}


def analyze_pdf(filepath: str) -> Optional[dict]:
    """Analyze PDF for suspicious elements."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None

    if not data[:5].startswith(b"%PDF"):
        return None

    result = {
        "type": "PDF",
        "version": "",
        "findings": [],
        "warnings": [],
        "stream_count": 0,
        "js_found": False,
        "auto_action": False,
    }

    # PDF version
    first_line = data[:20].split(b"\n")[0].decode("ascii", errors="replace")
    result["version"] = first_line.strip()

    # Scan for suspicious keywords
    for keyword, severity in PDF_SUSPICIOUS.items():
        count = data.count(keyword.encode())
        if count > 0:
            result["findings"].append({
                "keyword": keyword,
                "count": count,
                "severity": severity,
            })
            if keyword in ("/JavaScript", "/JS"):
                result["js_found"] = True
            if keyword in ("/OpenAction", "/AA"):
                result["auto_action"] = True

    # Auto-action + JavaScript = highly malicious
    if result["js_found"] and result["auto_action"]:
        result["warnings"].append("Auto-executing JavaScript detected")

    # Count streams
    result["stream_count"] = data.count(b"stream")

    # Check for multiple filter chains (obfuscation)
    filter_chain = re.findall(rb'/Filter\s*\[([^\]]+)\]', data)
    for chain in filter_chain:
        filters = re.findall(rb'/\w+Decode', chain)
        if len(filters) > 2:
            result["warnings"].append(f"Multi-layer stream encoding ({len(filters)} filters)")

    # Embedded URLs
    urls = re.findall(rb'/URI\s*\(([^)]+)\)', data)
    if urls:
        result["warnings"].append(f"{len(urls)} embedded URI(s)")

    return result


# ── Office Document Analysis ──

VBA_AUTO_TRIGGERS = [
    "AutoOpen", "AutoClose", "AutoExec", "AutoExit", "Auto_Open", "Auto_Close",
    "Document_Open", "Document_Close", "Document_BeforeClose",
    "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose",
]

VBA_SUSPICIOUS_KEYWORDS = {
    "execution": ["Shell", "WScript.Shell", "Run", "Exec", "CreateObject",
                   "CallByName", "ShellExecute"],
    "powershell": ["powershell", "-enc", "-EncodedCommand", "ExecutionPolicy Bypass",
                   "Invoke-Expression", "IEX"],
    "download": ["URLDownloadToFile", "XMLHTTP", "ServerXMLHTTP", "WinHttpRequest",
                 "Net.WebClient", "DownloadString", "DownloadFile"],
    "file_io": ["ADODB.Stream", "FileSystemObject", "SaveToFile", "Open.*For.*Output"],
    "registry": ["RegWrite", "RegRead", "RegDelete"],
    "obfuscation": ["Chr(", "ChrW(", "ChrB(", "Environ("],
}


def analyze_office(filepath: str) -> Optional[dict]:
    """Analyze Office documents for macros and suspicious content."""
    result = {
        "type": "Office",
        "format": "unknown",
        "has_macros": False,
        "auto_triggers": [],
        "suspicious_keywords": {},
        "warnings": [],
        "dde_found": False,
    }

    # Try OLE2 format first (.doc, .xls, .ppt)
    if OLEFILE_AVAILABLE:
        try:
            ole = olefile_mod.OleFileIO(filepath)
            result["format"] = "OLE2 (Office 97-2003)"

            # Check for VBA macros
            streams = ["/".join(s) for s in ole.listdir()]
            vba_streams = [s for s in streams if "VBA" in s.upper() or "vbaProject" in s]
            if vba_streams:
                result["has_macros"] = True

                # Try to extract macro text
                macro_text = ""
                for stream_path in vba_streams:
                    try:
                        data = ole.openstream(stream_path.split("/")).read()
                        # VBA source is often after "Attribute VB_"
                        text = data.decode("utf-8", errors="replace")
                        macro_text += text + "\n"
                    except Exception:
                        pass

                _scan_macro_text(macro_text, result)

            ole.close()
            return result
        except Exception:
            pass

    # Try OOXML format (.docx, .xlsx, .pptx)
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            names = zf.namelist()

            # Detect Office type
            if any("word/" in n for n in names):
                result["format"] = "OOXML (Word)"
            elif any("xl/" in n for n in names):
                result["format"] = "OOXML (Excel)"
            elif any("ppt/" in n for n in names):
                result["format"] = "OOXML (PowerPoint)"
            else:
                return None  # not an Office doc

            # Check for VBA project
            vba_bins = [n for n in names if "vbaProject.bin" in n]
            if vba_bins:
                result["has_macros"] = True

                # Extract and scan VBA binary
                for vba_path in vba_bins:
                    try:
                        vba_data = zf.read(vba_path)
                        macro_text = vba_data.decode("utf-8", errors="replace")
                        _scan_macro_text(macro_text, result)
                    except Exception:
                        pass

            # Check for DDE in XML content
            for name in names:
                if name.endswith(".xml"):
                    try:
                        xml_data = zf.read(name).decode("utf-8", errors="replace")
                        if "DDEAUTO" in xml_data or re.search(r'<w:fldChar[^>]*>.*?DDE\b', xml_data, re.DOTALL) or 'instrText' in xml_data and 'DDE' in xml_data:
                            result["dde_found"] = True
                            result["warnings"].append("DDE auto-link field detected")
                    except Exception:
                        pass

            # Check for external relationships (template injection)
            for name in names:
                if name.endswith(".rels"):
                    try:
                        rels_data = zf.read(name).decode("utf-8", errors="replace")
                        if "http://" in rels_data or "https://" in rels_data:
                            ext_urls = re.findall(r'Target="(https?://[^"]+)"', rels_data)
                            if ext_urls:
                                result["warnings"].append(f"External template/URL: {ext_urls[0][:60]}")
                    except Exception:
                        pass

            return result
    except Exception:
        pass

    return None


def _scan_macro_text(text: str, result: dict):
    """Scan macro source text for triggers and suspicious keywords."""
    for trigger in VBA_AUTO_TRIGGERS:
        if trigger.lower() in text.lower():
            result["auto_triggers"].append(trigger)

    for category, keywords in VBA_SUSPICIOUS_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text.lower():
                result["suspicious_keywords"].setdefault(category, []).append(kw)

    # Chr() chain obfuscation
    chr_count = text.lower().count("chr(")
    if chr_count > 10:
        result["warnings"].append(f"Heavy Chr() obfuscation ({chr_count} calls)")

    # Long strings (base64)
    long_strings = re.findall(r'"([A-Za-z0-9+/=]{50,})"', text)
    if long_strings:
        result["warnings"].append(f"{len(long_strings)} long encoded string(s)")


# ── LNK (Shortcut) Analysis ──

SUSPICIOUS_LNK_TARGETS = [
    "cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "schtasks.exe", "reg.exe",
]


def analyze_lnk(filepath: str) -> Optional[dict]:
    """Analyze Windows shortcut (.lnk) for suspicious targets."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None

    if len(data) < 76:
        return None
    if data[:4] != b"\x4c\x00\x00\x00":
        return None

    result = {
        "type": "LNK",
        "target_hints": [],
        "arguments_found": False,
        "warnings": [],
        "size": len(data),
    }

    # Large LNK files may have embedded payloads
    if len(data) > 50000:
        result["warnings"].append(f"Unusually large LNK ({len(data)} bytes) — may contain embedded payload")

    # Extract readable strings from the LNK
    ascii_strings = re.findall(rb'[\x20-\x7e]{8,}', data)
    unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){8,}', data)

    all_strings = set()
    for s in ascii_strings:
        all_strings.add(s.decode("ascii", errors="replace"))
    for s in unicode_strings:
        all_strings.add(s.decode("utf-16-le", errors="replace"))

    # Check for suspicious targets
    for s in all_strings:
        s_lower = s.lower()
        for target in SUSPICIOUS_LNK_TARGETS:
            if target in s_lower:
                result["target_hints"].append(target)
        # Suspicious argument patterns
        if any(x in s_lower for x in ["-enc", "-decode", "http://", "https://", "-executionpolicy",
                                        "invoke-", "downloadstring", "hidden"]):
            result["arguments_found"] = True
            result["warnings"].append(f"Suspicious argument: `{sanitize_path(s[:80])}`")

    if result["target_hints"]:
        result["warnings"].insert(0, f"Points to: {', '.join(set(result['target_hints']))}")

    return result


# ── Script Analysis ──

LOLBIN_PATTERNS = {
    "powershell_encoded": re.compile(r'powershell.*(?:-enc\b|-e\s|-EncodedCommand)', re.I),
    "powershell_hidden": re.compile(r'powershell.*-(?:w(?:indowstyle)?\s*h(?:idden)?|nop)', re.I),
    "powershell_bypass": re.compile(r'(?:-ep\s*bypass|-ExecutionPolicy\s*Bypass)', re.I),
    "certutil_decode": re.compile(r'certutil.*-(?:decode|urlcache)', re.I),
    "bitsadmin": re.compile(r'bitsadmin.*/(?:transfer|download)', re.I),
    "mshta_exec": re.compile(r'mshta\s+(?:http|javascript)', re.I),
    "regsvr32_squiblydoo": re.compile(r'regsvr32.*/s.*/(?:n|u|i:)', re.I),
    "rundll32_js": re.compile(r'rundll32.*javascript:', re.I),
    "wmic_exec": re.compile(r'wmic.*process\s+call\s+create', re.I),
    "schtasks_create": re.compile(r'schtasks.*/create', re.I),
}

SCRIPT_SUSPICIOUS = {
    "download_exec": ["Invoke-Expression", "IEX", "Invoke-WebRequest", "DownloadString",
                      "DownloadFile", "Net.WebClient", "Start-BitsTransfer",
                      "Invoke-RestMethod", "wget", "curl"],
    "encoding": ["FromBase64String", "ToBase64String", "[Convert]::",
                 "encodedcommand", "-enc "],
    "wscript": ["WScript.Shell", "ActiveXObject", "Scripting.FileSystemObject",
                "ADODB.Stream", "eval("],
    "persistence": ["CurrentVersion\\Run", "schtasks", "startup",
                    "Registry::HKLM", "HKCU:\\"],
    "evasion": ["bypass", "hidden", "-nop", "-sta", "unrestricted",
                "Add-MpPreference", "-ExclusionPath", "Set-MpPreference"],
}


def analyze_script(filepath: str) -> Optional[dict]:
    """Analyze script files for malicious patterns."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(512 * 1024)  # max 512KB
    except Exception:
        return None

    ext = os.path.splitext(filepath)[1].lower()
    result = {
        "type": "Script",
        "extension": ext,
        "size": len(text),
        "lolbins": [],
        "suspicious_keywords": {},
        "warnings": [],
        "obfuscation_score": 0,
    }

    # LOLBin patterns
    for name, pattern in LOLBIN_PATTERNS.items():
        if pattern.search(text):
            result["lolbins"].append(name)

    # Suspicious keywords by category
    for category, keywords in SCRIPT_SUSPICIOUS.items():
        for kw in keywords:
            if kw.lower() in text.lower():
                result["suspicious_keywords"].setdefault(category, []).append(kw)

    # Obfuscation detection
    # Caret insertion (CMD): p^o^w^e^r^s^h^e^l^l
    if text.count("^") > 10:
        result["obfuscation_score"] += 20
        result["warnings"].append("Caret insertion obfuscation detected")

    # String concatenation: "p"+"ow"+"er"
    concat_count = len(re.findall(r'"[^"]{1,5}"\s*[+&]\s*"', text))
    if concat_count > 5:
        result["obfuscation_score"] += 15
        result["warnings"].append(f"String concatenation obfuscation ({concat_count} fragments)")

    # Chr() chains (VBS)
    chr_count = text.lower().count("chr(")
    if chr_count > 10:
        result["obfuscation_score"] += 20
        result["warnings"].append(f"Chr() obfuscation ({chr_count} calls)")

    # Backtick insertion (PS): p`o`w`e`r`s`h`e`l`l
    if ext == ".ps1" and text.count("`") > 15:
        result["obfuscation_score"] += 15
        result["warnings"].append("Backtick obfuscation detected")

    # Long base64 strings
    b64_matches = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', text)
    if b64_matches:
        result["obfuscation_score"] += 10
        result["warnings"].append(f"{len(b64_matches)} long Base64 blob(s)")

    # High non-alpha ratio (possible encoding)
    if len(text) > 100:
        alpha_ratio = sum(1 for c in text if c.isalpha()) / len(text)
        if alpha_ratio < 0.3:
            result["obfuscation_score"] += 10
            result["warnings"].append("Low alpha character ratio (possible encoding)")

    return result


# ── MSI Analysis ──

def analyze_msi(filepath: str) -> Optional[dict]:
    """Analyze MSI installer files for suspicious content."""
    if not OLEFILE_AVAILABLE:
        return {"type": "MSI", "warnings": ["Install `olefile` for MSI analysis"], "findings": []}

    try:
        ole = olefile_mod.OleFileIO(filepath)
    except Exception:
        return None

    result = {
        "type": "MSI",
        "findings": [],
        "warnings": [],
        "has_custom_actions": False,
        "embedded_executables": [],
    }

    streams = ["/".join(s) for s in ole.listdir()]

    # Check for CustomAction (main attack vector in MSI)
    for stream in streams:
        if "CustomAction" in stream:
            result["has_custom_actions"] = True
            result["findings"].append("CustomAction table present")

    # Scan all streams for embedded executables and scripts
    for stream_parts in ole.listdir():
        stream_name = "/".join(stream_parts)
        try:
            data = ole.openstream(stream_parts).read()
            if len(data) > 2:
                # PE header
                if data[:2] == b"MZ":
                    result["embedded_executables"].append(stream_name)
                    result["warnings"].append(f"Embedded PE in stream: `{stream_name[:50]}`")
                # CAB archive
                if data[:4] == b"MSCF":
                    result["findings"].append(f"Embedded CAB archive: `{stream_name[:50]}`")
                # Script content
                text = data.decode("utf-8", errors="replace")
                for keyword in ["powershell", "cmd.exe", "wscript", "cscript", "mshta"]:
                    if keyword in text.lower():
                        result["warnings"].append(f"Script keyword `{keyword}` in stream: `{stream_name[:50]}`")
                        break
        except Exception:
            pass

    ole.close()
    return result


# ── ISO/IMG Analysis ──

def analyze_iso(filepath: str) -> Optional[dict]:
    """Basic ISO analysis — checks for suspicious file types inside."""
    result = {
        "type": "ISO",
        "warnings": [],
        "findings": [],
        "suspicious_files": [],
    }

    # Just scan the raw bytes for filenames and patterns
    try:
        with open(filepath, "rb") as f:
            data = f.read(min(os.path.getsize(filepath), 10 * 1024 * 1024))  # first 10MB
    except Exception:
        return result

    dangerous_exts = [".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                      ".js", ".hta", ".lnk", ".msi", ".wsf", ".com", ".pif"]

    # Look for filenames in the ISO directory records
    ascii_strings = re.findall(rb'[\x20-\x7e]{4,60}', data)
    found_files = set()
    for s in ascii_strings:
        s_str = s.decode("ascii", errors="replace")
        for ext in dangerous_exts:
            if s_str.lower().endswith(ext):
                found_files.add(s_str)

    if found_files:
        result["suspicious_files"] = sorted(found_files)
        result["warnings"].append(f"{len(found_files)} potentially dangerous file(s) inside ISO")

    # Check for autorun.inf
    if b"autorun.inf" in data.lower() or b"AUTORUN.INF" in data:
        result["warnings"].append("Contains autorun.inf")

    file_size = os.path.getsize(filepath)
    if file_size < 10 * 1024 * 1024:
        result["warnings"].append(f"Small ISO ({file_size / 1024 / 1024:.1f} MB) — likely malware delivery")

    return result


# ── Unified Multi-Format Analyzer ──

def analyze_file_format(filepath: str) -> Optional[dict]:
    """Run the appropriate analyzer based on file type. Returns analysis dict or None."""
    ftype = detect_file_type(filepath)

    if ftype == "pe":
        return analyze_pe(filepath)
    elif ftype == "pdf":
        return analyze_pdf(filepath)
    elif ftype == "ole":
        # Could be Office doc or MSI — try Office first
        office = analyze_office(filepath)
        if office and office.get("format") != "unknown":
            return office
        return analyze_msi(filepath)
    elif ftype == "lnk":
        return analyze_lnk(filepath)
    elif ftype == "script":
        return analyze_script(filepath)
    elif ftype == "iso":
        return analyze_iso(filepath)
    elif ftype == "zip":
        # OOXML Office docs are zips
        office = analyze_office(filepath)
        if office:
            return office
        return None  # regular zip/jar handled elsewhere
    else:
        return None


# ─── Zip Bomb Detection ─────────────────────────────────────────────────────

MAX_DECOMPRESSED_SIZE = 512 * 1024 * 1024  # 512MB max decompressed
MAX_ZIP_ENTRIES = 10000
MAX_NESTED_ARCHIVES = 50
MAX_COMPRESSION_RATIO = 1500  # legitimate JARs with compressed assets can hit 600:1+
MIN_BOMB_DECOMPRESSED = 100 * 1024 * 1024  # only flag ratio if decompressed > 100MB


def check_zip_bomb(filepath: str) -> Optional[str]:
    """Check for zip bomb characteristics. Returns warning string or None."""
    try:
        file_size = os.path.getsize(filepath)
        with zipfile.ZipFile(filepath, "r") as zf:
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            entry_count = len(zf.infolist())

            ratio = total_uncompressed / file_size if file_size > 0 else 0

            # High ratio alone isn't enough — compressed assets (textures, data)
            # in legitimate JARs/mods can easily hit 600:1. Only flag when BOTH
            # the ratio is extreme AND the decompressed size is large enough to
            # actually cause resource exhaustion.
            if ratio > MAX_COMPRESSION_RATIO and total_uncompressed > MIN_BOMB_DECOMPRESSED:
                return f"Compression ratio {ratio:.0f}:1 ({total_uncompressed / 1024 / 1024:.0f} MB uncompressed)"

            if total_uncompressed > MAX_DECOMPRESSED_SIZE:
                return f"Decompressed size {total_uncompressed / 1024 / 1024:.0f} MB exceeds limit"

            if entry_count > MAX_ZIP_ENTRIES:
                return f"Excessive entries: {entry_count}"

            zip_count = sum(1 for n in zf.namelist() if n.lower().endswith((".zip", ".jar")))
            if zip_count > MAX_NESTED_ARCHIVES:
                return f"Excessive nested archives: {zip_count}"
    except Exception:
        pass
    return None


# ─── Obfuscator Detection ───────────────────────────────────────────────────

OBFUSCATORS = {
    "Allatori": [b"AllatoriDemo", b"by Allatori", b"allatori"],
    "ZKM": [b"Zelix", b"zKM", b"com/zelix"],
    "Stringer": [b"com/vgames/stringer", b"StringEncryption"],
    "Bozar": [b"me/bozar", b"Bozar"],
    "Branchlock": [b"branchlock", b"me/iris/"],
    "ProGuard": [b"proguard", b"ProGuard"],
    "JNIC": [b"jnic", b"JNICLoader"],
    "DashO": [b"DashO", b"PreEmptive", b"com/preemptive"],
    "Skidfuscator": [b"skidfuscator", b"Skidfuscator"],
    "Caesium": [b"caesium", b"Caesium"],
    "Radon": [b"radon", b"Radon Obfuscator"],
    "Paramorphism": [b"paramorphism", b"Paramorphism"],
}


def detect_obfuscators(jar_path: str) -> list[str]:
    found = set()
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            if "META-INF/MANIFEST.MF" in zf.namelist():
                manifest = zf.read("META-INF/MANIFEST.MF")
                for name, patterns in OBFUSCATORS.items():
                    for p in patterns:
                        if p.lower() in manifest.lower():
                            found.add(name)

            names = zf.namelist()
            class_names = [n for n in names if n.endswith(".class")]

            # .class/ trailing slash evasion (qProtect, GambleRigger-family)
            # ZIP entries ending with ".class/" are directories, not class files,
            # causing decompilers to skip them entirely
            trailing_slash_classes = [n for n in names if n.endswith(".class/")]
            if trailing_slash_classes:
                found.add(f"Trailing-slash evasion ({len(trailing_slash_classes)} .class/ entries)")
                # Treat them as class names for further analysis
                class_names.extend(trailing_slash_classes)

            # qProtect detection — O/0 confusable class name patterns
            o0_pattern = re.compile(r'^(?:.*/)?((?:[O0o]+)\.class/?)')
            o0_names = sum(1 for n in class_names if o0_pattern.match(n))
            if o0_names >= 3:
                found.add("qProtect (O/0 confusable names)")

            # META-INF marker files (GambleRigger/4E family)
            marker_files = [n for n in names if re.match(r'^META-INF/[a-f0-9]{8,}$', n)]
            if marker_files:
                found.add(f"Suspicious META-INF marker ({marker_files[0]})")

            # HTML injection in ZIP entry names
            html_entries = [n for n in names if "<html>" in n.lower() or "<img " in n.lower()]
            if html_entries:
                found.add("HTML injection in ZIP entry names")

            # Encrypted config files (MD5-named .txt with high entropy)
            hex_configs = [n for n in names if re.match(r'^[a-f0-9]{16,}\.txt$', n)]
            for hc in hex_configs[:3]:
                try:
                    data = zf.read(hc)
                    if len(data) > 32 and shannon_entropy(data) > 6.0:
                        found.add("Encrypted config file")
                        break
                except Exception:
                    pass

            short_root = sum(
                1 for n in class_names if "/" not in n and len(n.replace(".class", "").replace("/", "")) <= 2
            )
            if short_root > 10:
                found.add("Generic (short class names)")

            unicode_names = sum(1 for n in class_names if any(ord(c) > 127 for c in n))
            if unicode_names > 5:
                # Check for Skidfuscator: uses Hangul fillers (ᅠ U+3164, ㅤ U+3164, ᅟ U+115F)
                # and invisible/zero-width joiners as class name identifiers
                hangul_names = sum(1 for n in class_names if any(
                    ord(c) in (0x3164, 0x115F, 0x1160, 0xFFA0, 0x2800, 0xFF9E, 0x3000) for c in n))
                # Check for DashO's combining character pattern (U+0300-U+036F, zero-width)
                dasho_chars = sum(1 for n in class_names if any(
                    0x0300 <= ord(c) <= 0x036F or ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF) for c in n))
                if hangul_names > 3:
                    found.add("Skidfuscator (Hangul/invisible chars)")
                elif dasho_chars > 3:
                    found.add("DashO (Unicode combining chars)")
                else:
                    found.add("Unicode class names")

            dat_files = [n for n in names if n.endswith((".dat", ".bin")) and "jnic" not in n.lower()]
            if dat_files:
                for df in dat_files[:5]:
                    try:
                        data = zf.read(df)
                        if len(data) > 1024 and shannon_entropy(data) > 7.8:
                            found.add("Encrypted payload detected")
                            break
                    except Exception:
                        pass

            # Check for ServiceLoader exploitation
            services = [n for n in names if n.startswith("META-INF/services/")]
            if services:
                found.add(f"ServiceLoader ({len(services)} service(s))")

            # Check for Java agent capabilities
            if "META-INF/MANIFEST.MF" in names:
                manifest_text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                if "Premain-Class:" in manifest_text:
                    found.add("Java Agent (Premain-Class)")
                if "Agent-Class:" in manifest_text:
                    found.add("Java Agent (Agent-Class)")

            for entry in class_names[:100]:
                try:
                    data = zf.read(entry)
                    for name, patterns in OBFUSCATORS.items():
                        for p in patterns:
                            if p in data:
                                found.add(name)
                except Exception:
                    pass
    except Exception:
        pass
    return sorted(found)


# ─── JarAnalyzer Subprocess ─────────────────────────────────────────────────


def derive_log_dir_name(jar_path: str) -> str:
    """Mirror JarAnalyzer.java's log directory naming."""
    name = os.path.basename(jar_path)
    name = re.sub(r"\.(jar|zip)(\.zip)?$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    return name


async def run_jar_analyzer(jar_path: str, progress_cb=None) -> dict:
    """Run JarAnalyzer as subprocess, return parsed results."""
    java = shutil.which(CFG["scanner"]["java_path"]) or CFG["scanner"]["java_path"]
    timeout = CFG["scanner"]["scan_timeout_seconds"]
    log_name = derive_log_dir_name(jar_path)
    log_dir = MASTER_DIR / "logs" / log_name

    if log_dir.exists():
        shutil.rmtree(log_dir, ignore_errors=True)

    cmd = [java, "-cp", "tools", "JarAnalyzer", str(jar_path)]
    log.info(f"Running JarAnalyzer on {os.path.basename(jar_path)}")

    if progress_cb:
        await progress_cb("Decompiling and analyzing...")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(MASTER_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Stream stdout line-by-line for live progress updates
    stdout_lines: list[str] = []
    stderr_buf = b""
    last_cb = 0.0

    async def _read_stdout():
        nonlocal last_cb
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace").rstrip()
            stdout_lines.append(decoded)
            log.info(f"[JarAnalyzer] {decoded}")
            # Forward key status lines to progress callback (throttled to 2s)
            if progress_cb and time.time() - last_cb >= 2.0:
                # Extract a short status from the line
                short = decoded[:80]
                if any(kw in decoded.lower() for kw in
                       ("step", "decompil", "analyz", "extract", "scan", "detect",
                        "variant", "decrypt", "marker", "ioc", "score", "xor",
                        "class", "writing", "done", "found", "warn")):
                    await progress_cb(short)
                    last_cb = time.time()

    async def _read_stderr():
        nonlocal stderr_buf
        stderr_buf = await proc.stderr.read()

    try:
        await asyncio.wait_for(
            asyncio.gather(_read_stdout(), _read_stderr()),
            timeout=timeout,
        )
        await proc.wait()
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return {"error": "Scan timed out", "exit_code": -1, "log_dir": str(log_dir)}

    stdout_text = "\n".join(stdout_lines)
    result = {
        "exit_code": proc.returncode,
        "stdout": sanitize_path(stdout_text),
        "stderr": sanitize_path(stderr_buf.decode("utf-8", errors="replace")),
        "log_dir": str(log_dir),
    }

    iocs_files = list(log_dir.glob("*_iocs.json")) if log_dir.exists() else []
    if iocs_files:
        try:
            with open(iocs_files[0], encoding="utf-8") as f:
                result["iocs"] = json.load(f)
        except Exception as e:
            log.warning(f"Failed to parse IOCs: {e}")

    analysis_txt = log_dir / "analysis.txt"
    if analysis_txt.exists():
        result["analysis_text"] = analysis_txt.read_text(encoding="utf-8", errors="replace")

    return result


# ─── File Hashing ────────────────────────────────────────────────────────────


def compute_hashes(filepath: str) -> dict:
    """Compute MD5, SHA1, SHA256 in a single pass."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


# ─── Risk Scoring ────────────────────────────────────────────────────────────

DETECTION_THRESHOLD = 25

HIGH_RISK_VARIANTS = {
    "adamrat", "weedhack", "session_harvester", "vape_curium",
    "mshta_dropper", "fractureiser", "skyrage", "comet", "ectasy",
    "mclauncher_loader", "silent_net",
}


def compute_risk_score(
    iocs: Optional[dict],
    vt: Optional[dict],
    yara_matches: list[dict],
    obfuscators: list[str],
    entropy: dict = None,
    extracted_strings: dict = None,
    manifest: dict = None,
    format_analysis: dict = None,
    mb_result: dict = None,
    ha_result: dict = None,
) -> tuple[int, str, int]:
    """Returns (score, level, color_int)."""
    score = 0

    if iocs:
        variant = (iocs.get("variant") or "").lower()
        markers = iocs.get("behavioralMarkers", [])

        if variant in HIGH_RISK_VARIANTS:
            score += 40
        elif variant and variant != "unknown":
            score += 25

        if iocs.get("c2Base") or iocs.get("ethContract") or iocs.get("contracts"):
            score += 15
        if iocs.get("exfilUrl") or iocs.get("stage2Url"):
            score += 5
        if iocs.get("urls") and len(iocs["urls"]) > 3:
            score += 10

        webhook_keys = [k for k in iocs if "webhook" in k.lower() and iocs[k]]
        if webhook_keys:
            score += 10

        high_risk_markers = [m for m in markers if "HIGH RISK" in m]
        score += min(len(high_risk_markers) * 5, 15)

        non_library_markers = [
            m for m in markers
            if m not in high_risk_markers and (
                not m.startswith("Bytecode API ref:")
                or (
                    "[LIB]" not in m  # Skip library-origin bytecode refs
                    and any(x in m for x in [
                        "Runtime.exec", "ProcessBuilder", "defineClass",
                        "URLClassLoader",
                    ])
                )
            )
        ]
        score += min(len(non_library_markers), 8)

        # Persistence indicators (LOCALAPPDATA paths, scheduled tasks, Python droppers)
        persistence_markers = [m for m in markers if any(x in m for x in [
            "persistence", "NtProfileIndex", "_bootstrap.py", "python312._pth",
            "schtasks", "scheduled task", "RuntimeBroker",
        ])]
        if persistence_markers:
            score += min(len(persistence_markers) * 5, 10)

        # Decompilation failure indicates advanced obfuscation
        decompile_fail = [m for m in markers if "Decompilation failure:" in m]
        if decompile_fail:
            score += 5

    # VirusTotal
    if vt and vt.get("total", 0) > 0:
        vt_ratio = vt["detected"] / vt["total"]
        score += min(int(vt_ratio * 40), 40)

    # MalwareBazaar — if found in database, it's known malware
    if mb_result and mb_result.get("status") == "found" and mb_result.get("signature"):
        score += 20

    # Hybrid Analysis
    if ha_result and ha_result.get("threat_score") is not None:
        ts = ha_result["threat_score"]
        if ts >= 80:
            score += 15
        elif ts >= 50:
            score += 8

    # YARA
    score += min(len(yara_matches) * 5, 15)

    # obfuscators — low weight for generic, high weight for evasion techniques
    if obfuscators:
        obf_str = " ".join(obfuscators)
        evasion_obfs = sum(1 for o in obfuscators if any(
            x in o for x in ["Trailing-slash", "qProtect", "HTML injection",
                              "Encrypted config", "META-INF marker"]))
        if evasion_obfs:
            score += min(evasion_obfs * 10, 25)
        generic_obfs = len(obfuscators) - evasion_obfs
        score += min(generic_obfs * 2, 6)

    # entropy — moderate weight; obfuscated but legitimate code often has high entropy
    if entropy:
        if entropy.get("suspicious_entries"):
            score += min(len(entropy["suspicious_entries"]) * 2, 6)
        if entropy.get("max_class_entropy", 0) > 7.5:
            score += 3

    # raw string extraction
    has_webhooks = False
    if extracted_strings:
        if extracted_strings.get("discord_webhooks"):
            score += 10
            has_webhooks = True
        if extracted_strings.get("discord_tokens"):
            score += 15
        if extracted_strings.get("eth_addresses"):
            score += 5

    # Combo: webhook + launcher_accounts is almost always a stealer
    has_launcher_accounts = iocs and any(
        "launcher_accounts" in m for m in iocs.get("behavioralMarkers", [])
    )
    if has_webhooks and has_launcher_accounts:
        score += 15

    # manifest — reduced weight for Mixin-related keys (Premain-Class, Can-Redefine-Classes)
    if manifest and manifest.get("suspicious_keys"):
        score += min(len(manifest["suspicious_keys"]) * 2, 8)

    # Multi-format analysis scoring
    if format_analysis:
        fa_type = format_analysis.get("type", "")

        if fa_type == "PE":
            si = format_analysis.get("suspicious_imports", {})
            if si.get("injection"):
                score += 20
            if si.get("keylogging"):
                score += 15
            if si.get("evasion"):
                score += 10
            if si.get("network") and si.get("persistence"):
                score += 10

            packers = format_analysis.get("packers", [])
            if packers:
                # PyInstaller+PyArmor combo is near-certain malware
                has_pyinstaller = "PyInstaller" in packers
                has_pyarmor = "PyArmor" in packers
                has_zipbomb = "Zipbomb-Dropper" in packers
                if has_pyinstaller and has_pyarmor:
                    score += 35  # encrypted Python = almost always a RAT/stealer
                elif has_pyinstaller:
                    score += 15  # PyInstaller alone is suspicious but not definitive
                elif has_zipbomb:
                    score += 40  # zipbomb dropper
                else:
                    score += 10  # generic packer (UPX, etc)

            # Dangerous bundled module combos
            bundled = format_analysis.get("bundled_modules", [])
            if bundled:
                mod_str = " ".join(bundled)
                if "credential theft" in mod_str or "keylogger" in mod_str:
                    score += 15
                if "webcam" in mod_str or "screenshot" in mod_str:
                    score += 10
                if "C2" in mod_str:
                    score += 10

            warnings = format_analysis.get("warnings", [])
            # Weight specific warnings higher
            stealer_warns = sum(1 for w in warnings if "Stealer toolkit" in w or "credential theft" in w)
            score += min(stealer_warns * 10, 20)
            other_warns = len(warnings) - stealer_warns
            score += min(other_warns * 3, 15)

        elif fa_type == "PDF":
            if format_analysis.get("js_found") and format_analysis.get("auto_action"):
                score += 30
            elif format_analysis.get("js_found"):
                score += 15
            critical = sum(1 for f in format_analysis.get("findings", []) if isinstance(f, dict) and f.get("severity") == "critical")
            high = sum(1 for f in format_analysis.get("findings", []) if isinstance(f, dict) and f.get("severity") == "high")
            score += min(critical * 10 + high * 5, 25)

        elif fa_type == "Office":
            if format_analysis.get("has_macros"):
                score += 10
            if format_analysis.get("auto_triggers"):
                score += 15
            sk = format_analysis.get("suspicious_keywords", {})
            if sk.get("execution"):
                score += 10
            if sk.get("powershell"):
                score += 15
            if sk.get("download"):
                score += 10
            if format_analysis.get("dde_found"):
                score += 15
            score += min(len(format_analysis.get("warnings", [])) * 3, 10)

        elif fa_type == "LNK":
            if format_analysis.get("target_hints"):
                score += 20
            if format_analysis.get("arguments_found"):
                score += 15
            score += min(len(format_analysis.get("warnings", [])) * 5, 15)

        elif fa_type == "Script":
            lolbins = format_analysis.get("lolbins", [])
            score += min(len(lolbins) * 8, 25)
            sk = format_analysis.get("suspicious_keywords", {})
            if sk.get("download_exec"):
                score += 10
            if sk.get("evasion"):
                score += 10
            obf = format_analysis.get("obfuscation_score", 0)
            score += min(obf, 20)

        elif fa_type == "MSI":
            if format_analysis.get("embedded_executables"):
                score += 20
            if format_analysis.get("has_custom_actions"):
                score += 5
            score += min(len(format_analysis.get("warnings", [])) * 5, 15)

        elif fa_type == "ISO":
            if format_analysis.get("suspicious_files"):
                score += 15
            score += min(len(format_analysis.get("warnings", [])) * 5, 15)

    # Minimum score floor for known high-risk variants
    if iocs:
        variant = (iocs.get("variant") or "").lower()
        if variant in HIGH_RISK_VARIANTS and score < 61:
            score = 61

    score = min(score, 100)

    if score <= DETECTION_THRESHOLD:
        return score, "LOW", 0x2ECC71
    elif score <= 60:
        return score, "MEDIUM", 0xF39C12
    else:
        return score, "HIGH", 0xE74C3C


# ─── Embed Builder ───────────────────────────────────────────────────────────

LEVEL_EMOJI = {"LOW": "\u2705", "MEDIUM": "\u26A0\uFE0F", "HIGH": "\U0001F6A8"}

STAGE_ICONS = {
    "pending": "\u23F3",     # hourglass
    "running": "\U0001F504", # arrows (spinner)
    "complete": "\u2705",    # check
    "skipped": "\u2796",     # dash
    "error": "\u274C",       # X
}

STAGE_ETAS = {
    "Local Analysis": "~10s",
    "VirusTotal": "~30s",
    "VT Upload": "~2-3min",
    "VT Sandbox": "~2s",
    "MalwareBazaar": "~2s",
    "Hybrid Analysis": "~5s",
}


def build_progress_embed(
    filename: str,
    file_size: int,
    hashes: dict,
    scan_id: str,
    stages: dict,
    stage_start_times: dict | None = None,
    stage_details: dict | None = None,
) -> discord.Embed:
    """Build a lightweight progress embed showing scan stage status."""
    size_str = (
        f"{file_size / 1024 / 1024:.1f} MB"
        if file_size > 1024 * 1024
        else f"{file_size / 1024:.1f} KB"
    )
    e = discord.Embed(
        title=f"\U0001F50E Scanning: {filename[:70]}",
        color=0x3498DB,
        timestamp=datetime.now(timezone.utc),
    )
    e.add_field(name="File", value=f"{size_str} | `{hashes['sha256'][:16]}...`", inline=False)

    now = time.time()
    lines = []
    for stage_name, status in stages.items():
        icon = STAGE_ICONS.get(status, STAGE_ICONS.get(status.split()[0], "\u2753"))
        eta = ""
        if status == "pending":
            eta = f" (ETA {STAGE_ETAS.get(stage_name, '~5s')})"
        elif status.startswith("running"):
            # Show live elapsed time
            if stage_start_times and stage_name in stage_start_times:
                elapsed = int(now - stage_start_times[stage_name])
                eta = f" ({elapsed}s elapsed)"
            elif "(" in status:
                eta = f" {status[status.index('('):]}"
            else:
                eta = f" (ETA {STAGE_ETAS.get(stage_name, '~5s')})"
            status = "running"
            icon = STAGE_ICONS["running"]
        elif status == "complete":
            # Show how long the stage took
            if stage_start_times and stage_name in stage_start_times:
                elapsed = stage_start_times.get(f"{stage_name}_done", now) - stage_start_times[stage_name]
                eta = f" ({elapsed:.0f}s)"
            icon = STAGE_ICONS["complete"]
        detail_line = ""
        if stage_details and stage_name in stage_details:
            detail_line = f"\n  \u2514 _{stage_details[stage_name]}_"
        lines.append(f"{icon} **{stage_name}**{eta}{detail_line}")
    e.add_field(name="Progress", value="\n".join(lines), inline=False)
    e.set_footer(text=f"Scan ID: {scan_id}")
    return e


MAX_EMBED_TOTAL = 5800  # Discord limit is 6000, leave margin


def _trunc(text: str, max_len: int = 1024) -> str:
    """Truncate text to fit Discord embed field limits."""
    if len(text) <= max_len:
        return text
    # Try to cut at last newline for cleaner break
    cut = text[: max_len - 20].rfind("\n")
    if cut < max_len // 2:
        cut = max_len - 20
    return text[:cut] + "\n*... (truncated)*"


def _embed_char_count(embed: discord.Embed) -> int:
    """Count total characters in an embed (Discord counts title, description, fields, footer)."""
    total = len(embed.title or "")
    total += len(embed.description or "")
    if embed.footer and embed.footer.text:
        total += len(embed.footer.text)
    for field in embed.fields:
        total += len(field.name or "")
        total += len(field.value or "")
    return total


def _safe_add_field(embed: discord.Embed, budget: list, **kwargs):
    """Add field only if within character budget. Returns True if added."""
    name = kwargs.get("name", "")
    value = kwargs.get("value", "")
    cost = len(name) + len(value)
    if budget[0] - cost < 0:
        return False
    budget[0] -= cost
    embed.add_field(**kwargs)
    return True


# ── Variant descriptions in plain language ──
_VARIANT_DESCRIPTIONS = {
    "adamrat": "AdamRAT (a Minecraft account stealer that sends your login info to the attacker via Discord webhook)",
    "weedhack": "Weedhack (downloads and runs a second malicious file using the Ethereum blockchain to hide the download link)",
    "session_harvester": "Session Harvester (steals your Minecraft login session so someone else can log in as you)",
    "vape_curium": "Vape Curium (a RAT that can control your computer remotely, download more malware, and spread to friends)",
    "silent_net": "Silent NET (steals Minecraft sessions using Polygon blockchain smart contracts to dynamically resolve its C2 server)",
    "mshta_dropper": "MSHTA Dropper (uses a Windows trick called MSHTA to run hidden malicious scripts)",
    "fractureiser": "Fractureiser (a very dangerous virus that spreads through Minecraft mods and steals passwords, tokens, and crypto wallets)",
    "skyrage": "SkyRage (steals your Discord token, browser passwords, and Minecraft account, and hides itself as a Windows service)",
    "weirdutils": "WeirdUtils (a hidden backdoor that pretends to be a normal mod but steals your data)",
    "comet": "Comet Backdoor (a Minecraft server backdoor that lets attackers run commands on the server)",
    "ectasy": "Ectasy (a server backdoor that downloads itself into your server and gives attackers remote control)",
    "server_crasher": "Server Crasher / Exploit Client (a tool designed to crash or exploit Minecraft servers)",
    "mclauncher_loader": "MCLauncher Loader (hides inside a normal-looking mod and secretly downloads and runs malware)",
}

_INFECTION_RESOURCES = (
    "\n\n**If you already ran this file, you should:**\n"
    "\u2022 Change your Minecraft, Discord, and email passwords immediately\n"
    "\u2022 Enable 2FA on all accounts if you haven't already\n"
    "\u2022 Check Discord Settings > Authorized Apps and remove anything suspicious\n"
    "\u2022 Run a full antivirus scan (Windows Defender, Malwarebytes, etc.)\n"
    "\u2022 Check for unknown programs in Task Manager / startup apps\n"
    "\u2022 See this guide for more help: https://prismlauncher.org/wiki/overview/getting-rid-of-malware/"
)


def _build_plain_summary(score, level, variant, iocs, vt, yara_matches,
                         extracted_strings, mb_result):
    """Build a plain-language summary for the top of the embed."""
    lines = []

    # Best guess at what it is
    if variant and variant != "unknown" and variant in _VARIANT_DESCRIPTIONS:
        lines.append(f"**What is this?** This file is **{_VARIANT_DESCRIPTIONS[variant]}**.")
    elif score > 60:
        lines.append("**What is this?** This file has strong indicators of being **malware** (a program designed to steal your data or harm your computer).")
    elif score > 35:
        lines.append("**What is this?** This file has some suspicious behaviors that could indicate malware, but it might also be a legitimate (but sketchy-looking) program. Check the details below.")
    elif score > DETECTION_THRESHOLD:
        lines.append("**What is this?** This file has a few minor flags. It's probably fine, but take a quick look at the details below to be sure.")
    else:
        lines.append("**What is this?** This file looks clean. No malware indicators were found.")

    # What the scan found (simplified)
    findings = []
    if vt and vt.get("detected", 0) > 0:
        findings.append(f"{vt['detected']} out of {vt['total']} antivirus engines flagged it")
    if mb_result and mb_result.get("status") == "found":
        findings.append("it's in a known malware database (MalwareBazaar)")
    if yara_matches:
        findings.append(f"it matched {len(yara_matches)} malware signature rule(s)")
    if extracted_strings and extracted_strings.get("discord_webhooks"):
        findings.append("it contains a Discord webhook URL (often used to send stolen data to attackers)")
    if iocs:
        if iocs.get("c2Base") or iocs.get("ethContract") or iocs.get("contracts"):
            findings.append("it connects to a known attacker-controlled server")
    if findings:
        lines.append("**Key findings:** " + "; ".join(findings) + ".")

    # Confidence + ran-it warning
    if score > 60:
        lines.append(_INFECTION_RESOURCES)
    elif score > 35:
        lines.append("\n*If you're unsure, don't run it. Ask someone you trust or check the details below.*")

    return "\n".join(lines)


def build_embeds(
    filename: str,
    file_size: int,
    hashes: dict,
    iocs: Optional[dict],
    vt: Optional[dict],
    yara_matches: list[dict],
    obfuscators: list[str],
    score: int,
    level: str,
    color: int,
    scan_time: float,
    scan_id: str,
    entropy: dict = None,
    extracted_strings: dict = None,
    manifest: dict = None,
    webhook_kills: dict = None,
    nested_count: int = 0,
    zip_bomb_warning: str = None,
    format_analysis: dict = None,
    deobfuscation: dict = None,
    mb_result: dict = None,
) -> list[discord.Embed]:
    embeds = []
    emoji = LEVEL_EMOJI.get(level, "")
    budget = [MAX_EMBED_TOTAL]  # mutable list so _safe_add_field can decrement

    # — Main embed —
    # Build a brief description of what was analyzed
    scan_steps = ["hash checked against threat databases"]
    if iocs:
        scan_steps.append("Java bytecode decompiled and inspected")
    if yara_matches:
        scan_steps.append(f"{len(yara_matches)} YARA rule(s) matched")
    if vt and vt.get("total", 0) > 0:
        scan_steps.append("checked VirusTotal")
    if mb_result and mb_result.get("status") == "found":
        scan_steps.append("found in MalwareBazaar")
    elif mb_result:
        scan_steps.append("not found in MalwareBazaar")
    scan_desc = "Analyzed: " + ", ".join(scan_steps) + "."

    e = discord.Embed(
        title=f"{emoji} Scan Results: {filename[:70]}",
        color=color,
        timestamp=datetime.now(timezone.utc),
    )

    # ── Plain-language summary at the top ──
    variant_raw = ""
    if iocs:
        variant_raw = (iocs.get("variant") or "").lower()
    summary = _build_plain_summary(score, level, variant_raw, iocs, vt, yara_matches,
                                   extracted_strings, mb_result)
    e.description = summary

    # risk score with context
    bar_filled = score // 10
    bar_empty = 10 - bar_filled
    bar = "\u2588" * bar_filled + "\u2591" * bar_empty
    if score <= DETECTION_THRESHOLD:
        risk_hint = "No significant threats detected \u2014 file appears safe"
    elif score <= 35:
        risk_hint = "Minor flags detected \u2014 likely normal behavior from libraries or installers, review details below to confirm"
    elif score <= 60:
        risk_hint = "Multiple suspicious indicators found \u2014 exercise caution and review the flagged behaviors before running"
    else:
        risk_hint = "Strong malware indicators \u2014 do not run this file"
    e.add_field(
        name="Risk Score",
        value=f"**{score}/100** ({level})\n`{bar}`\n{risk_hint}",
        inline=True,
    )

    # variant
    variant_display = "None detected"
    if iocs:
        v = iocs.get("variant", "")
        if v and v.lower() != "unknown":
            variant_display = v.upper()
            subtype = iocs.get("subtype", "")
            if subtype:
                variant_display += f" ({subtype})"
            campaign = iocs.get("campaignId", "")
            if campaign:
                variant_display += f"\nCampaign: `{campaign[:12]}...`"
    e.add_field(name="Variant", value=variant_display, inline=True)

    # file info
    size_str = (
        f"{file_size / 1024 / 1024:.1f} MB"
        if file_size > 1024 * 1024
        else f"{file_size / 1024:.1f} KB"
    )
    e.add_field(name="File Size", value=size_str, inline=True)

    # hashes
    sha256 = hashes["sha256"]
    hash_text = f"**SHA-256:** `{sha256}`\n**MD5:** `{hashes['md5']}`\n**SHA-1:** `{hashes['sha1']}`"
    e.add_field(name="Hashes", value=hash_text, inline=False)

    # zip bomb warning
    if zip_bomb_warning:
        e.add_field(
            name="\U0001F4A3 ZIP BOMB DETECTED",
            value=f"```{zip_bomb_warning}```\nScan was aborted for safety.",
            inline=False,
        )

    # VirusTotal — ALWAYS shown with link
    if vt:
        vt_status = vt.get("status", "found")
        if vt_status == "queued":
            vt_text = "Uploaded — analysis still processing on VirusTotal"
        elif vt_status in ("upload_failed", "error"):
            vt_text = f"Upload issue — check manually"
        else:
            vt_text = f"**{vt['detected']}/{vt['total']}** engines detected"
            if vt.get("meaningful_name"):
                vt_text += f"\nName: `{vt['meaningful_name']}`"
            if vt.get("first_seen"):
                try:
                    first = datetime.fromtimestamp(vt["first_seen"], tz=timezone.utc).strftime("%Y-%m-%d")
                    vt_text += f"\nFirst seen: {first}"
                except Exception:
                    pass
            if vt.get("detections"):
                top = list(vt["detections"].items())[:8]
                vt_text += "\n" + " | ".join(f"`{name}`" for name, _ in top)
                if len(vt["detections"]) > 8:
                    vt_text += f" +{len(vt['detections']) - 8} more"
        # Always include the link
        if vt.get("permalink"):
            vt_text += f"\n**[View on VirusTotal]({vt['permalink']})**"
        e.add_field(name="\U0001F9EA VirusTotal", value=_trunc(vt_text), inline=False)
    elif CFG["virustotal"]["enabled"] and CFG["virustotal"]["api_key"]:
        vt_link = f"https://www.virustotal.com/gui/file/{hashes['sha256']}"
        e.add_field(name="\U0001F9EA VirusTotal", value=f"[Check on VirusTotal]({vt_link})", inline=False)

    # C2 infrastructure
    if iocs:
        c2_parts = []
        if iocs.get("c2Base"):
            c2_parts.append(f"**C2 Base:** `{iocs['c2Base']}`")
        if iocs.get("ethContract"):
            c2_parts.append(f"**ETH Contract:** `{iocs['ethContract']}`")
        if iocs.get("contracts"):
            for c in iocs["contracts"]:
                c2_parts.append(f"**Contract:** `{c}`")
        if iocs.get("exfilUrl"):
            c2_parts.append(f"**Exfil:** `{iocs['exfilUrl']}`")
        if iocs.get("stage2Url"):
            c2_parts.append(f"**Stage 2:** `{iocs['stage2Url']}`")
        if iocs.get("ethMethod"):
            c2_parts.append(f"**ETH Method:** `{iocs['ethMethod']}`")
        if iocs.get("buyerUUID"):
            c2_parts.append(f"**Buyer UUID:** `{iocs['buyerUUID']}`")
        if c2_parts:
            e.add_field(name="\U0001F310 C2 Infrastructure", value=_trunc("\n".join(c2_parts)), inline=False)

    # Extracted IDs — Weedhack campaign + operator routing IDs
    if iocs and iocs.get("variant") == "weedhack" and iocs.get("campaignId"):
        campaign_uuid = iocs["campaignId"]
        # In Weedhack, the campaign UUID doubles as the operator userId on the C2 platform
        # It's sent as "minecraftInfo" in direct exfil and "userId" in Stage 2 context
        ids_text = f"```\n{campaign_uuid} : {campaign_uuid}\n```"
        ids_text += "*Campaign UUID (left) : Operator User ID (right) — same value, used as routing key on C2*"
        e.add_field(name="\U0001F50D Extracted IDs", value=ids_text, inline=False)

    # webhooks (with kill status)
    if iocs or (extracted_strings and extracted_strings.get("discord_webhooks")):
        wh_lines = []
        for key in ("webhook", "webhookUrl"):
            if iocs and iocs.get(key):
                url = iocs[key]
                status = ""
                if webhook_kills and url in webhook_kills:
                    status = f" **[{webhook_kills[url]}]**"
                wh_lines.append(f"`{url[:70]}...`{status}")
        if iocs and iocs.get("webhookStatus"):
            wh_lines.append(f"Status: {iocs['webhookStatus']}")
        if extracted_strings and extracted_strings.get("discord_webhooks"):
            for wh in extracted_strings["discord_webhooks"]:
                line = f"`{wh[:70]}...`"
                if webhook_kills and wh in webhook_kills:
                    line += f" **[{webhook_kills[wh]}]**"
                if line not in wh_lines:
                    wh_lines.append(line)
        if wh_lines:
            e.add_field(name="\U0001F4E3 Discord Webhooks", value=_trunc("\n".join(wh_lines[:5])), inline=False)

    # discord tokens found
    if extracted_strings and extracted_strings.get("discord_tokens"):
        count = len(extracted_strings["discord_tokens"])
        e.add_field(
            name="\U0001F512 Discord Tokens Found",
            value=f"**{count}** token(s) found embedded in file (redacted)",
            inline=False,
        )

    # YARA
    if yara_matches:
        yara_lines = []
        for m in yara_matches[:10]:
            severity = m.get("meta", {}).get("severity", "unknown")
            yara_lines.append(f"`{m['rule']}` ({severity})")
        e.add_field(
            name=f"\U0001F9EC YARA ({len(yara_matches)} match{'es' if len(yara_matches) != 1 else ''})",
            value=_trunc("\n".join(yara_lines)),
            inline=False,
        )

    # obfuscators
    if obfuscators:
        obf_text = ", ".join(f"`{o}`" for o in obfuscators)
        # If we have decrypted strings from JarAnalyzer, replace generic message
        decrypted = iocs.get("decryptedStrings", []) if iocs else []
        if decrypted:
            obf_text += f"\n**{len(decrypted)} string(s) auto-decrypted:**"
            for ds in decrypted[:10]:
                truncated = ds[:70] + ("..." if len(ds) > 70 else "")
                obf_text += f"\n`{truncated}`"
            if len(decrypted) > 10:
                obf_text += f"\n*...and {len(decrypted) - 10} more*"
        else:
            obf_text += "\n*Obfuscation scrambles the code to make it hard to read. Both malware AND legitimate programs use this to protect their code.*"
        e.add_field(
            name="\U0001F576 Obfuscators Detected",
            value=obf_text,
            inline=False,
        )

    # entropy
    if entropy:
        ent_text = f"Overall: **{entropy.get('overall', 0):.1f}**/8.0"
        if entropy.get("max_class_entropy", 0) > 0:
            ent_text += f" | Max class: **{entropy['max_class_entropy']:.1f}**"
        if entropy.get("suspicious_entries"):
            ent_text += f"\n**{len(entropy['suspicious_entries'])}** high-entropy entries (>7.5):"
            for se in entropy["suspicious_entries"][:3]:
                ent_text += f"\n  `{se['name'][:40]}` \u2014 {se['entropy']:.1f} ({se['size']} bytes)"
        ent_text += "\n*Entropy measures randomness. High values can mean encrypted/compressed data (normal in obfuscated mods) or hidden payloads.*"
        e.add_field(name="\U0001F4CA Entropy", value=_trunc(ent_text), inline=False)

    # manifest
    if manifest and manifest.get("suspicious_keys"):
        mf_text = "\n".join(f"`{k}`" for k in manifest["suspicious_keys"][:5])
        mf_text += "\n*The manifest is like a label on the JAR. These entries let the program run code automatically or modify other programs. Mixin-based mods use these legitimately.*"
        e.add_field(name="\U0001F4C4 Manifest Entries", value=mf_text, inline=False)

    # extracted URLs — sanitize paths
    if extracted_strings and extracted_strings.get("urls"):
        suspicious_urls = [
            u for u in extracted_strings["urls"]
            if not any(safe in u for safe in [
                "minecraft.net", "mojang.com", "github.com", "googleapis.com",
                "apache.org", "oracle.com", "java.com", "jetbrains.com",
                "fabricmc.net", "spongepowered.org", "curseforge.com",
                "launchermeta.mojang.com", "modrinth.com",
            ])
        ][:10]
        if suspicious_urls:
            url_text = "\n".join(f"`{sanitize_path(u[:80])}`" for u in suspicious_urls)
            e.add_field(name="\U0001F517 Extracted URLs", value=url_text, inline=False)

    # extracted IPs
    if extracted_strings and extracted_strings.get("ipv4"):
        ip_text = ", ".join(f"`{ip}`" for ip in extracted_strings["ipv4"][:10])
        e.add_field(name="\U0001F310 Extracted IPs", value=ip_text, inline=False)

    # ETH addresses
    if extracted_strings and extracted_strings.get("eth_addresses"):
        eth_text = "\n".join(f"`{a}`" for a in extracted_strings["eth_addresses"][:5])
        e.add_field(name="\U0001F4B0 Ethereum Addresses", value=eth_text, inline=False)

    # behavioral markers — split into threats vs informational
    marker_details = {}
    if iocs:
        marker_details = iocs.get("markerDetails", {})
        markers = iocs.get("behavioralMarkers", [])
        important = [m for m in markers if not m.startswith("Bytecode API ref:")]
        high_risk = [m for m in important if "HIGH RISK" in m]
        # Markers with " — " contain our detailed descriptions
        threats = high_risk[:]
        info_markers = []
        for m in important:
            if m in high_risk:
                continue
            # Known malicious domains/infra are always threats
            if any(x in m.lower() for x in ["known malicious", "confirmed", "c2", "exfil", "stealer"]):
                threats.append(m)
            else:
                info_markers.append(m)

        def _format_marker_with_details(marker_label, prefix=""):
            """Format a marker with file/line details if available."""
            line = f"{prefix}{sanitize_path(marker_label)}"
            details = marker_details.get(marker_label, [])
            if details:
                # Show first location
                d = details[0]
                f_name = d.get("file", "")
                f_line = d.get("line", "0")
                if f_name:
                    loc = f"`{f_name}"
                    if f_line and f_line != "0":
                        loc += f":{f_line}"
                    loc += "`"
                    line += f"\n  {loc}"
                    ctx = d.get("context", "").strip()
                    if ctx and len(ctx) > 3:
                        line += f" — `{sanitize_path(ctx[:60])}`"
                if len(details) > 1:
                    line += f" (+{len(details) - 1} more location{'s' if len(details) > 2 else ''})"
            return line

        if threats:
            text = "\n".join(_format_marker_with_details(m, "\U0001F6A8 ") for m in threats[:6])
            if len(threats) > 6:
                text += f"\n*... and {len(threats) - 6} more*"
            _safe_add_field(e, budget, name="\U0001F6A8 Threat Indicators", value=_trunc(text), inline=False)
        if info_markers:
            text = ("*These are things the file CAN do. Many normal programs do these things too "
                    "(like game launchers, mods, installers). They're only concerning when combined "
                    "with other red flags above:*\n")
            text += "\n".join(_format_marker_with_details(m, "\u2022 ") for m in info_markers[:8])
            if len(info_markers) > 8:
                text += f"\n*... and {len(info_markers) - 8} more*"
            _safe_add_field(e, budget, name="\U0001F50D Observed Behaviors", value=_trunc(text), inline=False)

    # ── Deobfuscated strings ──
    if deobfuscation and deobfuscation.get("detected"):
        deob_lines = [f"**String encryption cracked** — {deobfuscation['total_decrypted']} strings "
                      f"from {deobfuscation['classes_with_strings']} classes"]
        algos = deobfuscation.get("algorithms", [])
        if algos:
            deob_lines.append(f"Algorithms: {', '.join(algos)}")
        # Show interesting decrypted strings (URLs, domains, paths, tokens)
        interesting = []
        mundane = []
        for s in deobfuscation.get("strings", []):
            d = s["decrypted"]
            if any(x in d.lower() for x in ["http", "://", ".com", ".net", ".ru", ".shop",
                    "webhook", "token", "password", "discord", "minecraft", "session",
                    "appdata", "roaming", ".exe", ".dll", ".jar", "launcher_accounts"]):
                interesting.append(d)
            elif len(d) > 3:
                mundane.append(d)
        if interesting:
            deob_lines.append("**Notable decrypted strings:**")
            for s in interesting[:8]:
                deob_lines.append(f"  `{sanitize_path(s[:80])}`")
            if len(interesting) > 8:
                deob_lines.append(f"  *... and {len(interesting) - 8} more*")
        elif mundane:
            deob_lines.append("**Sample decrypted strings:**")
            for s in mundane[:5]:
                deob_lines.append(f"  `{sanitize_path(s[:80])}`")
        _safe_add_field(e, budget, name="\U0001F513 Deobfuscated Strings", value=_trunc("\n".join(deob_lines)), inline=False)

    # ── Format-specific analysis ──
    if format_analysis:
        fa_type = format_analysis.get("type", "")

        if fa_type == "PE":
            pe_lines = [f"**Type:** {fa_type} ({format_analysis.get('arch', '?')})"]
            if format_analysis.get("is_dll"):
                pe_lines.append("**DLL:** Yes")
            if format_analysis.get("timestamp"):
                pe_lines.append(f"**Compiled:** {format_analysis['timestamp']}")
            if format_analysis.get("packers"):
                pe_lines.append(f"**Packers:** {', '.join(f'`{p}`' for p in format_analysis['packers'])}")
            if format_analysis.get("bundled_modules"):
                mod_text = ", ".join(f"`{m.split(':')[0].strip()}`" for m in format_analysis["bundled_modules"][:8])
                pe_lines.append(f"**Bundled Modules:** {mod_text}")
            if format_analysis.get("import_count"):
                pe_lines.append(f"**Imports:** {format_analysis['import_count']}")
            for w in format_analysis.get("warnings", [])[:5]:
                pe_lines.append(f"\u26A0 {sanitize_path(w)}")
            si = format_analysis.get("suspicious_imports", {})
            for cat, apis in list(si.items())[:4]:
                pe_lines.append(f"**{cat}:** {', '.join(f'`{a}`' for a in apis[:5])}")
            if format_analysis.get("sections"):
                high_ent = [s for s in format_analysis["sections"] if s["entropy"] > 7.0]
                if high_ent:
                    for s in high_ent[:3]:
                        pe_lines.append(f"Section `{s['name']}`: entropy {s['entropy']}")
            e.add_field(name="\U0001F4BB PE Analysis", value=_trunc("\n".join(pe_lines[:15])), inline=False)

        elif fa_type == "PDF":
            pdf_lines = [f"**{format_analysis.get('version', 'PDF')}** | {format_analysis.get('stream_count', 0)} stream(s)"]
            for f_item in format_analysis.get("findings", [])[:8]:
                if isinstance(f_item, dict):
                    sev_icon = "\U0001F6A8" if f_item.get("severity") == "critical" else "\u26A0" if f_item.get("severity") == "high" else "\u2139"
                    pdf_lines.append(f"{sev_icon} `{f_item.get('keyword', '?')}` \u00d7{f_item.get('count', '?')}")
                else:
                    pdf_lines.append(f"\u2022 {f_item}")
            for w in format_analysis.get("warnings", [])[:3]:
                pdf_lines.append(f"\U0001F6A8 {w}")
            e.add_field(name="\U0001F4C4 PDF Analysis", value=_trunc("\n".join(pdf_lines[:12])), inline=False)

        elif fa_type == "Office":
            off_lines = [f"**Format:** {format_analysis.get('format', '?')}"]
            if format_analysis.get("has_macros"):
                off_lines.append("\U0001F6A8 **VBA Macros detected**")
            if format_analysis.get("auto_triggers"):
                off_lines.append(f"**Auto-exec triggers:** {', '.join(f'`{t}`' for t in format_analysis['auto_triggers'])}")
            if format_analysis.get("dde_found"):
                off_lines.append("\U0001F6A8 **DDE auto-link detected**")
            sk = format_analysis.get("suspicious_keywords", {})
            for cat, kws in list(sk.items())[:4]:
                off_lines.append(f"**{cat}:** {', '.join(f'`{k}`' for k in kws[:5])}")
            for w in format_analysis.get("warnings", [])[:3]:
                off_lines.append(f"\u26A0 {sanitize_path(w)}")
            e.add_field(name="\U0001F4C3 Office Analysis", value=_trunc("\n".join(off_lines[:12])), inline=False)

        elif fa_type == "LNK":
            lnk_lines = []
            for w in format_analysis.get("warnings", [])[:6]:
                lnk_lines.append(f"\u26A0 {sanitize_path(w)}")
            if format_analysis.get("size", 0) > 0:
                lnk_lines.append(f"**Size:** {format_analysis['size']} bytes")
            e.add_field(name="\U0001F517 Shortcut (LNK) Analysis", value=_trunc("\n".join(lnk_lines[:8]) or "Clean"), inline=False)

        elif fa_type == "Script":
            sc_lines = [f"**Extension:** `{format_analysis.get('extension', '?')}`"]
            if format_analysis.get("lolbins"):
                sc_lines.append(f"**LOLBins:** {', '.join(f'`{l}`' for l in format_analysis['lolbins'])}")
            sk = format_analysis.get("suspicious_keywords", {})
            for cat, kws in list(sk.items())[:4]:
                sc_lines.append(f"**{cat}:** {', '.join(f'`{k}`' for k in kws[:5])}")
            obf = format_analysis.get("obfuscation_score", 0)
            if obf > 0:
                sc_lines.append(f"**Obfuscation score:** {obf}")
            for w in format_analysis.get("warnings", [])[:4]:
                sc_lines.append(f"\u26A0 {sanitize_path(w)}")
            e.add_field(name="\U0001F4DC Script Analysis", value=_trunc("\n".join(sc_lines[:12])), inline=False)

        elif fa_type == "MSI":
            msi_lines = []
            if format_analysis.get("has_custom_actions"):
                msi_lines.append("\u26A0 CustomAction table present")
            if format_analysis.get("embedded_executables"):
                msi_lines.append(f"\U0001F6A8 **{len(format_analysis['embedded_executables'])} embedded PE(s)**")
            for w in format_analysis.get("warnings", [])[:5]:
                msi_lines.append(f"\u26A0 {sanitize_path(w)}")
            for f_item in format_analysis.get("findings", [])[:3]:
                if isinstance(f_item, dict):
                    msi_lines.append(f"- {f_item.get('keyword', f_item)}")
                else:
                    msi_lines.append(f"- {f_item}")
            e.add_field(name="\U0001F4E6 MSI Analysis", value=_trunc("\n".join(msi_lines[:10]) or "No issues found"), inline=False)

        elif fa_type == "ISO":
            iso_lines = []
            if format_analysis.get("suspicious_files"):
                iso_lines.append(f"**Dangerous files inside:**")
                for sf in format_analysis["suspicious_files"][:8]:
                    iso_lines.append(f"  `{sf}`")
            for w in format_analysis.get("warnings", [])[:4]:
                iso_lines.append(f"\u26A0 {w}")
            e.add_field(name="\U0001F4BF ISO/IMG Analysis", value=_trunc("\n".join(iso_lines[:12]) or "No issues found"), inline=False)

    # footer
    footer_parts = [f"Scan ID: {scan_id}", f"{scan_time:.1f}s"]
    if nested_count > 0:
        footer_parts.append(f"{nested_count} nested JAR(s)")
    if format_analysis:
        footer_parts.append(format_analysis.get("type", ""))
    e.set_footer(text=" | ".join(footer_parts))

    embeds.append(e)

    # — Suspicious bytecode overflow embed with context —
    if iocs:
        bytecode_markers = [m for m in iocs.get("behavioralMarkers", []) if m.startswith("Bytecode API ref:")]
        # Split into non-library (interesting) vs library (noise)
        non_lib_markers = [m for m in bytecode_markers if "[LIB]" not in m]
        lib_markers = [m for m in bytecode_markers if "[LIB]" in m]
        # Categorize non-library bytecode refs by risk level
        high_concern = []  # APIs that are almost always suspicious in mods
        moderate_concern = []  # APIs that are common but worth noting
        other_concern = []  # Everything else worth showing
        ALWAYS_SUSPICIOUS = ["defineClass", "URLClassLoader"]
        CONTEXT_DEPENDENT = ["Runtime.exec", "ProcessBuilder", "System.load", "System.loadLibrary", "deleteOnExit", "setAccessible"]
        for m in non_lib_markers:
            if any(x in m for x in ALWAYS_SUSPICIOUS):
                high_concern.append(m)
            elif any(x in m for x in CONTEXT_DEPENDENT):
                moderate_concern.append(m)
            else:
                other_concern.append(m)
        if high_concern or moderate_concern or other_concern:
            e2 = discord.Embed(title="\U0001F50E Bytecode API Analysis", color=color)
            lines = [("*We looked at what Java commands this file uses. "
                       "Think of these like capabilities \u2014 things it CAN do. "
                       "Normal mods use some of these too, so they're not automatically bad. "
                       "Library code (LWJGL, Fabric, etc.) is already filtered out.*\n")]
            # Clean up obfuscated class names for readability
            _obf_map = {}  # shared across all categories so numbering is consistent
            if high_concern:
                lines.append("**High-interest APIs** (dual-use — legitimate in some contexts, also used by malware):")
                for m in high_concern[:10]:
                    cleaned = _clean_class_name(sanitize_path(m.replace('[LIB] ', '')), _obf_map)
                    lines.append(f"\U0001F6A8 {cleaned}")
            if moderate_concern:
                lines.append("**Context-dependent** (normal for installers/launchers, also used by malware):")
                for m in moderate_concern[:10]:
                    cleaned = _clean_class_name(sanitize_path(m.replace('[LIB] ', '')), _obf_map)
                    lines.append(f"\u26A0 {cleaned}")
            if other_concern:
                lines.append("**Other API references:**")
                for m in other_concern[:8]:
                    cleaned = _clean_class_name(sanitize_path(m.replace('[LIB] ', '')), _obf_map)
                    lines.append(f"\u2022 {cleaned}")
            total = len(high_concern) + len(moderate_concern) + len(other_concern)
            if total > 28:
                lines.append(f"*... and {total - 28} more*")
            if lib_markers:
                lines.append(f"\n*{len(lib_markers)} additional API refs from known libraries were excluded from scoring*")
            e2.description = _trunc("\n".join(lines), 4000)
            embeds.append(e2)
        elif lib_markers:
            # Only library markers — don't show the embed at all (no suspicious non-library bytecode)
            pass

    # Enforce Discord's 6000 total character limit across all embeds
    total_chars = sum(_embed_char_count(em) for em in embeds)
    while total_chars > MAX_EMBED_TOTAL and len(embeds) > 1:
        # Drop the overflow embed first
        removed = embeds.pop()
        total_chars = sum(_embed_char_count(em) for em in embeds)
    # If single embed still too large, trim fields from the end (keep first 6: score, variant, size, hashes, bomb, VT)
    if total_chars > MAX_EMBED_TOTAL and embeds:
        main = embeds[0]
        while _embed_char_count(main) > MAX_EMBED_TOTAL and len(main.fields) > 6:
            main.remove_field(len(main.fields) - 1)
        # If still over, truncate the last field value
        if _embed_char_count(main) > MAX_EMBED_TOTAL and main.fields:
            last = main.fields[-1]
            overflow = _embed_char_count(main) - MAX_EMBED_TOTAL
            new_val = last.value[:max(50, len(last.value) - overflow - 30)] + "\n*... (trimmed for size)*"
            main.set_field_at(len(main.fields) - 1, name=last.name, value=new_val, inline=last.inline)

    return embeds


# ─── Service-Specific Embeds (each sent as its own message) ──────────────────

def build_vt_embed(vt: dict, sha256: str, scan_id: str) -> discord.Embed:
    """Build a standalone VirusTotal embed."""
    vt_status = vt.get("status", "found")
    if vt_status == "queued":
        color = 0xF39C12
        desc = "Uploaded \u2014 analysis still processing on VirusTotal\nResults will appear once scanning completes."
    elif vt_status in ("upload_failed", "error"):
        color = 0xE74C3C
        desc = "Upload issue \u2014 check manually"
    else:
        detected = vt.get("detected", 0)
        total = vt.get("total", 0)
        if detected == 0:
            color = 0x2ECC71
        elif detected <= 5:
            color = 0xF39C12
        else:
            color = 0xE74C3C
        desc = f"**{detected}/{total}** engines detected this file"
        if vt.get("meaningful_name"):
            desc += f"\n**Name:** `{vt['meaningful_name']}`"
        if vt.get("first_seen"):
            try:
                first = datetime.fromtimestamp(vt["first_seen"], tz=timezone.utc).strftime("%Y-%m-%d")
                desc += f"\n**First seen:** {first}"
            except Exception:
                pass
        if vt.get("detections"):
            top = list(vt["detections"].items())[:12]
            desc += "\n\n**Detections:**\n"
            desc += " | ".join(f"`{name}`" for name, _ in top)
            if len(vt["detections"]) > 12:
                desc += f" +{len(vt['detections']) - 12} more"

    e = discord.Embed(
        title="\U0001F9EA VirusTotal",
        description=_trunc(desc, 2000),
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    if vt.get("permalink"):
        e.add_field(name="Link", value=f"**[View Full Report on VirusTotal]({vt['permalink']})**", inline=False)
    if vt.get("tags"):
        e.add_field(name="Tags", value=" ".join(f"`{t}`" for t in vt["tags"][:10]), inline=False)
    e.set_footer(text=f"Scan ID: {scan_id}")
    return e


def build_vt_sandbox_embed(vt_sandbox: list, sha256: str, scan_id: str) -> discord.Embed:
    """Build a standalone VT Sandbox embed."""
    e = discord.Embed(
        title="\U0001F9EC VirusTotal Sandbox Analysis",
        color=0x5865F2,
        timestamp=datetime.now(timezone.utc),
    )
    if vt_sandbox:
        desc_lines = []
        for i, sb in enumerate(vt_sandbox[:2], 1):
            desc_lines.append(f"**VM {i}: {sb['sandbox_name']}**")
            desc_lines.append(f"[View Behavior Report]({sb['link']})")
            if sb.get("analysis_date"):
                desc_lines.append(f"Analyzed: {sb['analysis_date']}")
            desc_lines.append("")
        behavior_link = f"https://www.virustotal.com/gui/file/{sha256}/behavior"
        desc_lines.append(f"**[View All Behavior Reports]({behavior_link})**")
        e.description = "\n".join(desc_lines)
    else:
        behavior_link = f"https://www.virustotal.com/gui/file/{sha256}/behavior"
        e.description = (
            "Sandbox analysis may still be processing.\n"
            f"**[Check Sandbox Results]({behavior_link})**\n\n"
            "VT typically runs files in 2 sandbox environments. "
            "Results appear within 5\u201310 minutes of upload."
        )
    e.set_footer(text=f"Scan ID: {scan_id}")
    return e


def build_mb_embed(mb_result: Optional[dict], sha256: str, scan_id: str) -> discord.Embed:
    """Build a standalone MalwareBazaar embed."""
    permalink = f"https://bazaar.abuse.ch/sample/{sha256}/"
    if mb_result and mb_result.get("status") == "found":
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            color=0xE74C3C,
            timestamp=datetime.now(timezone.utc),
        )
        desc_parts = ["**Known malware sample found in database**\n"]
        if mb_result.get("signature"):
            desc_parts.append(f"**Signature:** `{mb_result['signature']}`")
        if mb_result.get("file_type"):
            desc_parts.append(f"**File Type:** `{mb_result['file_type']}`")
        if mb_result.get("tags"):
            desc_parts.append(f"**Tags:** {', '.join(f'`{t}`' for t in mb_result['tags'][:10])}")
        if mb_result.get("first_seen"):
            desc_parts.append(f"**First Seen:** {mb_result['first_seen']}")
        if mb_result.get("delivery_method"):
            desc_parts.append(f"**Delivery Method:** `{mb_result['delivery_method']}`")
        if mb_result.get("reporter"):
            desc_parts.append(f"**Reported By:** {mb_result['reporter']}")
        if mb_result.get("downloads"):
            desc_parts.append(f"**Downloads:** {mb_result['downloads']}")
        desc_parts.append(f"\n**[View on MalwareBazaar]({permalink})**")
        e.description = _trunc("\n".join(desc_parts), 2000)
    elif mb_result and mb_result.get("status") == "uploaded":
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"Sample uploaded to abuse.ch database.\n\n**[View on MalwareBazaar]({permalink})**",
            color=0xF39C12,
            timestamp=datetime.now(timezone.utc),
        )
    elif mb_result and mb_result.get("status") == "already_exists":
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"Sample already exists in abuse.ch database.\n\n**[View on MalwareBazaar]({permalink})**",
            color=0xF39C12,
            timestamp=datetime.now(timezone.utc),
        )
    elif mb_result and mb_result.get("status") == "not_found":
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"Not found in abuse.ch database — this sample has not been reported.\n\n**[Search MalwareBazaar]({permalink})**",
            color=0x2ECC71,
            timestamp=datetime.now(timezone.utc),
        )
    elif mb_result and mb_result.get("status") == "upload_failed":
        detail = mb_result.get("detail", "unknown error")
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"Upload failed: {detail}\n\n**[Search MalwareBazaar]({permalink})**",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc),
        )
    elif mb_result and mb_result.get("status") == "error":
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"API request failed.\n\n**[Search Manually]({permalink})**",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc),
        )
    else:
        e = discord.Embed(
            title="\U0001F9A0 MalwareBazaar",
            description=f"Lookup returned no results — API may be unreachable.\n\n**[Search MalwareBazaar]({permalink})**",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc),
        )
    e.set_footer(text=f"Scan ID: {scan_id}")
    return e


def build_ha_embed(ha_result: Optional[dict], sha256: str, scan_id: str) -> discord.Embed:
    """Build a standalone Hybrid Analysis embed."""
    permalink = f"https://www.hybrid-analysis.com/sample/{sha256}"
    if ha_result and ha_result.get("status") == "found":
        threat_score = ha_result.get("threat_score")
        if threat_score is not None and threat_score >= 80:
            color = 0xE74C3C
        elif threat_score is not None and threat_score >= 50:
            color = 0xF39C12
        else:
            color = 0x2ECC71
        e = discord.Embed(
            title="\U0001F50D Hybrid Analysis",
            color=color,
            timestamp=datetime.now(timezone.utc),
        )
        desc_parts = []
        if ha_result.get("verdict"):
            desc_parts.append(f"**Verdict:** `{ha_result['verdict']}`")
        if threat_score is not None:
            bar_filled = threat_score // 10
            bar_empty = 10 - bar_filled
            bar = "\u2588" * bar_filled + "\u2591" * bar_empty
            desc_parts.append(f"**Threat Score:** {threat_score}/100\n`{bar}`")
        if ha_result.get("environment"):
            desc_parts.append(f"**Environment:** {ha_result['environment']}")
        if ha_result.get("analysis_start_time"):
            desc_parts.append(f"**Analyzed:** {ha_result['analysis_start_time']}")
        desc_parts.append(f"\n**[View Full Report on Hybrid Analysis]({permalink})**")
        e.description = "\n".join(desc_parts)
    elif ha_result and ha_result.get("status") == "submitted":
        e = discord.Embed(
            title="\U0001F50D Hybrid Analysis",
            description=(
                "File submitted for sandbox analysis.\n"
                "**Environment:** Windows 10 64-bit\n"
                "**ETA:** ~5\u201310 minutes\n\n"
                f"**[View Results on Hybrid Analysis]({permalink})**\n"
                "*(page will update when analysis completes)*"
            ),
            color=0xF39C12,
            timestamp=datetime.now(timezone.utc),
        )
    elif ha_result and ha_result.get("status") == "not_found":
        e = discord.Embed(
            title="\U0001F50D Hybrid Analysis",
            description=(
                "Not previously analyzed.\n"
                "File was submitted for sandbox analysis.\n"
                "**ETA:** ~5\u201310 minutes\n\n"
                f"**[View Results on Hybrid Analysis]({permalink})**\n"
                "*(page will update when analysis completes)*"
            ),
            color=0xF39C12,
            timestamp=datetime.now(timezone.utc),
        )
    elif ha_result and ha_result.get("status") == "error":
        error_detail = ha_result.get("error", "Unknown error")
        e = discord.Embed(
            title="\U0001F50D Hybrid Analysis",
            description=f"Lookup failed: {error_detail}\n\n**[Check Manually]({permalink})**",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc),
        )
    else:
        e = discord.Embed(
            title="\U0001F50D Hybrid Analysis",
            description=f"Lookup skipped or unavailable.\n\n**[Check Manually]({permalink})**",
            color=0x95A5A6,
            timestamp=datetime.now(timezone.utc),
        )
    e.set_footer(text=f"Scan ID: {scan_id}")
    return e


def _build_service_pending_embed(title: str, icon: str, eta: str, scan_id: str) -> discord.Embed:
    """Build a pending/loading embed for a service."""
    return discord.Embed(
        title=f"{icon} {title}",
        description=f"\U0001F504 Scanning... (ETA {eta})",
        color=0x3498DB,
        timestamp=datetime.now(timezone.utc),
    ).set_footer(text=f"Scan ID: {scan_id}")


# ─── File Handling ───────────────────────────────────────────────────────────


MAX_ENTRY_SIZE = 50 * 1024 * 1024  # 50MB per entry hard limit


# File extensions worth extracting from zip archives for analysis
SCANNABLE_EXTS = {
    ".jar", ".zip", ".exe", ".dll", ".scr", ".com", ".pif",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".lnk", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".wsf", ".msi", ".iso", ".img",
}


def _is_scannable_entry(name: str, data: bytes) -> bool:
    """Check if a zip entry is worth extracting based on extension or magic bytes."""
    ext = os.path.splitext(name)[1].lower()
    if ext in SCANNABLE_EXTS:
        return True
    # Also check magic bytes for extensionless / misnamed files
    if len(data) >= 4:
        if data[:2] == b"PK":       return True   # JAR/ZIP
        if data[:2] == b"MZ":       return True   # PE (EXE/DLL)
        if data[:5] == b"%PDF-":    return True   # PDF
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":  return True  # OLE2 (doc/xls)
        if data[:4] == b"\x4c\x00\x00\x00":  return True  # LNK
    return False


def extract_files_from_zip(zip_path: str, extract_to: str, depth: int = 0, max_extract_bytes: int = 200 * 1024 * 1024) -> list[str]:
    """Extract scannable files from zip with streaming decompression and size limits."""
    if depth > 3:
        return []
    extracted = []
    total_extracted = 0
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in zf.namelist():
                try:
                    info = zf.getinfo(entry)
                    if info.is_dir():
                        continue
                    if info.file_size > max_extract_bytes or info.file_size > MAX_ENTRY_SIZE:
                        continue
                    chunks = []
                    entry_size = 0
                    per_entry_limit = min(MAX_ENTRY_SIZE, max_extract_bytes - total_extracted)
                    if per_entry_limit <= 0:
                        log.warning(f"Extraction budget exhausted at {total_extracted} bytes")
                        break
                    with zf.open(entry) as ef:
                        while True:
                            chunk = ef.read(65536)
                            if not chunk:
                                break
                            entry_size += len(chunk)
                            if entry_size > per_entry_limit:
                                log.warning(f"Entry {entry} exceeded size limit ({entry_size} bytes), skipping")
                                chunks = None
                                break
                            chunks.append(chunk)
                    if chunks is None:
                        continue
                    data = b"".join(chunks)
                    total_extracted += len(data)
                    if total_extracted > max_extract_bytes:
                        log.warning(f"Extraction budget exceeded at {total_extracted} bytes")
                        break
                    if _is_scannable_entry(entry, data):
                        safe_name = re.sub(r"[^\w.\-]", "_", os.path.basename(entry))
                        if not safe_name:
                            safe_name = f"nested_{depth}_{len(extracted)}"
                        dest = os.path.join(extract_to, f"depth{depth}_{safe_name}")
                        # Zip slip protection: ensure dest stays within extract_to
                        if not os.path.abspath(dest).startswith(os.path.abspath(extract_to)):
                            log.warning(f"Zip slip blocked: {entry} -> {dest}")
                            continue
                        with open(dest, "wb") as dst:
                            dst.write(data)
                        extracted.append(dest)
                        # Recurse into nested zips/jars
                        if len(data) >= 2 and data[:2] == b"PK":
                            extracted.extend(extract_files_from_zip(dest, extract_to, depth + 1,
                                                                     max_extract_bytes - total_extracted))
                except Exception:
                    pass
    except zipfile.BadZipFile:
        pass
    return extracted


def is_valid_jar(filepath: str) -> bool:
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            return any(n.endswith(".class") for n in zf.namelist())
    except Exception:
        return False


# ─── Full Report Writer ──────────────────────────────────────────────────────


def write_full_report(log_dir: str, **kwargs):
    """Write full_report.txt and decrypted_strings.txt into the log directory.

    Includes everything shown in Discord embeds plus all deobfuscated data.
    """
    ld = Path(log_dir)
    if not ld.exists():
        return

    filename = kwargs.get("filename", "unknown")
    file_size = kwargs.get("file_size", 0)
    hashes = kwargs.get("hashes", {})
    iocs = kwargs.get("iocs")
    vt = kwargs.get("vt")
    yara_matches = kwargs.get("yara_matches", [])
    obfuscators = kwargs.get("obfuscators", [])
    score = kwargs.get("score", 0)
    level = kwargs.get("level", "LOW")
    scan_id = kwargs.get("scan_id", "")
    scan_time = kwargs.get("scan_time", 0)
    entropy = kwargs.get("entropy")
    extracted_strings = kwargs.get("extracted_strings")
    manifest = kwargs.get("manifest")
    webhook_kills = kwargs.get("webhook_kills", {})
    format_analysis = kwargs.get("format_analysis")
    deobfuscation = kwargs.get("deobfuscation")
    mb_result = kwargs.get("mb_result")
    ha_result = kwargs.get("ha_result")
    vt_sandbox = kwargs.get("vt_sandbox")

    try:
        lines = []
        lines.append("=" * 70)
        lines.append("  FULL SCAN REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"File:       {filename}")
        lines.append(f"Size:       {file_size:,} bytes")
        lines.append(f"SHA-256:    {hashes.get('sha256', '')}")
        lines.append(f"MD5:        {hashes.get('md5', '')}")
        lines.append(f"SHA-1:      {hashes.get('sha1', '')}")
        lines.append(f"Scan ID:    {scan_id}")
        lines.append(f"Scan Time:  {scan_time:.1f}s")
        lines.append(f"Score:      {score}/100 ({level})")
        lines.append("")

        # Variant
        if iocs:
            v = iocs.get("variant", "")
            if v and v.lower() != "unknown":
                lines.append(f"Variant:    {v.upper()}")
                if iocs.get("subtype"):
                    lines.append(f"Sub-type:   {iocs['subtype']}")
                if iocs.get("campaignId"):
                    lines.append(f"Campaign:   {iocs['campaignId']}")
            lines.append("")

        # C2 Infrastructure
        if iocs:
            c2_fields = [("c2Base", "C2 Base"), ("ethContract", "ETH Contract"),
                         ("ethMethod", "ETH Method"), ("exfilUrl", "Exfil URL"),
                         ("stage2Url", "Stage 2 URL"), ("stage2Class", "Stage 2 Class"),
                         ("stage2Method", "Stage 2 Method")]
            c2_lines = []
            for key, label in c2_fields:
                if iocs.get(key):
                    c2_lines.append(f"  {label:16s}: {iocs[key]}")
            # Silent NET / generic contract array support
            if iocs.get("contracts"):
                for c in iocs["contracts"]:
                    c2_lines.append(f"  {'Contract':16s}: {c}")
            if iocs.get("buyerUUID"):
                c2_lines.append(f"  {'Buyer UUID':16s}: {iocs['buyerUUID']}")
            if c2_lines:
                lines.append("── C2 INFRASTRUCTURE ──")
                lines.extend(c2_lines)
                lines.append("")

        # Webhooks
        all_wh = set()
        if iocs:
            for key in ("webhook", "webhookUrl"):
                if iocs.get(key):
                    all_wh.add(iocs[key])
        if extracted_strings and extracted_strings.get("discord_webhooks"):
            all_wh.update(extracted_strings["discord_webhooks"])
        if all_wh:
            lines.append("── DISCORD WEBHOOKS ──")
            for wh in all_wh:
                status = ""
                if webhook_kills and wh in webhook_kills:
                    status = f"  [{webhook_kills[wh]}]"
                lines.append(f"  {wh}{status}")
            lines.append("")

        # VirusTotal
        lines.append("── VIRUSTOTAL ──")
        sha256 = hashes.get("sha256", "")
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}"
        if vt:
            vt_status = vt.get("status", "found")
            if vt_status == "queued":
                lines.append("  Status: Uploaded — analysis still processing")
            elif vt_status in ("upload_failed", "error"):
                lines.append("  Status: Upload issue")
            else:
                lines.append(f"  Detections: {vt['detected']}/{vt['total']}")
                if vt.get("meaningful_name"):
                    lines.append(f"  Name: {vt['meaningful_name']}")
                if vt.get("first_seen"):
                    try:
                        first = datetime.fromtimestamp(vt["first_seen"], tz=timezone.utc).strftime("%Y-%m-%d")
                        lines.append(f"  First seen: {first}")
                    except Exception:
                        pass
                if vt.get("detections"):
                    lines.append(f"  Engines: {', '.join(vt['detections'].keys())}")
            if vt.get("permalink"):
                lines.append(f"  Link: {vt['permalink']}")
            else:
                lines.append(f"  Link: {vt_link}")
        else:
            lines.append(f"  Link: {vt_link}")
        lines.append("")

        # MalwareBazaar
        lines.append("── MALWAREBAZAAR ──")
        mb_link = f"https://bazaar.abuse.ch/sample/{sha256}/"
        if mb_result:
            status = mb_result.get("status", "unknown")
            if status == "found":
                lines.append(f"  Status: FOUND in database")
                if mb_result.get("signature"):
                    lines.append(f"  Signature: {mb_result['signature']}")
                if mb_result.get("first_seen"):
                    lines.append(f"  First seen: {mb_result['first_seen']}")
                if mb_result.get("tags"):
                    lines.append(f"  Tags: {', '.join(mb_result['tags'])}")
            else:
                lines.append(f"  Status: {status}")
            lines.append(f"  Link: {mb_result.get('permalink', mb_link)}")
        else:
            lines.append(f"  Link: {mb_link}")
        lines.append("")

        # Hybrid Analysis
        if ha_result:
            lines.append("── HYBRID ANALYSIS ──")
            if ha_result.get("verdict"):
                lines.append(f"  Verdict: {ha_result['verdict']}")
            if ha_result.get("threat_score") is not None:
                lines.append(f"  Threat Score: {ha_result['threat_score']}/100")
            lines.append(f"  Link: {ha_result.get('permalink', '')}")
            lines.append("")

        # VT Sandbox (vt_sandbox is a list of dicts from vt_get_sandbox_links)
        if vt_sandbox and isinstance(vt_sandbox, list):
            lines.append("── VT SANDBOX REPORTS ──")
            for sb in vt_sandbox:
                name = sb.get("sandbox_name", "Unknown") if isinstance(sb, dict) else str(sb)
                link = sb.get("link", "") if isinstance(sb, dict) else ""
                lines.append(f"  {name}: {link}")
            lines.append("")

        # YARA
        if yara_matches:
            lines.append("── YARA MATCHES ──")
            for m in yara_matches:
                sev = m.get("meta", {}).get("severity", "unknown")
                desc = m.get("meta", {}).get("description", "")
                lines.append(f"  [{sev.upper()}] {m['rule']}")
                if desc:
                    lines.append(f"    {desc}")
            lines.append("")

        # Obfuscators
        if obfuscators:
            lines.append("── OBFUSCATORS ──")
            for o in obfuscators:
                lines.append(f"  {o}")
            # Show auto-decrypted strings from JarAnalyzer
            decrypted = iocs.get("decryptedStrings", []) if iocs else []
            if decrypted:
                lines.append(f"  Auto-decrypted {len(decrypted)} string(s):")
                for ds in decrypted:
                    lines.append(f"    {ds}")
            lines.append("")

        # Entropy
        if entropy:
            lines.append("── ENTROPY ──")
            lines.append(f"  Overall: {entropy.get('overall', 0):.2f}/8.0")
            if entropy.get("max_class_entropy", 0) > 0:
                lines.append(f"  Max class: {entropy['max_class_entropy']:.2f}")
            if entropy.get("suspicious_entries"):
                lines.append(f"  High-entropy entries ({len(entropy['suspicious_entries'])}):")
                for se in entropy["suspicious_entries"]:
                    lines.append(f"    {se['name']} — {se['entropy']:.2f} ({se['size']} bytes)")
            lines.append("")

        # Manifest
        if manifest and manifest.get("suspicious_keys"):
            lines.append("── MANIFEST ENTRIES ──")
            for k in manifest["suspicious_keys"]:
                lines.append(f"  {k}")
            lines.append("")

        # Extracted URLs
        if extracted_strings:
            if extracted_strings.get("urls"):
                lines.append("── EXTRACTED URLS ──")
                for u in extracted_strings["urls"][:50]:
                    lines.append(f"  {u}")
                if len(extracted_strings["urls"]) > 50:
                    lines.append(f"  ... and {len(extracted_strings['urls']) - 50} more")
                lines.append("")

            if extracted_strings.get("ipv4"):
                lines.append("── EXTRACTED IPS ──")
                for ip in extracted_strings["ipv4"]:
                    lines.append(f"  {ip}")
                lines.append("")

            if extracted_strings.get("eth_addresses"):
                lines.append("── ETHEREUM ADDRESSES ──")
                for a in extracted_strings["eth_addresses"]:
                    lines.append(f"  {a}")
                lines.append("")

            if extracted_strings.get("discord_tokens"):
                lines.append("── DISCORD TOKENS ──")
                lines.append(f"  {len(extracted_strings['discord_tokens'])} token(s) found (redacted)")
                lines.append("")

        # Behavioral markers with details
        if iocs:
            markers = iocs.get("behavioralMarkers", [])
            marker_details = iocs.get("markerDetails", {})
            if markers:
                lines.append("── BEHAVIORAL MARKERS ──")
                for m in markers:
                    lines.append(f"  - {m}")
                    details = marker_details.get(m, [])
                    for d in details:
                        f_name = d.get("file", "")
                        f_line = d.get("line", "0")
                        ctx = d.get("context", "").strip()
                        if f_name:
                            loc = f"    @ {f_name}"
                            if f_line and f_line != "0":
                                loc += f":{f_line}"
                            if ctx:
                                loc += f"  →  {ctx}"
                            lines.append(loc)
                lines.append("")

        # Deobfuscated strings summary
        if deobfuscation and deobfuscation.get("detected"):
            lines.append("── DEOBFUSCATED STRINGS ──")
            lines.append(f"  Method: DashO string encryption")
            lines.append(f"  Total decrypted: {deobfuscation['total_decrypted']}")
            lines.append(f"  Classes: {deobfuscation['classes_with_strings']}")
            if deobfuscation.get("algorithms"):
                lines.append(f"  Algorithms: {', '.join(deobfuscation['algorithms'])}")
            lines.append(f"  See decrypted_strings.txt for full list")
            lines.append("")

        # Format analysis
        if format_analysis:
            lines.append("── FORMAT ANALYSIS ──")
            lines.append(f"  Type: {format_analysis.get('type', 'unknown')}")
            for w in format_analysis.get("warnings", []):
                lines.append(f"  WARNING: {w}")
            for f_item in format_analysis.get("findings", []):
                if isinstance(f_item, dict):
                    lines.append(f"  [{f_item.get('severity', '?')}] {f_item.get('keyword', '?')} x{f_item.get('count', '?')}")
                else:
                    lines.append(f"  {f_item}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)

        (ld / "full_report.txt").write_text("\n".join(lines), encoding="utf-8")

    except Exception as e:
        log.warning(f"Failed to write full_report.txt: {e}")

    # Write decrypted_strings.txt
    try:
        str_lines = []

        # DashO deobfuscated strings
        if deobfuscation and deobfuscation.get("detected"):
            str_lines.append("=" * 60)
            str_lines.append("  DECRYPTED / DEOBFUSCATED STRINGS")
            str_lines.append("=" * 60)
            str_lines.append("")
            str_lines.append(f"Source: DashO string encryption")
            str_lines.append(f"Total: {deobfuscation['total_decrypted']} strings from {deobfuscation['classes_with_strings']} classes")
            if deobfuscation.get("algorithms"):
                str_lines.append(f"Algorithms: {', '.join(deobfuscation['algorithms'])}")
            str_lines.append("")
            for s in deobfuscation.get("strings", []):
                cls = s.get("class", "unknown")
                dec = s.get("decrypted", "")
                method = s.get("method", "")
                line = f"[{cls}]"
                if method:
                    line += f" ({method})"
                line += f"  {dec}"
                str_lines.append(line)
            str_lines.append("")

        # Extracted strings from raw scan
        if extracted_strings:
            if extracted_strings.get("discord_webhooks"):
                str_lines.append("── Discord Webhooks ──")
                for wh in extracted_strings["discord_webhooks"]:
                    str_lines.append(f"  {wh}")
                str_lines.append("")
            if extracted_strings.get("urls"):
                str_lines.append("── URLs ──")
                for u in extracted_strings["urls"]:
                    str_lines.append(f"  {u}")
                str_lines.append("")
            if extracted_strings.get("ipv4"):
                str_lines.append("── IP Addresses ──")
                for ip in extracted_strings["ipv4"]:
                    str_lines.append(f"  {ip}")
                str_lines.append("")
            if extracted_strings.get("eth_addresses"):
                str_lines.append("── Ethereum Addresses ──")
                for a in extracted_strings["eth_addresses"]:
                    str_lines.append(f"  {a}")
                str_lines.append("")

        # IOC-extracted URLs and domains
        if iocs:
            ioc_urls = iocs.get("urls", [])
            ioc_extra = iocs.get("extraUrls", [])
            ioc_domains = iocs.get("domains", [])
            if ioc_urls:
                str_lines.append("── IOC URLs ──")
                for u in ioc_urls:
                    str_lines.append(f"  {u}")
                str_lines.append("")
            if ioc_extra:
                str_lines.append("── Extra URLs (from config) ──")
                for u in ioc_extra:
                    str_lines.append(f"  {u}")
                str_lines.append("")
            if ioc_domains:
                str_lines.append("── Domains ──")
                for d in ioc_domains:
                    str_lines.append(f"  {d}")
                str_lines.append("")
            # Decrypted config (AdamRat)
            if iocs.get("decryptedConfig"):
                str_lines.append("── Decrypted Config (AdamRat) ──")
                str_lines.append(iocs["decryptedConfig"])
                str_lines.append("")

        if str_lines:
            (ld / "decrypted_strings.txt").write_text("\n".join(str_lines), encoding="utf-8")

    except Exception as e:
        log.warning(f"Failed to write decrypted_strings.txt: {e}")


# ─── Log Packaging ───────────────────────────────────────────────────────────

MAX_ZIP_SIZE = 9.5 * 1024 * 1024

# Only include source code and analysis text — never binaries or malicious files
_SAFE_SOURCE_EXTS = {
    ".java", ".kt", ".scala", ".groovy",  # JVM source
    ".txt", ".log", ".json", ".xml", ".yml", ".yaml", ".toml",  # data/config
    ".properties", ".cfg", ".conf", ".ini", ".csv",
    ".md", ".rst", ".html", ".css",
    ".py", ".rb", ".lua", ".sh",  # script source
    ".gradle", ".maven", ".mf",  # build files
    ".mcmeta", ".lang",  # Minecraft-specific
}

# Explicitly banned — never include these even if somehow text-readable
_BANNED_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".sys", ".drv",  # PE
    ".jar", ".class", ".war", ".ear",  # compiled JVM
    ".so", ".dylib",  # native libs
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf",  # scripts
    ".msi", ".iso", ".img",  # installers/images
    ".lnk", ".url",  # shortcuts
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",  # docs
    ".zip", ".rar", ".7z", ".tar", ".gz",  # archives
}


def _is_safe_source_file(filepath: str) -> bool:
    """Check if a file is safe source code / analysis output to include in results."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in _BANNED_EXTS:
        return False
    if ext in _SAFE_SOURCE_EXTS:
        return True
    # No extension — check if it looks like text (not binary)
    if not ext:
        try:
            with open(filepath, "rb") as f:
                sample = f.read(512)
            # If more than 10% non-text bytes, treat as binary
            non_text = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20 and b != 0x1B))
            return len(sample) > 0 and (non_text / len(sample)) < 0.10
        except Exception:
            return False
    # Unknown extension — skip to be safe
    return False


def sanitize_log_file(filepath: str) -> str:
    """Read a log file and strip sensitive paths. Returns sanitized content."""
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        return sanitize_path(content)
    except Exception:
        return ""


def package_logs(log_dir: str, work_dir: str, mod_name: str) -> list[str]:
    """Package source code & analysis into zip files, excluding all binaries/malware."""
    log_path = Path(log_dir)
    if not log_path.exists():
        return []

    all_files = []
    skipped = []
    for root, dirs, files in os.walk(log_path):
        for f in files:
            fp = os.path.join(root, f)
            rel = os.path.relpath(fp, log_path)
            if _is_safe_source_file(fp):
                all_files.append((fp, rel))
            else:
                skipped.append(rel)

    if skipped:
        log.info(f"Stripped {len(skipped)} non-source file(s) from output: {skipped[:10]}")

    if not all_files:
        return []

    def sort_key(item):
        _, rel = item
        if rel == "analysis.txt":
            return (0, rel)
        if rel.endswith("_iocs.json"):
            return (1, rel)
        if rel.endswith("_config.log"):
            return (2, rel)
        if rel.endswith("_info.log"):
            return (3, rel)
        if "important" in rel:
            return (4, rel)
        if rel.startswith(("main/", "main\\")):
            return (5, rel)
        return (6, rel)

    all_files.sort(key=sort_key)

    # Name zip as "analysis-of-<name>"
    clean_name = re.sub(r"[^\w\-]", "_", mod_name)[:60]
    if not clean_name:
        clean_name = "scan_results"
    zip_basename = f"analysis-of-{clean_name}"

    zips = []
    part = 1
    current_size = 0
    total_size = sum(os.path.getsize(fp) for fp, _ in all_files)
    needs_split = total_size > MAX_ZIP_SIZE
    # Only add -pt1 suffix if splitting is needed
    zip_path = os.path.join(work_dir, f"{zip_basename}-pt{part}.zip" if needs_split else f"{zip_basename}.zip")
    zf = None
    try:
        zf = zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED)

        for fp, rel in all_files:
            sanitized = sanitize_log_file(fp)
            if not sanitized:
                continue

            if current_size > 0 and current_size + len(sanitized.encode()) > MAX_ZIP_SIZE:
                zf.close()
                if os.path.getsize(zip_path) > 0:
                    zips.append(zip_path)
                part += 1
                zip_path = os.path.join(work_dir, f"{zip_basename}-pt{part}.zip")
                zf = zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED)
                current_size = 0

            zf.writestr(rel, sanitized)
            current_size += len(sanitized.encode())

        zf.close()
        zf = None
        if current_size > 0 and os.path.getsize(zip_path) > 0:
            zips.append(zip_path)
    finally:
        if zf is not None:
            try:
                zf.close()
            except Exception:
                pass
    return zips


# ─── Archival ────────────────────────────────────────────────────────────────


def archive_scan(log_dir: str, original_file: str, sha256: str = ""):
    """Archive scan results. If sha256 matches an existing scanned/ folder, reuse it."""
    scanned_dir = MASTER_DIR / "scanned"
    scanned_dir.mkdir(exist_ok=True)

    # ── Dupe detection: check catalog for existing scanned_path ──
    dest = None
    if sha256:
        cat_entry = file_catalog.get(sha256)
        if cat_entry and cat_entry.get("scanned_path"):
            existing = Path(cat_entry["scanned_path"])
            if existing.exists() and existing.is_dir():
                dest = existing
                log.info(f"Dupe detected (SHA256={sha256[:16]}...) — reusing {dest.name}")

    if dest is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = Path(original_file).stem
        dest = scanned_dir / f"{ts}_{fname}"
        dest.mkdir(parents=True, exist_ok=True)

    # Move logs — if dest already has logs, merge into it
    log_path = Path(log_dir)
    if log_path.exists():
        dest_logs = dest / "logs"
        if dest_logs.exists():
            # Merge: copy new log files into existing logs dir
            for item in log_path.iterdir():
                target = dest_logs / item.name
                if item.is_file():
                    shutil.copy2(str(item), str(target))
                elif item.is_dir():
                    if target.exists():
                        shutil.rmtree(str(target), ignore_errors=True)
                    shutil.copytree(str(item), str(target))
            shutil.rmtree(str(log_path), ignore_errors=True)
        else:
            shutil.move(str(log_path), str(dest_logs))

    if os.path.exists(original_file):
        shutil.copy2(original_file, str(dest / os.path.basename(original_file)))

    return str(dest)


def cleanup_old_scans():
    """Remove scanned/ entries older than auto_cleanup_days."""
    days = CFG["scanner"].get("auto_cleanup_days", 30)
    scanned_dir = MASTER_DIR / "scanned"
    if not scanned_dir.exists():
        return
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    for entry in scanned_dir.iterdir():
        if entry.is_dir():
            try:
                ts_str = entry.name[:15]
                ts = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                if ts < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed += 1
            except (ValueError, IndexError):
                pass
    if removed:
        log.info(f"Cleaned up {removed} old scan(s) from scanned/")


# ─── URL Download (with Tor + anti-IP-grabber protection) ────────────────────

# Optional SOCKS proxy support for Tor
AIOHTTP_SOCKS_AVAILABLE = False
try:
    from aiohttp_socks import ProxyConnector
    AIOHTTP_SOCKS_AVAILABLE = True
except ImportError:
    pass

URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$')
MAX_URL_DOWNLOAD = 100 * 1024 * 1024  # 100MB

# Known IP grabber / redirect tracking domains
IP_GRABBER_DOMAINS = {
    "grabify.link", "iplogger.org", "iplogger.com", "2no.co", "yip.su",
    "iplogger.ru", "ipgrabber.ru", "ipgraber.ru", "ezstat.ru",
    "lovebird.guru", "blasze.tk", "blasze.com", "iplis.ru",
    "02telecom.co.uk", "ps3cfw.com", "urlz.fr", "ow.ly",
    "cutt.ly", "shorturl.at", "bit.do", "bc.vc",
    "webhook.site", "requestbin.com", "pipedream.com",
    "canarytokens.com", "canarytokens.org",
    "canary.tools", "thinkst.com",
}

# Domains that serve web pages / streaming content, not downloadable files
NON_DOWNLOAD_DOMAINS = {
    # Video / streaming
    "youtube.com", "www.youtube.com", "youtu.be", "m.youtube.com",
    "twitch.tv", "www.twitch.tv", "clips.twitch.tv",
    "vimeo.com", "dailymotion.com", "tiktok.com", "www.tiktok.com",
    "vm.tiktok.com", "rumble.com", "odysee.com",
    # Social media
    "twitter.com", "x.com", "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com", "reddit.com", "www.reddit.com",
    "old.reddit.com", "linkedin.com", "www.linkedin.com",
    "threads.net", "bsky.app", "mastodon.social",
    # Search engines / portals
    "google.com", "www.google.com", "bing.com", "www.bing.com",
    "duckduckgo.com", "yahoo.com", "www.yahoo.com",
    # Chat / communication
    "discord.com", "discord.gg", "t.me", "web.telegram.org",
    # Wiki / docs
    "wikipedia.org", "en.wikipedia.org", "docs.google.com",
    "stackoverflow.com", "stackexchange.com",
    # News / media
    "medium.com", "substack.com", "nytimes.com", "cnn.com",
    # Gaming (non-download)
    "store.steampowered.com", "steamcommunity.com",
    "namemc.com", "minecraft.net", "www.minecraft.net",
    # Paste / code viewing (not raw file downloads)
    "pastebin.com", "hastebin.com", "gist.github.com",
    "codepen.io", "jsfiddle.net", "replit.com",
    # URL shorteners (suspicious for file downloads)
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "v.gd",
    "rb.gy", "s.id", "shorturl.at",
}

# Content types that indicate a file, not a tracking pixel/page
SAFE_CONTENT_TYPES = {
    "application/octet-stream", "application/zip", "application/java-archive",
    "application/x-java-archive", "application/pdf", "application/x-msdownload",
    "application/x-executable", "application/x-dosexec", "application/x-msi",
    "application/x-iso9660-image", "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument", "application/x-rar-compressed",
    "application/x-7z-compressed", "application/gzip",
}


def _is_blocked_ip(ip_str: str) -> Optional[str]:
    """Check if a resolved IP address is private/reserved/blocked."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid IP address"
    if addr.is_loopback:
        return "Loopback address"
    if addr.is_private:
        return "Private IP range"
    if addr.is_link_local:
        return "Link-local address"
    if addr.is_reserved:
        return "Reserved IP range"
    if addr.is_multicast:
        return "Multicast address"
    if addr.is_unspecified:
        return "Unspecified address (0.0.0.0)"
    # CGNAT range 100.64.0.0/10
    if isinstance(addr, ipaddress.IPv4Address):
        if addr in ipaddress.IPv4Network("100.64.0.0/10"):
            return "CGNAT range"
    return None


def _is_blocked_host(hostname: str) -> Optional[str]:
    """Returns reason string if host is blocked, None if OK."""
    if not hostname:
        return "Empty hostname"
    hn = hostname.lower().strip("[]")
    # Check if it's a raw IP
    ip_block = _is_blocked_ip(hn)
    if ip_block:
        return ip_block
    # Domain-based checks
    if hn in ("localhost",):
        return "Loopback address"
    if hn.endswith(".local") or hn.endswith(".internal"):
        return "Local network domain"
    # IP grabbers
    for domain in IP_GRABBER_DOMAINS:
        if hn == domain or hn.endswith("." + domain):
            return f"Known IP grabber/tracker domain: {domain}"
    return None


async def _resolve_and_check(hostname: str) -> Optional[str]:
    """Resolve hostname to IPs and validate none are private/reserved."""
    import socket
    try:
        infos = await asyncio.get_running_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        )
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            block = _is_blocked_ip(ip_str)
            if block:
                return f"{block} (resolved {hostname} -> {ip_str})"
    except socket.gaierror:
        pass  # DNS resolution failure handled by aiohttp
    return None


class _SafeResolver(aiohttp.DefaultResolver):
    """Custom DNS resolver that blocks private/reserved IPs at connect time.

    Prevents DNS rebinding attacks where a hostname resolves to a safe IP
    during pre-flight check but rebinds to 127.0.0.1/169.254.x.x for the
    actual connection.
    """

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        results = await super().resolve(host, port, family)
        for entry in results:
            ip_str = entry["host"]
            block = _is_blocked_ip(ip_str)
            if block:
                raise OSError(f"DNS rebinding blocked: {host} resolved to {ip_str} ({block})")
        return results


async def _do_download(session, url: str, work_dir: str, dl_path: str, display_name: str) -> tuple[str, str, int]:
    """Execute the actual GET download. Returns (filepath, display_name, total_bytes)."""
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=120),
                           allow_redirects=True, max_redirects=5) as resp:
        if resp.status != 200:
            raise ValueError(f"Download failed: HTTP {resp.status}")

        # Re-check final URL after GET redirects
        final_url = str(resp.url)
        final_parsed = urlparse(final_url)
        if final_parsed.scheme not in ("http", "https"):
            raise ValueError(f"Redirect to unsafe scheme: {final_parsed.scheme}")
        final_host = final_parsed.hostname or ""
        final_block = _is_blocked_host(final_host)
        if final_block:
            raise ValueError(f"Redirect blocked: {final_block}")
        final_dns_block = await _resolve_and_check(final_host)
        if final_dns_block:
            raise ValueError(f"Redirect blocked: {final_dns_block}")

        # Check content-length
        content_length = resp.content_length
        if content_length and content_length > MAX_URL_DOWNLOAD:
            raise ValueError(f"File too large ({content_length / 1024 / 1024:.1f} MB)")

        # Content type check on GET
        ct = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ct == "text/html":
            cd = resp.headers.get("Content-Disposition", "")
            if "attachment" not in cd.lower():
                raise ValueError(
                    "URL serves an HTML page, not a file download.\n"
                    "Please provide a **direct download link** to a file."
                )

        # Try to get filename from content-disposition
        cd = resp.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            match = re.search(r'filename[*]?=["\']?([^"\';]+)', cd)
            if match:
                cd_name = match.group(1)
                # Strip RFC 5987 charset prefix (e.g., "UTF-8''filename.jar")
                if "''" in cd_name:
                    cd_name = cd_name.split("''", 1)[-1]
                cd_name = re.sub(r"[^\w.\-]", "_", cd_name)[:100]
                # Block Windows reserved device names
                stem = cd_name.split(".")[0].upper()
                _WIN_RESERVED = {"CON", "PRN", "AUX", "NUL",
                                 "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                 "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
                                 "CLOCK$"}
                if stem in _WIN_RESERVED:
                    cd_name = f"_{cd_name}"
                if cd_name:
                    display_name = cd_name
                    dl_path = os.path.join(work_dir, display_name)

        total = 0
        try:
            async with aiofiles.open(dl_path, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    total += len(chunk)
                    if total > MAX_URL_DOWNLOAD:
                        raise ValueError(f"File too large (>{MAX_URL_DOWNLOAD / 1024 / 1024:.0f} MB)")
                    await f.write(chunk)
        except Exception:
            # Clean up partial file on error
            try:
                os.unlink(dl_path)
            except OSError:
                pass
            raise

    return dl_path, display_name, total


async def download_from_url(url: str, work_dir: str) -> tuple[str, str]:
    """Download a file from URL via Tor (if configured). Returns (filepath, display_filename)."""
    if not URL_PATTERN.match(url):
        raise ValueError("Invalid URL format. Please provide a direct `http://` or `https://` link to a file.")

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Block dangerous hosts (domain + IP string checks)
    block_reason = _is_blocked_host(hostname)
    if block_reason:
        raise ValueError(f"Blocked: {block_reason}")

    # Block non-download domains (YouTube, social media, etc.)
    hn_lower = hostname.lower()
    for nd_domain in NON_DOWNLOAD_DOMAINS:
        if hn_lower == nd_domain or hn_lower.endswith("." + nd_domain):
            raise ValueError(
                f"**{nd_domain}** is not a file download link.\n"
                "This command scans files for malware — please provide a direct download URL "
                "(e.g. a `.jar`, `.zip`, or `.exe` link)."
            )

    # Resolve DNS and check resolved IPs against private ranges (anti-SSRF)
    dns_block = await _resolve_and_check(hostname)
    if dns_block:
        raise ValueError(f"Blocked: {dns_block}")

    # Tor requirement check
    use_tor = CFG["scanner"].get("require_tor_for_urls", True)
    tor_proxy = CFG["scanner"].get("tor_proxy", "socks5://127.0.0.1:9050")

    if use_tor and not AIOHTTP_SOCKS_AVAILABLE:
        raise ValueError(
            "URL downloads require Tor but `aiohttp-socks` is not installed.\n"
            "Install: `pip install aiohttp-socks`\n"
            "And ensure Tor is running on port 9050.\n"
            "Or set `require_tor_for_urls: false` in config.yml (not recommended)."
        )

    # Extract filename from URL
    url_path = parsed.path.rstrip("/")
    raw_name = os.path.basename(url_path) if url_path else "download"
    if not raw_name or raw_name == "/":
        raw_name = "download"
    display_name = re.sub(r"[^\w.\-]", "_", raw_name)[:100]
    if not display_name:
        display_name = "download"

    dl_path = os.path.join(work_dir, display_name)
    total = 0

    # Build session — through Tor or direct
    # When not using Tor, use SafeResolver to block DNS rebinding at connect time.
    # When using Tor, DNS resolves at the exit node (not locally), so rebinding
    # can't reach the bot's localhost/LAN. Pre-flight _resolve_and_check still
    # catches obvious private IPs before the request is sent.
    connector = None
    tor_failed = False
    if use_tor and AIOHTTP_SOCKS_AVAILABLE:
        connector = ProxyConnector.from_url(tor_proxy)
    else:
        connector = aiohttp.TCPConnector(resolver=_SafeResolver())

    async with aiohttp.ClientSession(connector=connector) as session:
        # First, HEAD request to check for redirects and content type
        # (catches IP grabbers that redirect through tracking)
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=15),
                                     allow_redirects=True, max_redirects=5) as head_resp:
                # Check final URL after redirects
                final_url = str(head_resp.url)
                final_parsed = urlparse(final_url)
                # Block non-HTTP(S) schemes after redirect (C2 fix)
                if final_parsed.scheme not in ("http", "https"):
                    raise ValueError(f"Redirect to unsafe scheme: {final_parsed.scheme}")
                final_host = final_parsed.hostname or ""
                final_block = _is_blocked_host(final_host)
                if final_block:
                    raise ValueError(f"Redirect blocked: {final_block} (redirected to {final_host})")
                # Re-check resolved IPs of redirect target
                final_dns_block = await _resolve_and_check(final_host)
                if final_dns_block:
                    raise ValueError(f"Redirect blocked: {final_dns_block}")

                # Check content type
                ct = head_resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if ct and ct.startswith("text/html"):
                    # HTML response = likely a webpage, not a file
                    # Only allow if content-disposition suggests a download
                    cd = head_resp.headers.get("Content-Disposition", "")
                    if "attachment" not in cd.lower():
                        raise ValueError(
                            "URL returns an HTML page, not a downloadable file.\n"
                            "Please provide a **direct download link** to a file "
                            "(e.g. a `.jar`, `.zip`, or `.exe` URL)."
                        )
        except (asyncio.TimeoutError, TimeoutError, OSError, ConnectionError) as tor_err:
            if use_tor:
                log.warning(f"Tor proxy failed for HEAD request: {tor_err}")
                tor_failed = True
            else:
                raise ValueError(f"Connection failed: {tor_err}")
        except aiohttp.ClientError as head_err:
            log.warning(f"HEAD request failed for URL: {head_err}")
            if use_tor:
                # Could be Tor proxy down — flag it
                err_name = type(head_err).__name__
                if "proxy" in err_name.lower() or "socks" in str(head_err).lower() or "connect" in err_name.lower():
                    tor_failed = True
                else:
                    raise ValueError(
                        "HEAD request failed — cannot verify URL safety through Tor. "
                        "The URL may be unreachable or an IP grabber."
                    )

        if not tor_failed:
            # Actual download via current session (Tor or direct)
            try:
                dl_path, display_name, total = await _do_download(
                    session, url, work_dir, dl_path, display_name
                )
            except (asyncio.TimeoutError, TimeoutError, OSError, ConnectionError) as dl_err:
                if use_tor:
                    log.warning(f"Tor proxy failed during download: {dl_err}")
                    tor_failed = True
                else:
                    raise ValueError(f"Download failed: {dl_err}")
            except aiohttp.ClientError as dl_err:
                if use_tor:
                    err_str = f"{type(dl_err).__name__}: {dl_err}"
                    if any(k in err_str.lower() for k in ("proxy", "socks", "connect", "timeout")):
                        log.warning(f"Tor proxy failed during download: {dl_err}")
                        tor_failed = True
                    else:
                        raise ValueError(f"Download failed: {dl_err}")
                else:
                    raise ValueError(f"Download failed: {dl_err}")

    # ── Tor fallback: retry without proxy ──
    if tor_failed:
        log.warning("Tor proxy unreachable — falling back to direct download (no Tor)")
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=_SafeResolver())) as direct_session:
            # Re-do HEAD check without Tor
            try:
                async with direct_session.head(url, timeout=aiohttp.ClientTimeout(total=15),
                                                allow_redirects=True, max_redirects=5) as head_resp:
                    final_url = str(head_resp.url)
                    final_parsed = urlparse(final_url)
                    if final_parsed.scheme not in ("http", "https"):
                        raise ValueError(f"Redirect to unsafe scheme: {final_parsed.scheme}")
                    final_host = final_parsed.hostname or ""
                    final_block = _is_blocked_host(final_host)
                    if final_block:
                        raise ValueError(f"Redirect blocked: {final_block} (redirected to {final_host})")
                    final_dns_block = await _resolve_and_check(final_host)
                    if final_dns_block:
                        raise ValueError(f"Redirect blocked: {final_dns_block}")
                    ct = head_resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                    if ct and ct.startswith("text/html"):
                        cd = head_resp.headers.get("Content-Disposition", "")
                        if "attachment" not in cd.lower():
                            raise ValueError(
                                "URL returns an HTML page, not a downloadable file.\n"
                                "Please provide a **direct download link** to a file."
                            )
            except aiohttp.ClientError as head_err:
                raise ValueError(f"Download failed (Tor down, direct also failed): {head_err}")
            except (asyncio.TimeoutError, TimeoutError) as head_err:
                raise ValueError(f"Download timed out (Tor down, direct also timed out): {head_err}")

            try:
                dl_path, display_name, total = await _do_download(
                    direct_session, url, work_dir, dl_path, display_name
                )
            except (asyncio.TimeoutError, TimeoutError, aiohttp.ClientError) as dl_err:
                raise ValueError(f"Download failed (Tor down, direct also failed): {dl_err}")

    download_method = "via Tor" if (use_tor and AIOHTTP_SOCKS_AVAILABLE and not tor_failed) else "direct"
    if tor_failed:
        download_method = "direct (Tor was down)"
    log.info(f"Downloaded {download_method}: {display_name} ({total} bytes)")

    return dl_path, display_name


# ─── Scan Queue ──────────────────────────────────────────────────────────────


class ScanQueue:
    def __init__(self, max_concurrent: int = 3):
        self._sem = asyncio.Semaphore(max_concurrent)
        self._pending = 0
        self._active = 0
        self._lock = asyncio.Lock()
        self._waiters: list[asyncio.Event] = []

    @property
    def pending(self):
        return self._pending

    @property
    def active(self):
        return self._active

    async def submit(self, coro, on_dequeue=None):
        """Submit a coroutine to the scan queue.
        on_dequeue is called (if provided) when the scan leaves the queue and starts running.
        """
        entered_sem = False
        async with self._lock:
            self._pending += 1
            evt = asyncio.Event()
            self._waiters.append(evt)
        try:
            async with self._sem:
                async with self._lock:
                    self._pending -= 1
                    self._active += 1
                    entered_sem = True
                    if evt in self._waiters:
                        self._waiters.remove(evt)
                    evt.set()
                    # Notify remaining waiters so they can update position
                    for w in self._waiters:
                        w.set()
                        w.clear()
                if on_dequeue:
                    try:
                        await on_dequeue()
                    except Exception:
                        pass
                try:
                    return await coro
                finally:
                    async with self._lock:
                        self._active -= 1
        except BaseException:
            if not entered_sem:
                async with self._lock:
                    if self._pending > 0:
                        self._pending -= 1
                    if evt in self._waiters:
                        self._waiters.remove(evt)
            raise

    def position_of(self, evt: asyncio.Event) -> int:
        """Return 1-based queue position for the given event, or 0 if not queued."""
        try:
            return self._waiters.index(evt) + 1
        except ValueError:
            return 0


# ─── Cooldown Tracker ────────────────────────────────────────────────────────

user_cooldowns: dict[int, float] = {}


def check_and_set_cooldown(user_id: int) -> Optional[int]:
    """Check cooldown and set it atomically. Returns seconds remaining if on cooldown, else None."""
    cd = CFG["scanner"].get("cooldown_seconds", 30)
    if cd <= 0:
        return None
    now = time.time()
    last = user_cooldowns.get(user_id, 0)
    elapsed = now - last
    if elapsed < cd:
        return int(cd - elapsed)
    user_cooldowns[user_id] = now
    return None


# ─── Bot ─────────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
if CFG["discord"].get("allow_dms", False):
    intents.dm_messages = True
bot = discord.Bot(intents=intents)
scan_queue = ScanQueue(CFG["scanner"]["max_concurrent_scans"])

# ─── Build integration_types / contexts for slash commands ───────────────────

def _build_command_install_params() -> dict:
    """Return kwargs (integration_types, contexts) for slash_command decorators."""
    params = {}
    itypes = {discord.IntegrationType.guild_install}
    ctxs = {discord.InteractionContextType.guild}
    if CFG["discord"].get("allow_user_install", False):
        itypes.add(discord.IntegrationType.user_install)
    if CFG["discord"].get("allow_dms", False):
        ctxs.add(discord.InteractionContextType.private_channel)
        ctxs.add(discord.InteractionContextType.bot_dm)
    if CFG["discord"].get("allow_external_guilds", False):
        # guild context already included; user_install handles external guilds
        pass
    params["integration_types"] = itypes
    params["contexts"] = ctxs
    return params

_install_params = _build_command_install_params()
http_session: Optional[aiohttp.ClientSession] = None
_ready_fired = False
_background_poll_tasks: set = set()  # prevent GC of fire-and-forget tasks
_bot_start_time: float = time.time()
_cancelled_scans: set[str] = set()  # scan IDs that have been cancelled


class CancelScanView(discord.ui.View):
    """Persistent view with a cancel button for in-progress scans."""

    def __init__(self, scan_id: str, requester_id: int):
        super().__init__(timeout=600)  # 10 min timeout
        self.scan_id = scan_id
        self.requester_id = requester_id

    @discord.ui.button(label="Cancel Scan", style=discord.ButtonStyle.danger, emoji="\u274C")
    async def cancel_button(self, button: discord.ui.Button, interaction: discord.Interaction):
        if interaction.user.id != self.requester_id:
            return await interaction.response.send_message("Only the scan requester can cancel.", ephemeral=True)
        _cancelled_scans.add(self.scan_id)
        button.disabled = True
        button.label = "Cancelling..."
        await interaction.response.edit_message(view=self)
        log.info(f"[{self.scan_id}] Scan cancelled by {interaction.user}")


async def ensure_http_session() -> aiohttp.ClientSession:
    """Lazily create or return the global aiohttp session."""
    global http_session
    if http_session is None or http_session.closed:
        http_session = aiohttp.ClientSession()
    return http_session


@bot.event
async def on_ready():
    global http_session, _ready_fired
    # Ensure session exists (may already be created by a scan command)
    await ensure_http_session()
    # Only run setup tasks on first ready
    if not _ready_fired:
        _ready_fired = True
        await asyncio.to_thread(load_yara_rules)
        await asyncio.to_thread(cleanup_old_scans)
        if not update_presence.is_running():
            update_presence.start()
        if not monitor_alerts.is_running():
            monitor_alerts.start()
    log.info(f"Bot ready as {bot.user} — serving {len(bot.guilds)} guild(s)")
    log.info(f"VT enabled: {CFG['virustotal']['enabled'] and bool(CFG['virustotal']['api_key'])}")
    log.info(f"YARA enabled: {YARA_AVAILABLE and CFG['yara']['enabled']}")
    log.info(f"Webhook killing: {CFG['scanner'].get('auto_delete_webhooks', True)}")


@tasks.loop(seconds=30)
async def update_presence():
    active = scan_queue.active
    if active > 0:
        await bot.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name=f"{active} scan(s)")
        )
    else:
        await bot.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name=f"{scan_stats['total_scans']} scans completed"
            )
        )


@tasks.loop(minutes=5)
async def monitor_alerts():
    """Periodic monitoring: storage usage, request rate, stale state cleanup."""
    try:
        # ── Storage alert ──
        threshold_gb = CFG.get("alerts", {}).get("storage_threshold_gb", 10)
        usage_bytes = await asyncio.to_thread(_get_storage_usage_bytes)
        usage_gb = usage_bytes / (1024 ** 3)
        if usage_gb >= threshold_gb:
            await send_alert(
                "storage_high",
                "Storage Threshold Exceeded",
                f"File storage is at **{usage_gb:.1f} GB** (threshold: {threshold_gb} GB).\n"
                f"Consider running cleanup or increasing `auto_cleanup_days`.\n"
                f"Checked: `logs/`, `scanned/`, `bot/logs/`, `PUT_JAR_HERE/`",
            )

        # ── Hourly request rate alert ──
        threshold_hr = CFG.get("alerts", {}).get("hourly_request_threshold", 20)
        req_count = _hourly_request_count()
        if req_count >= threshold_hr:
            await send_alert(
                "high_request_rate",
                "High Request Rate",
                f"**{req_count}** scan requests in the last hour (threshold: {threshold_hr}).\n"
                f"Active scans: **{scan_queue.active}** | Queued: **{scan_queue.pending}**",
            )

        # ── Stale state cleanup (prevents unbounded memory growth) ──
        # Clean user_cooldowns older than 2x cooldown period
        cd = CFG["scanner"].get("cooldown_seconds", 30)
        cutoff = time.time() - (cd * 2)
        stale_users = [uid for uid, ts in user_cooldowns.items() if ts < cutoff]
        for uid in stale_users:
            del user_cooldowns[uid]

        # Clean cancelled scans older than 10 minutes
        # (can't track age directly, but limit set size)
        if len(_cancelled_scans) > 100:
            _cancelled_scans.clear()

        # Clean old bot log files (keep last 20)
        bot_log_dir = BOT_DIR / "logs"
        if bot_log_dir.exists():
            log_files = sorted(bot_log_dir.glob("scanner_*.log"), key=lambda p: p.stat().st_mtime)
            if len(log_files) > 20:
                for old_log in log_files[:-20]:
                    try:
                        old_log.unlink()
                    except OSError:
                        pass

        # Clean old JarAnalyzer log directories (keep last 200)
        jar_log_dir = MASTER_DIR / "logs"
        if jar_log_dir.exists():
            log_dirs = sorted(
                [d for d in jar_log_dir.iterdir() if d.is_dir()],
                key=lambda p: p.stat().st_mtime,
            )
            if len(log_dirs) > 200:
                for old_dir in log_dirs[:-200]:
                    try:
                        shutil.rmtree(old_dir, ignore_errors=True)
                    except OSError:
                        pass

    except Exception as e:
        log.error(f"monitor_alerts error: {e}")


@monitor_alerts.before_loop
async def _wait_for_bot_ready():
    await bot.wait_until_ready()


# ─── /giverat command ────────────────────────────────────────────────────────

@bot.slash_command(name="giverat", description="Scan a file for RAT/malware signatures", **_install_params)
async def giverat_command(
    ctx: discord.ApplicationContext,
    private: discord.Option(
        bool,
        description="Private scan — local only, no uploads to VT/MB/HA",
        required=False,
        default=False,
    ),
    file: discord.Option(
        discord.Attachment,
        description="File to scan (up to 100MB)",
        required=False,
        default=None,
    ),
    file2: discord.Option(
        discord.Attachment,
        description="Second file to scan",
        required=False,
        default=None,
    ),
    file3: discord.Option(
        discord.Attachment,
        description="Third file to scan",
        required=False,
        default=None,
    ),
    file4: discord.Option(
        discord.Attachment,
        description="Fourth file to scan",
        required=False,
        default=None,
    ),
    file5: discord.Option(
        discord.Attachment,
        description="Fifth file to scan",
        required=False,
        default=None,
    ),
    url: discord.Option(
        str,
        description="URL to download and scan",
        required=False,
        default=None,
    ),
):
    # Collect all provided files
    all_files = [f for f in [file, file2, file3, file4, file5] if f is not None]

    # Must provide at least one input
    if not all_files and not url:
        return await ctx.respond("Provide at least one file attachment or a URL to scan.", ephemeral=True)
    if all_files and url:
        return await ctx.respond("Provide file(s) **or** a URL, not both.", ephemeral=True)

    # cooldown (atomic check-and-set)
    remaining = check_and_set_cooldown(ctx.author.id)
    if remaining:
        return await ctx.respond(
            f"Cooldown \u2014 try again in **{remaining}s**.",
            ephemeral=True,
        )

    # Track request for hourly rate alerting
    _track_hourly_request()
    threshold_hr = CFG.get("alerts", {}).get("hourly_request_threshold", 20)
    req_count = _hourly_request_count()
    if req_count >= threshold_hr and req_count % 5 == 0:  # alert every 5th request over threshold
        asyncio.create_task(send_alert(
            "high_request_rate",
            "High Request Rate",
            f"**{req_count}** scan requests in the last hour (threshold: {threshold_hr}).\n"
            f"Active scans: **{scan_queue.active}** | Queued: **{scan_queue.pending}**",
        ))

    # validate size for all attachments
    max_bytes = CFG["scanner"]["max_file_size_mb"] * 1024 * 1024
    for af in all_files:
        if af.size > max_bytes:
            return await ctx.respond(
                f"File `{af.filename}` too large ({af.size / 1024 / 1024:.1f} MB). Max is {CFG['scanner']['max_file_size_mb']} MB.",
                ephemeral=True,
            )

    # For multi-file: queue each file as a separate scan
    scan_targets = []  # list of (attachment_or_None, url_or_None, scan_id, display_name)
    if all_files:
        for af in all_files:
            sid = uuid.uuid4().hex[:8]
            scan_targets.append((af, None, sid, af.filename))
    else:
        sid = uuid.uuid4().hex[:8]
        scan_targets.append((None, url, sid, url[:60]))

    # ephemeral ack
    private_tag = " (private — local only)" if private else ""
    if len(scan_targets) == 1:
        ack_text = f"Scanning `{scan_targets[0][3]}`{private_tag} \u2014 results will be posted publicly.\nScan ID: `{scan_targets[0][2]}`"
    else:
        lines = [f"Queuing **{len(scan_targets)}** file(s) for scanning:"]
        for _, _, sid, dname in scan_targets:
            lines.append(f"  \u2022 `{dname}` (ID: `{sid}`)")
        ack_text = "\n".join(lines)
    await ctx.respond(ack_text, ephemeral=True)

    # ── Queue each scan ──
    send_channel = ctx.channel

    for attach, scan_url, scan_id, display_name in scan_targets:
        queue_msg = None

        if scan_queue.active >= scan_queue._sem._value:
            queue_text = (
                f"Scan `{display_name}` by {ctx.author.mention} is queued — "
                f"position **{scan_queue.pending + 1}**, {scan_queue.active} active scan(s)."
            )
            try:
                queue_msg = await send_channel.send(queue_text)
            except discord.Forbidden:
                try:
                    queue_msg = await ctx.followup.send(queue_text)
                except Exception:
                    pass
            except Exception:
                pass

            _qm = queue_msg  # capture for closure
            _dn = display_name

            async def _update_queue_msg(_qm=_qm, _dn=_dn):
                if _qm is None:
                    return
                while True:
                    await asyncio.sleep(3)
                    pos = scan_queue.pending
                    if pos <= 0:
                        break
                    try:
                        await _qm.edit(
                            content=(
                                f"Scan `{_dn}` by {ctx.author.mention} is queued — "
                                f"position **{pos}**, {scan_queue.active} active scan(s)."
                            )
                        )
                    except Exception:
                        break

            update_task = asyncio.create_task(_update_queue_msg())
        else:
            update_task = None
            _qm = None

        async def _on_dequeue(_ut=update_task, _qm=_qm):
            if _ut is not None:
                _ut.cancel()
            if _qm is not None:
                try:
                    await _qm.delete()
                except Exception:
                    pass

        try:
            # Use create_task so multiple files scan concurrently (up to semaphore limit)
            asyncio.create_task(
                scan_queue.submit(run_scan(ctx, attach, scan_url, scan_id, private=private), on_dequeue=_on_dequeue)
            )
        except Exception as e:
            log.exception(f"Scan submit failed for {display_name}")
            if update_task is not None:
                update_task.cancel()
            try:
                err_embed = discord.Embed(
                    title="Scan Failed",
                    description=f"`{display_name}`: ```{sanitize_path(str(e)[:1000])}```",
                    color=0xE74C3C,
                )
                try:
                    await send_channel.send(embed=err_embed)
                except discord.Forbidden:
                    await ctx.followup.send(embed=err_embed)
            except Exception:
                pass


# ─── /stats command ──────────────────────────────────────────────────────────

@bot.slash_command(name="stats", description="Show scanner statistics", **_install_params)
async def stats_command(ctx: discord.ApplicationContext):
    async with _stats_lock:
        stats = dict(scan_stats)
    total = stats.get("total_scans", 0)
    detections = stats.get("detections", 0)
    clean = stats.get("clean", 0)
    rate = f"{detections / total * 100:.1f}%" if total > 0 else "N/A"
    e = discord.Embed(title="\U0001F4CA Scanner Statistics", color=0x3498DB)
    e.add_field(name="Total Scans", value=str(total), inline=True)
    e.add_field(name="Detections", value=f"{detections} ({rate})", inline=True)
    e.add_field(name="Clean Files", value=str(clean), inline=True)
    e.add_field(name="Webhooks Killed", value=str(stats.get("webhooks_killed", 0)), inline=True)
    e.add_field(name="Files Sent to VT", value=str(stats.get("files_sent_to_vt", 0)), inline=True)
    e.add_field(
        name="Queue",
        value=f"{scan_queue.active} active / {scan_queue.pending} pending",
        inline=True,
    )
    # Uptime
    uptime_s = int(time.time() - _bot_start_time) if _bot_start_time else 0
    hours, rem = divmod(uptime_s, 3600)
    mins, secs = divmod(rem, 60)
    e.add_field(name="Uptime", value=f"{hours}h {mins}m {secs}s", inline=True)
    if YARA_RULES:
        e.add_field(name="YARA Rules", value="Loaded", inline=True)
    # Scanned file database (includes offline scans)
    scanned_dir = MASTER_DIR / "scanned"
    if scanned_dir.exists():
        try:
            scanned_dirs = [d for d in scanned_dir.iterdir() if d.is_dir()]
            total_scanned = len(scanned_dirs)
            # Count unique variants from IOC files
            variants = {}
            for sd in scanned_dirs:
                iocs = list((sd / "logs").glob("*_iocs.json")) if (sd / "logs").is_dir() else []
                if iocs:
                    try:
                        ioc_data = json.loads(iocs[0].read_text(encoding="utf-8"))
                        v = ioc_data.get("variant", "unknown").lower()
                        variants[v] = variants.get(v, 0) + 1
                    except Exception:
                        pass
            catalog_count = len(file_catalog)
            offline_count = total_scanned - catalog_count
            db_lines = [f"**{total_scanned}** files scanned total"]
            db_lines.append(f"{catalog_count} via Discord, {offline_count} offline")
            db_lines.append(f"{len(approved_exceptions)} exception(s) approved")
            # Show top variants (exclude unknown)
            known = {k: v for k, v in variants.items() if k != "unknown"}
            if known:
                top = sorted(known.items(), key=lambda x: x[1], reverse=True)[:5]
                db_lines.append("**Top variants:** " + ", ".join(f"{v} ({c})" for v, c in top))
            unknown_count = variants.get("unknown", 0)
            if unknown_count:
                db_lines.append(f"{unknown_count} clean/unknown")
            e.add_field(name="Scan Database", value="\n".join(db_lines), inline=False)
        except Exception:
            pass
    # Server list
    guilds = sorted(bot.guilds, key=lambda g: g.member_count or 0, reverse=True)
    if guilds:
        server_lines = []
        for g in guilds:
            members = f"{g.member_count:,}" if g.member_count else "?"
            server_lines.append(f"**{g.name}** ({members} members)")
        server_list = "\n".join(server_lines)
        if len(server_list) > 1024:
            server_list = server_list[:1020] + "\n..."
        e.add_field(name=f"Servers ({len(guilds)})", value=server_list, inline=False)
    else:
        e.add_field(name="Servers", value="None", inline=True)
    await ctx.respond(embed=e, ephemeral=True)


# ─── /reload command ─────────────────────────────────────────────────────────

@bot.slash_command(name="reload", description="Reload YARA rules (admin only)", **_install_params)
async def reload_command(ctx: discord.ApplicationContext):
    if not ctx.guild or not hasattr(ctx.author, "guild_permissions") or not ctx.author.guild_permissions.administrator:
        return await ctx.respond("Admin only.", ephemeral=True)
    load_yara_rules()
    await ctx.respond(f"YARA rules reloaded. {YARA_RULES is not None}", ephemeral=True)


# ─── /reload-exceptions command ──────────────────────────────────────────────

@bot.slash_command(name="reload-exceptions", description="Reload exception list (admin only)", **_install_params)
async def reload_exceptions_command(ctx: discord.ApplicationContext):
    if not ctx.guild or not hasattr(ctx.author, "guild_permissions") or not ctx.author.guild_permissions.administrator:
        return await ctx.respond("Admin only.", ephemeral=True)
    global approved_exceptions
    approved_exceptions = load_exceptions()
    await ctx.respond(f"Exception list reloaded. {len(approved_exceptions)} approved hash(es).", ephemeral=True)


# ─── /save command ───────────────────────────────────────────────────────────

@bot.slash_command(name="save", description="Toggle saving scanned files to disk (admin only)", **_install_params)
async def save_command(
    ctx: discord.ApplicationContext,
    enabled: discord.Option(
        bool,
        description="Save scanned files and logs to disk?",
        required=True,
    ),
):
    if not ctx.guild or not hasattr(ctx.author, "guild_permissions") or not ctx.author.guild_permissions.administrator:
        return await ctx.respond("Admin only.", ephemeral=True)
    CFG["scanner"]["save_samples"] = enabled
    # Persist to config.yml so it survives restarts
    try:
        import yaml
        config_path = BOT_DIR / "config.yml"
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        raw.setdefault("scanner", {})["save_samples"] = enabled
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(raw, f, default_flow_style=False, sort_keys=False)
    except Exception as e:
        log.warning(f"Failed to persist save_samples to config.yml: {e}")
    status = "enabled" if enabled else "disabled"
    await ctx.respond(f"Sample saving **{status}**. Scanned files will {'be archived in `scanned/`' if enabled else 'be deleted after scan'}.", ephemeral=True)
    log.info(f"Sample saving set to {enabled} by {ctx.author}")


# ─── /die command (emergency kill) ───────────────────────────────────────────

@bot.slash_command(name="die", description="Emergency shutdown — kills the bot immediately (alert IDs only)", **_install_params)
async def die_command(ctx: discord.ApplicationContext):
    alert_ids = _get_alert_user_ids()
    if ctx.author.id not in alert_ids:
        return await ctx.respond("You are not authorized to use this command.", ephemeral=True)
    log.critical(f"EMERGENCY SHUTDOWN triggered by {ctx.author} ({ctx.author.id})")
    await ctx.respond("Shutting down immediately.", ephemeral=True)
    try:
        await asyncio.wait_for(asyncio.to_thread(stop_tor), timeout=5)
    except asyncio.TimeoutError:
        log.warning("stop_tor timed out during emergency shutdown")
    await bot.close()
    sys.exit(0)


# ─── /scrapemods command ─────────────────────────────────────────────────────

try:
    from mod_scraper import ModScrapeRunner
    SCRAPER_AVAILABLE = True
except ImportError:
    SCRAPER_AVAILABLE = False

_scrape_runner: Optional["ModScrapeRunner"] = None
_scrape_task: Optional[asyncio.Task] = None


@bot.slash_command(name="scrapemods", description="Scrape & scan mods from Modrinth/CurseForge/etc (alert IDs only)", **_install_params)
async def scrapemods_command(
    ctx: discord.ApplicationContext,
    action: discord.Option(
        str,
        description="start or stop",
        choices=["start", "stop", "status"],
        required=True,
    ),
):
    global _scrape_runner, _scrape_task

    alert_ids = _get_alert_user_ids()
    if ctx.author.id not in alert_ids:
        return await ctx.respond("You are not authorized to use this command.", ephemeral=True)

    if not SCRAPER_AVAILABLE:
        return await ctx.respond("Scraper module not available (`mod_scraper.py` missing).", ephemeral=True)

    if action == "stop":
        if _scrape_runner:
            _scrape_runner.stop()
            await ctx.respond("Scraper stopping after current batch finishes...", ephemeral=True)
        else:
            await ctx.respond("Scraper is not running.", ephemeral=True)
        return

    if action == "status":
        if _scrape_runner and _scrape_task and not _scrape_task.done():
            s = _scrape_runner.stats
            total_db = _scrape_runner.progress.total_downloaded
            await ctx.respond(
                f"**Scraper running**\n"
                f"This session: {s['downloaded']} downloaded, {s['scanned']} scanned, "
                f"{s['skipped']} skipped, {s['oversize']} oversize, {s['errors']} errors\n"
                f"Total in database: {total_db}",
                ephemeral=True,
            )
        else:
            await ctx.respond("Scraper is not running.", ephemeral=True)
        return

    # action == "start"
    if _scrape_task and not _scrape_task.done():
        return await ctx.respond("Scraper is already running. Use `/scrapemods stop` first.", ephemeral=True)

    # Wait for previous task to fully finish if it was recently stopped
    if _scrape_task and _scrape_task.done():
        _scrape_task = None

    await ctx.respond("Starting mod scraper... will download and scan in batches of 20.", ephemeral=True)

    scraper_cfg = CFG.get("scraper", {})
    cf_key = scraper_cfg.get("curseforge_api_key", "")
    nx_key = scraper_cfg.get("nexusmods_api_key", "")
    batch_size = scraper_cfg.get("batch_size", 20)

    mods_dir = MASTER_DIR / "scraped_mods"
    mods_dir.mkdir(exist_ok=True)
    progress_file = BOT_DIR / "scrape_progress.json"

    _scrape_runner = ModScrapeRunner(
        mods_dir=mods_dir,
        progress_file=progress_file,
        cf_api_key=cf_key,
        nx_api_key=nx_key,
        batch_size=batch_size,
    )

    async def _scrape_loop():
        global _scrape_runner
        runner = _scrape_runner
        batch_num = 0
        # Capture the channel reference now — ctx.followup expires after 15 min
        channel = ctx.channel

        try:
            conn = aiohttp.TCPConnector(limit=20, limit_per_host=5)
            async with aiohttp.ClientSession(connector=conn) as session:
                while not runner.stopped:
                    batch_num += 1
                    log.info(f"[scraper] Batch {batch_num}: collecting {runner.batch_size} mods...")

                    try:
                        batch = await runner.collect_batch(session)
                    except Exception as e:
                        log.exception(f"[scraper] Batch collect error: {e}")
                        await asyncio.sleep(10)
                        continue

                    if not batch:
                        log.info("[scraper] No more mods to download. Stopping.")
                        break

                    log.info(f"[scraper] Batch {batch_num}: downloaded {len(batch)} JARs, scanning...")

                    # Send status update via channel (not ctx.followup which expires)
                    try:
                        await channel.send(
                            f"**[Scraper] Batch {batch_num}:** Downloaded {len(batch)} mods, scanning...\n"
                            f"Session totals: {runner.stats['downloaded']} downloaded, "
                            f"{runner.stats['scanned']} scanned",
                        )
                    except discord.Forbidden:
                        log.warning("[scraper] Lost channel access — status updates will only appear in logs")
                    except discord.NotFound:
                        log.warning("[scraper] Channel no longer exists — status updates will only appear in logs")
                    except Exception as e:
                        log.debug(f"[scraper] Channel send failed: {e}")

                    # Scan each JAR in the batch
                    for jar_path, mod_name, source in batch:
                        if runner.stopped:
                            break
                        try:
                            scan_id = f"scrape_{uuid.uuid4().hex[:8]}"
                            log.info(f"[scraper] Scanning: {mod_name} ({jar_path.name})")
                            await run_scan(
                                ctx=None,
                                attachment=None,
                                url=None,
                                scan_id=scan_id,
                                local_file=str(jar_path),
                                private=True,
                                silent=True,  # no Discord output for background scrape scans
                            )
                            runner.stats["scanned"] += 1
                        except Exception as e:
                            log.warning(f"[scraper] Scan error {mod_name}: {e}")

                    # Flush scrape progress to disk after each batch
                    runner.progress.flush()

                    log.info(f"[scraper] Batch {batch_num} complete. "
                             f"Stats: {runner.stats}")

            log.info(f"[scraper] Finished. Final stats: {runner.stats}")
            runner.progress.flush()
            try:
                await channel.send(
                    f"**[Scraper] Finished.**\n"
                    f"Downloaded: {runner.stats['downloaded']} | Scanned: {runner.stats['scanned']} | "
                    f"Skipped: {runner.stats['skipped']} | Errors: {runner.stats['errors']}",
                )
            except Exception:
                pass
        except Exception as e:
            log.exception(f"[scraper] Fatal error in scrape loop: {e}")
            try:
                await channel.send(f"**[Scraper] Crashed:** {e}")
            except Exception:
                pass

    _scrape_task = asyncio.create_task(_scrape_loop())


# ─── Scan Runner ─────────────────────────────────────────────────────────────

async def run_scan(
    ctx: Optional[discord.ApplicationContext],
    attachment: Optional[discord.Attachment],
    url: Optional[str],
    scan_id: str,
    local_file: Optional[str] = None,  # for multi-JAR ZIP: path to an already-extracted JAR
    private: bool = False,  # private scan: local analysis only, no uploads to VT/MB/HA
    silent: bool = False,  # silent mode: skip all Discord messaging (for background scrape scans)
):
    start = time.time()
    work_dir = tempfile.mkdtemp(prefix="scan_")
    scan_msg = None  # The public progress message we'll edit
    _use_followup = [False]  # Flag: True if ctx.channel.send fails (user-install in external server)

    async def safe_send(**kwargs) -> Optional[discord.Message]:
        """Send to channel, falling back to followup if bot lacks channel access (user-install)."""
        if silent or ctx is None:
            return None
        if not _use_followup[0]:
            try:
                return await ctx.channel.send(**kwargs)
            except discord.Forbidden:
                _use_followup[0] = True
                log.info(f"[{scan_id}] No channel access — falling back to followup responses")
            except discord.HTTPException:
                pass
        # Fallback: use interaction followup (always works for the invoking user)
        try:
            return await ctx.followup.send(**kwargs)
        except Exception:
            return None

    async def progress(msg: str):
        if silent or ctx is None:
            return
        try:
            await ctx.followup.send(f"`[{scan_id}]` {msg}", ephemeral=True)
        except Exception:
            pass

    # Throttled message edit to respect Discord rate limits (min 2s between edits)
    _last_edit = [0.0]

    stage_start_times: dict[str, float] = {}
    stage_details: dict[str, str] = {}

    async def update_progress(stages: dict, filename: str, file_size: int, hashes: dict, force: bool = False):
        nonlocal scan_msg
        if silent or ctx is None:
            return
        now = time.time()
        if not force and now - _last_edit[0] < 2.0:
            return
        _last_edit[0] = now
        try:
            embed = build_progress_embed(filename, file_size, hashes, scan_id, stages,
                                         stage_start_times=stage_start_times,
                                         stage_details=stage_details)
            cancel_view = CancelScanView(scan_id, ctx.author.id if ctx else 0)
            if scan_msg is None:
                scan_msg = await safe_send(
                    content=f"Scan requested by {ctx.author.mention}" if ctx else "Background scan",
                    embed=embed,
                    view=cancel_view,
                )
            else:
                await scan_msg.edit(embed=embed, view=cancel_view)
        except discord.HTTPException:
            pass

    _spawned_sub_scans = False  # Set True when multi-JAR sub-scans are spawned (skip work_dir cleanup)

    try:
        scanned_path = None

        # ── Download / locate file ──
        if local_file:
            # Already extracted (multi-JAR ZIP sub-scan)
            dl_path = local_file
            filename = os.path.basename(local_file)
            await progress(f"Scanning extracted JAR: {filename}")
        elif attachment:
            await progress("Downloading file...")
            filename = re.sub(r"[^\w.\-]", "_", attachment.filename or "unknown")
            dl_path = os.path.join(work_dir, filename)
            max_bytes = CFG["scanner"]["max_file_size_mb"] * 1024 * 1024
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as dl_session:
                async with dl_session.get(attachment.url) as resp:
                    total_dl = 0
                    async with aiofiles.open(dl_path, "wb") as f:
                        async for chunk in resp.content.iter_chunked(65536):
                            total_dl += len(chunk)
                            if total_dl > max_bytes:
                                raise ValueError(f"File exceeded {CFG['scanner']['max_file_size_mb']} MB during download")
                            await f.write(chunk)
        else:
            await progress("Downloading from URL...")
            try:
                dl_path, filename = await download_from_url(url, work_dir)
            except ValueError as ve:
                await safe_send(
                    embed=discord.Embed(
                        title="Download Failed",
                        description=sanitize_path(str(ve)),
                        color=0xE74C3C,
                    )
                )
                return

        file_size = os.path.getsize(dl_path)
        hashes = await asyncio.to_thread(compute_hashes, dl_path)
        sha256 = hashes["sha256"]
        mod_name = re.sub(r"\.(jar|zip|exe|dll|bin|dat)$", "", filename, flags=re.IGNORECASE)
        mod_name = re.sub(r"[^\w\-]", "_", mod_name)
        if not mod_name:
            mod_name = sha256[:12]
        log.info(f"[{scan_id}] Downloaded {filename} ({file_size} bytes, SHA256={sha256[:16]}...)")

        # ── Exception check ──
        if await check_exception(sha256):
            await safe_send(
                embed=discord.Embed(
                    title=f"\u2705 Known Safe: {filename[:70]}",
                    description=(
                        f"This file (`{sha256[:16]}...`) is in the **approved exceptions list** and has been verified as safe.\n\n"
                        f"**SHA-256:** `{sha256}`\n"
                        f"**Size:** {file_size:,} bytes\n\n"
                        f"*To remove this exception, edit `exceptions.var` in the bot folder.*"
                    ),
                    color=0x2ECC71,
                )
            )
            return

        # ── Catalog check ──
        prev_scan = await catalog_lookup(sha256)
        if prev_scan:
            scan_count = prev_scan.get("scan_count", 1)
            prev_time = prev_scan.get("last_scan", "unknown")
            n_submitters = len(prev_scan.get("submitters", []))
            n_guilds = len(prev_scan.get("guilds", []))
            rep_info = f"Previously scanned {scan_count} time(s) (last: {prev_time})"
            if n_submitters > 1 or n_guilds > 1:
                rep_info += f" by {n_submitters} user(s) across {n_guilds} server(s)"
            await progress(f"{rep_info}. Refreshing analysis...")

        # ── Ensure HTTP session exists (on_ready may not have fired yet) ──
        await ensure_http_session()

        # ── Build stage tracker ──
        # Private scan: skip all external API uploads/lookups
        vt_enabled = CFG["virustotal"]["enabled"] and CFG["virustotal"]["api_key"] and not private
        mb_enabled = CFG.get("malwarebazaar", {}).get("enabled", True) and not private
        ha_enabled = (CFG.get("hybrid_analysis", {}).get("enabled", True)
                      and CFG.get("hybrid_analysis", {}).get("api_key", "") and not private)
        stages = {
            "Local Analysis": "pending",
            "VirusTotal": "pending" if vt_enabled else "skipped",
            "VT Sandbox": "pending" if vt_enabled else "skipped",
            "MalwareBazaar": "pending" if mb_enabled else "skipped",
            "Hybrid Analysis": "pending" if ha_enabled else "skipped",
        }
        if private:
            log.info(f"[{scan_id}] Private scan — external APIs disabled")

        # Send initial progress embed
        await update_progress(stages, filename, file_size, hashes)

        # ── Zip bomb check — ABORT if detected ──
        zip_bomb_warning = await asyncio.to_thread(check_zip_bomb, dl_path)
        if zip_bomb_warning:
            log.warning(f"[{scan_id}] ZIP BOMB DETECTED: {zip_bomb_warning}")
            stages["Local Analysis"] = "complete"
            await update_progress(stages, filename, file_size, hashes)

            # Run VT + YARA + external APIs on the outer file (safe, no decompression)
            vt_result = None
            mb_result = None
            ha_result = None
            vt_sandbox = None

            # Send ALL pending embeds up front
            vt_msg = None
            vt_sb_msg = None
            mb_msg = None
            ha_msg = None
            if http_session and vt_enabled:
                vt_msg = await safe_send(embed=_build_service_pending_embed("VirusTotal", "\U0001F9EA", "~30s", scan_id))
                vt_sb_msg = await safe_send(embed=_build_service_pending_embed("VT Sandbox Analysis", "\U0001F9EC", "~2s", scan_id))
            if http_session and mb_enabled:
                mb_msg = await safe_send(embed=_build_service_pending_embed("MalwareBazaar", "\U0001F9A0", "~2s", scan_id))
            if http_session and ha_enabled:
                ha_msg = await safe_send(embed=_build_service_pending_embed("Hybrid Analysis", "\U0001F50D", "~5s", scan_id))

            # VT helper for zip bomb path
            async def _zb_vt_lookup_or_upload():
                result = await vt_lookup(sha256, http_session)
                if result is None:
                    if vt_msg:
                        try:
                            await vt_msg.edit(embed=_build_service_pending_embed(
                                "VirusTotal", "\U0001F9EA", "uploading ~2-3min", scan_id))
                        except discord.HTTPException:
                            pass
                    result = await vt_upload(dl_path, sha256, http_session)
                return result

            # Launch ALL concurrently
            api_tasks = {}
            if http_session and vt_enabled:
                stages["VirusTotal"] = "running"
                stage_start_times["VirusTotal"] = time.time()
                api_tasks["vt"] = asyncio.create_task(_zb_vt_lookup_or_upload())
            if http_session and mb_enabled:
                stages["MalwareBazaar"] = "running"
                stage_start_times["MalwareBazaar"] = time.time()
                api_tasks["mb"] = asyncio.create_task(mb_lookup(sha256, http_session))
            if http_session and ha_enabled:
                stages["Hybrid Analysis"] = "running"
                stage_start_times["Hybrid Analysis"] = time.time()
                api_tasks["ha"] = asyncio.create_task(ha_search_or_submit(sha256, dl_path, http_session))

            # Collect VT result first (needed for VT Sandbox)
            if "vt" in api_tasks:
                try:
                    vt_result = await api_tasks["vt"]
                except Exception as exc:
                    log.warning(f"VirusTotal task failed: {exc}")
                    vt_result = {"detected": 0, "total": 0, "detections": {},
                                 "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                                 "meaningful_name": "", "tags": [], "first_seen": None, "status": "error"}
                stages["VirusTotal"] = "complete"
                if vt_result and vt_msg:
                    try:
                        await vt_msg.edit(embed=build_vt_embed(vt_result, sha256, scan_id))
                    except discord.HTTPException:
                        pass
                    if vt_result.get("status") == "queued" and vt_msg:
                        _track_poll_task(_poll_vt_completion(sha256, vt_msg, scan_id))
                if vt_result and vt_result.get("status") in ("found", "completed"):
                    stages["VT Sandbox"] = "running"
                    api_tasks["vt_sb"] = asyncio.create_task(vt_get_sandbox_links(sha256, http_session))

            # Collect MB result
            if "mb" in api_tasks:
                try:
                    mb_result = await api_tasks["mb"]
                except Exception as exc:
                    log.warning(f"MalwareBazaar task failed: {exc}")
                    mb_result = {"status": "error", "permalink": f"https://bazaar.abuse.ch/sample/{sha256}/"}
                stages["MalwareBazaar"] = "complete"
                if mb_result and mb_result.get("status") == "found":
                    await update_stats(mb_hits=1)
                if mb_msg:
                    try:
                        await mb_msg.edit(embed=build_mb_embed(mb_result, sha256, scan_id))
                    except discord.HTTPException:
                        pass
            elif mb_msg:
                try:
                    await mb_msg.edit(embed=build_mb_embed(None, sha256, scan_id))
                except discord.HTTPException:
                    pass

            # Collect HA result
            if "ha" in api_tasks:
                try:
                    ha_result = await api_tasks["ha"]
                except Exception as exc:
                    log.warning(f"Hybrid Analysis task failed: {exc}")
                    ha_result = None
                stages["Hybrid Analysis"] = "complete"
                if ha_msg:
                    try:
                        await ha_msg.edit(embed=build_ha_embed(ha_result, sha256, scan_id))
                    except discord.HTTPException:
                        pass
                    if ha_result and ha_result.get("status") == "submitted" and ha_msg:
                        _track_poll_task(_poll_ha_completion(sha256, ha_msg, scan_id))

            # Collect VT Sandbox result
            if "vt_sb" in api_tasks:
                try:
                    vt_sandbox = await api_tasks["vt_sb"]
                except Exception as exc:
                    log.debug(f"VT Sandbox task failed: {exc}")
                    vt_sandbox = None
                stages["VT Sandbox"] = "complete"
                if vt_sb_msg:
                    try:
                        await vt_sb_msg.edit(embed=build_vt_sandbox_embed(vt_sandbox, sha256, scan_id))
                    except discord.HTTPException:
                        pass
            elif vt_sb_msg:
                try:
                    await vt_sb_msg.edit(embed=build_vt_sandbox_embed(None, sha256, scan_id))
                except discord.HTTPException:
                    pass

            yara_matches = await asyncio.to_thread(run_yara, dl_path)
            seen_rules = set()
            unique_yara = []
            for m in yara_matches:
                if m["rule"] not in seen_rules:
                    seen_rules.add(m["rule"])
                    unique_yara.append(m)
            yara_matches = unique_yara

            score, level, color = compute_risk_score(
                None, vt_result, yara_matches, [], None, None, None,
                mb_result=mb_result, ha_result=ha_result,
            )
            score = max(score, 75)
            level = "HIGH"
            color = 0xE74C3C

            await update_stats(total_scans=1, detections=1)

            embeds = build_embeds(
                filename=filename, file_size=file_size, hashes=hashes,
                iocs=None, vt=vt_result, yara_matches=yara_matches,
                obfuscators=[], score=score, level=level, color=color,
                scan_time=time.time() - start, scan_id=scan_id,
                zip_bomb_warning=zip_bomb_warning,
            )
            zb_header = f"Scan requested by {ctx.author.mention}" if ctx else "Background scan"
            if scan_msg:
                await scan_msg.edit(content=zb_header, embeds=embeds, view=None)
            else:
                await safe_send(content=zb_header, embeds=embeds)
            return

        # ── Determine what to scan ──
        stages["Local Analysis"] = "running"
        stage_start_times["Local Analysis"] = time.time()
        stage_details["Local Analysis"] = "Preparing..."
        await update_progress(stages, filename, file_size, hashes, force=True)
        jars_to_scan = []
        is_zip = False

        try:
            with open(dl_path, "rb") as f:
                magic = f.read(4)
            is_zip = magic[:2] == b"PK"
        except Exception:
            pass

        # Collect all files to scan (extracted from zip or just the original)
        extracted_files = []  # non-JAR files extracted from zip (EXE, PDF, etc.)

        if is_zip:
            jar_path = dl_path
            if not dl_path.lower().endswith((".jar", ".zip")):
                jar_path = dl_path + ".jar"
                shutil.copy2(dl_path, jar_path)

            if is_valid_jar(jar_path):
                jars_to_scan.append(jar_path)

            nested = await asyncio.to_thread(extract_files_from_zip, jar_path, work_dir)
            for nf in nested:
                if nf in jars_to_scan:
                    continue
                # Check if it's a JAR/ZIP (PK magic) or another file type
                try:
                    with open(nf, "rb") as _f:
                        _magic = _f.read(4)
                    if _magic[:2] == b"PK" and is_valid_jar(nf):
                        jars_to_scan.append(nf)
                    else:
                        extracted_files.append(nf)
                except Exception:
                    extracted_files.append(nf)

            if not jars_to_scan and not extracted_files:
                jars_to_scan.append(jar_path)

            # ── Multi-JAR ZIP: if a .zip contains multiple inner JARs, scan each separately ──
            if dl_path.lower().endswith(".zip") and not local_file:
                # Count inner JARs only (not the zip itself acting as a jar)
                inner_jars = [j for j in jars_to_scan if j != jar_path and j != dl_path]
                if len(inner_jars) > 1:
                    await safe_send(
                        content=f"ZIP `{filename}` contains **{len(inner_jars)} JAR files** — scanning each separately.",
                    )
                    # Schedule work_dir cleanup after all sub-scans complete
                    async def _cleanup_after_sub_scans(tasks, wd):
                        try:
                            # Timeout: scan_timeout * number of tasks + buffer
                            max_wait = CFG["scanner"].get("scan_timeout_seconds", 300) * len(tasks) + 60
                            await asyncio.wait_for(
                                asyncio.gather(*tasks, return_exceptions=True),
                                timeout=max_wait,
                            )
                        except asyncio.TimeoutError:
                            log.warning(f"Sub-scan cleanup timed out after {max_wait}s — forcing cleanup")
                        try:
                            shutil.rmtree(wd, ignore_errors=True)
                        except Exception:
                            pass
                    sub_tasks = []
                    for inner_jar in inner_jars:
                        sub_scan_id = uuid.uuid4().hex[:8]
                        inner_name = os.path.basename(inner_jar)
                        log.info(f"[{scan_id}] Multi-JAR ZIP: spawning sub-scan {sub_scan_id} for {inner_name}")
                        def _sub_scan_done(t, _name=inner_name):
                            if not t.cancelled() and t.exception():
                                log.warning(f"[{scan_id}] Sub-scan for {_name} failed: {t.exception()}")
                        task = asyncio.create_task(
                            scan_queue.submit(run_scan(ctx, None, None, sub_scan_id, local_file=inner_jar, private=private))
                        )
                        task.add_done_callback(_sub_scan_done)
                        sub_tasks.append(task)
                    asyncio.create_task(_cleanup_after_sub_scans(sub_tasks, work_dir))
                    # Set flag AFTER all tasks are spawned — if spawning fails, finally block cleans up
                    _spawned_sub_scans = True

                    if scan_msg:
                        try:
                            await scan_msg.delete()
                        except Exception:
                            pass
                    return
        else:
            jars_to_scan.append(dl_path)

        # ── Primary file for external API lookups ──
        # When a ZIP wraps an inner file (JAR, EXE, etc.), use the inner file's
        # hash for VT/MB/HA since analysts submit the payload, not the wrapper ZIP.
        primary_path = dl_path  # file to upload to VT/HA
        primary_hashes = hashes  # hashes to query VT/MB/HA
        primary_sha256 = sha256
        is_wrapper_zip = False

        if is_zip and dl_path.lower().endswith(".zip"):
            inner_files = [f for f in (jars_to_scan + extracted_files) if f != dl_path and f != dl_path + ".jar"]
            if inner_files:
                # Use the first extracted file as the primary for API lookups
                primary_path = inner_files[0]
                primary_hashes = await asyncio.to_thread(compute_hashes, primary_path)
                primary_sha256 = primary_hashes["sha256"]
                is_wrapper_zip = True
                inner_name = os.path.basename(primary_path)
                log.info(f"[{scan_id}] ZIP wrapper detected — using inner file '{inner_name}' "
                         f"(SHA256={primary_sha256[:16]}...) for API lookups")

        # ── JarAnalyzer ──
        all_iocs = None
        all_analysis = None
        all_log_dirs = []

        async def _jar_progress(msg: str):
            """Update the Local Analysis stage detail and refresh embed."""
            if scan_id in _cancelled_scans:
                raise asyncio.CancelledError("Scan cancelled by user")
            stage_details["Local Analysis"] = msg[:80]
            await update_progress(stages, filename, file_size, hashes)

        for jar in jars_to_scan:
            if scan_id in _cancelled_scans:
                raise asyncio.CancelledError("Scan cancelled by user")
            result = await run_jar_analyzer(jar, progress_cb=_jar_progress)
            if result.get("log_dir"):
                all_log_dirs.append(result["log_dir"])
            if result.get("iocs"):
                if all_iocs is None or (result["iocs"].get("variant", "").lower() != "unknown"):
                    all_iocs = result["iocs"]
                    all_analysis = result.get("analysis_text")

        # ── Obfuscator detection ──
        stage_details["Local Analysis"] = "Detecting obfuscators..."
        await update_progress(stages, filename, file_size, hashes)
        obfuscators = await asyncio.to_thread(detect_obfuscators, dl_path)

        # ── DashO string deobfuscation ──
        deobfuscation = None
        if DEOBFUSCATOR_AVAILABLE and is_zip:
            try:
                deobfuscation = await asyncio.to_thread(_deobfuscate_jar, str(dl_path))
                if deobfuscation and deobfuscation.get("detected"):
                    log.info(f"DashO deobfuscation: {deobfuscation['total_decrypted']} strings from "
                             f"{deobfuscation['classes_with_strings']} classes")
                    if "DashO" not in obfuscators:
                        obfuscators.append("DashO (string encryption cracked)")
                else:
                    deobfuscation = None
            except Exception as exc:
                log.warning(f"Deobfuscation failed: {exc}")

        # ── Generic string deobfuscation (XOR, base64, ROT, hex, etc.) ──
        if GENERIC_DEOBFUSCATOR_AVAILABLE and is_zip:
            try:
                generic_result = await asyncio.to_thread(_deobfuscate_generic, str(dl_path))
                if generic_result and generic_result.get("detected"):
                    log.info(f"Generic deobfuscation: {generic_result['total_decrypted']} strings from "
                             f"{generic_result['classes_with_strings']} classes "
                             f"(algorithms: {', '.join(generic_result.get('algorithms', []))})")
                    if deobfuscation and deobfuscation.get("detected"):
                        # Merge generic results into existing DashO results
                        existing_keys = {(s["class"], s["decrypted"]) for s in deobfuscation.get("strings", [])}
                        new_strings = [s for s in generic_result.get("strings", [])
                                       if (s["class"], s["decrypted"]) not in existing_keys]
                        if new_strings:
                            deobfuscation["strings"].extend(new_strings)
                            deobfuscation["total_decrypted"] += len(new_strings)
                            deobfuscation["classes_with_strings"] = len(
                                {s["class"] for s in deobfuscation["strings"]})
                            existing_algos = set(deobfuscation.get("algorithms", []))
                            for a in generic_result.get("algorithms", []):
                                if a not in existing_algos:
                                    deobfuscation["algorithms"].append(a)
                    else:
                        deobfuscation = generic_result
            except Exception as exc:
                log.warning(f"Generic deobfuscation failed: {exc}")

        # ── Entropy analysis ──
        stage_details["Local Analysis"] = "Analyzing entropy..."
        await update_progress(stages, filename, file_size, hashes)
        entropy = await asyncio.to_thread(analyze_entropy, dl_path)

        # ── Manifest inspection ──
        stage_details["Local Analysis"] = "Inspecting manifest..."
        manifest = await asyncio.to_thread(inspect_manifest, dl_path)

        # ── Raw string extraction (original file + extracted files) ──
        stage_details["Local Analysis"] = "Extracting strings..."
        await update_progress(stages, filename, file_size, hashes)
        extracted_strings = await asyncio.to_thread(extract_strings, dl_path)
        for ef in extracted_files:
            ef_strings = await asyncio.to_thread(extract_strings, ef)
            if ef_strings:
                for key in ("discord_webhooks", "discord_tokens", "urls", "ipv4", "eth_addresses"):
                    if ef_strings.get(key):
                        extracted_strings.setdefault(key, []).extend(ef_strings[key])

        # ── Multi-format analysis (PE, PDF, Office, LNK, Script, MSI, ISO) ──
        stage_details["Local Analysis"] = "Analyzing file format..."
        await update_progress(stages, filename, file_size, hashes)
        # Analyze original file + all extracted files, merge results
        format_analysis = await asyncio.to_thread(analyze_file_format, dl_path)
        for ef in extracted_files:
            ef_name = os.path.basename(ef)
            ef_fmt = await asyncio.to_thread(analyze_file_format, ef)
            if ef_fmt and ef_fmt.get("findings"):
                # Prefix findings with the extracted filename
                if format_analysis is None:
                    format_analysis = {"type": "ZIP archive", "findings": []}
                if not format_analysis.get("findings"):
                    format_analysis["findings"] = []
                format_analysis["findings"].append(f"--- Extracted: `{ef_name}` ({ef_fmt.get('type', 'unknown')}) ---")
                format_analysis["findings"].extend(ef_fmt["findings"])
                # Merge sub-fields
                for subkey in ("suspicious_imports", "suspicious_sections", "suspicious_files"):
                    if ef_fmt.get(subkey):
                        format_analysis.setdefault(subkey, []).extend(ef_fmt[subkey])

        # ── YARA (original + all extracted files) ──
        stage_details["Local Analysis"] = "Running YARA rules..."
        await update_progress(stages, filename, file_size, hashes)
        yara_matches = await asyncio.to_thread(run_yara, dl_path)
        all_scan_files = jars_to_scan + extracted_files
        for sf in all_scan_files:
            if sf != dl_path:
                yara_matches.extend(await asyncio.to_thread(run_yara, sf))
        seen_rules = set()
        unique_yara = []
        for m in yara_matches:
            if m["rule"] not in seen_rules:
                seen_rules.add(m["rule"])
                unique_yara.append(m)
        yara_matches = unique_yara

        stages["Local Analysis"] = "complete"
        stage_start_times["Local Analysis_done"] = time.time()
        stage_details.pop("Local Analysis", None)
        await update_progress(stages, filename, file_size, hashes, force=True)

        # ── External API lookups — ALL run concurrently with pending embeds ──
        vt_result = None
        mb_result = None
        ha_result = None
        vt_sandbox = None

        # Track per-service messages so we can edit them when results arrive
        vt_msg = None
        vt_sb_msg = None
        mb_msg = None
        ha_msg = None

        # ── Send ALL pending embeds up front ──
        if http_session and vt_enabled:
            vt_msg = await safe_send(
                embed=_build_service_pending_embed("VirusTotal", "\U0001F9EA", "~30s", scan_id)
            )
            vt_sb_msg = await safe_send(
                embed=_build_service_pending_embed("VT Sandbox Analysis", "\U0001F9EC", "~2s", scan_id)
            )
        if http_session and mb_enabled:
            mb_msg = await safe_send(
                embed=_build_service_pending_embed("MalwareBazaar", "\U0001F9A0", "~2s", scan_id)
            )
        if http_session and ha_enabled:
            ha_msg = await safe_send(
                embed=_build_service_pending_embed("Hybrid Analysis", "\U0001F50D", "~5s", scan_id)
            )

        # ── VT helper: lookup then upload if needed (runs as concurrent task) ──
        async def _vt_lookup_or_upload():
            result = await vt_lookup(primary_sha256, http_session)
            if result is None:
                if vt_msg:
                    try:
                        await vt_msg.edit(embed=_build_service_pending_embed(
                            "VirusTotal", "\U0001F9EA", "uploading ~2-3min", scan_id))
                    except discord.HTTPException:
                        pass
                result = await vt_upload(primary_path, primary_sha256, http_session)
            return result

        # ── Launch ALL services concurrently ──
        api_tasks = {}
        log.info(f"[{scan_id}] API launch: http_session={'OK' if http_session else 'NONE'} "
                 f"vt={vt_enabled} mb={mb_enabled} ha={ha_enabled}")
        if http_session and vt_enabled:
            stages["VirusTotal"] = "running"
            stage_start_times["VirusTotal"] = time.time()
            api_tasks["vt"] = asyncio.create_task(_vt_lookup_or_upload())
        if http_session and mb_enabled:
            stages["MalwareBazaar"] = "running"
            stage_start_times["MalwareBazaar"] = time.time()
            api_tasks["mb"] = asyncio.create_task(mb_lookup(primary_sha256, http_session))
        if http_session and ha_enabled:
            stages["Hybrid Analysis"] = "running"
            stage_start_times["Hybrid Analysis"] = time.time()
            api_tasks["ha"] = asyncio.create_task(ha_search_or_submit(primary_sha256, primary_path, http_session))
        log.info(f"[{scan_id}] API tasks created: {list(api_tasks.keys())}")
        if api_tasks:
            await update_progress(stages, filename, file_size, hashes)

        # ── Collect results and update each message as it completes ──

        # VT result
        if "vt" in api_tasks:
            try:
                vt_result = await api_tasks["vt"]
                log.info(f"[{scan_id}] VT result: status={vt_result.get('status') if vt_result else 'None'}")
            except Exception as exc:
                log.warning(f"[{scan_id}] VirusTotal task failed: {exc}")
                vt_result = {"detected": 0, "total": 0, "detections": {},
                             "permalink": f"https://www.virustotal.com/gui/file/{primary_sha256}",
                             "meaningful_name": "", "tags": [], "first_seen": None, "status": "error"}
            stages["VirusTotal"] = "complete"
            stage_start_times["VirusTotal_done"] = time.time()
            if vt_result and vt_msg:
                try:
                    await vt_msg.edit(embed=build_vt_embed(vt_result, primary_sha256, scan_id))
                except discord.HTTPException:
                    pass
                # If VT analysis is still queued, start a background poller to update the message
                if vt_result.get("status") == "queued" and vt_msg:
                    _track_poll_task(_poll_vt_completion(primary_sha256, vt_msg, scan_id))

            # Now that VT is done, launch VT Sandbox lookup
            if vt_result and vt_result.get("status") in ("found", "completed"):
                stages["VT Sandbox"] = "running"
                stage_start_times["VT Sandbox"] = time.time()
                api_tasks["vt_sb"] = asyncio.create_task(vt_get_sandbox_links(primary_sha256, http_session))
            await update_progress(stages, filename, file_size, hashes)

        # MB result
        if "mb" in api_tasks:
            try:
                mb_result = await api_tasks["mb"]
                log.info(f"[{scan_id}] MB result: status={mb_result.get('status') if mb_result else 'None'}")
            except Exception as exc:
                log.warning(f"[{scan_id}] MalwareBazaar task failed: {exc}")
                mb_result = {"status": "error", "permalink": f"https://bazaar.abuse.ch/sample/{primary_sha256}/"}
            stages["MalwareBazaar"] = "complete"
            stage_start_times["MalwareBazaar_done"] = time.time()
            if mb_result and mb_result.get("status") == "found":
                await update_stats(mb_hits=1)
            if mb_msg:
                try:
                    await mb_msg.edit(embed=build_mb_embed(mb_result, primary_sha256, scan_id))
                except discord.HTTPException:
                    pass
        elif mb_msg:
            try:
                await mb_msg.edit(embed=build_mb_embed(None, primary_sha256, scan_id))
            except discord.HTTPException:
                pass

        # HA result
        if "ha" in api_tasks:
            try:
                ha_result = await api_tasks["ha"]
                log.info(f"[{scan_id}] HA result: status={ha_result.get('status') if ha_result else 'None'}")
            except Exception as exc:
                log.warning(f"[{scan_id}] Hybrid Analysis task failed: {exc}")
                ha_result = None
            stages["Hybrid Analysis"] = "complete"
            stage_start_times["Hybrid Analysis_done"] = time.time()
            if ha_msg:
                try:
                    await ha_msg.edit(embed=build_ha_embed(ha_result, primary_sha256, scan_id))
                except discord.HTTPException:
                    pass
                # If HA file was submitted for sandbox, start background poller to update message
                if ha_result and ha_result.get("status") == "submitted" and ha_msg:
                    _track_poll_task(_poll_ha_completion(primary_sha256, ha_msg, scan_id))

        # VT Sandbox result
        if "vt_sb" in api_tasks:
            try:
                vt_sandbox = await api_tasks["vt_sb"]
            except Exception as exc:
                log.debug(f"VT Sandbox task failed: {exc}")
                vt_sandbox = None
            stages["VT Sandbox"] = "complete"
            stage_start_times["VT Sandbox_done"] = time.time()
            if vt_sb_msg:
                try:
                    await vt_sb_msg.edit(embed=build_vt_sandbox_embed(vt_sandbox, primary_sha256, scan_id))
                except discord.HTTPException:
                    pass
        elif vt_sb_msg:
            try:
                await vt_sb_msg.edit(embed=build_vt_sandbox_embed(None, primary_sha256, scan_id))
            except discord.HTTPException:
                pass

        await update_progress(stages, filename, file_size, hashes)

        # Mark skipped stages
        for k in stages:
            if stages[k] == "pending":
                stages[k] = "skipped"

        # ── Webhook killing ──
        webhook_kills = {}
        all_webhooks = set()
        if extracted_strings and extracted_strings.get("discord_webhooks"):
            all_webhooks.update(extracted_strings["discord_webhooks"])
        if all_iocs:
            for key in ("webhook", "webhookUrl"):
                if all_iocs.get(key):
                    all_webhooks.add(all_iocs[key])
        if all_webhooks and http_session:
            await progress(f"Killing {len(all_webhooks)} webhook(s)...")
            for wh_url in all_webhooks:
                webhook_kills[wh_url] = await kill_webhook(wh_url, http_session)

        # ── Risk score ──
        score, level, color = compute_risk_score(
            all_iocs, vt_result, yara_matches, obfuscators,
            entropy, extracted_strings, manifest, format_analysis,
            mb_result=mb_result, ha_result=ha_result,
        )

        # ── Upload to MalwareBazaar if not already in database ──
        # Only upload files that actually scored above detection threshold
        mb_upload_enabled = CFG.get("malwarebazaar", {}).get("upload_flagged", False)
        if (score > DETECTION_THRESHOLD
                and mb_result and mb_result.get("status") == "not_found"
                and http_session and mb_enabled and mb_upload_enabled):
            mb_tags = []
            if all_iocs and all_iocs.get("variant", "").lower() != "unknown":
                mb_tags.append(all_iocs["variant"])
            if yara_matches:
                mb_tags.extend(m["rule"] for m in yara_matches[:5])
            comment = f"Auto-submitted by RATScanner (score {score}/100, {level})"
            upload_result = await mb_upload(primary_path, primary_sha256, http_session, tags=mb_tags, comment=comment)
            if upload_result:
                mb_result = upload_result
                if mb_msg:
                    try:
                        await mb_msg.edit(embed=build_mb_embed(mb_result, primary_sha256, scan_id))
                    except discord.HTTPException:
                        pass

        # ── Update stats ──
        if score > DETECTION_THRESHOLD:
            await update_stats(total_scans=1, detections=1)
        else:
            await update_stats(total_scans=1, clean=1)

        # ── Archive + catalog update (locked per SHA256 to prevent races) ──
        sha_lock = await _get_sha256_lock(sha256)
        async with sha_lock:
            # Archive must happen before catalog update so scanned_path is set
            if CFG["scanner"].get("save_samples", False):
                for ld in all_log_dirs:
                    scanned_path = archive_scan(ld, dl_path, sha256=sha256)

            # Re-read catalog under lock to get latest submitters/guilds
            prev_scan_locked = await catalog_lookup(sha256)
            # Preserve insertion order: deduplicate while keeping most recent last
            raw_submitters = [str(s) for s in (prev_scan_locked or {}).get("submitters", [])]
            new_submitter = str(ctx.author.id) if ctx else "scraper"
            # Remove dupe if present, then append (most recent last)
            raw_submitters = [s for s in raw_submitters if s != new_submitter]
            raw_submitters.append(new_submitter)
            # Deduplicate preserving order (last occurrence wins)
            seen_sub = set()
            prev_submitters = []
            for s in reversed(raw_submitters):
                if s not in seen_sub:
                    seen_sub.add(s)
                    prev_submitters.append(s)
            prev_submitters.reverse()

            guild_id = str(ctx.guild.id) if (ctx and ctx.guild) else ("DM" if ctx else "scraper")
            raw_guilds = [str(g) for g in (prev_scan_locked or {}).get("guilds", [])]
            raw_guilds = [g for g in raw_guilds if g != guild_id]
            raw_guilds.append(guild_id)
            seen_guild = set()
            prev_guilds = []
            for g in reversed(raw_guilds):
                if g not in seen_guild:
                    seen_guild.add(g)
                    prev_guilds.append(g)
            prev_guilds.reverse()
            existing_scanned_path = (prev_scan_locked or {}).get("scanned_path", "")
            final_scanned_path = scanned_path or existing_scanned_path
            prev_count = (prev_scan_locked or {}).get("scan_count", 0)

            await catalog_update(sha256, {
                "filename": filename,
                "file_size": file_size,
                "last_scan": datetime.now(timezone.utc).isoformat(),
                "score": score,
                "level": level,
                "variant": (all_iocs.get("variant", "") if all_iocs else ""),
                "scan_count": prev_count + 1,
                "submitters": prev_submitters[-50:],
                "guilds": prev_guilds[-50:],
                "yara_hits": len(yara_matches),
                "vt_detected": vt_result.get("detected", 0) if vt_result else 0,
                "vt_total": vt_result.get("total", 0) if vt_result else 0,
                "scanned_path": final_scanned_path,
            })

        # ── Auto-research for exception candidates ──
        if score <= DETECTION_THRESHOLD and extracted_strings and http_session:
            all_urls = extracted_strings.get("urls", [])
            if all_urls:
                try:
                    url_matches = await auto_research_urls(all_urls, sha256, http_session)
                    variant_name = all_iocs.get("variant", "") if all_iocs else ""
                    await write_exception_candidate(
                        filename, sha256, file_size, score, level,
                        variant_name, all_urls[:10], url_matches,
                    )
                except Exception as e:
                    log.debug(f"Auto-research failed: {e}")

        # ── Build main results embed (local analysis + YARA + strings etc.) ──
        embeds = build_embeds(
            filename=filename,
            file_size=file_size,
            hashes=hashes,
            iocs=all_iocs,
            vt=vt_result,
            yara_matches=yara_matches,
            obfuscators=obfuscators,
            score=score,
            level=level,
            color=color,
            scan_time=time.time() - start,
            scan_id=scan_id,
            entropy=entropy,
            extracted_strings=extracted_strings,
            manifest=manifest,
            webhook_kills=webhook_kills,
            nested_count=max(0, len(jars_to_scan) - 1),
            zip_bomb_warning=zip_bomb_warning,
            format_analysis=format_analysis,
            deobfuscation=deobfuscation,
            mb_result=mb_result,
        )

        if not is_zip and not format_analysis:
            embeds[0].add_field(
                name="\u2139\uFE0F Note",
                value="Unknown file type. VT, YARA, and string extraction results only.",
                inline=False,
            )

        # ── Ensure at least one log dir exists for the report ──
        if not all_log_dirs:
            fallback_log_dir = os.path.join(work_dir, "logs")
            os.makedirs(fallback_log_dir, exist_ok=True)
            all_log_dirs.append(fallback_log_dir)

        # ── Write full report + decrypted strings into each log dir ──
        for ld in all_log_dirs:
            try:
                write_full_report(
                    ld,
                    filename=filename,
                    file_size=file_size,
                    hashes=hashes,
                    iocs=all_iocs,
                    vt=vt_result,
                    yara_matches=yara_matches,
                    obfuscators=obfuscators,
                    score=score,
                    level=level,
                    scan_id=scan_id,
                    scan_time=time.time() - start,
                    entropy=entropy,
                    extracted_strings=extracted_strings,
                    manifest=manifest,
                    webhook_kills=webhook_kills,
                    format_analysis=format_analysis,
                    deobfuscation=deobfuscation,
                    mb_result=mb_result,
                    ha_result=ha_result,
                    vt_sandbox=vt_sandbox,
                )
            except Exception as e:
                log.debug(f"write_full_report failed for {ld}: {e}")

        # ── Package logs (named after mod, sanitized) ──
        zip_files = []
        for ld in all_log_dirs:
            zip_files.extend(package_logs(ld, work_dir, mod_name))

        # ── Send main results — replace progress embed ──
        scan_header = f"Scan requested by {ctx.author.mention}" if ctx else "Background scan"
        if private:
            scan_header += " \U0001F512 **Private scan** — no external uploads"

        files_to_send = []
        for zp in zip_files:
            if os.path.getsize(zp) > 0:
                files_to_send.append(discord.File(zp, filename=os.path.basename(zp)))

        try:
            if scan_msg:
                await scan_msg.edit(content=scan_header, embeds=embeds, view=None)
                if files_to_send:
                    if private:
                        # Private: send zip as ephemeral DM to the requester
                        if ctx is not None:
                            for i in range(0, len(files_to_send), 10):
                                batch = files_to_send[i:i + 10]
                                try:
                                    await ctx.followup.send(
                                        content="\U0001F512 Private scan logs:",
                                        files=batch,
                                        ephemeral=True,
                                    )
                                except Exception:
                                    pass
                    else:
                        # Public: send in channel
                        for i in range(0, len(files_to_send), 10):
                            batch = files_to_send[i:i + 10]
                            try:
                                await safe_send(files=batch, reference=discord.MessageReference.from_message(scan_msg))
                            except (TypeError, Exception):
                                await safe_send(files=batch)
            else:
                # First message: embeds + up to 10 files
                first_batch = files_to_send[:10] if not private else []
                await safe_send(
                    content=scan_header,
                    embeds=embeds,
                    files=first_batch,
                )
                if private and files_to_send and ctx is not None:
                    # Private: send zip as ephemeral DM
                    for i in range(0, len(files_to_send), 10):
                        batch = files_to_send[i:i + 10]
                        try:
                            await ctx.followup.send(
                                content="\U0001F512 Private scan logs:",
                                files=batch,
                                ephemeral=True,
                            )
                        except Exception:
                            pass
                else:
                    # Remaining files in follow-up messages
                    for i in range(10, len(files_to_send), 10):
                        batch = files_to_send[i:i + 10]
                        await safe_send(files=batch)
        finally:
            for f_obj in files_to_send:
                try:
                    f_obj.close()
                except Exception:
                    pass

        # ── Cleanup log dirs if not archiving ──
        if not CFG["scanner"].get("save_samples", False):
            for ld in all_log_dirs:
                try:
                    shutil.rmtree(ld, ignore_errors=True)
                except Exception:
                    pass

        log.info(f"[{scan_id}] Scan complete: {filename} — score={score} level={level}")

    except asyncio.CancelledError:
        log.info(f"[{scan_id}] Scan cancelled by user")
        cancel_embed = discord.Embed(
            title="\u274C Scan Cancelled",
            description="The scan was cancelled by the requester.",
            color=0x95A5A6,
        )
        if scan_msg:
            try:
                await scan_msg.edit(embed=cancel_embed, view=None)
            except discord.HTTPException:
                await safe_send(embed=cancel_embed)
        else:
            await safe_send(embed=cancel_embed)
    except Exception as e:
        log.exception(f"[{scan_id}] Scan error")
        error_embed = discord.Embed(
            title="Scan Error",
            description=f"An error occurred during analysis:\n```{sanitize_path(str(e)[:1500])}```",
            color=0xE74C3C,
        )
        if scan_msg:
            try:
                await scan_msg.edit(embed=error_embed, view=None)
            except discord.HTTPException:
                await safe_send(embed=error_embed)
        else:
            await safe_send(embed=error_embed)
    finally:
        _cancelled_scans.discard(scan_id)
        if not _spawned_sub_scans:
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass


# ─── Tor Auto-Launch ─────────────────────────────────────────────────────────

_tor_process: Optional[subprocess.Popen] = None
_tor_lock = threading.Lock()


def _find_tor_exe() -> Optional[str]:
    """Find tor.exe in the project's tor/ directory."""
    tor_path = MASTER_DIR / "tor" / "tor.exe"
    if tor_path.exists():
        return str(tor_path)
    # Also check if tor is on PATH
    return shutil.which("tor")


def _is_tor_running(proxy: str) -> bool:
    """Quick check if Tor SOCKS proxy is already listening."""
    import socket
    try:
        parsed = urlparse(proxy)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9050
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def start_tor():
    """Auto-launch Tor if configured and not already running."""
    global _tor_process
    if not CFG["scanner"].get("require_tor_for_urls", True):
        return

    tor_proxy = CFG["scanner"].get("tor_proxy", "socks5://127.0.0.1:9050")

    if _is_tor_running(tor_proxy):
        log.info("Tor is already running on %s", tor_proxy)
        return

    tor_exe = _find_tor_exe()
    if not tor_exe:
        log.warning(
            "Tor not found. Place the Tor Expert Bundle in master/tor/ "
            "or install Tor and ensure it's on PATH. "
            "URL downloads will fall back to direct connections."
        )
        return

    tor_dir = Path(tor_exe).parent
    data_dir = tor_dir / "data"

    # Remove stale lock file from previous crash
    lock_file = data_dir / "lock"
    if lock_file.exists():
        try:
            lock_file.unlink()
            log.info("Removed stale Tor lock file")
        except OSError:
            pass

    log.info(f"Starting Tor from {tor_exe}...")
    try:
        torrc = tor_dir / "torrc"
        cmd = [tor_exe]
        if torrc.exists():
            cmd += ["-f", str(torrc)]
        _tor_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd=str(tor_dir),
        )
        # Wait for Tor to bootstrap (check every second, up to 30s)
        for i in range(30):
            time.sleep(1)
            if _is_tor_running(tor_proxy):
                log.info(f"Tor is ready (took {i + 1}s)")
                return
            # Check if process died
            if _tor_process.poll() is not None:
                stderr_out = ""
                try:
                    stderr_out = _tor_process.stderr.read().decode("utf-8", errors="replace")[:500]
                except Exception:
                    pass
                log.error(f"Tor process exited with code {_tor_process.returncode}"
                          + (f": {stderr_out}" if stderr_out else ""))
                _tor_process = None
                # If it failed due to lock/address in use, try one more time
                if i == 0:
                    log.info("Retrying Tor startup...")
                    if lock_file.exists():
                        try:
                            lock_file.unlink()
                        except OSError:
                            pass
                    _tor_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        cwd=str(tor_dir),
                    )
                    continue
                return
        log.warning("Tor started but proxy not responding after 30s — URL downloads will fall back to direct")
    except Exception as e:
        log.error(f"Failed to start Tor: {e}")
        _tor_process = None


def stop_tor():
    """Shut down Tor if we started it."""
    global _tor_process
    with _tor_lock:
        if _tor_process is not None:
            log.info("Shutting down Tor...")
            try:
                _tor_process.terminate()
                _tor_process.wait(timeout=4)
            except Exception:
                try:
                    _tor_process.kill()
                except Exception:
                    pass
            _tor_process = None


import atexit
atexit.register(stop_tor)


def _cleanup_stale_temp_dirs():
    """Remove any leftover scan_ temp dirs older than 1 hour."""
    try:
        tmp = tempfile.gettempdir()
        cutoff = time.time() - 3600
        for entry in os.scandir(tmp):
            if entry.name.startswith("scan_") and entry.is_dir():
                try:
                    if entry.stat().st_mtime < cutoff:
                        shutil.rmtree(entry.path, ignore_errors=True)
                except Exception:
                    pass
    except Exception:
        pass

atexit.register(_cleanup_stale_temp_dirs)


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    yml_path = BOT_DIR / "config.yml"

    # First-time setup: no config.yml or no token
    if not yml_path.exists() or not CFG["discord"]["token"]:
        if not yml_path.exists():
            setup_cfg = run_setup()
        else:
            # config.yml exists but token is empty/placeholder
            print("No Discord bot token found in config.yml.")
            print()
            new_token = _ask("Enter your Discord bot token")
            if new_token:
                # Update the token in the existing config
                with open(yml_path, encoding="utf-8") as f:
                    raw = f.read()
                # Replace placeholder or empty token
                for placeholder in ('""', "''", '"YOUR_BOT_TOKEN_HERE"'):
                    old_line = f"token: {placeholder}"
                    if old_line in raw:
                        raw = raw.replace(old_line, f'token: "{new_token}"', 1)
                        break
                else:
                    # Token key exists but has some other value — replace the whole line
                    raw = re.sub(r'(token:\s*)(".*?"|\'.*?\'|.*)', f'\\1"{new_token}"', raw, count=1)
                with open(yml_path, "w", encoding="utf-8") as f:
                    f.write(raw)
                setup_cfg = None
            else:
                print("ERROR: A Discord bot token is required to run.")
                sys.exit(1)

        # Reload config after setup
        CFG.clear()
        CFG.update(load_config())

    token = CFG["discord"]["token"]
    if not token or token in ("YOUR_BOT_TOKEN_HERE",):
        print("ERROR: No valid Discord token configured.")
        print("Edit bot/config.yml or set DISCORD_TOKEN env var.")
        sys.exit(1)

    guild_id = CFG["discord"].get("guild_id")
    # debug_guilds is incompatible with integration_types/contexts (user-installable apps)
    # Only set it when user_install is disabled
    if guild_id and not CFG["discord"].get("allow_user_install", False):
        try:
            bot.debug_guilds = [int(guild_id)]
        except (ValueError, TypeError):
            print(f"WARNING: Invalid guild_id '{guild_id}' in config — ignoring.")

    # Graceful shutdown handler
    async def shutdown():
        """Clean up resources before exit."""
        log.info("Shutting down...")
        # Cancel background poll tasks
        for task in list(_background_poll_tasks):
            task.cancel()
        # Close aiohttp session
        if http_session is not None and not http_session.closed:
            await http_session.close()
        # Stop Tor
        stop_tor()
        # Close the bot
        if not bot.is_closed():
            await bot.close()

    @bot.event
    async def on_close():
        """Called when the bot is closing."""
        stop_tor()
        if http_session is not None and not http_session.closed:
            await http_session.close()

    # Auto-launch Tor before starting the bot
    start_tor()

    try:
        bot.run(token)
    except KeyboardInterrupt:
        log.info("Ctrl+C received — shutting down")
    finally:
        stop_tor()
