# Architecture

Technical breakdown of every component in RATScanner.

---

## System Overview

```
User uploads file via Discord (/giverat) or CLI (run.bat)
         │
         ▼
   ┌─────────────┐
   │  Magic Byte  │  Identifies file type regardless of extension
   │  Detection   │  (PE, PDF, ZIP/JAR, OLE, LNK, Script, ISO)
   └──────┬──────┘
          │
          ▼
   ┌─────────────────────────────────────────────────┐
   │              Parallel Analysis Pipeline           │
   │                                                   │
   │  ┌──────────────┐  ┌──────────┐  ┌───────────┐  │
   │  │ JarAnalyzer  │  │ VirusTotal│  │   YARA    │  │
   │  │ (Java subprocess)│ (API)    │  │  (7,800+) │  │
   │  └──────────────┘  └──────────┘  └───────────┘  │
   │                                                   │
   │  ┌──────────────┐  ┌──────────┐  ┌───────────┐  │
   │  │ Format-Specific│ │ Entropy  │  │  String   │  │
   │  │ Analyzer      │  │ Analysis │  │ Extraction│  │
   │  └──────────────┘  └──────────┘  └───────────┘  │
   │                                                   │
   │  ┌──────────────┐  ┌──────────┐  ┌───────────┐  │
   │  │ Obfuscator   │  │ Manifest │  │  Webhook  │  │
   │  │ Detection    │  │ Inspect  │  │  Killer   │  │
   │  └──────────────┘  └──────────┘  └───────────┘  │
   └──────────────────────┬───────────────────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │ Risk Scoring │  Weighted 0-100 score from all sources
                   │   Engine     │  LOW (0-25) / MEDIUM (26-60) / HIGH (61-100)
                   └──────┬──────┘
                          │
                          ▼
               ┌──────────────────┐
               │ Discord Embeds + │  Color-coded results, VT link,
               │ Log ZIP Upload   │  sanitized logs as attachments
               └──────────────────┘
```

---

## File: `bot/bot.py` (~3,000 lines)

> **Note:** Line numbers below are approximate and may shift as code evolves.

The Discord bot and entire analysis orchestrator. Single-file design — no fragmented imports to chase.

### Sections (in order)

#### Config & Setup (lines 1-170)
- Loads `config.yml` with `_deep_merge()` for nested overrides
- Environment variable fallbacks (`DISCORD_TOKEN`, `VT_API_KEY`, `DISCORD_GUILD_ID`)
- Persistent stats in `stats.json`

#### Path Sanitizer (lines 95-120)
- `sanitize_path()` — strips all local filesystem paths before anything reaches Discord
- Builds a list of sensitive paths at startup: home dir, bot dir, temp dir, all Windows env vars
- Regex catch-all for any `C:\Users\<name>\...` or `/home/<name>/...` patterns
- Applied to: error messages, JarAnalyzer stdout/stderr, log file contents, embed fields

#### YARA Engine (lines 125-175)
- `load_yara_rules()` — recursively discovers `.yar`/`.yara` files using `rglob`
- Compiles each file individually first, skips broken ones, then batch-compiles the valid set
- Uses relative-path namespacing to avoid rule name collisions across 40 repos
- `run_yara()` — matches with 60s timeout per file

#### VirusTotal Integration (lines 180-290)
- `vt_lookup()` — hash-based lookup, returns detection stats + permalink
- `vt_upload()` — uploads unknown files, polls for completion (up to 3 minutes)
- **Always returns a permalink** even if analysis times out (status: "queued")
- Handles large files (>32MB) via VT's upload URL endpoint

#### Entropy Analysis (lines 295-335)
- `shannon_entropy()` — byte-level Shannon entropy (0.0-8.0 scale)
- `analyze_entropy()` — scans overall file + individual ZIP entries
- Flags entries with entropy >7.5 and size >512 bytes as suspicious
- Tracks max `.class` entropy separately (normal range: 5.5-6.5)

#### Manifest Inspection (lines 340-420)
- Checks JAR `META-INF/MANIFEST.MF` for Java agent injection indicators
- Flags: `Premain-Class`, `Agent-Class`, `Launcher-Agent-Class`, `Boot-Class-Path`, `Can-Redefine-Classes`, `Can-Retransform-Classes`

#### Raw String Extraction (lines 425-490)
- Regex-based extraction from raw bytes AND inside ZIP entries
- Patterns: URLs, Discord webhooks, Discord tokens, IPv4, Ethereum addresses
- Scans `.class`, `.properties`, `.json`, `.yml`, `.xml`, `.txt`, `.cfg` entries
- IP filtering: removes localhost, private ranges, version-number lookalikes

#### Webhook Killer (lines 495-510)
- `kill_webhook()` — sends HTTP DELETE to malicious Discord webhooks found during scanning
- Tracks kill count in persistent stats
- Configurable via `auto_delete_webhooks` setting

#### Multi-Format File Analysis (lines 515-1050)

Seven format-specific analyzers, all accessed through `analyze_file_format()`:

**`detect_file_type()`** — Magic byte router:
| Bytes | Type |
|---|---|
| `MZ` | PE (exe/dll/scr) |
| `%PDF` | PDF |
| `PK` | ZIP (JAR/Office OOXML) |
| `D0 CF 11 E0` | OLE2 (doc/xls/msi) |
| `4C 00 00 00` + CLSID | LNK shortcut |
| `CD001` at 0x8001 | ISO |
| Extension-based | Scripts (.bat/.ps1/.vbs/etc.) |

**`analyze_pe()`** — PE/EXE/DLL analysis:
- Uses `pefile` library (falls back to basic string scan without it)
- Checks imports against 7 categories: injection, keylogging, persistence, network, evasion, dynamic_load, crypto
- Section entropy analysis (>7.2 = packed/encrypted)
- Packer detection: UPX, ASPack, Themida, VMProtect, PEtite, MEW, RLPack, yP
- Entry point validation (outside `.text` = suspicious)
- Compile timestamp anomaly detection
- Low import count warning (dynamic API resolution)

**`analyze_pdf()`** — PDF analysis:
- Scans for 13 suspicious keywords (/JavaScript, /OpenAction, /Launch, /EmbeddedFile, etc.)
- Each keyword has severity rating (critical/high/medium/low)
- Detects auto-executing JavaScript (OpenAction + JS = critical combo)
- Multi-layer stream encoding detection (chained /Filter arrays)
- Embedded URI counting

**`analyze_office()`** — Office document analysis:
- **OLE2** (.doc/.xls): Uses `olefile` to find VBA macro streams
- **OOXML** (.docx/.xlsx): Uses `zipfile` to find `vbaProject.bin`
- Scans macro source for auto-exec triggers (AutoOpen, Document_Open, Workbook_Open, etc.)
- Keyword detection: Shell, WScript, PowerShell, download functions, registry, obfuscation
- DDE attack detection in XML content
- External template injection via `.rels` relationship files
- Chr() chain obfuscation scoring

**`analyze_lnk()`** — Windows shortcut analysis:
- Validates LNK magic + CLSID header
- Extracts ASCII and Unicode strings from binary
- Checks for 12 suspicious targets (cmd, powershell, mshta, certutil, bitsadmin, etc.)
- Argument pattern detection (-enc, -decode, http://, hidden)
- Large LNK warning (>50KB = likely embedded payload)

**`analyze_script()`** — Script file analysis:
- 10 LOLBin regex patterns (powershell encoded/hidden/bypass, certutil, bitsadmin, mshta, regsvr32, rundll32, wmic, schtasks)
- 5 suspicious keyword categories (download/exec, encoding, wscript, persistence, evasion)
- Obfuscation scoring:
  - Caret insertion (`p^o^w^e^r^s^h^e^l^l`)
  - String concatenation (`"p"+"ow"+"er"`)
  - Chr() chains
  - Backtick insertion (PowerShell)
  - Long Base64 blobs
  - Low alpha-character ratio

**`analyze_msi()`** — MSI installer analysis:
- Uses `olefile` to enumerate OLE streams
- CustomAction table detection (primary MSI attack vector)
- Scans all streams for embedded PE headers (`MZ`)
- Detects embedded CAB archives (`MSCF`)
- Script keyword scanning in stream content

**`analyze_iso()`** — ISO/IMG analysis:
- Scans raw bytes for dangerous filenames (.exe, .dll, .scr, .bat, .ps1, .lnk, etc.)
- Autorun.inf detection
- Small ISO heuristic (<10MB = likely malware delivery, not legitimate software)

#### Zip Bomb Detection (lines 1055-1090)
- Compression ratio check (>100:1)
- Decompressed size limit (512MB)
- Entry count limit (10,000)
- Nested archive count limit (50)
- **Aborts full scan on detection** — only runs VT + YARA on outer file

#### Obfuscator Detection (lines 1095-1165)
- Signature-based: Allatori, ZKM, Stringer, Bozar, Branchlock, ProGuard, JNIC
- Heuristic: short root class names (>10 with <=2 chars), Unicode class names
- Encrypted payload detection: .dat/.bin files with entropy >7.8

#### JarAnalyzer Subprocess (lines 1170-1230)
- Runs `java -cp tools JarAnalyzer <jar_path>` with configurable timeout
- Working directory is `master/` so JarAnalyzer can find its decompilers
- Parses `*_iocs.json` output for machine-readable results
- All stdout/stderr is path-sanitized before storage

#### Risk Scoring Engine (lines 1250-1380)
Weighted scoring across all analysis sources:

| Source | Max Points | Triggers |
|---|---|---|
| Known variant | 40 | HIGH_RISK_VARIANTS set match |
| C2/ETH contract | 15 | c2Base, ethContract fields |
| Webhooks | 10 | Discord webhook in IOCs |
| Behavioral markers | 25 | HIGH RISK markers + general |
| VirusTotal | 40 | Detection ratio scaled |
| YARA | 15 | 5 per match, capped |
| Obfuscators | 10 | 3 per obfuscator |
| Entropy | 15 | High-entropy entries + class entropy |
| String extraction | 30 | Webhooks, tokens, ETH addresses |
| Manifest | 10 | Agent injection keys |
| **PE analysis** | 45+ | Injection imports, packers, warnings |
| **PDF analysis** | 55 | Auto-exec JS, critical keywords |
| **Office analysis** | 60+ | Macros + auto-triggers + powershell |
| **LNK analysis** | 35+ | Suspicious targets + arguments |
| **Script analysis** | 55+ | LOLBins + download + obfuscation |
| **MSI analysis** | 35+ | Embedded PEs, script keywords |
| **ISO analysis** | 30+ | Dangerous files, autorun |

Final score clamped to 0-100. Thresholds: LOW (0-25), MEDIUM (26-60), HIGH (61-100).

#### Embed Builder (lines 1390-1710)
- Builds Discord embeds with color-coding (green/yellow/red)
- Risk score bar visualization
- Format-specific analysis sections (PE, PDF, Office, LNK, Script, MSI, ISO)
- VT link is **always** present
- All text fields pass through `sanitize_path()`

#### Log Packaging (lines 1715-1785)
- `package_logs()` — creates `analysis-of-[name].zip` files
- **Strips all binaries/malicious files** — only source code (.java, .xml, .json, etc.) and analysis text are included
- Splits into `analysis-of-[name]-pt1.zip`, `-pt2.zip` etc. at 9.5MB (Discord's 10MB limit)
- Priority ordering: analysis.txt first, then IOCs, configs, info logs, source
- All log file contents are path-sanitized before being written to the ZIP

#### Scan Runner (lines 1920-2680)
The main orchestration function `run_scan()`:

1. Download file (from attachment or URL)
2. Compute hashes (MD5, SHA1, SHA256)
3. Zip bomb check (abort if detected)
4. Detect file type and extract nested JARs
5. Run JarAnalyzer on each JAR
6. Obfuscator detection
7. Entropy analysis
8. Manifest inspection
9. String extraction
10. **Format-specific analysis** (PE/PDF/Office/LNK/Script/MSI/ISO)
11. YARA matching (on main file + all nested JARs)
12. VirusTotal lookup (or upload if not found)
13. Webhook killing
14. Risk score computation
15. Build embeds
16. Package and send logs
17. Archive scan results
18. Cleanup temp directory

#### URL Download (lines 1790-1860)
- `download_from_url()` — validates URL format, resolves DNS to check IPs against private/reserved ranges
- Uses Python `ipaddress` module for robust SSRF protection (IPv4 + IPv6, loopback, private, link-local, reserved, multicast, CGNAT)
- HEAD request failures abort download when Tor is required (prevents IP grabber bypass)
- Redirect destinations are re-validated (both hostname and resolved IPs)
- Streaming download with size limit (50MB)
- Respects Content-Disposition headers for filename
- Used by `/giverat url:` parameter

#### Scan Queue (lines 1865-1910)
- Semaphore-based concurrency limiter
- Configurable max concurrent scans (default 3)
- Tracks pending vs active count for status display

---

## File: `tools/JarAnalyzer.java` (~4,900 lines)

The core Java analysis engine. Handles decompilation, variant detection, and config decryption.

### Key Components

**Variant Detection (`Variant` enum)**
- 13 known variants with signature-based detection
- Each variant has specific class names, package patterns, and string constants
- Fallback to behavioral heuristics for unknown variants

**Decompiler Cascade**
1. Vineflower (primary) — best output quality
2. CFR (fallback) — used when Vineflower fails
3. Failed-decompile detection with automatic retry using alternate decompiler

**AES Config Decryption**
1. XOR key extraction from byte array literals in bytecode
2. N-value recovery via algebraic analysis of XOR chains (up to 2000+ candidates)
3. AES-256-CBC decryption with IV from first 16 bytes
4. JSON config parsing (webhooks, attacker IDs, C2 URLs)

**Constant Pool Scanner**
- Bytecode-level method reference scanning
- Detects dangerous APIs: `Runtime.exec`, `URLClassLoader`, `defineClass`, `ProcessBuilder`, etc.
- Static initializer injection detection (Fractureiser signature)

**Output Files**
- `*_iocs.json` — machine-readable IOCs (consumed by bot.py)
- `*_info.log` — full analysis log
- `*_config.log` — decrypted config
- `analysis.txt` — human-readable report
- `source/` — full decompiled source
- `main/` — malware-only source (libraries filtered)
- `main/important/` — key files (C2, config handlers, exploits)

---

## File: `tools/config.properties`

Detection configuration with 80+ behavioral patterns, 13 variant hint definitions, and Ethereum RPC endpoints for EtherHiding C2 resolution.

---

## File: `bot/rules/`

YARA rule directory. Two custom files plus 40 cloned repositories:

- `minecraft_rat.yar` — 10 rules (Weedhack, AdamRAT, Skyrage, Fractureiser, Discord webhook exfil, Ethereum C2, etc.)
- `minecraft_malware.yar` — 22 rules (all Fractureiser stages, Skyrage, Weedhack, WeirdUtils, Ectasy, Blurry, Comet, BaikalClub, Seroxen, BleedingPipe, Minegrief, GasAuth, generic session stealers, Force-OP backdoors, self-propagation worms)
- 40 public repositories (Neo23x0/signature-base, Elastic, Malpedia, ReversingLabs, etc.)

The bot loads all rules recursively via `rglob`. Broken files are compiled individually first and skipped if they fail, so one bad rule doesn't break the entire set.

---

## Data Flow

```
/giverat [file.jar]
    │
    ├── Ephemeral ACK to user ("Scanning...")
    │
    ├── Download to temp dir
    │
    ├── SHA256 hash ──► VT lookup
    │                      │
    │                      ├── Found? Return results
    │                      └── Not found? Upload + poll (up to 3 min)
    │
    ├── Magic byte check
    │   ├── PK (ZIP) ──► Extract all scannable files (EXE, PDF, etc.) ──► analyze each
    │   ├── MZ (PE) ──► PE analyzer
    │   ├── %PDF ──► PDF analyzer
    │   ├── OLE2 ──► Office / MSI analyzer
    │   ├── LNK ──► Shortcut analyzer
    │   ├── Script ext ──► Script analyzer
    │   └── ISO sig ──► ISO analyzer
    │
    ├── YARA scan (main file + all extracted files)
    ├── Entropy analysis
    ├── String extraction (URLs, webhooks, tokens, IPs, ETH)
    ├── Obfuscator detection
    ├── Manifest inspection
    │
    ├── Webhook killing (DELETE any found webhooks)
    │
    ├── Risk score computation (all sources weighted)
    │
    ├── Build Discord embeds (color-coded, VT link always present)
    │
    ├── Package logs into analysis-of-[name].zip (source only, binaries stripped)
    │
    └── Send public message with embeds + log attachments
```

---

## Security Model

| Threat | Mitigation |
|---|---|
| Path leaks in Discord | `sanitize_path()` strips all local paths from every output (case-insensitive on Windows) |
| Zip bombs | Ratio/size/entry limits, streaming decompression with per-entry caps, scan abort on detection |
| SSRF via URL param | DNS resolution + `ipaddress` module validates all resolved IPs (IPv4/IPv6 private, loopback, link-local, reserved, CGNAT) |
| DNS rebinding | Resolved IPs checked before connection; redirect targets re-resolved and re-validated |
| IP grabber links | HEAD validation required when Tor is enabled; HTML responses rejected; known grabber domains blocked |
| Resource exhaustion | Semaphore-based scan queue, timeout per scan, all blocking I/O in thread pool |
| Abuse | Atomic per-user cooldown (TOCTOU-safe) |
| Temp file leaks | `finally` block cleanup; VT upload file handles properly closed |
| Nested archive bombs | Depth limit (3), extraction byte budget (200MB), 50MB per-entry limit |
| Malicious log content | All log files sanitized before ZIP packaging |
| Webhook SSRF | Webhook URLs validated against Discord pattern before DELETE |
| Discord API limits | All embed fields truncated to 1024 chars; rotating log files (10MB, 5 backups) |
