# RATScanner

Automated malware analysis toolkit with a Discord bot frontend. Drop any file — JARs, EXEs, PDFs, Office docs, scripts, ISOs — and get instant threat intelligence with VirusTotal, YARA, behavioral analysis, and format-specific deep inspection.

Built for the Minecraft community but works on any file type.

---

## Features

- **13+ Minecraft malware variant detection** (Weedhack, Fractureiser, Skyrage, AdamRAT, etc.)
- **Multi-format analysis** — PE (.exe/.dll/.scr), PDF, Office (.doc/.docx/.xls), LNK, scripts (.bat/.ps1/.vbs), MSI, ISO
- **VirusTotal integration** — hash lookup, upload, sandbox behavior reports
- **MalwareBazaar integration** — abuse.ch threat intel database (no API key needed)
- **Hybrid Analysis integration** — CrowdStrike sandbox with automated submission
- **Progressive scan updates** — live embed updates as each service completes with ETAs
- **7,800+ YARA rules** from 43 public threat intelligence repositories
- **Discord webhook killing** — automatically DELETEs malicious webhooks found in samples
- **AES config decryption** — dynamically cracks encrypted RAT configs without hardcoded keys
- **Entropy analysis, string extraction, obfuscator detection, manifest inspection**
- **Zero trust on file extensions** — all detection is magic-byte based
- **Tor integration** — URL downloads routed through Tor for operator safety
- **SSRF protection** — blocks private IPs, loopback, link-local, CGNAT, cloud metadata via DNS resolution checks

---

## Quick Start

### Option A: Discord Bot (recommended)

```bash
cd master/bot
pip install -r requirements.txt
```

Edit `config.yml` (copy from `config.yml.example`). See `config.yml.example` for all available options.

**Never share your project folder without deleting `config.yml` first** — it contains your bot token and API keys.
```yaml
discord:
  token: "YOUR_BOT_TOKEN"
  guild_id: "YOUR_SERVER_ID"     # optional, speeds up command registration

virustotal:
  api_key: "YOUR_VT_API_KEY"    # free at https://www.virustotal.com/gui/join-us

hybrid_analysis:
  api_key: "YOUR_HA_API_KEY"    # free at https://www.hybrid-analysis.com/signup

# MalwareBazaar is enabled by default, no API key needed
```

Alternatively, set environment variables (these override `config.yml`):
```
DISCORD_TOKEN=your_token
VT_API_KEY=your_key
HA_API_KEY=your_key
DISCORD_GUILD_ID=your_guild_id   # optional
```

Run:
```bash
python bot.py
```

Use `/giverat` in your Discord server — attach a file or paste a URL.

### Option B: CLI (no bot needed)

Run from the `master/` directory:
```bash
cd master

# Analyze a single JAR
java -cp tools JarAnalyzer path/to/suspicious.jar

# Batch analyze a directory
java -cp tools JarAnalyzer --batch path/to/directory

# Scan your system for existing infections
java -cp tools JarAnalyzer --scan
```

Or just drop files into `PUT_JAR_HERE/` and double-click `run.bat`.

---

## Requirements

### Core (always needed)
| Dependency | Version | Install |
|---|---|---|
| **Java JDK** | 17+ | [Adoptium](https://adoptium.net/) or [Azul](https://www.azul.com/downloads/) |
| **Python** | 3.10+ | [python.org](https://www.python.org/downloads/) |

### Python Packages
```bash
pip install -r master/bot/requirements.txt
```

| Package | Purpose | Required? |
|---|---|---|
| `py-cord` | Discord bot framework | Yes |
| `pyyaml` | Config file parsing | Yes |
| `aiohttp` | Async HTTP (VT API, downloads) | Yes |
| `aiofiles` | Async file I/O | Yes |
| `yara-python` | YARA rule matching | Recommended |
| `pefile` | PE/EXE/DLL analysis | Recommended |
| `olefile` | Office macro / MSI analysis | Recommended |
| `aiohttp-socks` | Tor SOCKS5 proxy for URL downloads | Recommended |

### Decompilers (included in `tools/`)
These ship with the repo — no download needed:

| Tool | File | Source |
|---|---|---|
| **Vineflower** | `tools/vineflower.jar` | [github.com/Vineflower/vineflower](https://github.com/Vineflower/vineflower) |
| **CFR** | `tools/cfr-0.152.jar` | [github.com/leibnitz27/cfr](https://github.com/leibnitz27/cfr) |

JarAnalyzer uses Vineflower as the primary decompiler and falls back to CFR if Vineflower fails on a file.

### Tor Setup (recommended for URL scanning)

Tor routes URL downloads through the Tor network so the bot operator's IP is never exposed to potentially malicious download servers.

1. Download the **Tor Expert Bundle** (not Tor Browser):
   - [torproject.org/download/tor](https://www.torproject.org/download/tor/) — select your OS and download the **Expert Bundle**
2. Extract the archive and place the `tor` folder inside the `master/` directory:
   ```
   master/
   ├── tor/
   │   └── tor.exe        (Windows)
   │   └── tor             (Linux/macOS)
   ├── bot/
   ├── tools/
   └── ...
   ```
3. Start Tor before running the bot:
   ```bash
   # Windows
   master/tor/tor.exe

   # Linux/macOS
   master/tor/tor
   ```
   Tor will start a SOCKS5 proxy on `127.0.0.1:9050` by default.
4. The bot is pre-configured to use `socks5://127.0.0.1:9050` — no config changes needed.

If you use **Tor Browser** instead of the Expert Bundle, change the port in `config.yml`:
```yaml
scanner:
  tor_proxy: "socks5://127.0.0.1:9150"
```

To disable Tor (not recommended):
```yaml
scanner:
  require_tor_for_urls: false
```

### Other External Tools (optional)
| Tool | Purpose | Download |
|---|---|---|
| **Ghidra** | Binary RE (DLL/EXE disassembly) | [ghidra-sre.org](https://ghidra-sre.org/) |
| **VirusTotal account** | API key for hash lookups | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |

---

## Discord Bot Setup

### 1. Create a Discord Application

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. Click **New Application** and name it
3. Go to **Bot** tab, click **Reset Token**, copy it
4. Enable **Message Content Intent** under Privileged Gateway Intents
5. Go to **OAuth2 > URL Generator**, select `bot` + `applications.commands`
6. Select permissions: `Send Messages`, `Attach Files`, `Embed Links`, `Use Slash Commands`
7. Copy the invite URL and add the bot to your server

### 2. Configure

```bash
cp master/bot/config.yml.example master/bot/config.yml
```

Paste your bot token and VT API key into `config.yml`.

### 3. Run

```bash
cd master/bot
python bot.py
```

### Bot Commands

| Command | Description |
|---|---|
| `/giverat [file]` | Scan an uploaded file |
| `/giverat [url]` | Download and scan a file from URL (routed through Tor) |
| `/stats` | Show scan statistics |
| `/save [true/false]` | Toggle saving scanned files to disk (admin only) |
| `/reload` | Reload YARA rules (admin only) |

---

## What It Detects

### Minecraft Malware Families

| Family | Type | Detection Method |
|---|---|---|
| **Weedhack** | RAT/Stealer | JNIC obfuscation, `me/mclauncher` package, EtherHiding C2 |
| **Fractureiser** | Supply chain worm | `dev.neko` package, known C2 IPs, `.ref` marker |
| **Skyrage** | Server RAT | `skyrage.de` domain, persistence artifacts |
| **AdamRAT** | AES-encrypted RAT | Dynamic config decryption, webhook extraction |
| **BaikalClub** | Stealer | Stargazers Ghost Network distribution |
| **WeirdUtils** | SkyBlock stealer | Sponge masquerade, AES/CBC backdoor |
| **Ectasy** | Server backdoor | `ectasy.club` C2, BungeeCord plugin drops |
| **Blurry** | Backdoor + miner | `fluyd.dev` C2, XMRig deployment |
| **BleedingPipe** | Deserialization RCE | Gadget chain detection in Forge mods |
| **Minegrief** | Self-spreading worm | World encryption, server scanning |
| + 3 more | Various | See `tools/config.properties` |

### General File Types

| Format | What's Analyzed |
|---|---|
| **PE** (.exe/.dll/.scr) | Imports (injection, keylogging, evasion), packers (UPX, Themida), section entropy, timestamps |
| **PDF** | /JavaScript, /OpenAction, /Launch, embedded files, stream encoding |
| **Office** (.doc/.docx/.xls) | VBA macros, auto-exec triggers, DDE attacks, template injection |
| **LNK** (.lnk) | Suspicious targets (cmd, powershell, mshta), embedded payloads |
| **Scripts** (.bat/.ps1/.vbs/.js) | LOLBins, obfuscation (caret, concat, Chr(), base64), download cradles |
| **MSI** | CustomActions, embedded PEs, script streams |
| **ISO/IMG** | Dangerous files inside, autorun.inf, MOTW bypass delivery |

---

## YARA Rules

7,800+ rules from 43 repositories, plus custom Minecraft-specific rules:

- `minecraft_rat.yar` — 10 rules for Weedhack, AdamRAT, Skyrage, Fractureiser, etc.
- `minecraft_malware.yar` — 22 rules covering Fractureiser (all stages), Skyrage, Weedhack, WeirdUtils, Ectasy, Blurry, Comet, BaikalClub, Seroxen, BleedingPipe, Minegrief, GasAuth
- **43 public repos** — Neo23x0/signature-base, Elastic, Malpedia, ReversingLabs, Mandiant, ESET, JPCERT, Yara-Rules, DarkenCode, and more

Rules auto-load recursively from `bot/rules/`. Broken files are skipped gracefully.

### Optional: Microsoft Defender YARA Rules (76,700+ additional rules)

Too large to include in the repo (292 MB), but you can download them with one command:

```bash
cd master/bot/rules
python download-defender-yara.py
```

The bot will auto-load them on next start or `/reload`.

---

## Project Structure

```
master/
├── README.md
├── ARCHITECTURE.md
├── run.bat                  # CLI launcher
├── PUT_JAR_HERE/            # Drop JARs here for CLI mode
├── tor/                     # Tor Expert Bundle (you add this)
│   └── tor.exe
├── bot/
│   ├── bot.py               # Discord bot (~3,000 lines)
│   ├── config.yml.example   # Config template
│   ├── requirements.txt     # Python dependencies
│   └── rules/               # YARA rules (7,800+ files)
│       ├── minecraft_rat.yar
│       ├── minecraft_malware.yar
│       └── <33 repo dirs>/
├── tools/
│   ├── JarAnalyzer.java     # Core analysis engine
│   ├── JarAnalyzer.class    # Compiled
│   ├── cfr-0.152.jar        # CFR decompiler
│   ├── vineflower.jar       # Vineflower decompiler
│   └── config.properties    # Detection config (80+ patterns)
├── logs/                    # Analysis output (auto-created)
└── scanned/                 # Archived scans (auto-created)
```

All paths are relative — clone/copy the repo anywhere and it works.

---

## Building From Source

### JarAnalyzer
```bash
cd master/tools
javac JarAnalyzer.java
```

Single file, no build system, no dependencies beyond JDK.

### Bot
```bash
cd master/bot
pip install -r requirements.txt
python bot.py
```

---

## Security Notes

- The bot **never** exposes local file paths in Discord output — all paths are sanitized (case-insensitive on Windows)
- Zip bomb detection aborts scans that exceed safe decompression limits (streaming decompression with per-entry size caps)
- URL downloads validate resolved IPs against private/reserved ranges using Python's `ipaddress` module (blocks IPv4 + IPv6 SSRF)
- DNS resolution is checked before connecting — prevents DNS rebinding attacks
- HEAD request failures abort the download when Tor is required
- Webhook URLs are validated against the Discord webhook pattern before DELETE requests are sent
- Discord embed field values are truncated to prevent API rejections
- All blocking I/O runs in thread pool executors to keep the bot responsive
- Scans run in isolated temp directories that are cleaned up after each scan
- Concurrent scan limit prevents resource exhaustion
- Cooldown system prevents abuse
- File samples are **not** saved by default — enable with `/save true`
- No hardcoded paths — everything uses relative paths from the project directory

---

## License

This tool is provided for **defensive security research and educational purposes only**. Use it to protect your Minecraft community, not to harm others.

---

## Credits

- **JarAnalyzer** — custom static analysis engine
- **Vineflower** — [github.com/Vineflower/vineflower](https://github.com/Vineflower/vineflower)
- **CFR** — [github.com/leibnitz27/cfr](https://github.com/leibnitz27/cfr)
- **YARA rules** — Neo23x0, Elastic, Malpedia, ReversingLabs, Mandiant, and 28 other open-source contributors
- **Threat intelligence** — fractureiser-investigation, MMPA, Check Point Research, Bitdefender, JPCERT
