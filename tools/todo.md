# Scanner Testing & Improvement TODO

## Rescan Validation
- [x] Rescan dQrkis_1.21.4.jar with updated scanner — score 76/HIGH (was 46/MEDIUM)
- [x] Verify new constant pool / raw byte fallbacks extract opaque predicate markers — 19 markers detected
- [x] Verify URL regex captures RPC endpoints with query params (API keys) — polygon-mainnet.rpcfast.com?api_key=... captured
- [x] Verify contracts array is displayed in Discord embeds and text report — confirmed at embed line 2806 + text report line 3611
- [x] Verify buyerUUID field displays in C2 Infrastructure section — added to embed + text report
- [ ] Cross-check DonutDupe1.21 and DonutAuctions samples — may be Silent NET, currently tagged weedhack in catalog (needs sample access)

## Remaining dQrkis Analysis
- [x] Crack Core.java setupPython, pullAssets, downloadFromCdn, download — 27 strings decrypted via javap bytecode XOR chain tracing
- [x] Analyze lang.dat — contains `locale=93cd1fbb-7c8c-480f-a60b-568f0a1431e8` (buyer/license UUID)
- [ ] Crack 15 remaining strings in setupPython/decryptFernet — opaque predicate paths diverge from linear fall-through, needs dynamic analysis
- [ ] Crack Libmod.java null-path `rwxaadhdffwidpp` string — intermediate opaque predicate XOR in label224 switch not traced
- [ ] Analyze assets/ukaduutk.bin (131072 bytes) — JNIC v3.7.0 native obfuscation blob, needs JNIC RE tooling

## Scanner Code Improvements
- [x] Add JADX as a third decompiler — supplementFailedFiles already handles cascade
- [x] Make constant pool string extraction a first-class pipeline stage — URLs/domains fed to IOCs
- [x] Add JNIC blob detection — checks binary resources for JNIC signatures
- [x] Add persistence path scoring category to `compute_risk_score` (+5 per marker, max 10)
- [x] Add encryption complexity as a scoring signal — multiple XOR schemes marker
- [x] Add decompilation failure rate as scoring signal (+5 points)
- [x] Speed optimization — stripped JAR excludes library classes before decompilation (6 classes vs hundreds)
- [x] Vineflower performance flags — auto-threading, skip generics, keep literals
- [ ] Implement Scheme 1 substring pool decryption in JarAnalyzer — needs cjcwynliws pool reconstruction
- [ ] Add support for parameterized XOR keys — RpcHelper passes key as method return value

## Detection Improvements
- [x] Reflection-based payload detection — Class.forName + getMethod + invoke patterns
- [x] invokedynamic/MethodHandle detection — suspicious bootstrap method patterns
- [x] Unsafe.defineClass detection — runtime code injection
- [x] DNS tunneling C2 detection — JNDI/DirContext patterns
- [x] Timer/delayed execution detection — ScheduledExecutorService, Timer.schedule
- [x] ServiceLoader exploitation detection — META-INF/services/ scanning
- [x] ClassLoader manipulation detection — defineClass, URLClassLoader
- [x] Java agent/instrumentation detection — Premain-Class, Agent-Class in MANIFEST
- [x] 6 new YARA rules — reflection chains, dynamic classloading, DNS tunneling, polymorphic webhooks, agent instrumentation, delayed payloads
- [x] 20+ new behavioral patterns in config.properties

## Regression Testing
- [ ] Create automated test cases from decrypt_strings.py / decrypt_rpchelper.py known-good outputs
- [ ] Validate JarAnalyzer XOR decryption produces same results as manual Python decryptors
- [ ] Test Silent NET YARA rule against known samples (dQrkis) and verify no false positives on clean mods
- [ ] Test Polygon_Contract_C2 YARA rule
- [ ] Test Ethereum_Contract_C2 updated rule (now includes Polygon contract)

## API & Integration
- [x] Fix Hybrid Analysis 410 deprecation — POST /search/hash -> GET /search/hash
- [x] Fix HA poller also using POST — changed to GET
- [x] Fix write_full_report crash — vt_sandbox is a list, not a dict with "sandbox_links" key
- [x] Fix IOC schema mismatch — bot.py now checks both "ethContract" and "contracts" keys
- [x] Fix URL regex — now captures query parameters (?api_key=...)
- [x] Add minimum score floor (61) for HIGH_RISK_VARIANTS
- [x] Fix Ctrl+C not closing bot — added on_close handler, cleanup of background tasks/sessions/Tor
- [x] Per-run unique log files — bot/logs/scanner_YYYYMMDD_HHMMSS.log
- [x] Active ETAs — progress embed shows live elapsed time per stage, completion time when done
- [x] Verbose local analysis — JarAnalyzer stdout streamed line-by-line, sub-stage details shown in embed
- [x] Auto-decrypt display — JarAnalyzer writes decryptedStrings to IOCs JSON, bot displays them in embed + text report
- [x] Fix VT/MB/HA not running — http_session was None because on_ready hadn't fired; added ensure_http_session()
- [x] Fix Tor startup — pass -f torrc explicitly, add DataDirectory, log stderr on failure
- [x] VT lookup safer .get() chains — prevents KeyError on malformed API responses
- [x] save_stats/catalog use tempfile — prevents predictable temp file race
- [x] /save persists to config.yml — survives restarts
- [x] VT upload exponential backoff — starts polling at 5s instead of 10s

## Bot UX
- [x] Cancel button — users can cancel in-progress scans via Discord button
- [x] /stats improvements — detection rate, uptime, guild count
- [x] Community reputation tracking — unique submitters and guilds per file hash
- [x] Scan history enrichment — shows how many users/servers have submitted same file
- [x] analyze_entropy memory optimization — single-pass instead of reading file twice
- [x] Temp dir atexit cleanup — removes stale scan_ dirs older than 1 hour
- [x] catalog_lookup with lock — consistent read under _catalog_lock

## Not Implementable (needs manual work / infrastructure)
- [ ] Windows Sandbox analysis of dQrkis — awaiting user permission
- [ ] Cross-check DonutDupe1.21 samples — needs sample access
- [ ] Automated test framework — needs pytest setup + test fixtures
- [ ] Bytecode-level analysis with ASM — major feature, bypasses decompiler dependency
- [ ] Generic string decryption engine — major feature
- [ ] Bot.py modularization — 5700+ line file, massive refactor
- [ ] File similarity hashing (ssdeep/TLSH) — needs C library
- [ ] Mod platform cross-reference (CurseForge/Modrinth API) — needs API integration
- [ ] Sandbox execution trace — needs container infrastructure
