# Scanner Codebase Analysis — Bugs, Security, Detection Gaps, Features, Architecture

Generated: 2026-03-17

---

## BUGS & CRASHES

- [x] **[HIGH] `_poll_ha_completion` uses POST instead of GET** — `bot.py:1064` uses `poll_session.post()` for `/search/hash`, but the TODO at line 36 says "Fix Hybrid Analysis 410 deprecation — POST /search/hash -> GET /search/hash" was already done. The main `ha_search()` function likely uses GET, but the background poller still uses POST. If HA enforces GET-only, the poller will silently fail every poll cycle and never update the HA embed.

- [ ] **[MEDIUM] `catalog_lookup` is sync, not async-safe** — `bot.py:410-411` reads `file_catalog` dict without holding `_catalog_lock`. While CPython GIL makes simple dict reads safe, this breaks the pattern set by `update_stats`/`catalog_update` and could cause stale reads if another coroutine is mid-update via `catalog_update`.

- [x] **[MEDIUM] `vt_lookup` KeyError on malformed API response** — `bot.py:609` accesses `data["data"]["attributes"]["last_analysis_stats"]` without `.get()`, and line 614 does `r["category"]` without `.get()`. If VT returns a partial/malformed response (rate-limit HTML, changed schema), this crashes with KeyError. The poller version at line 1016-1026 uses safer `.get()` chains.

- [x] **[MEDIUM] `analyze_entropy` reads entire file into memory twice** — `bot.py:1118-1122` reads the full file as raw bytes for overall entropy, then reopens it as a ZipFile and reads each entry. For large JARs (50 MB max), this could consume 100+ MB of memory. The overall entropy could be computed incrementally or from the ZipFile entries.

- [ ] **[LOW] `ScanQueue._waiters` set/clear race** — `bot.py:4383-4385` calls `w.set()` then `w.clear()` on other waiters to notify them of position changes. If a waiter checks between `set()` and `clear()`, it sees the event as set. If it checks after `clear()`, it misses the notification. This is benign (queue position display only) but the pattern is fragile.

- [ ] **[LOW] `cleanup_old_scans` timestamp parsing is fragile** — `bot.py:4075` slices `entry.name[:15]` and parses as `%Y%m%d_%H%M%S`. If any non-scan directory is placed in `scanned/` with a name starting with digits, it could either throw (caught) or accidentally match and get deleted.

- [ ] **[LOW] JarAnalyzer static global state not reset between batch runs** — `JarAnalyzer.java:45-51` uses static fields (`infoLog`, `configLog`, `outDir`, `markerDetails`). While `analyzeJar()` clears `markerDetails` at line 723, other statics like `infoLog`/`configLog` from a prior run could leak if the previous run threw an exception before reassignment. In batch mode, this could cause log entries to go to the wrong file.

- [ ] **[LOW] JarAnalyzer `extractClasses` opens ZipFile twice** — `JarAnalyzer.java:2343,2368` opens the JAR as a ZipFile in Pass 1, closes it, then reopens in Pass 2. This is a minor inefficiency; both passes could share a single ZipFile handle.

- [x] **[MEDIUM] Temp directory not always cleaned up on error** — `bot.py:4707` creates `work_dir = tempfile.mkdtemp(prefix="scan_")`. The cleanup at the end of `run_scan` is inside a `finally` block, but if the function is cancelled (e.g., bot shutdown during scan), the `finally` may not fully execute, leaving temp dirs behind. Consider a periodic temp cleanup or `atexit` handler.

- [ ] **[LOW] `check_and_set_cooldown` is not async-safe** — `bot.py:4418-4429` is a synchronous function that reads/writes `user_cooldowns` dict. While the GIL prevents corruption, two near-simultaneous calls from the same user could both pass the cooldown check before either sets the timestamp, allowing a double-scan.

---

## RACE CONDITIONS

- [x] **[HIGH] `scan_stats` read without lock in `stats_command`** — `bot.py:4643-4646` reads `scan_stats["total_scans"]` etc. directly in the `/stats` command without acquiring `_stats_lock`. While `update_stats` holds the lock, the read side doesn't. This can show inconsistent intermediate state (e.g., `total_scans` incremented but `detections` not yet).

- [ ] **[MEDIUM] `approved_exceptions` global replaced without lock** — `bot.py:4674` does `approved_exceptions = load_exceptions()` in `reload_exceptions_command`. If a scan is concurrently calling `check_exception`, it could see a partially-constructed set during the assignment. In practice CPython makes this safe due to atomic reference assignment, but it's not guaranteed by the language spec.

- [ ] **[LOW] YARA_RULES global replaced without lock** — `bot.py:545,575` sets `YARA_RULES` in `load_yara_rules()` which is called from `/reload`. If a scan is concurrently calling `run_yara()` at line 582, it could see `None` momentarily during reassignment. Same CPython atomic ref caveat.

---

## SECURITY

- [ ] **[HIGH] TOCTOU between HEAD and GET in URL download** — `bot.py:4237-4275` performs HEAD request with anti-SSRF checks, then does a separate GET. The server could return safe headers on HEAD and redirect to a malicious target on GET. While the GET also checks the final URL (line 4280-4291), the DNS resolution could return different IPs between the two requests (DNS rebinding attack). Consider pinning the resolved IP from HEAD and reusing it for GET, or at minimum re-resolving and re-checking after GET completes.

- [ ] **[MEDIUM] Webhook kill has no authorization check** — `bot.py:1248-1265` will DELETE any Discord webhook URL found in scanned malware. While the URL pattern is validated, any user who submits a file containing a webhook URL they want killed could weaponize the bot as a webhook deletion service. The bot has no way to verify the webhook is actually malicious vs. belonging to a legitimate server.

- [ ] **[MEDIUM] API keys in CFG dict accessible to all code paths** — `bot.py` loads VT, HA, and MB API keys into the global `CFG` dict. Any exception that dumps CFG contents (e.g., in error logging or a debug command) could leak these keys. Consider isolating secrets into a separate non-serializable store.

- [ ] **[MEDIUM] JarAnalyzer `SHARED_HTTP` follows redirects unconditionally** — `JarAnalyzer.java:41` sets `HttpClient.Redirect.NORMAL`. When fetching C2 URLs from Ethereum contracts (for analysis), a malicious contract could point to an internal IP. The Java HttpClient will follow redirects to internal addresses. Add IP validation on resolved addresses before fetching.

- [x] **[LOW] `save_stats` / `save_catalog` write to predictable temp file** — `bot.py:361-363` writes to `str(STATS_FILE) + ".tmp"` then renames. On a shared system, another process could race to write to this predictable path. Use `tempfile.NamedTemporaryFile` in the same directory instead.

- [x] **[LOW] `/save` command modifies runtime config without persistence** — `bot.py:4692` sets `CFG["scanner"]["save_samples"]` but doesn't write to config.yml. After a restart, the setting reverts. An admin might think they disabled sample saving but it re-enables on restart.

- [ ] **[LOW] JarAnalyzer subprocess command injection theoretically possible** — `bot.py:2149` constructs `cmd = [java, "-cp", "tools", "JarAnalyzer", str(jar_path)]`. The `jar_path` comes from user-controlled filenames sanitized at line 4763 (`re.sub(r"[^\w.\-]", "_", ...)`), but a malicious filename with newlines or special characters could potentially cause issues on some platforms.

---

## DETECTION GAPS

- [x] **[CRITICAL] No detection for reflection-based payload loading** — Malware can use `Class.forName()` + `getMethod()` + `invoke()` chains to execute payloads without any direct method references appearing in decompiled source. JarAnalyzer's behavioral pattern matching only checks decompiled source strings; it won't catch reflection-heavy dispatch patterns.

- [x] **[CRITICAL] No invokedynamic / MethodHandle string encryption detection** — Modern Java obfuscators (Bozar, Paramorphism, Radon) use `invokedynamic` bootstrap methods to decrypt strings at runtime. These produce no readable strings in decompiled output. JarAnalyzer should scan for suspicious `invokedynamic` patterns in the constant pool (specifically BSM entries pointing to decryption methods).

- [x] **[HIGH] No detection for in-memory class loading via `Unsafe`** — `sun.misc.Unsafe.defineClass()` or `Lookup.defineClass()` can load classes from byte arrays without touching the filesystem. Current patterns only check for `URLClassLoader` and `defineClass` strings in source.

- [ ] **[HIGH] No DNS tunneling C2 detection** — Malware can use DNS TXT records for C2 communication (e.g., `InetAddress.getByName` + custom DNS resolver). Current C2 detection focuses on HTTP URLs and Ethereum contracts. Add patterns for `javax.naming.directory.DirContext`, `InitialDirContext`, DNS record lookups.

- [ ] **[HIGH] XOR decryption relies on decompiler-specific output patterns** — JarAnalyzer's XOR key extraction at lines 2500-2625 looks for specific decompiled code patterns. If a different obfuscator produces a slightly different code structure (or a different decompiler is used), the extraction fails silently. The constant pool scanner partially mitigates this, but the decryption logic should also operate on bytecode directly.

- [ ] **[HIGH] No detection for Java Native Interface (JNI) payload execution** — Beyond JNIC obfuscation (which is detected), generic JNI calls via `System.loadLibrary()` / `System.load()` to execute native payloads are not flagged. A malware sample could bundle a `.so`/`.dll` and call native methods for all malicious behavior, completely bypassing Java-level analysis.

- [ ] **[MEDIUM] No detection for ClassLoader hierarchy manipulation** — Malware can define custom ClassLoaders that intercept `loadClass()` to inject malicious code into legitimate classes at load time. This is especially relevant for Fabric/Forge mods that can access the mod classloader.

- [ ] **[MEDIUM] No detection for Instrumentation/agent-based hooking at JAR level** — While JVMTI agent injection is detected via YARA (`JVMTI_Agent_Injection`), the JarAnalyzer doesn't check for `Premain-Class`/`Agent-Class` in MANIFEST.MF. The bot's `inspect_manifest()` does check suspicious keys, but the JarAnalyzer's own analysis path doesn't cross-reference this.

- [ ] **[MEDIUM] No detection for Timer/ScheduledExecutorService-based delayed execution** — Malware commonly delays payload execution using `java.util.Timer` or `ScheduledExecutorService` to evade sandbox analysis. Add behavioral patterns for `Timer.schedule`, `ScheduledThreadPoolExecutor`, and `Thread.sleep` with large values (>30000).

- [ ] **[MEDIUM] No Gradle/Maven plugin attack detection** — Malicious Minecraft mods distributed as Gradle projects can include build-time attacks via custom plugins or init scripts. Current analysis only handles JAR files.

- [ ] **[MEDIUM] YARA rules don't detect polymorphic webhook URLs** — `Discord_Webhook_Exfil` rule looks for literal webhook URLs, but malware can split the URL across multiple strings or construct it dynamically. Consider also matching the webhook ID pattern (`/\d{17,20}/`) combined with the token pattern.

- [ ] **[LOW] No detection for steganographic payloads in JAR resources** — Malware can embed payloads in PNG/JPG image resources within the JAR. Current analysis checks entropy of resources but doesn't attempt to detect steganography patterns (e.g., LSB encoding in image data).

- [ ] **[LOW] No detection for `ServiceLoader` exploitation** — Java's `ServiceLoader` mechanism (META-INF/services/) can be used to auto-load malicious implementations. JarAnalyzer doesn't scan `META-INF/services/` entries.

---

## FEATURE IDEAS

- [ ] **[HIGH] Automated string decryption engine** — Build a generic string decryption framework that tries common schemes (XOR with key, XOR with index, Base64+XOR, RC4, AES/ECB with embedded key) against encrypted string arrays found in constant pools. Currently only AdamRAT and specific XOR schemes are handled. A generic engine would catch new variants without manual reverse engineering.

- [ ] **[HIGH] Bytecode-level analysis (no decompiler dependency)** — Parse class files at the bytecode level to extract method calls, field accesses, and string constants directly. This eliminates dependency on decompiler output quality and catches obfuscated patterns that survive decompilation. Libraries like ASM or BCEL could be integrated.

- [ ] **[HIGH] Differential analysis against known-good mod versions** — Allow users to submit a "known good" version of a mod. The scanner diffs the class list, added/modified files, and new behavioral markers against the baseline. This catches supply-chain attacks where a legitimate mod is trojanized.

- [ ] **[MEDIUM] Sandbox execution trace** — Integrate with a Java sandbox (SecurityManager-based or container) to actually execute the mod in a controlled environment and log all file/network/process operations. This catches runtime-only behavior invisible to static analysis.

- [ ] **[MEDIUM] Multi-JAR dependency analysis** — Some malware splits payloads across multiple JARs (e.g., a mod JAR + a "library" JAR). Allow scanning a set of JARs together and cross-referencing their interactions.

- [ ] **[MEDIUM] Community reputation scoring** — Track how many times a file has been submitted, by how many unique users/servers, and whether it's been flagged before. High submission count with no detections increases confidence it's clean.

- [ ] **[MEDIUM] Automated YARA rule generation from IOCs** — When JarAnalyzer extracts new IOCs (domains, contracts, unique strings), auto-generate candidate YARA rules and present them for review.

- [ ] **[LOW] Historical trend dashboard** — Track detection rates, most common variants, new IOCs over time. Expose via a web dashboard or periodic Discord report.

- [ ] **[LOW] File similarity hashing (ssdeep/TLSH)** — Compute fuzzy hashes to detect variants of known malware even when binaries are slightly modified.

- [ ] **[LOW] Mod platform cross-reference** — Check file hashes against CurseForge/Modrinth APIs to verify the file matches an official release. Flag if the file claims to be a known mod but the hash doesn't match any published version.

---

## PERFORMANCE

- [ ] **[MEDIUM] Duplicate file reads in entropy + string extraction** — `bot.py` calls `analyze_entropy()` (reads full file + all ZIP entries) and then `extract_strings()` likely does the same. Both are called sequentially in `run_scan`. Combine into a single pass that computes entropy while extracting strings.

- [ ] **[MEDIUM] JarAnalyzer opens the JAR ZIP multiple times** — The JAR is opened separately for: class extraction (2x in `extractClasses`), padding detection, metadata extraction, config file detection, and repackaging. Consider opening once and passing the ZipFile handle through the pipeline.

- [ ] **[LOW] `run_yara` redirects stdout on every call** — `bot.py:586-588` creates a `StringIO` and `redirect_stdout` context manager for every YARA scan. This is a minor overhead but unnecessary if no YARA rules use `console` module.

- [ ] **[LOW] VT upload polls with fixed sleep intervals** — `bot.py:670` uses hardcoded waits `[10, 15, 20, 30, 45, 60]` totaling 180 seconds. For files that complete quickly, this wastes time. Consider exponential backoff starting from 5 seconds.

- [ ] **[LOW] Decompiler cascade tries all decompilers even when first succeeds partially** — `JarAnalyzer.java:3286-3310` tries Vineflower, and if any files failed, tries JADX/CFR for those files. But the `supplementFailedFiles` function may re-decompile files that already succeeded. Track which specific files failed and only retry those.

---

## ARCHITECTURE

- [ ] **[HIGH] JarAnalyzer uses static mutable state everywhere** — `JarAnalyzer.java` stores all state in static fields (lines 44-51: `infoLog`, `configLog`, `jarName`, `outDir`, `markerDetails`). This makes it impossible to run concurrent analyses and creates subtle bugs in batch mode. Refactor to an instance-based design where `analyzeJar()` operates on a `JarAnalysis` context object.

- [ ] **[HIGH] Manual JSON construction in JarAnalyzer** — `JarAnalyzer.java:2198-2220` and throughout uses manual StringBuilder JSON construction with `escJson()`. This is error-prone (missing commas, unclosed brackets, incorrect escaping of special characters). Use a JSON library (Jackson, Gson, or even `javax.json`) for reliable serialization.

- [ ] **[MEDIUM] Duplicated URL/domain extraction logic** — URL extraction happens in both `bot.py` (via regex in `extract_strings`) and `JarAnalyzer.java` (via behavioral patterns and source scanning). IOC deduplication and normalization should happen in one place.

- [ ] **[MEDIUM] Config pattern lists are unwieldy** — `config.properties:102` has a single `behavioral.patterns` key with 150+ pipe-separated entries in one line. This is hard to maintain, review, and diff. Consider splitting into category-specific files (e.g., `patterns/c2_domains.txt`, `patterns/api_calls.txt`) or at minimum one pattern per line.

- [ ] **[MEDIUM] No structured error reporting from JarAnalyzer** — JarAnalyzer communicates results to the bot via stdout text and JSON files. Errors are mixed into stdout/stderr with no structured format. Add a standardized JSON status output that includes error codes, partial results, and which analysis stages succeeded/failed.

- [ ] **[LOW] `bot.py` is a single 5700-line file** — Core logic (scanning, scoring, embeds, API clients, URL download, file analysis) is all in one file. Extract into modules: `scanner.py` (core scan logic), `scoring.py` (risk score computation), `embeds.py` (Discord embed builders), `apis.py` (VT/MB/HA clients), `download.py` (URL download + anti-SSRF).

- [ ] **[LOW] No abstract interface for threat intel APIs** — VT, MB, and HA each have bespoke lookup/upload functions with duplicated error handling patterns. Define a `ThreatIntelProvider` interface and implement each API as a provider.

- [ ] **[LOW] Hardcoded decompiler version in path** — `JarAnalyzer.java:3225` hardcodes `jadx-1.5.1-all.jar`. When JADX is updated, this path breaks. Use glob pattern matching (which the fallback at line 3228 does, but only if the hardcoded path fails first).

---

## UX IMPROVEMENTS

- [ ] **[MEDIUM] No way to cancel an in-progress scan** — Once a scan starts, the user must wait for it to complete or timeout. Add a cancel button (Discord button component) that kills the subprocess and cleans up.

- [ ] **[MEDIUM] Error messages expose internal paths** — While `sanitize_path()` exists (line 271+), not all error paths use it. JarAnalyzer stderr output at line 2206 is sanitized, but exception tracebacks from Python-level errors might leak paths through Discord embeds.

- [ ] **[LOW] Queue position not updated in real-time** — `ScanQueue` notifies waiters of position changes (line 4383-4385), but the mechanism (set+clear) is unreliable. Users in queue see stale position numbers.

- [ ] **[LOW] `/stats` shows raw numbers without context** — Detection rate (detections/total), average scan time, and uptime would be more useful than raw counters.

- [ ] **[LOW] No per-server or per-user scan history** — Users can't see their previous scans. Consider storing a ring buffer of recent scan results per user/server.
