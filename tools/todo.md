# Scanner Testing & Improvement TODO

## Rescan Validation
- [ ] Rescan dQrkis_1.21.4.jar with updated scanner — verify score jumps from 46/MEDIUM to HIGH
- [ ] Verify new constant pool / raw byte fallbacks extract opaque predicate markers
- [ ] Verify URL regex captures RPC endpoints with query params (API keys)
- [ ] Verify contracts array is displayed in Discord embeds and text report
- [ ] Verify buyerUUID field displays in C2 Infrastructure section
- [ ] Cross-check DonutDupe1.21 and DonutAuctions samples — may be Silent NET, currently tagged weedhack in catalog

## Remaining dQrkis Analysis
- [ ] Crack Core.java `spawnInstaller()` Python bootstrap script (zjpiktbkekgodgp blob) — need to trace opaque predicate n value through Core.java bytecode
- [ ] Crack Core.java methods that failed decompile: setupPython, pullAssets, downloadFromCdn, decryptFernet — n values unknown
- [ ] Crack Libmod.java null-path `rwxaadhdffwidpp` string — intermediate opaque predicate XOR in label224 switch not traced
- [ ] Analyze lang.dat (43 bytes) — could be campaign UUID, buyer ID, or encrypted config
- [ ] Analyze assets/ukaduutk.bin (131072 bytes) — JNIC v3.7.0 native obfuscation blob, unknown payload

## Scanner Code Improvements
- [ ] Add JADX as a third decompiler — handles opaque predicates better than CFR/Vineflower; `supplementFailedFiles` already has the framework
- [ ] Make constant pool string extraction a first-class pipeline stage — currently logs findings but doesn't feed them to behavioral markers or IOC systems
- [ ] Add JNIC blob detection — check binary resources for JNIC header magic, identify version, add to scoring
- [ ] Add persistence path scoring category to `compute_risk_score` — samples with persistence should score higher
- [ ] Add encryption complexity as a scoring signal — multiple XOR schemes indicate deliberate malware engineering
- [ ] Add decompilation failure rate > 30% as an automatic HIGH severity flag
- [ ] Implement Scheme 1 substring pool decryption in JarAnalyzer (currently only brute-forces n, doesn't reconstruct the cjcwynliws pool)
- [ ] Add support for parameterized XOR keys (RpcHelper passes key as method return value, not static array)

## Regression Testing
- [ ] Create automated test cases from decrypt_strings.py / decrypt_rpchelper.py known-good outputs
- [ ] Validate JarAnalyzer XOR decryption produces same results as manual Python decryptors
- [ ] Test Silent NET YARA rule against known samples (dQrkis) and verify no false positives on clean mods
- [ ] Test Polygon_Contract_C2 YARA rule
- [ ] Test Ethereum_Contract_C2 updated rule (now includes Polygon contract)

## API & Integration
- [x] Fix Hybrid Analysis 410 deprecation — POST /search/hash -> GET /search/hash
- [x] Fix write_full_report crash — vt_sandbox is a list, not a dict with "sandbox_links" key
- [x] Fix IOC schema mismatch — bot.py now checks both "ethContract" and "contracts" keys
- [x] Fix URL regex — now captures query parameters (?api_key=...)
- [x] Add minimum score floor (61) for HIGH_RISK_VARIANTS
- [ ] Verify Tor startup failure (exit code 1) — may need config or path fix

## Dynamic Analysis
- [ ] Windows Sandbox analysis of dQrkis — capture live C2 domain from Polygon contract, Stage 2 payload, full Python installer script (awaiting user permission)
