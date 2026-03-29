import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * JarAnalyzer — Minecraft malicious JAR analyzer
 *
 * Usage:
 *   java JarAnalyzer <file.jar>
 *   java JarAnalyzer --batch <directory>
 *
 * External config files (optional, place alongside JarAnalyzer.class):
 *   config.properties     — all tunable detection parameters (domains, sizes, patterns)
 *   campaigns.properties  — UUID=Campaign Name (one per line)
 *   field_map.properties  — jsonKey=Human readable label (one per line)
 *   blocklist.txt         — known-bad domains/IDs/hashes (one per line, # = comment)
 */
public class JarAnalyzer {

    // ── ANSI colors ────────────────────────────────────────────────
    static final String RESET  = "\u001B[0m";
    static final String RED    = "\u001B[31m";
    static final String GREEN  = "\u001B[32m";
    static final String YELLOW = "\u001B[33m";
    static final String CYAN   = "\u001B[36m";
    static final String BOLD   = "\u001B[1m";

    // ── Shared HttpClient (reused across all HTTP calls) ──────────
    static final HttpClient SHARED_HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();

    // ── Log file writers ───────────────────────────────────────────
    static PrintWriter infoLog;
    static PrintWriter configLog;
    static String jarName  = "output";
    static Path   outDir   = Paths.get(".");   // set per-JAR in analyzeJar()

    /** Per-marker location details: marker label → list of {file, line, context} */
    static Map<String, List<Map<String, String>>> markerDetails = new LinkedHashMap<>();

    /** Constant pool URLs collected during metadata extraction — available to all variant analyzers */
    static Set<String> cpUrlsCollected = new LinkedHashSet<>();
    /** Constant pool domains collected during metadata extraction — available to all variant analyzers */
    static Set<String> cpDomainsCollected = new LinkedHashSet<>();
    /** Detected mod loader(s): "fabric", "quilt", "forge", "bukkit", etc. */
    static Set<String> detectedModLoaders = new LinkedHashSet<>();

    /** Resolve a file path inside the per-JAR output directory. */
    static Path out(String filename) { return outDir.resolve(filename); }

    // ── Variant enum ───────────────────────────────────────────────
    enum Variant {
        ADAMRAT,            // com.example + vubsyodfkejzllnk + XOR/AES + Discord webhook
        WEEDHACK,           // com.example + FabricAdapter + Ethereum C2
        SESSION_HARVESTER,  // dev.majanito + LoginScreen/APIUtils — Minecraft token harvester
        VAPE_CURIUM,        // Multi-class XOR, stage2 download, worm spreading
        SILENT_NET,         // com.libmod, Polygon blockchain C2, per-class XOR+UTF16
        MSHTA_DROPPER,      // mshta command execution dropper
        FRACTUREISER,       // Multi-stage infector: URLClassLoader + IP, dev.neko, .ref, lib.jar
        SKYRAGE,            // SkyRage token stealer: skyrage.de, discord_rpc.dll
        WEIRDUTILS,         // AES/CBC + Base64 LDC, org.spongepowered obfuscation, owouwu.tk
        COMET,              // *auth chat command, MD5 default password, Replit C2
        ECTASY,             // * command prefix, downloads bungee.jar, ectasy.club C2
        SERVER_CRASHER,     // Bundled MC client with crash/exploit tools (2Packets, xynis, etc.)
        MCLAUNCHER_LOADER,  // me/mclauncher package: IMCL defineClass injector, MEntrypoint ProcessBuilder, StagingHelper
        PACKUTIL_RAT,      // com/example/addon + PackUtil* classes: session theft, screen capture, Runtime.exec, Unsafe
        UNKNOWN             // unrecognized — do best-effort analysis
    }

    // ── Known malicious IOCs (IPs, domains, file indicators) ────────
    static final Set<String> KNOWN_C2_IPS = new LinkedHashSet<>(Arrays.asList(
        "85.217.144.130", "107.189.3.101",  // Fractureiser Stage 1/2
        "185.178.208.143", "185.178.208.162" // Weedhack (DDoS-Guard)
    ));
    static final Set<String> KNOWN_C2_DOMAINS = new LinkedHashSet<>(Arrays.asList(
        "adamrat.shop", "whnewreceive.ru", "whereceiver.ru", "api.donutsmp.net",
        "sltnnt.ru", "boobility.online", "feathermc.com",
        "connect.skyrage.de", "files.skyrage.de", "files-8ie.pages.dev",
        "owouwu.tk", "ectasy.club",
        // Weedhack C2 infrastructure (single operator — shared Cloudflare NS: mcgrory + rihana)
        "weedhack.to", "weedhack.cy", "receiver.cy", "whrc.ru",
        "whreceiverrrrrrrr.ru", "remotev2.whrc.ru", "mclauncher.su"
    ));
    static final Set<String> KNOWN_BAD_RESOURCES = new LinkedHashSet<>(Arrays.asList(
        ".ref",                 // Fractureiser Stage 2 marker
        "hook.dll",             // Fractureiser native payload
        "discord_rpc.dll",      // SkyRage Discord theft DLL
        "lib.dll",              // Fractureiser native
        "client.jar",           // Fractureiser Stage 3
        "libWebGL64.jar"        // Fractureiser Stage 2
    ));
    static final Set<String> KNOWN_BAD_PACKAGES = new LinkedHashSet<>(Arrays.asList(
        "dev/neko/", "dev/neko/nekoclient/", "dev/neko/nekoinjector/",
        "dev/neko/e/e/e/",  // Fractureiser mod-type detectors
        "org/spongepowered/tools/obfuscation/",  // WeirdUtils fake package
        "dev/majanito/", "dev/jnic/",  // Weedhack Stage 2 + JNIC obfuscation
        "me/mclauncher/"               // Weedhack loader
    ));

    // ── Runtime config (loaded from config.properties, with defaults) ──
    static final java.util.Properties CFG = new java.util.Properties();
    static {
        // Dropper / Weedhack defaults
        CFG.setProperty("dropper.eth.contract",  "0x1280a841Fbc1F883365d3C83122260E0b2995B74");
        CFG.setProperty("dropper.eth.method",    "0xce6d41de");
        CFG.setProperty("dropper.exfil.path",    "/api/delivery/handler");
        CFG.setProperty("dropper.stage2.path",   "/files/jar/module");
        CFG.setProperty("dropper.stage2.class",  "dev.majanito.Main");
        CFG.setProperty("dropper.stage2.method", "initializeWeedhack");
        CFG.setProperty("dropper.eth.rpcs",
            "https://eth.llamarpc.com|https://eth.api.onfinality.io/public|" +
            "https://rpc.eth.gateway.fm|https://ethereum-rpc.publicnode.com|" +
            "https://eth.rpc.blxrbdn.com|https://ethereum.rpc.subquery.network/public|" +
            "https://ethereum-json-rpc.stakely.io|https://ethereum-public.nodies.app|" +
            "https://mainnet.gateway.tenderly.co|https://ethereum-mainnet.gateway.tatum.io|" +
            "https://eth1.lava.build|https://eth.meowrpc.com|" +
            "https://rpc.flashbots.net/fast|https://rpc.flashbots.net|" +
            "https://eth.drpc.org|https://1rpc.io/eth");

        // XOR key extraction size heuristics
        CFG.setProperty("xor.key.primary.min",  "44");
        CFG.setProperty("xor.key.primary.max",  "48");
        CFG.setProperty("xor.key.fallback.min", "20");
        CFG.setProperty("xor.key.fallback.max", "100");

        // Variant classification hints (pipe-separated)
        CFG.setProperty("session.harvester.packages", "dev_majanito|dev/majanito");
        CFG.setProperty("session.harvester.classes",  "SessionIDLogin|LoginScreen|APIUtils");
        CFG.setProperty("weedhack.dropper.classes",   "FabricAdapter");
        CFG.setProperty("weedhack.dropper.helpers",   "Helper_class|Helper.class");
        CFG.setProperty("weedhack.dropper.zipentry",  "fabric.api.json");
        CFG.setProperty("weedhack.dropper.rawstrings","eth_call|initializeWeedhack|dev.majanito");
        CFG.setProperty("adamrat.obf.classes",        "vubsyodfkejzllnk|upokyqklsolkxbys");
        CFG.setProperty("adamrat.client.class",       "ExampleModClient");
        CFG.setProperty("adamrat.inner.classes",      "$xyz123|$abc456|$c0nfig|$aPconf");
        CFG.setProperty("adamrat.obf.signatures",     "pynvtoxahbmzany|feghssgcoq|upokyqklsolkxbys");

        // SILENT_NET detection
        CFG.setProperty("silent.net.packages", "com_libmod|com/libmod");
        CFG.setProperty("silent.net.classes", "Libmod");
        CFG.setProperty("silent.net.rawstrings", "polygon-rpc.com|epqfgikdhiuzuybl|cwmhwqsenglvcost|glcqksioqxlglmmb|ktfdumxluduvzmma|azmssbnclpvvzpam|bzwkkgywwylfhgzl|xnhyeinlaaoruzua|sltnnt.ru|prefireMc|ukaduutk.bin");

        // VAPE_CURIUM detection
        // NetworkManager removed — too common in legitimate mods (every Fabric/Forge networking mod has one)
        CFG.setProperty("vape.curium.classes", "TextureAtlasCache|ShaderCompileCache|ChunkMeshPool");
        // lazydfu and fabric-perf-tweaks removed: legitimate mod names that cause FPs
        CFG.setProperty("vape.curium.rawstrings", "curium|boobility|daddydex");
        CFG.setProperty("vape.curium.packages", "com_curium|com/curium");

        // MSHTA_DROPPER detection
        CFG.setProperty("mshta.dropper.rawstrings", "mshta|settings.tel|cmd.exe /k mshta");

        // FRACTUREISER detection
        CFG.setProperty("fractureiser.rawstrings", "dev.neko|nekoclient|85.217.144.130|107.189.3.101|files.skyrage.de|libWebGL64|lib.jar|neko.run");
        CFG.setProperty("fractureiser.classes", "dev_neko|nekoclient|nekoinjector");
        CFG.setProperty("fractureiser.manifest", "Premain-Class|Agent-Class");

        // SKYRAGE detection
        CFG.setProperty("skyrage.rawstrings", "skyrage.de|connect.skyrage.de|vmd-gnu|MicrosoftEdgeUpdateTaskMachineVM|discord_rpc.dll");
        CFG.setProperty("skyrage.classes", "skyrage|SkyRage");

        // WEIRDUTILS detection
        // Note: "spongepowered/tools/obfuscation" removed — too generic, triggers on
        // legitimate mixin libraries like mixinsquared that reference SpongePowered's
        // obfuscation API. The remaining signatures are specific to WeirdUtils malware.
        CFG.setProperty("weirdutils.rawstrings", "owouwu.tk|ObfuscatedClassloader|aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3");
        CFG.setProperty("weirdutils.classes", "ObfuscatedClassloader|WeirdUtils");

        // COMET detection
        // Comet: require MD5 hash or replit C2 — *auth alone is too generic
        CFG.setProperty("comet.rawstrings", "81dc9bdb52d04dc20036dbd8313ed055|replit.dev|replit.app");
        CFG.setProperty("comet.classes", "CometBackdoor");

        // ECTASY detection
        // Ectasy: PluginMetrics removed (matches bStats in thousands of legit plugins)
        // bungee.jar removed (matches legitimate BungeeCord); keeping ectasy.club domain + specific class
        CFG.setProperty("ectasy.rawstrings", "ectasy.club|TranslatableComponentDeserializer");
        CFG.setProperty("ectasy.classes", "Ectasy|TranslatableComponentDeserializer");

        // SERVER_CRASHER detection (2Packets, xynis, etc.)
        CFG.setProperty("server.crasher.packages", "us/whitedev|us\\whitedev");
        CFG.setProperty("server.crasher.classes", "Main2PacketsClient|CrashManager|ExploitManager");
        CFG.setProperty("server.crasher.rawstrings", "2PacketsClient|2Packets Client|main2packets|xynis|us.whitedev|accXynisMap");

        // MCLAUNCHER_LOADER detection (me/mclauncher / Weedhack family)
        CFG.setProperty("mclauncher.packages", "me/mclauncher|me\\mclauncher|dev/jnic|dev\\jnic");
        CFG.setProperty("mclauncher.classes", "IMCL|MEntrypoint|LoaderClient|StagingHelper|JNICLoader|$jnicLoader");

        // Polygon RPC endpoints for SILENT_NET
        CFG.setProperty("silent.net.polygon.rpcs",
            "https://polygon-rpc.com|https://rpc.ankr.com/polygon|" +
            "https://polygon-bor-rpc.publicnode.com|https://1rpc.io/matic|" +
            "https://polygon-mainnet.rpcfast.com|https://polygon.llamarpc.com|" +
            "https://rpc-mainnet.matic.quiknode.pro|https://polygon-public.nodies.app|" +
            "https://api.zan.top/polygon-mainnet|https://polygon.rpc.subquery.network/public|" +
            "https://endpoints.omniatech.io/v1/matic/mainnet/public");

        // Casino cheat class hints (pipe-separated)
        CFG.setProperty("casino.class.hints", "LegitRigController|PaperGameDispenser|aseity|optimization_rig");

        // Library class prefixes to skip during decompilation (pipe-separated)
        // Covers: Google libs, Apache, Kotlin, Netty, Mojang, SLF4J, javax, java stdlib,
        // ASM, Fabric/Quilt internals, ViaVersion protocol libs, Architectury, Mixin,
        // LWJGL, JNA, Guava, Jackson, Fastutil, Adventure text, Log4j, commons-*
        CFG.setProperty("library.class.prefixes",
            "com_google_|org_apache_|kotlin_|io_netty_|com_mojang_|org_slf4j_|javax_|java_|org_objectweb_|" +
            "net_fabricmc_|org_quiltmc_|com_viaversion_|com_raphfrk_|de_gerrygames_|" +
            "net_raphimc_|com_llamalad7_|org_spongepowered_|net_lenni0451_|" +
            "io_github_classgraph_|org_lwjgl_|com_sun_jna_|it_unimi_dsi_|" +
            "net_kyori_|org_joml_|com_fasterxml_|org_json_|org_yaml_|" +
            "org_checkerframework_|org_jetbrains_|org_intellij_|" +
            "org_ow2_|net_minecraftforge_|cpw_mods_|" +
            "com_electronwill_|org_jline_|io_github_retrooper_|com_github_retrooper_|" +
            "net_minecraft_|org_vineflower_|org_benf_|de_florianmichael_");

        // Behavioral source patterns: "srcPattern=label" entries, pipe-separated
        // IMPORTANT: These defaults are the fallback when config.properties is missing.
        // Only include patterns that are KNOWN MALICIOUS — never patterns that fire on
        // legitimate Minecraft mods/clients (e.g., HttpURLConnection, ProcessBuilder,
        // accessToken, ModInitializer, minecraftservices.com, Thread.sleep, etc.)
        CFG.setProperty("behavioral.patterns",
            // Known malicious domains/infrastructure
            "discord.com/api/webhooks=Contains Discord webhook URL — commonly used to exfiltrate stolen data|" +
            "adamrat.shop=Known malicious domain (adamrat.shop)|" +
            "whnewreceive.ru=Known malicious domain (whnewreceive.ru)|" +
            "whereceiver.ru=Known malicious domain (whereceiver.ru)|" +
            "weedhack=Known malicious infrastructure (weedhack)|" +
            "initializeWeedhack=Weedhack Stage 2 invocation|" +
            "initializeWeedhack2=Weedhack Stage 2 alternate entry|" +
            "eth_call=Ethereum RPC call (EtherHiding C2)|" +
            "FabricAdapter=Weedhack dropper component|" +
            "launcher_accounts=Reads launcher_accounts.json — contains Minecraft session tokens|" +
            "LegitRigController=Casino rig cheat module|" +
            "writeDigitValue=Item NBT manipulation (casino cheating)|" +
            "polygon-rpc.com=Polygon blockchain RPC (EtherHiding C2)|" +
            "boobility.online=Known C2 domain (Vape Curium)|" +
            "curium.cfg=Curium malware config|" +
            "com.libmod=Silent NET malware package|" +
            "sltnnt.ru=Known C2 domain (Silent NET)|" +
            "api.donutsmp.net=Known C2 domain (DonutSMP/ADAMRAT)|" +
            "feathermc.com=Known infrastructure (FeatherMC decoy)|" +
            "owouwu.tk=Known C2 domain (WeirdUtils)|" +
            "ectasy.club=Known C2 domain (Ectasy)|" +
            "neko.run=Fractureiser reinfection flag|" +
            "DOMStore=SkyRage persistence path|" +
            "microsoft-vm-core=SkyRage payload filename|" +
            "MicrosoftEdgeUpdateTaskMachineVM=SkyRage scheduled task persistence|" +
            "receiver.cy=Known Weedhack C2 domain|" +
            "whrc.ru=Known Weedhack C2 domain|" +
            "whreceiverrrrrrrr.ru=Known Weedhack C2 domain|" +
            "weedhack.cy=Known Weedhack C2 domain|" +
            "mclauncher.su=Known Weedhack distribution domain|" +
            "$jnicLoader=JNIC obfuscation loader (Weedhack)|" +
            "$jnicClinit=JNIC static initializer (Weedhack)|" +
            "dev.jnic=JNIC obfuscation package (Weedhack)|" +
            "addDefenderExclusions=Windows Defender exclusion bypass|" +
            "Add-MpPreference=Windows Defender exclusion (PowerShell)|" +
            "RuntimeBroker=Fake RuntimeBroker process (Weedhack native payload)|" +
            "TelemetryHelper=Weedhack telemetry/exfil module|" +
            "submitData=Data exfiltration API endpoint|" +
            "submitFile=File exfiltration API endpoint|" +
            "submitLogs=Log exfiltration API endpoint|" +
            // Exploitation capabilities
            "WDAGUtilityAccount=Windows Sandbox detection (anti-analysis)|" +
            "Player.setOp=OP privilege escalation|" +
            "setOp(true)=OP privilege escalation (Bukkit/Spigot)|" +
            "ForceOpExploit=ForceOp privilege escalation exploit|" +
            "Log4JExploit=Log4Shell exploitation capability|" +
            "BungeeExploit=BungeeCord/Velocity exploit|" +
            "CrashManager=Server crasher module manager|" +
            "ExploitManager=Server exploit module manager|" +
            "accXynisMap=2Packets/xynis account storage|" +
            "2PacketsClient=2Packets server crasher client|" +
            "Main2PacketsClient=2Packets client entry point|" +
            // Credential/data theft indicators (specific enough to not FP)
            "Login Data=Browser credential database access|" +
            "leveldb=LevelDB access (browser data extraction)|" +
            ".ssh=SSH key directory access|" +
            "KeyLogger=Keylogging functionality|" +
            "ScreenCapture=Screen capture functionality|" +
            // C2/exfil hosting
            "api.telegram.org=Telegram bot exfiltration|" +
            "pastebin.com/raw=Pastebin raw C2 config fetch|" +
            "ngrok=Ngrok tunnel (dynamic C2)|" +
            "trycloudflare=Cloudflare tunnel (dynamic C2)|" +
            // Persistence/evasion
            "schtasks=Scheduled task persistence|" +
            "cmstp=CMSTP UAC bypass technique");

        // Raw-byte patterns: "bytesPattern=label" entries, pipe-separated
        CFG.setProperty("raw.patterns",
            "pynput=Keylogger library (pynput) referenced|" +
            "win32crypt=DPAPI credential decryption (win32crypt) referenced|" +
            "adamrat.shop=Known C2 domain in class data (adamrat.shop)|" +
            "whnewreceive=Known C2 domain in class data (whnewreceive.ru)|" +
            "0x1280a841=Known Ethereum contract address|" +
            "dev.majanito=Weedhack author namespace in class data|" +
            "0x9c0a5073=Known Polygon contract address (Silent NET)|" +
            "donutsmp=DonutSMP infrastructure reference|" +
            "api.donutsmp.net=DonutSMP C2 API|" +
            "feathermc.com=FeatherMC decoy infrastructure|" +
            "receiver.cy=Known Weedhack C2 in class data|" +
            "whrc.ru=Known Weedhack C2 in class data|" +
            "weedhack.cy=Known Weedhack C2 in class data|" +
            "whreceiverrrrrrrr=Known Weedhack C2 in class data|" +
            "mclauncher.su=Known Weedhack distribution in class data|" +
            "$jnicLoader=JNIC obfuscation in class data|" +
            "b8c7315a-c159-4497-8e4c-2eb1c2319335=Weedhack JNIC payload UUID|" +
            "cf48e453-190a-490c-b102-f7719ec11734=Weedhack telemetry UUID|" +
            "certutil=Certificate utility (download/decode)|" +
            "bitsadmin=BITS download utility");
    }

    // Convenience accessors
    static String   cfg(String key)      { String v = CFG.getProperty(key); return v != null ? v : ""; }
    static int      cfgInt(String key)   {
        String v = CFG.getProperty(key);
        if (v == null || v.isBlank()) return 0;
        try { return Integer.parseInt(v.trim()); }
        catch (NumberFormatException e) { System.err.println("WARNING: invalid int for config key '" + key + "', defaulting to 0"); return 0; }
    }
    static String[] cfgArr(String key)   { String v = CFG.getProperty(key); return v != null ? v.split("\\|") : new String[0]; }

    // Dropper constant accessors (read live from CFG so config.properties overrides take effect)
    static String   DROPPER_ETH_CONTRACT()  { return cfg("dropper.eth.contract"); }
    static String   DROPPER_ETH_METHOD()    { return cfg("dropper.eth.method"); }
    static String   DROPPER_EXFIL_PATH()    { return cfg("dropper.exfil.path"); }
    static String   DROPPER_STAGE2_PATH()   { return cfg("dropper.stage2.path"); }
    static String   DROPPER_STAGE2_CLASS()  { return cfg("dropper.stage2.class"); }
    static String   DROPPER_STAGE2_METHOD() { return cfg("dropper.stage2.method"); }
    static String[] DROPPER_ETH_RPCS()      { return cfgArr("dropper.eth.rpcs"); }

    // ── Known campaign UUIDs (extended at runtime from campaigns.properties) ──
    static final Map<String, String> CAMPAIGN_MAP = new LinkedHashMap<>();
    static {
        CAMPAIGN_MAP.put("bfe0b88a-d6a9-4a9f-8c66-753bee597522", "Adam Rat Builder");
        CAMPAIGN_MAP.put("d19c1853-bd55-4638-b85c-68d0e39e5b24", "CasinoRig/SilentNET/Radium batch");
        CAMPAIGN_MAP.put("4f106cc1-3592-473f-80f7-812be70fc112", "weedhack.to distribution");
    }

    // ── Known config field mappings (extended at runtime from field_map.properties) ──
    static final Map<String, String> FIELD_MAP = new LinkedHashMap<>();
    static {
        // AdamRat v1 field names
        FIELD_MAP.put("q9p0r1", "userWebhook (Discord C2 exfil webhook)");
        FIELD_MAP.put("q9w8e7", "userId (attacker Discord snowflake ID)");
        FIELD_MAP.put("r4t5y6", "payloadUrl (primary payload download)");
        FIELD_MAP.put("u7i8o9", "alwaysUrl (always-execute URL)");
        FIELD_MAP.put("p0o9i8", "downloadUrl (secondary payload download)");
        FIELD_MAP.put("l0k9j8", "premium (premium features flag)");
        FIELD_MAP.put("m1n2b3", "autoPay (auto-payment theft config)");
        FIELD_MAP.put("v4c5x6", "autoPay.enabled");
        FIELD_MAP.put("z7a8s9", "autoPay.maxMoney");
        FIELD_MAP.put("d1f2g3", "autoPay.maxPlaytime");
        FIELD_MAP.put("h4j5k6", "autoPay.targetUsername");
    }

    // ─────────────────────────────────────────────────────────────────────
    // MAIN
    // ─────────────────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("Usage:");
            System.out.println("  java JarAnalyzer <file.jar|file.zip>");
            System.out.println("  java JarAnalyzer --batch <directory>");
            System.out.println("  java JarAnalyzer --scan               (check if this PC is infected)");
            System.exit(1);
        }

        if (args[0].equals("--scan")) {
            scanForInfection();
            return;
        }

        // Load external configs
        loadConfig();
        loadCampaigns();
        loadExtraFieldMap();

        // Batch mode
        if (args[0].equals("--batch")) {
            String dir = args.length > 1 ? args[1] : ".";
            Path batchDir = Paths.get(dir);
            if (!Files.isDirectory(batchDir)) {
                throw new RuntimeException("Not a directory: " + dir);
            }
            Set<String> analyzedHashes = new LinkedHashSet<>();
            try (java.util.stream.Stream<Path> fileStream = Files.list(batchDir)) {
                fileStream.filter(p -> {
                    String n = p.getFileName().toString().toLowerCase();
                    if (n.endsWith(".jar") || n.endsWith(".jar.zip") || n.endsWith(".zip")) return true;
                    // Also accept files without extension if they are ZIP/JAR archives
                    if (!n.contains(".") || Files.isDirectory(p)) return false;
                    try (InputStream is = Files.newInputStream(p)) {
                        byte[] magic = new byte[4];
                        return is.read(magic) == 4 && magic[0] == 0x50 && magic[1] == 0x4B && magic[2] == 0x03 && magic[3] == 0x04;
                    } catch (Exception e) { return false; }
                })
                .sorted()
                .forEach(p -> {
                    // Dedup: skip files with identical SHA-256
                    try {
                        String sha = sha256(p.toString());
                        if (!analyzedHashes.add(sha)) {
                            System.out.println("\n" + YELLOW + "  SKIP: " + p.getFileName() + " (duplicate SHA-256 of already-analyzed file)" + RESET);
                            return;
                        }
                    } catch (Exception ignored) {}
                    System.out.println("\n" + BOLD + CYAN + "═".repeat(60) + RESET);
                    System.out.println(BOLD + " Analyzing: " + p.getFileName() + RESET);
                    System.out.println(BOLD + CYAN + "═".repeat(60) + RESET);
                    try { analyzeJar(p.toString()); }
                    catch (Exception e) { System.err.println("ERROR on " + p + ": " + e.getMessage()); }
                });
            }
            return;
        }

        // Single file
        analyzeJar(args[args.length - 1]);
    }

    // ─────────────────────────────────────────────────────────────────────
    // LOCAL INFECTION SCANNER
    // ─────────────────────────────────────────────────────────────────────

    static void scanForInfection() {
        System.out.println(BOLD + CYAN + "═══════════════════════════════════════════════════════" + RESET);
        System.out.println(BOLD + "  LOCAL INFECTION SCANNER" + RESET);
        System.out.println(BOLD + CYAN + "═══════════════════════════════════════════════════════" + RESET);
        System.out.println();

        String appdata = System.getenv("APPDATA");
        if (appdata == null) appdata = "";
        String localAppdata = System.getenv("LOCALAPPDATA");
        if (localAppdata == null) localAppdata = "";
        String userHome = System.getProperty("user.home");
        if (userHome == null) userHome = "";
        String os = System.getProperty("os.name", "").toLowerCase();
        boolean isWindows = os.contains("win");

        int found = 0;
        int checked = 0;

        // ── FRACTUREISER indicators ──────────────────────────────
        System.out.println(BOLD + "── Checking for Fractureiser ──" + RESET);

        // .ref marker file
        String[][] fracPaths = {
            {appdata + "/.ref", "Fractureiser Stage 2 marker (.ref)"},
            {userHome + "/.ref", "Fractureiser Stage 2 marker (.ref in home)"},
            {appdata + "/.minecraft/lib.dll", "Fractureiser native payload (lib.dll)"},
            {appdata + "/.minecraft/libWebGL64.jar", "Fractureiser Stage 2 loader"},
            {appdata + "/.minecraft/client.jar", "Fractureiser Stage 3 payload"},
            {localAppdata + "/Microsoft Edge/libWebGL64.jar", "Fractureiser disguised as Edge component"},
            {localAppdata + "/Microsoft Edge/.ref", "Fractureiser marker in Edge directory"},
            {localAppdata + "/Microsoft Edge/lib.dll", "Fractureiser native payload in Edge directory"},
            // Linux paths
            {userHome + "/.config/.data/lib.jar", "Fractureiser Linux payload"},
        };
        for (String[] p : fracPaths) {
            checked++;
            if (p[0] != null && Files.exists(Paths.get(p[0]))) {
                System.out.println(RED + BOLD + "  [INFECTED] " + p[1] + RESET);
                System.out.println(RED + "             " + p[0] + RESET);
                found++;
            } else {
                System.out.println(GREEN + "  [CLEAN] " + p[1] + RESET);
            }
        }

        // Fractureiser Java system properties
        checked++;
        String neko = System.getProperty("neko.run");
        if (neko != null) {
            System.out.println(RED + BOLD + "  [INFECTED] neko.run system property set: " + neko + RESET);
            found++;
        } else {
            System.out.println(GREEN + "  [CLEAN] neko.run system property not set" + RESET);
        }

        // Fractureiser Windows Run key persistence
        if (isWindows) {
            checked++;
            try {
                Process proc = new ProcessBuilder("reg", "query",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/s")
                    .redirectErrorStream(true).start();
                String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                boolean done = proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                proc.destroyForcibly();
                if (done && (output.contains("libWebGL64") || output.contains("lib.dll")
                    || output.contains("microsoft-vm-core"))) {
                    System.out.println(RED + BOLD + "  [INFECTED] Malware persistence in Windows Run registry key" + RESET);
                    found++;
                } else {
                    System.out.println(GREEN + "  [CLEAN] No malware in Windows Run registry" + RESET);
                }
            } catch (Exception e) {
                System.out.println(YELLOW + "  [SKIP] Could not check Run key: " + e.getMessage() + RESET);
            }
        }

        // Fractureiser Linux systemd service
        if (!isWindows) {
            checked++;
            if (Files.exists(Paths.get("/etc/systemd/system/systemd-utility.service"))) {
                System.out.println(RED + BOLD + "  [INFECTED] Fractureiser systemd service found" + RESET);
                found++;
            } else {
                System.out.println(GREEN + "  [CLEAN] No Fractureiser systemd service" + RESET);
            }
        }

        // ── SKYRAGE indicators ───────────────────────────────────
        System.out.println();
        System.out.println(BOLD + "── Checking for SkyRage ──" + RESET);

        String[][] skyPaths = {
            {appdata + "/Microsoft/DOMStore/microsoft-vm-core", "SkyRage persistence payload"},
            {appdata + "/Microsoft/DOMStore/discord_rpc.dll", "SkyRage Discord token stealer DLL"},
            {userHome + "/../LocalLow/Microsoft/Internet Explorer/DOMStore/microsoft-vm-core", "SkyRage DOMStore payload"},
            // Linux paths
            {"/bin/vmd-gnu", "SkyRage Linux binary"},
            {"/etc/systemd/system/vmd-gnu.service", "SkyRage Linux systemd service"},
        };
        for (String[] p : skyPaths) {
            checked++;
            if (p[0] != null && Files.exists(Paths.get(p[0]))) {
                System.out.println(RED + BOLD + "  [INFECTED] " + p[1] + RESET);
                System.out.println(RED + "             " + p[0] + RESET);
                found++;
            } else {
                System.out.println(GREEN + "  [CLEAN] " + p[1] + RESET);
            }
        }

        // Check for SkyRage scheduled task (Windows only)
        if (isWindows) {
            checked++;
            try {
                Process proc = new ProcessBuilder("schtasks", "/query", "/TN", "MicrosoftEdgeUpdateTaskMachineVM")
                    .redirectErrorStream(true).start();
                String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                boolean done = proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (done && proc.exitValue() == 0 && output.contains("MicrosoftEdgeUpdateTaskMachineVM")) {
                    System.out.println(RED + BOLD + "  [INFECTED] SkyRage scheduled task found: MicrosoftEdgeUpdateTaskMachineVM" + RESET);
                    found++;
                } else {
                    System.out.println(GREEN + "  [CLEAN] No SkyRage scheduled task" + RESET);
                }
                proc.destroyForcibly();
            } catch (Exception e) {
                System.out.println(YELLOW + "  [SKIP] Could not check scheduled tasks: " + e.getMessage() + RESET);
            }
        }

        // ── ADAMRAT indicators ───────────────────────────────────
        System.out.println();
        System.out.println(BOLD + "── Checking for AdamRat ──" + RESET);

        // AdamRat typically drops to .minecraft or temp
        String mcDir = appdata + "/.minecraft";
        checked++;
        // Check for suspicious JARs in mods folder with obfuscated class names
        Path modsDir = Paths.get(mcDir, "mods");
        int suspiciousMods = 0;
        if (Files.isDirectory(modsDir)) {
            try (var mods = Files.list(modsDir)) {
                var modList = mods.filter(p -> p.toString().endsWith(".jar")).toList();
                for (Path mod : modList) {
                    try (ZipFile zf = new ZipFile(mod.toString())) {
                        boolean hasExample = false, hasObf = false;
                        var entries = zf.entries();
                        while (entries.hasMoreElements()) {
                            String name = entries.nextElement().getName();
                            if (name.contains("ExampleModClient")) hasExample = true;
                            if (name.contains("vubsyodfkejzllnk") || name.contains("upokyqklsolkxbys")
                                || name.contains("pynvtoxahbmzany")) hasObf = true;
                        }
                        if (hasExample && hasObf) {
                            System.out.println(RED + BOLD + "  [INFECTED] AdamRat mod found: " + mod.getFileName() + RESET);
                            found++;
                            suspiciousMods++;
                        }
                    } catch (Exception ignored) {}
                }
            } catch (Exception ignored) {}
            if (suspiciousMods == 0) {
                System.out.println(GREEN + "  [CLEAN] No AdamRat mods in " + modsDir + RESET);
            }
        } else {
            System.out.println(YELLOW + "  [SKIP] Mods directory not found: " + modsDir + RESET);
        }

        // ── GENERIC MALWARE indicators ───────────────────────────
        System.out.println();
        System.out.println(BOLD + "── Checking for generic Minecraft malware ──" + RESET);

        // Check Minecraft launcher_accounts.json for unauthorized access
        checked++;
        Path launcherAccounts = Paths.get(mcDir, "launcher_accounts.json");
        if (Files.exists(launcherAccounts)) {
            System.out.println(GREEN + "  [INFO] launcher_accounts.json exists — verify your accounts are not compromised" + RESET);
        }

        // Check common persistence locations
        if (isWindows) {
            // Check Startup folder
            String startupDir = appdata + "/Microsoft/Windows/Start Menu/Programs/Startup";
            checked++;
            try (var startupFiles = Files.list(Paths.get(startupDir))) {
                var suspicious = startupFiles.filter(p -> {
                    String name = p.getFileName().toString().toLowerCase();
                    return name.endsWith(".jar") || name.endsWith(".vbs") || name.endsWith(".bat")
                        || name.endsWith(".hta") || name.endsWith(".ps1");
                }).toList();
                if (!suspicious.isEmpty()) {
                    for (Path s : suspicious) {
                        System.out.println(YELLOW + "  [WARNING] Suspicious startup item: " + s.getFileName() + RESET);
                    }
                } else {
                    System.out.println(GREEN + "  [CLEAN] No suspicious items in Startup folder" + RESET);
                }
            } catch (Exception ignored) {
                System.out.println(GREEN + "  [CLEAN] Startup folder check passed" + RESET);
            }

            // Check for suspicious Java Preferences registry (used by some RATs)
            checked++;
            try {
                Process proc = new ProcessBuilder("reg", "query",
                    "HKCU\\Software\\JavaSoft\\Prefs", "/s")
                    .redirectErrorStream(true).start();
                String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                boolean done = proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                proc.destroyForcibly();
                if (done && (output.contains("neko") || output.contains("skyrage") || output.contains("adamrat"))) {
                    System.out.println(RED + BOLD + "  [INFECTED] Malware-related Java Preferences found in registry" + RESET);
                    found++;
                } else {
                    System.out.println(GREEN + "  [CLEAN] Java Preferences registry clean" + RESET);
                }
            } catch (Exception e) {
                System.out.println(YELLOW + "  [SKIP] Could not check registry: " + e.getMessage() + RESET);
            }
        }

        // ── 2PACKETS / XYNIS indicators ──────────────────────────
        System.out.println();
        System.out.println(BOLD + "── Checking for 2Packets/xynis ──" + RESET);
        checked++;
        Path xynisAccounts = Paths.get(mcDir, "accXynisMap.ser");
        if (Files.exists(xynisAccounts)) {
            System.out.println(RED + BOLD + "  [INFECTED] 2Packets/xynis account storage found: " + xynisAccounts + RESET);
            found++;
        } else {
            System.out.println(GREEN + "  [CLEAN] No 2Packets/xynis account file" + RESET);
        }

        // Check for xynis version profile
        checked++;
        Path versionsDir = Paths.get(mcDir, "versions/xynis");
        if (Files.isDirectory(versionsDir)) {
            System.out.println(RED + BOLD + "  [INFECTED] xynis version profile found: " + versionsDir + RESET);
            found++;
        } else {
            System.out.println(GREEN + "  [CLEAN] No xynis version profile" + RESET);
        }

        // ── VAPE CURIUM indicators ───────────────────────────────
        System.out.println();
        System.out.println(BOLD + "── Checking for Vape Curium ──" + RESET);

        // Curium spreads to all launcher mod folders
        String[][] curiumPaths = {
            {userHome + "/curseforge/minecraft/instances", "CurseForge instances"},
            {appdata + "/PrismLauncher/instances", "PrismLauncher instances"},
            {appdata + "/com.modrinth.theseus/profiles", "Modrinth profiles"},
            {mcDir + "/mods", ".minecraft/mods"},
        };
        for (String[] cp : curiumPaths) {
            checked++;
            Path dir = Paths.get(cp[0]);
            if (Files.isDirectory(dir)) {
                try (var files = Files.walk(dir, 3)) {
                    var suspJars = files.filter(p -> p.toString().endsWith(".jar"))
                        .filter(p -> {
                            try (ZipFile zf = new ZipFile(p.toString())) {
                                return zf.getEntry("com/curium") != null
                                    || zf.getEntry("curium.cfg") != null;
                            } catch (Exception e) { return false; }
                        }).toList();
                    if (!suspJars.isEmpty()) {
                        for (Path sj : suspJars) {
                            System.out.println(RED + BOLD + "  [INFECTED] Curium malware in " + cp[1] + ": " + sj.getFileName() + RESET);
                            found++;
                        }
                    } else {
                        System.out.println(GREEN + "  [CLEAN] " + cp[1] + RESET);
                    }
                } catch (Exception ignored) {
                    System.out.println(GREEN + "  [CLEAN] " + cp[1] + RESET);
                }
            } else {
                System.out.println(YELLOW + "  [SKIP] " + cp[1] + " not found" + RESET);
            }
        }

        // ── SUMMARY ──────────────────────────────────────────────
        System.out.println();
        System.out.println(BOLD + CYAN + "═══════════════════════════════════════════════════════" + RESET);
        if (found == 0) {
            System.out.println(BOLD + GREEN + "  RESULT: NO INFECTIONS DETECTED" + RESET);
            System.out.println(GREEN + "  Checked " + checked + " indicators — all clean." + RESET);
        } else {
            System.out.println(BOLD + RED + "  RESULT: " + found + " INFECTION INDICATOR(S) FOUND" + RESET);
            System.out.println(RED + "  Checked " + checked + " indicators." + RESET);
            System.out.println();
            System.out.println(YELLOW + "  Recommended actions:" + RESET);
            System.out.println(YELLOW + "  1. Change all passwords (Discord, Minecraft, email, etc.)" + RESET);
            System.out.println(YELLOW + "  2. Enable 2FA on all accounts" + RESET);
            System.out.println(YELLOW + "  3. Revoke Discord tokens (change password)" + RESET);
            System.out.println(YELLOW + "  4. Delete infected files listed above" + RESET);
            System.out.println(YELLOW + "  5. Run a full antivirus scan" + RESET);
            System.out.println(YELLOW + "  6. Check Task Scheduler for unknown tasks" + RESET);
        }
        System.out.println(BOLD + CYAN + "═══════════════════════════════════════════════════════" + RESET);
    }

    // ─────────────────────────────────────────────────────────────────────
    // CORE ANALYSIS ENTRY POINT
    // ─────────────────────────────────────────────────────────────────────

    static void analyzeJar(String jarPath) throws Exception {
        // Reset ALL static state to prevent cross-contamination in batch mode
        markerDetails.clear();
        cpUrlsCollected.clear();
        cpDomainsCollected.clear();
        detectedModLoaders.clear();
        infoLog = null;
        configLog = null;
        cachedBlocklist = null;
        jarName = Paths.get(jarPath).getFileName().toString()
            .replaceAll("\\.(jar|zip)(\\.zip)?$", "")
            .replaceAll("[^a-zA-Z0-9_\\-]", "_");
        if (jarName.isEmpty()) jarName = "unnamed";
        // Create a dedicated output folder named after the JAR inside logs/
        outDir = Paths.get("logs", jarName);
        Files.createDirectories(outDir);
        infoLog   = new PrintWriter(new BufferedWriter(new FileWriter(out(jarName + "_info.log").toFile())),   true);
        configLog = new PrintWriter(new BufferedWriter(new FileWriter(out(jarName + "_config.log").toFile())), true);

        String cfrPath  = findCFR();
        String ts       = java.time.Instant.now().toString();
        String jarSha256 = sha256(jarPath);
        String jarMd5    = hash(jarPath, "MD5");
        String jarSha1   = hash(jarPath, "SHA-1");
        long   jarSize   = Files.size(Paths.get(jarPath));

        // Locate all available decompilers
        String vineflowerPath = findDecompiler("vineflower.jar");
        String jadxPath = findDecompiler("jadx");
        String procyonPath = findDecompiler("procyon-decompiler.jar");
        String decompilerUsed = "none";

        banner();
        ilog("Jar Config Extractor — " + ts);
        ilog("Target JAR : " + jarPath);
        ilog("SHA-256    : " + jarSha256);
        ilog("SHA-1      : " + jarSha1);
        ilog("MD5        : " + jarMd5);
        ilog("Size       : " + String.format("%,d", jarSize) + " bytes");
        ilog("Decompilers: CFR=" + cfrPath + " Vineflower=" + vineflowerPath
            + (jadxPath != null ? " JADX=" + jadxPath : "")
            + (procyonPath != null ? " Procyon=" + procyonPath : ""));
        ilog("");
        ok("SHA-256: " + jarSha256);

        // ── Step 1: Extract class bytes ──────────────────────────────
        step("Extracting class bytes from JAR...");
        Path tempDir = Files.createTempDirectory("jar_analysis_");
        Path cleanJar = null;
        try {
        Map<String, byte[]> classes = extractClasses(jarPath, tempDir);
        ok("Extracted " + classes.size() + " class file(s)");

        // Check for trailing "/" trick entries
        boolean hasTrailingSlashEntries = false;
        try (ZipFile zf = new ZipFile(jarPath)) {
            var en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.getName().endsWith(".class/") && e.getSize() > 0) {
                    hasTrailingSlashEntries = true;
                    break;
                }
            }
        } catch (Exception ignored) {}

        // ── Step 2: Padding detection ────────────────────────────────
        PaddingInfo padding = detectPadding(jarPath);
        if (padding != null) {
            warn("Padding detected: " + padding.entryName
                + " (" + String.format("%,d", padding.paddingBytes) + " bytes junk) "
                + "— real payload ~" + String.format("%,d", jarSize - padding.paddingBytes) + " bytes");
            ilog("  [PADDING] " + padding.entryName + " (" + padding.paddingBytes + " bytes, "
                + padding.method + ")");
        }

        // ── Step 2b: JAR metadata extraction ─────────────────────────
        step("Extracting JAR metadata...");
        extractJarMetadata(jarPath, classes);

        // ── Step 3: Classify variant ─────────────────────────────────
        step("Classifying variant...");
        Variant variant = classifyVariant(classes, jarPath);
        ok("Variant: " + variant);

        // Additional sub-type flags
        boolean hasCasinoClasses = detectCasinoClasses(classes);
        if (hasCasinoClasses) warn("Casino cheat classes detected (net.aseity.optimization.rig)");

        // ── Step 4: Find encrypted config ────────────────────────────
        step("Scanning JAR for encrypted config file...");
        String[] configEntry = findConfigFile(jarPath);
        String configRaw = configEntry != null ? configEntry[1] : null;
        if (configRaw != null) {
            String fmt = configEntry.length > 2 ? configEntry[2] : "hex";
            ok("Found config file: " + configEntry[0] + " (" + configRaw.length() + " chars) [format: " + fmt + "]");
        } else {
            warn("No config file found — will still decompile");
        }

        // ── Step 5: Full decompilation to source/ ────────────────────
        Path sourceDir = outDir.resolve("source");
        Files.createDirectories(sourceDir);

        // Build a stripped JAR with only non-library classes for faster decompilation
        step("Building stripped JAR (excluding library classes)...");
        cleanJar = buildStrippedJar(jarPath, tempDir, hasTrailingSlashEntries);
        String decompileTarget = cleanJar.toString();
        long strippedClasses = 0;
        try (ZipFile szf = new ZipFile(cleanJar.toFile())) {
            strippedClasses = szf.stream().filter(e -> e.getName().endsWith(".class")).count();
        } catch (Exception ignored) {}
        ok("Stripped JAR: " + strippedClasses + " class(es) to decompile (library classes excluded)");

        step("Decompiling full JAR to source/...");
        decompilerUsed = decompileFullJar(decompileTarget, sourceDir, vineflowerPath, jadxPath, procyonPath, cfrPath, strippedClasses);
        ok("Full decompilation complete (used: " + decompilerUsed + ")");

        // Also build the in-memory source string + per-file map for pattern matching
        final long MAX_SOURCE_CHARS = 100_000_000L; // 100MB cap
        StringBuilder decompiled = new StringBuilder();
        Map<String, String> sourceFiles = new LinkedHashMap<>(); // relative path → content
        try (var walker = Files.walk(sourceDir)) {
            walker.filter(p -> p.toString().endsWith(".java"))
                .forEach(p -> {
                    try {
                        if (decompiled.length() < MAX_SOURCE_CHARS) {
                            String content = Files.readString(p);
                            decompiled.append(content).append("\n");
                            String relPath = sourceDir.relativize(p).toString().replace('\\', '/');
                            sourceFiles.put(relPath, content);
                        }
                    }
                    catch (Exception ignored) {}
                });
        } catch (Exception ignored) {}

        // Fallback: if source/ is empty, decompile in-memory with CFR
        if (decompiled.length() == 0 && cfrPath != null) {
            warn("Source dir empty, falling back to in-memory CFR decompilation");
            for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                if (isLibraryClass(e.getKey())) continue;
                try {
                    Path classFile = tempDir.resolve(e.getKey());
                    Files.createDirectories(classFile.getParent());
                    Files.write(classFile, e.getValue());
                    String cfrSrc = runCFR(cfrPath, classFile.toString());
                    decompiled.append(cfrSrc).append("\n");
                    sourceFiles.put(e.getKey().replace(".class", ".java"), cfrSrc);
                } catch (Exception cfrEx) {
                    warn("  CFR in-memory failed for " + e.getKey() + ": " + cfrEx.getMessage());
                }
            }
        } else if (decompiled.length() == 0) {
            warn("Source dir empty and no CFR available — analysis will rely on bytecode markers only");
        }
        String src = decompiled.toString();

        // ── Step 6: Behavioral markers ───────────────────────────────
        step("Scanning for behavioral markers...");
        markerDetails.clear();
        List<String> markers = detectBehavioralMarkers(src, classes, jarPath, sourceFiles);
        if (markers.isEmpty()) ok("No behavioral markers detected");
        else {
            ok("Detected " + markers.size() + " behavioral marker(s):");
            for (String m : markers) warn("  " + m);
        }

        // ── Encryption complexity scoring ──
        // Count distinct encryption schemes found in markers
        int encSchemeCount = 0;
        for (String m : markers) {
            String ml = m.toLowerCase();
            if (ml.contains("xor") || ml.contains("byte[] string") || ml.contains("byte array string")) encSchemeCount++;
            else if (ml.contains("aes") || ml.contains("crypto api")) encSchemeCount++;
            else if (ml.contains("base64 encoded")) encSchemeCount++;
            else if (ml.contains("char array string construction")) encSchemeCount++;
        }
        if (encSchemeCount > 1) {
            String encMsg = "Multiple encryption schemes detected (" + encSchemeCount + " schemes)";
            if (!markers.contains(encMsg)) {
                markers.add(encMsg);
                warn("  " + encMsg);
            }
        }

        // ── MANIFEST agent markers → behavioral markers ──
        // Re-read MANIFEST to add Premain-Class/Agent-Class as behavioral markers
        try (ZipFile mfZf = new ZipFile(jarPath)) {
            ZipEntry mfEntry = mfZf.getEntry("META-INF/MANIFEST.MF");
            if (mfEntry != null) {
                try (InputStream mfIs = mfZf.getInputStream(mfEntry)) {
                    java.util.jar.Manifest mf = new java.util.jar.Manifest(mfIs);
                    String premain = mf.getMainAttributes().getValue("Premain-Class");
                    String agent = mf.getMainAttributes().getValue("Agent-Class");
                    if (premain != null) {
                        String m = "Java agent: Premain-Class found (" + premain + ")";
                        if (!markers.contains(m)) markers.add(m);
                    }
                    if (agent != null) {
                        String m = "Java agent: Agent-Class found (" + agent + ")";
                        if (!markers.contains(m)) markers.add(m);
                    }
                }
            }
        } catch (Exception ignored) {}

        // ── JNIC blob marker ──
        try (ZipFile jnicZf = new ZipFile(jarPath)) {
            var jnicEntries = jnicZf.entries();
            while (jnicEntries.hasMoreElements()) {
                ZipEntry e = jnicEntries.nextElement();
                String name = e.getName().toLowerCase();
                if (e.isDirectory() || e.getSize() <= 0) continue;
                if (name.endsWith(".bin") || name.endsWith(".dat")) {
                    try (InputStream is = jnicZf.getInputStream(e)) {
                        byte[] header = new byte[(int)Math.min(e.getSize(), 64)];
                        int rd = is.read(header);
                        if (rd >= 4) {
                            String headerStr = new String(header, 0, rd, StandardCharsets.US_ASCII);
                            boolean hasJnic = headerStr.contains("JNIC");
                            boolean hasCafeBabe = false;
                            for (int off = 4; off < rd - 3; off++) {
                                if ((header[off] & 0xFF) == 0xCA && (header[off+1] & 0xFF) == 0xFE
                                    && (header[off+2] & 0xFF) == 0xBA && (header[off+3] & 0xFF) == 0xBE) {
                                    hasCafeBabe = true;
                                    break;
                                }
                            }
                            if (hasJnic || hasCafeBabe) {
                                String m = "JNIC native obfuscation blob detected (" + e.getSize() + " bytes)";
                                if (!markers.contains(m)) markers.add(m);
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}

        // ── ServiceLoader exploitation marker ──
        try (ZipFile slZf = new ZipFile(jarPath)) {
            var slEntries = slZf.entries();
            while (slEntries.hasMoreElements()) {
                ZipEntry e = slEntries.nextElement();
                if (e.getName().startsWith("META-INF/services/") && !e.isDirectory()) {
                    String m = "META-INF/services/ entries found (potential ServiceLoader exploitation)";
                    if (!markers.contains(m)) markers.add(m);
                    break;
                }
            }
        } catch (Exception ignored) {}

        // ── Constant pool URLs/domains into markers ──
        if (!cpUrlsCollected.isEmpty()) {
            for (String url : cpUrlsCollected) {
                String m = "Constant pool URL: " + url;
                if (!markers.contains(m)) markers.add(m);
            }
        }

        // Check for decompilation failures — indicates advanced obfuscation
        long failedDecompiles = countFailedDecompiles(sourceDir);
        long totalJavaFiles = countJavaFiles(sourceDir);
        if (failedDecompiles > 0 && totalJavaFiles > 0) {
            int failPct = (int)(failedDecompiles * 100 / totalJavaFiles);
            String failMsg = "Decompilation failure: " + failedDecompiles + "/" + totalJavaFiles
                + " files (" + failPct + "%) — indicates advanced obfuscation";
            markers.add(failMsg);
            warn("  " + failMsg);
        }

        // ── Dispatch to variant-specific analyzer ────────────────────
        // Wrapped in try/catch so a crash in any variant analyzer still produces IOCs JSON
        try {
        switch (variant) {
            case WEEDHACK:
                analyzeDropper(jarPath, jarSha256, src, classes, markers, ts, hasCasinoClasses);
                break;
            case SESSION_HARVESTER:
                analyzeSessionHarvester(jarPath, jarSha256, src, classes, markers, ts);
                break;
            case ADAMRAT:
                analyzeAdamRat(jarPath, jarSha256, src, classes, markers, ts, configEntry, configRaw, cfrPath, tempDir);
                break;
            case VAPE_CURIUM:
                analyzeVapeCurium(jarPath, jarSha256, src, classes, markers, ts, sourceDir);
                break;
            case SILENT_NET:
                analyzeSilentNet(jarPath, jarSha256, src, classes, markers, ts, sourceDir);
                break;
            case MSHTA_DROPPER:
                analyzeMshtaDropper(jarPath, jarSha256, src, classes, markers, ts);
                break;
            case FRACTUREISER:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "FRACTUREISER",
                    "Multi-stage Minecraft mod infector. Uses URLClassLoader to download stages from C2 IPs. " +
                    "Known C2: 85.217.144.130, 107.189.3.101. Creates .ref marker in APPDATA. " +
                    "Stage 2 downloads lib.jar/libWebGL64.jar. Stage 3 (dev.neko) steals browser creds, " +
                    "Discord tokens, crypto wallets, and Minecraft credentials.");
                break;
            case SKYRAGE:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "SKYRAGE",
                    "SkyRage token stealer variant. C2: connect.skyrage.de. " +
                    "Creates scheduled task 'MicrosoftEdgeUpdateTaskMachineVM' and service 'vmd-gnu' for persistence. " +
                    "Drops discord_rpc.dll for token theft. Steals Discord, browser, and Minecraft credentials.");
                break;
            case WEIRDUTILS:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "WEIRDUTILS",
                    "WeirdUtils backdoor. Uses AES/CBC encrypted payloads with Base64-encoded LDC instructions. " +
                    "Masquerades under org.spongepowered.tools.obfuscation package. Fetches config from " +
                    "Pastebin (Base64 LDC: aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3LzRMaG5EQ3Rm). " +
                    "Exfiltrates data to owouwu.tk. Uses custom ClassLoader obfuscation.");
                break;
            case COMET:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "COMET",
                    "Comet backdoor for Bukkit/Spigot servers. Registers '*auth' chat command with default " +
                    "password MD5 81dc9bdb52d04dc20036dbd8313ed055 ('test'). C2 hosted on Replit. " +
                    "Allows remote command execution, OP escalation, and plugin management.");
                break;
            case ECTASY:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "ECTASY",
                    "Ectasy backdoor. Uses '*' command prefix. Downloads 'bungee.jar' to plugins/PluginMetrics/. " +
                    "C2: ectasy.club. Features TranslatableComponentDeserializer class for obfuscation. " +
                    "Provides remote shell, file manager, and server takeover capabilities.");
                break;
            case SERVER_CRASHER:
                analyzeServerCrasher(jarPath, jarSha256, src, classes, markers, ts);
                break;
            case MCLAUNCHER_LOADER:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "MCLAUNCHER_LOADER",
                    "MCLauncher Loader — malicious mod loader using me/mclauncher package. " +
                    "IMCL class uses ClassLoader.defineClass for runtime code injection. " +
                    "MEntrypoint uses ProcessBuilder for command execution. " +
                    "StagingHelper uses reflective invocation + System.load for native code loading. " +
                    "LoaderClient orchestrates the payload delivery. Often bundled with legitimate mods " +
                    "(Meteor Client, AppleSkin, NoChatReports, Glazed, etc.) as a trojanized wrapper.");
                break;
            case PACKUTIL_RAT:
                analyzeGenericMalware(jarPath, jarSha256, src, classes, markers, ts, "PACKUTIL_RAT",
                    "PackUtil RAT — trojanized Minecraft mod using com.example.addon package with PackUtil* utility classes. " +
                    "Capabilities: Minecraft session theft (getUuidOrNull/getAccessToken), screen capture, " +
                    "Runtime.exec() command execution, sun.misc.Unsafe memory manipulation, " +
                    "dynamic class loading via Class.forName, reflective method invocation, and native library loading. " +
                    "Disguised as a legitimate Fabric mod addon (e.g. 'YungLightUI'). " +
                    "Uses control-flow obfuscation and braille art ASCII arrays as padding.");
                break;
            default:
                analyzeUnknown(jarPath, jarSha256, src, classes, markers, ts, configEntry, configRaw, cfrPath, tempDir);
                break;
        }
        } catch (Exception variantEx) {
            // Variant analyzer crashed — still produce IOCs so the scan isn't lost
            warn("Variant analyzer (" + variant + ") crashed: " + variantEx.getMessage());
            ilog("  Stack trace: " + Arrays.toString(variantEx.getStackTrace()).substring(0, Math.min(500, Arrays.toString(variantEx.getStackTrace()).length())));
            try {
                // Export whatever we have as generic IOCs
                exportGenericIocsJson(jarPath, jarSha256, variant.name().toLowerCase() + "_crashed",
                    markers, new ArrayList<>(), new LinkedHashMap<>());
                warn("Exported partial IOCs despite crash");
            } catch (Exception iocsEx) {
                warn("Failed to export fallback IOCs: " + iocsEx.getMessage());
            }
        }

        // ── Step 7: Create main/ and main/important/ ─────────────────
        step("Creating main/ and main/important/ directories...");
        Path mainDir = outDir.resolve("main");
        Path importantDir = mainDir.resolve("important");
        Files.createDirectories(importantDir);
        copyMainFiles(sourceDir, mainDir, importantDir, variant, classes, src);
        ok("Main files copied");

        // ── Step 8: Write analysis.txt ───────────────────────────────
        step("Writing analysis.txt...");
        writeAnalysisTxt(outDir, jarPath, jarSha256, variant, markers, decompilerUsed, src, configRaw, hasTrailingSlashEntries);
        ok("Analysis report written");

        System.out.println();
        System.out.println(BOLD + GREEN + "Output folder: " + outDir.toAbsolutePath() + RESET);
        System.out.println(BOLD + GREEN + "  " + jarName + "_info.log" + RESET);
        System.out.println(BOLD + GREEN + "  " + jarName + "_config.log" + RESET);
        System.out.println(BOLD + GREEN + "  " + jarName + "_iocs.json" + RESET);
        System.out.println(BOLD + GREEN + "  source/ (full decompiled source)" + RESET);
        System.out.println(BOLD + GREEN + "  main/ (main application source)" + RESET);
        System.out.println(BOLD + GREEN + "  main/important/ (C2/config code)" + RESET);
        System.out.println(BOLD + GREEN + "  " + jarName + "_analysis.txt" + RESET);
        } finally {
            closeLogs();
            if (cleanJar != null) try { Files.deleteIfExists(cleanJar); } catch (Exception ignored) {}
            cleanUp(tempDir);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // VARIANT CLASSIFICATION
    // ─────────────────────────────────────────────────────────────────────

    static Variant classifyVariant(Map<String, byte[]> classes, String jarPath) {
        Set<String> names = classes.keySet();
        String namesJoined = String.join("|", names).toLowerCase();

        // Weedhack dropper — FabricAdapter + Helper + Ethernet C2
        // (checked BEFORE session harvester because both match on dev/majanito)
        String[] dropperClasses = cfgArr("weedhack.dropper.classes");
        String[] dropperHelpers = cfgArr("weedhack.dropper.helpers");
        boolean hasFabricAdapter = names.stream().anyMatch(n ->
            Arrays.stream(dropperClasses).anyMatch(h -> !h.isEmpty() && n.contains(h)));
        boolean hasHelper = names.stream().anyMatch(n ->
            Arrays.stream(dropperHelpers).anyMatch(h -> !h.isEmpty() && n.endsWith(h)));
        boolean hasFabricApi = false;
        String zipEntry = cfg("weedhack.dropper.zipentry");
        try (ZipFile zf = new ZipFile(jarPath)) {
            hasFabricApi = !zipEntry.isEmpty() && zf.getEntry(zipEntry) != null;
        } catch (Exception ignored) {}

        if (hasFabricAdapter || (hasHelper && hasFabricApi)) {
            ilog("  → Weedhack dropper: FabricAdapter=" + hasFabricAdapter + ", " + zipEntry + "=" + hasFabricApi);
            return Variant.WEEDHACK;
        }

        // Session harvester — MUST match package first, then class names confirm
        boolean hasHarvesterPackage = false;
        for (String pkg : cfgArr("session.harvester.packages")) {
            if (!pkg.isEmpty() && namesJoined.contains(pkg.toLowerCase())) {
                hasHarvesterPackage = true;
                ilog("  → Session harvester: package fragment '" + pkg + "' detected");
                break;
            }
        }
        if (hasHarvesterPackage) {
            // Only check class name fragments if the package was found
            for (String cls : cfgArr("session.harvester.classes")) {
                for (String n : names) {
                    if (!cls.isEmpty() && n.contains(cls)) {
                        ilog("  → Session harvester: class '" + n + "' matched hint '" + cls + "' (with package match)");
                        return Variant.SESSION_HARVESTER;
                    }
                }
            }
            // Package alone is enough if it's a very specific namespace
            ilog("  → Session harvester: package matched but no class hints — classifying anyway");
            return Variant.SESSION_HARVESTER;
        }

        // FRACTUREISER — dev.neko, URLClassLoader + IP, lib.jar
        for (String cls : cfgArr("fractureiser.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.toLowerCase().contains(cls.toLowerCase())) {
                    ilog("  → Fractureiser: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.FRACTUREISER;
                }
            }
        }
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("fractureiser.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → Fractureiser (raw sig '" + sig + "' in class data)");
                    return Variant.FRACTUREISER;
                }
            }
        }

        // SKYRAGE — skyrage.de, discord_rpc.dll
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("skyrage.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → SkyRage (raw sig '" + sig + "' in class data)");
                    return Variant.SKYRAGE;
                }
            }
        }

        // WEIRDUTILS — ObfuscatedClassloader, owouwu.tk, AES/CBC LDC patterns
        for (String cls : cfgArr("weirdutils.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    ilog("  → WeirdUtils: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.WEIRDUTILS;
                }
            }
        }
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("weirdutils.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → WeirdUtils (raw sig '" + sig + "' in class data)");
                    return Variant.WEIRDUTILS;
                }
            }
        }

        // COMET — *auth command, MD5 default password, Replit C2
        // Require class name match OR 2+ raw signature hits (single raw sig too generic)
        for (String cls : cfgArr("comet.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    ilog("  → Comet: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.COMET;
                }
            }
        }
        {
            int cometRawHits = 0;
            for (byte[] classData : classes.values()) {
                String ascii = new String(classData, StandardCharsets.US_ASCII);
                for (String sig : cfgArr("comet.rawstrings")) {
                    if (!sig.isEmpty() && ascii.contains(sig)) {
                        ilog("  → Comet candidate: raw sig '" + sig + "' in class data");
                        cometRawHits++;
                        break; // one hit per class
                    }
                }
            }
            if (cometRawHits >= 2) {
                ilog("  → Comet: " + cometRawHits + " raw signature hits — classifying");
                return Variant.COMET;
            }
        }

        // ECTASY — ectasy.club, bungee.jar download, TranslatableComponentDeserializer
        for (String cls : cfgArr("ectasy.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    ilog("  → Ectasy: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.ECTASY;
                }
            }
        }
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("ectasy.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → Ectasy (raw sig '" + sig + "' in class data)");
                    return Variant.ECTASY;
                }
            }
        }

        // SERVER_CRASHER — 2Packets, xynis, us.whitedev
        for (String pkg : cfgArr("server.crasher.packages")) {
            if (!pkg.isEmpty() && namesJoined.contains(pkg.toLowerCase())) {
                ilog("  → Server Crasher: package fragment '" + pkg + "' detected");
                return Variant.SERVER_CRASHER;
            }
        }
        for (String cls : cfgArr("server.crasher.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    ilog("  → Server Crasher: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.SERVER_CRASHER;
                }
            }
        }
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("server.crasher.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → Server Crasher (raw sig '" + sig + "' in class data)");
                    return Variant.SERVER_CRASHER;
                }
            }
        }

        // MCLAUNCHER_LOADER — package match is definitive; class names require 2+ hits
        boolean hasMclauncherPkg = false;
        for (String pkg : cfgArr("mclauncher.packages")) {
            if (!pkg.isEmpty() && namesJoined.contains(pkg.toLowerCase())) {
                hasMclauncherPkg = true;
                ilog("  → MCLauncher Loader: package fragment '" + pkg + "' detected");
                break;
            }
        }
        if (hasMclauncherPkg) {
            return Variant.MCLAUNCHER_LOADER;
        }
        {
            int mclauncherClassHits = 0;
            for (String cls : cfgArr("mclauncher.classes")) {
                for (String n : names) {
                    if (!cls.isEmpty() && n.contains(cls)) {
                        mclauncherClassHits++;
                        ilog("  → MCLauncher candidate: class '" + n + "' matched hint '" + cls + "'");
                        break;
                    }
                }
            }
            if (mclauncherClassHits >= 2) {
                ilog("  → MCLauncher Loader: " + mclauncherClassHits + " class hits — classifying");
                return Variant.MCLAUNCHER_LOADER;
            }
        }

        // PACKUTIL_RAT — com/example/addon + PackUtil* classes (session theft, screen capture, Unsafe)
        {
            boolean hasExampleAddon = namesJoined.contains("com/example/addon") || namesJoined.contains("com_example_addon");
            int packUtilCount = 0;
            for (String n : names) {
                if (n.contains("PackUtil")) packUtilCount++;
            }
            if (hasExampleAddon && packUtilCount >= 3) {
                ilog("  → PackUtil RAT: com/example/addon + " + packUtilCount + " PackUtil* classes");
                return Variant.PACKUTIL_RAT;
            }
        }

        // MSHTA dropper — require 2+ raw signature hits to avoid single-keyword FP
        {
            int mshtaHits = 0;
            Set<String> mshtaMatched = new LinkedHashSet<>();
            for (byte[] classData : classes.values()) {
                String ascii = new String(classData, StandardCharsets.US_ASCII).toLowerCase();
                for (String sig : cfgArr("mshta.dropper.rawstrings")) {
                    if (!sig.isEmpty() && !mshtaMatched.contains(sig) && ascii.contains(sig.toLowerCase())) {
                        mshtaMatched.add(sig);
                        mshtaHits++;
                        ilog("  → MSHTA candidate: raw sig '" + sig + "' in class data");
                    }
                }
            }
            if (mshtaHits >= 2) {
                ilog("  → MSHTA dropper: " + mshtaHits + " raw signature hits — classifying");
                return Variant.MSHTA_DROPPER;
            }
        }

        // SILENT_NET — com.libmod package or Polygon/opaque predicate markers
        for (String pkg : cfgArr("silent.net.packages")) {
            if (!pkg.isEmpty() && namesJoined.contains(pkg.toLowerCase())) {
                ilog("  → Silent NET: package fragment '" + pkg + "' detected");
                return Variant.SILENT_NET;
            }
        }
        for (String cls : cfgArr("silent.net.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    ilog("  → Silent NET: class '" + n + "' matched hint '" + cls + "'");
                    return Variant.SILENT_NET;
                }
            }
        }
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String sig : cfgArr("silent.net.rawstrings")) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → Silent NET (raw sig '" + sig + "' in class data)");
                    return Variant.SILENT_NET;
                }
            }
        }

        // VAPE_CURIUM — curium/boobility markers or specific class names
        for (String pkg : cfgArr("vape.curium.packages")) {
            if (!pkg.isEmpty() && namesJoined.contains(pkg.toLowerCase())) {
                ilog("  → Vape Curium: package fragment '" + pkg + "' detected");
                return Variant.VAPE_CURIUM;
            }
        }
        int curiumClassHits = 0;
        for (String cls : cfgArr("vape.curium.classes")) {
            for (String n : names) {
                if (!cls.isEmpty() && n.contains(cls)) {
                    curiumClassHits++;
                    ilog("  → Vape Curium candidate: class '" + n + "' matched hint '" + cls + "'");
                    break; // count each pattern once
                }
            }
        }
        if (curiumClassHits >= 2) {
            ilog("  → Vape Curium: " + curiumClassHits + " signature classes matched");
            return Variant.VAPE_CURIUM;
        }
        {
            int curiumRawHits = 0;
            Set<String> curiumRawMatched = new LinkedHashSet<>();
            for (byte[] classData : classes.values()) {
                String ascii = new String(classData, StandardCharsets.US_ASCII);
                for (String sig : cfgArr("vape.curium.rawstrings")) {
                    if (!sig.isEmpty() && !curiumRawMatched.contains(sig) && ascii.contains(sig)) {
                        curiumRawMatched.add(sig);
                        curiumRawHits++;
                        ilog("  → Vape Curium candidate: raw sig '" + sig + "' in class data");
                    }
                }
            }
            if (curiumRawHits >= 2) {
                ilog("  → Vape Curium: " + curiumRawHits + " distinct raw signature hits — classifying");
                return Variant.VAPE_CURIUM;
            }
        }

        // AdamRat — obfuscation class names (from CFG) or client+inner class combo
        String[] obfClasses   = cfgArr("adamrat.obf.classes");
        String   clientClass  = cfg("adamrat.client.class");
        String[] innerClasses = cfgArr("adamrat.inner.classes");
        boolean hasObfClass = names.stream().anyMatch(n ->
            Arrays.stream(obfClasses).anyMatch(h -> !h.isEmpty() && n.contains(h)));
        boolean hasExampleClient = !clientClass.isEmpty() &&
            names.stream().anyMatch(n -> n.contains(clientClass));
        boolean hasFakeDirClasses = names.stream().anyMatch(n ->
            Arrays.stream(innerClasses).anyMatch(h -> !h.isEmpty() && n.contains(h)));

        if (hasObfClass || (hasExampleClient && hasFakeDirClasses)) {
            ilog("  → AdamRat: obf class=" + hasObfClass + ", client=" + hasExampleClient + ", innerClasses=" + hasFakeDirClasses);
            return Variant.ADAMRAT;
        }

        // Scan raw class bytes for dropper string signatures (from CFG)
        String[] rawSigs = cfgArr("weedhack.dropper.rawstrings");
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            // Also always check for the ETH method selector from CFG
            String ethMethod = cfg("dropper.eth.method");
            if ((!ethMethod.isEmpty() && ascii.contains(ethMethod))) {
                ilog("  → Weedhack dropper (eth method " + ethMethod + " in class data)");
                return Variant.WEEDHACK;
            }
            for (String sig : rawSigs) {
                if (!sig.isEmpty() && ascii.contains(sig)) {
                    ilog("  → Weedhack dropper (raw sig '" + sig + "' in class data)");
                    return Variant.WEEDHACK;
                }
            }
        }

        ilog("  → Unknown variant — will attempt generic extraction");
        return Variant.UNKNOWN;
    }

    // ─────────────────────────────────────────────────────────────────────
    // PADDING DETECTION
    // ─────────────────────────────────────────────────────────────────────

    static class PaddingInfo {
        String entryName;
        long   paddingBytes;
        String method; // "stored" / "deflated"
        PaddingInfo(String n, long b, String m) { entryName = n; paddingBytes = b; method = m; }
    }

    static PaddingInfo detectPadding(String jarPath) {
        try (ZipFile zf = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                // Padding signatures: META-INF/padding/, META-INF/junk/, or very large non-class non-asset files
                String name = e.getName().toLowerCase();
                boolean isPaddingPath = name.startsWith("meta-inf/padding/") ||
                                        name.startsWith("meta-inf/junk/")    ||
                                        name.startsWith("padding/");
                // Also detect anonymous large binary files with random-looking names
                boolean isLargeBinary = !e.isDirectory() && e.getSize() > 1_000_000
                    && !name.endsWith(".class") && !name.endsWith(".json")
                    && !name.endsWith(".png")   && !name.endsWith(".jar")
                    && (name.matches(".*/[0-9a-f]{8,}\\..*") || isPaddingPath);

                if (isPaddingPath || isLargeBinary) {
                    String method = e.getMethod() == ZipEntry.STORED ? "stored/uncompressed" : "deflated";
                    return new PaddingInfo(e.getName(), e.getSize(), method);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // CASINO CLASS DETECTION
    // ─────────────────────────────────────────────────────────────────────

    static boolean detectCasinoClasses(Map<String, byte[]> classes) {
        String[] hints = cfgArr("casino.class.hints");
        for (String name : classes.keySet()) {
            for (String hint : hints) {
                if (!hint.isEmpty() && name.contains(hint)) return true;
            }
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────
    // BEHAVIORAL MARKER DETECTION (extended)
    // ─────────────────────────────────────────────────────────────────────

    /** Record a marker detail (file, line, context) for a given marker label. */
    static void addMarkerDetail(String label, String file, int line, String context) {
        markerDetails.computeIfAbsent(label, k -> new ArrayList<>()).add(Map.of(
            "file", file != null ? file : "unknown",
            "line", String.valueOf(line),
            "context", context != null ? context.substring(0, Math.min(120, context.length())).trim() : ""
        ));
    }

    /** Find the line number and context of a pattern in a source string. Returns {line, context} or null. */
    static int[] findLineNumber(String content, String pattern) {
        int idx = content.indexOf(pattern);
        if (idx < 0) return null;
        int line = 1;
        for (int i = 0; i < idx; i++) {
            if (content.charAt(i) == '\n') line++;
        }
        return new int[]{line, idx};
    }

    static List<String> detectBehavioralMarkers(String src, Map<String, byte[]> classes, String jarPath,
                                                  Map<String, String> sourceFiles) {
        List<String> findings = new ArrayList<>();

        // Source-level patterns — loaded from CFG (format: "pattern=label", pipe-separated)
        // Search per-file for location details
        for (String entry : cfgArr("behavioral.patterns")) {
            int eq = entry.indexOf('=');
            if (eq <= 0) continue;
            String pat   = entry.substring(0, eq);
            String label = entry.substring(eq + 1);
            if (src.contains(pat)) {
                if (!findings.contains(label)) {
                    findings.add(label);
                    ilog("  [MARKER] " + label + " (pattern: " + pat.trim() + ")");
                    // Find which file(s) contain this pattern
                    for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
                        int[] loc = findLineNumber(sf.getValue(), pat);
                        if (loc != null) {
                            String[] lines = sf.getValue().split("\n");
                            String ctx = (loc[0] - 1 < lines.length) ? lines[loc[0] - 1] : "";
                            addMarkerDetail(label, sf.getKey(), loc[0], ctx);
                        }
                    }
                }
            }
        }

        // IP address detection in source (with per-file location)
        Pattern ipSrcPat = Pattern.compile("\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?::\\d+)?\"");
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            Matcher ipSrcM = ipSrcPat.matcher(sf.getValue());
            while (ipSrcM.find()) {
                String ip = ipSrcM.group(1);
                if (!isPrivateOrInvalidIP(ip)) {
                    String m = "Hardcoded IP address: " + ip;
                    if (!findings.contains(m)) {
                        findings.add(m); ilog("  [MARKER] " + m);
                    }
                    int line = 1;
                    for (int i = 0; i < ipSrcM.start(); i++) { if (sf.getValue().charAt(i) == '\n') line++; }
                    addMarkerDetail(m, sf.getKey(), line, ipSrcM.group());
                }
            }
        }

        // Base64 encoded strings in source (with per-file location)
        Pattern b64SrcPat = Pattern.compile("\"([A-Za-z0-9+/]{40,}={0,2})\"");
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            Matcher b64SrcM = b64SrcPat.matcher(sf.getValue());
            while (b64SrcM.find()) {
                try {
                    byte[] dec = Base64.getDecoder().decode(b64SrcM.group(1));
                    String decoded = new String(dec, StandardCharsets.UTF_8);
                    if (decoded.contains("http") || decoded.contains("discord") || decoded.contains("token")) {
                        String m = "Base64 encoded suspicious string: " + decoded.substring(0, Math.min(80, decoded.length()));
                        if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
                        int line = 1;
                        for (int i = 0; i < b64SrcM.start(); i++) { if (sf.getValue().charAt(i) == '\n') line++; }
                        addMarkerDetail(m, sf.getKey(), line, "Base64: " + b64SrcM.group(1).substring(0, Math.min(40, b64SrcM.group(1).length())) + "...");
                    }
                } catch (Exception ignored) {}
            }
        }

        // Char array string construction detection
        Pattern charArrPat = Pattern.compile("new\\s+char\\[\\]\\s*\\{([^}]{10,})\\}");
        Matcher cam = charArrPat.matcher(src);
        while (cam.find()) {
            try {
                String arrContent = cam.group(1);
                StringBuilder reconstructed = new StringBuilder();
                for (String part : arrContent.split(",")) {
                    part = part.trim();
                    if (part.startsWith("'") && part.endsWith("'") && part.length() == 3) {
                        reconstructed.append(part.charAt(1));
                    } else if (part.startsWith("(char)")) {
                        int val = Integer.parseInt(part.substring(6).trim());
                        if (val >= 32 && val < 127) reconstructed.append((char) val);
                    }
                }
                String s = reconstructed.toString();
                if (s.length() >= 6 && (s.contains("http") || s.contains(".") || s.contains("/"))) {
                    String m = "Char array string construction: " + s.substring(0, Math.min(80, s.length()));
                    if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
                }
            } catch (Exception ignored) {}
        }

        // Discord token pattern detection
        Pattern discordTokenPat = Pattern.compile("[MN][A-Za-z0-9]{23,}\\.[A-Za-z0-9\\-_]{6}\\.[A-Za-z0-9\\-_]{27,}");
        Matcher dtm = discordTokenPat.matcher(src);
        if (dtm.find()) {
            String m = "Discord bot/user token detected: " + dtm.group().substring(0, Math.min(20, dtm.group().length())) + "...";
            if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
        }

        // GitHub token detection
        Pattern ghTokenPat = Pattern.compile("gh[ps]_[A-Za-z0-9_]{36,}");
        Matcher gtm = ghTokenPat.matcher(src);
        if (gtm.find()) {
            String m = "GitHub token detected: " + gtm.group().substring(0, 10) + "...";
            if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
        }

        // new String(new byte[]{...}) static decoding
        Pattern newStrPat = Pattern.compile("new\\s+String\\(new\\s+byte\\[\\]\\s*\\{([^}]{8,400})\\}");
        Matcher nsm = newStrPat.matcher(src);
        while (nsm.find()) {
            try {
                byte[] arr = parseByteArray(nsm.group(1));
                if (arr != null && arr.length >= 4) {
                    String decoded = new String(arr, StandardCharsets.UTF_8);
                    if (isAsciiPrintable(decoded) && decoded.length() >= 4) {
                        String m = "Static byte[] string: " + decoded.substring(0, Math.min(80, decoded.length()));
                        if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
                    }
                }
            } catch (Exception ignored) {}
        }

        // Raw-byte patterns — loaded from CFG (format: "pattern=label", pipe-separated)
        // Also track which class file(s) contain each pattern
        Set<String> rawStrings = extractRawStrings(classes);
        for (String entry : cfgArr("raw.patterns")) {
            int eq = entry.indexOf('=');
            if (eq <= 0) continue;
            String pat   = entry.substring(0, eq);
            String label = entry.substring(eq + 1);
            boolean found = false;
            for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
                String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);
                if (ascii.contains(pat)) {
                    found = true;
                    addMarkerDetail(label, classEntry.getKey(), 0, "Raw bytes in class file");
                }
            }
            if (found && !findings.contains(label)) {
                findings.add(label);
                ilog("  [MARKER/RAW] " + label);
            }
        }

        // AdamRat obfuscation signatures (loaded from CFG)
        for (String sig : cfgArr("adamrat.obf.signatures")) {
            if (!sig.isEmpty() && src.contains(sig)) {
                String m = "AdamRat control-flow obfuscation signature";
                if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
                break;
            }
        }

        // Known C2 IP matching in raw strings
        for (String ip : KNOWN_C2_IPS) {
            if (rawStrings.stream().anyMatch(s -> s.contains(ip)) || src.contains(ip)) {
                String m = "KNOWN MALICIOUS IP: " + ip;
                if (!findings.contains(m)) { findings.add(m); warn(m); }
            }
        }

        // Known C2 domain matching in raw strings
        for (String domain : KNOWN_C2_DOMAINS) {
            if (rawStrings.stream().anyMatch(s -> s.contains(domain)) || src.contains(domain)) {
                String m = "KNOWN MALICIOUS DOMAIN: " + domain;
                if (!findings.contains(m)) { findings.add(m); warn(m); }
            }
        }

        // Known-bad package detection in class names
        for (String pkg : KNOWN_BAD_PACKAGES) {
            String pkgUnderscore = pkg.replace("/", "_");
            for (String cls : classes.keySet()) {
                if (cls.contains(pkg) || cls.contains(pkgUnderscore)) {
                    String m = "KNOWN MALICIOUS PACKAGE: " + pkg + " (class: " + cls + ")";
                    if (!findings.contains(m)) { findings.add(m); warn(m); }
                    break;
                }
            }
        }

        // Known-bad JAR resource scanning
        try (ZipFile zf = new ZipFile(jarPath)) {
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                String name = ze.getName();
                String basename = name.contains("/") ? name.substring(name.lastIndexOf('/') + 1) : name;
                for (String bad : KNOWN_BAD_RESOURCES) {
                    if (basename.equals(bad) || name.endsWith(bad)) {
                        String m = "KNOWN MALICIOUS FILE IN JAR: " + name + " (indicator: " + bad + ")";
                        if (!findings.contains(m)) { findings.add(m); warn(m); }
                    }
                }
            }
        } catch (Exception ignored) {}

        // Constant pool method reference scanning (bytecode-level API detection)
        scanConstantPoolMethodRefs(classes, findings);

        // Static initializer injection detection: method named _[0-9a-f]{32}
        detectStaticInitInjection(src, findings);

        // new String(new byte[]{...}) density analysis
        detectByteArrayStringDensity(src, findings);

        // Allatori obfuscator watermark detection
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            if (ascii.contains("Allatori") || ascii.contains("allatori")) {
                String m = "Allatori commercial obfuscator detected";
                if (!findings.contains(m)) { findings.add(m); ilog("  [MARKER] " + m); }
                break;
            }
        }

        // Blocklist check
        Set<String> blocklist = loadBlocklist();
        if (!blocklist.isEmpty()) {
            for (String entry : blocklist) {
                boolean hit = src.contains(entry) || rawStrings.stream().anyMatch(s -> s.contains(entry));
                if (hit) {
                    String m = "BLOCKLIST HIT: " + entry;
                    if (!findings.contains(m)) { findings.add(m); warn(m); }
                }
            }
        }

        return findings;
    }

    /** Scan class constant pools for dangerous method references (like nekodetector/JarAnalyzerTool approach) */
    static void scanConstantPoolMethodRefs(Map<String, byte[]> classes, List<String> findings) {
        // Method signatures that are suspicious when found together
        Map<String, String> dangerousRefs = new LinkedHashMap<>();
        dangerousRefs.put("java/lang/Runtime\u0001exec", "Runtime.exec() command execution");
        dangerousRefs.put("java/lang/ProcessBuilder\u0001start", "ProcessBuilder command execution");
        dangerousRefs.put("java/net/URLClassLoader\u0001<init>", "URLClassLoader dynamic class loading from URL");
        dangerousRefs.put("java/lang/ClassLoader\u0001defineClass", "ClassLoader.defineClass() code injection");
        dangerousRefs.put("java/lang/reflect/Method\u0001invoke", "Reflective method invocation");
        dangerousRefs.put("java/lang/Class\u0001forName", "Class.forName() dynamic class resolution");
        dangerousRefs.put("java/lang/System\u0001load", "System.load() native library loading");
        dangerousRefs.put("java/lang/System\u0001loadLibrary", "System.loadLibrary() native library loading");
        dangerousRefs.put("java/lang/reflect/Field\u0001setAccessible", "Field.setAccessible() access bypass");
        dangerousRefs.put("java/io/File\u0001delete", "File.delete() file deletion");
        dangerousRefs.put("java/io/File\u0001deleteOnExit", "File.deleteOnExit() deferred file deletion on JVM exit");

        // Track non-library hits separately for combo detection
        boolean nonLibURLClassLoader = false, nonLibDefineClass = false;
        boolean nonLibReflection = false, nonLibExec = false;

        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            boolean isLib = isLibraryClass(classEntry.getKey());
            byte[] data = classEntry.getValue();
            String ascii = new String(data, StandardCharsets.US_ASCII);
            for (Map.Entry<String, String> ref : dangerousRefs.entrySet()) {
                String[] parts = ref.getKey().split("\u0001");
                // Check if both the class ref and method name exist in constant pool strings
                if (ascii.contains(parts[0]) && ascii.contains(parts[1])) {
                    // Tag library-origin markers so bot can filter them from scoring
                    String tag = isLib ? "[LIB] " : "";
                    String m = "Bytecode API ref: " + tag + ref.getValue() + " (in " + classEntry.getKey() + ")";
                    if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
                    // Track non-library hits for combo detection
                    if (!isLib) {
                        String desc = ref.getValue();
                        if (desc.contains("URLClassLoader")) nonLibURLClassLoader = true;
                        if (desc.contains("defineClass")) nonLibDefineClass = true;
                        if (desc.contains("Reflective method")) nonLibReflection = true;
                        if (desc.contains("Runtime.exec") || desc.contains("ProcessBuilder")) nonLibExec = true;
                    }
                }
            }
        }

        // ── Change 5: Reflection/invokedynamic bytecode detection ──
        boolean hasForName = false, hasGetMethod = false, hasInvoke = false;
        boolean hasMethodHandle = false, hasUnsafe = false;
        boolean hasDefineClass = false, hasURLClassLoader = false;
        boolean extendsClassLoader = false;
        // ── Change 6: DNS tunneling detection ──
        boolean hasDnsLookup = false;
        // ── Change 7: Timer/delayed execution detection ──
        boolean hasTimer = false, hasScheduledExecutor = false, hasThreadSleep = false;

        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            boolean isLib = isLibraryClass(classEntry.getKey());
            if (isLib) continue;
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // Change 5: Reflection chains
            if (ascii.contains("java/lang/Class") && ascii.contains("forName")) hasForName = true;
            if (ascii.contains("getMethod") || ascii.contains("getDeclaredMethod")) hasGetMethod = true;
            if (ascii.contains("java/lang/reflect/Method") && ascii.contains("invoke")) hasInvoke = true;
            if (ascii.contains("java/lang/invoke/MethodHandle")) hasMethodHandle = true;
            if (ascii.contains("sun/misc/Unsafe") || ascii.contains("jdk/internal/misc/Unsafe")) hasUnsafe = true;

            // Change 6: DNS tunneling
            if (ascii.contains("javax/naming/directory") || ascii.contains("InitialDirContext")
                || ascii.contains("DirContext")) hasDnsLookup = true;

            // Change 7: Timer/delayed execution
            if (ascii.contains("java/util/Timer") && ascii.contains("schedule")) hasTimer = true;
            if (ascii.contains("ScheduledThreadPoolExecutor") || ascii.contains("ScheduledExecutorService")) hasScheduledExecutor = true;
            if (ascii.contains("java/lang/Thread") && ascii.contains("sleep")) hasThreadSleep = true;

            // Change 9: ClassLoader manipulation
            if (ascii.contains("defineClass")) hasDefineClass = true;
            if (ascii.contains("URLClassLoader")) hasURLClassLoader = true;
            // Check if class extends ClassLoader (constant pool contains "java/lang/ClassLoader" as superclass ref)
            if (ascii.contains("java/lang/ClassLoader") && !ascii.contains("URLClassLoader")) extendsClassLoader = true;
        }

        // Change 5 markers
        if (hasForName && hasGetMethod && hasInvoke) {
            String m = "Reflection-based execution chain: Class.forName + getMethod + invoke";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }
        if (hasMethodHandle) {
            String m = "invokedynamic dispatch: java/lang/invoke/MethodHandle reference";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }
        if (hasUnsafe) {
            String m = "Unsafe class access: sun/misc/Unsafe or jdk/internal/misc/Unsafe (unsafe class loading)";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }

        // Change 6 markers
        if (hasDnsLookup) {
            String m = "DNS lookup API (potential DNS tunneling C2)";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }

        // Change 7 markers
        if (hasTimer) {
            String m = "Timer-based delayed execution: java/util/Timer + schedule";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }
        if (hasScheduledExecutor) {
            String m = "Scheduled execution: ScheduledThreadPoolExecutor/ScheduledExecutorService";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }
        if (hasThreadSleep && findings.size() > 3) {
            // Thread.sleep is only suspicious in combination with other markers
            String m = "Thread.sleep in suspicious context (delayed execution with " + (findings.size()-1) + " other markers)";
            if (!findings.contains(m)) { findings.add(m); ilog("  [CPREF] " + m); }
        }

        // Change 9 markers
        if (hasDefineClass) {
            String m2 = "ClassLoader.defineClass usage (runtime bytecode injection)";
            if (!findings.contains(m2)) { findings.add(m2); ilog("  [CPREF] " + m2); }
        }
        if (hasURLClassLoader) {
            String m2 = "URLClassLoader usage (remote class loading)";
            if (!findings.contains(m2)) { findings.add(m2); ilog("  [CPREF] " + m2); }
        }
        if (extendsClassLoader) {
            String m2 = "Custom ClassLoader subclass detected (potential code injection)";
            if (!findings.contains(m2)) { findings.add(m2); ilog("  [CPREF] " + m2); }
        }

        // Combo detection: only flag HIGH RISK when dangerous combos appear in NON-library code
        if (nonLibURLClassLoader && (nonLibDefineClass || nonLibReflection)) {
            String m = "HIGH RISK: URLClassLoader + dynamic class loading combo (stage2 download pattern)";
            if (!findings.contains(m)) { findings.add(m); warn(m); }
        }
        if (nonLibExec && nonLibURLClassLoader) {
            String m = "HIGH RISK: Command execution + URL class loading combo (dropper pattern)";
            if (!findings.contains(m)) { findings.add(m); warn(m); }
        }
    }

    /** Detect methods named _[0-9a-f]{32} called from <clinit> — fractureiser injection signature */
    static void detectStaticInitInjection(String src, List<String> findings) {
        // Look for method declarations with hex names: void _a1b2c3d4e5f6...()
        Pattern hexMethodPat = Pattern.compile("(?:static|private|void)\\s+_([0-9a-f]{32,})\\s*\\(");
        Matcher hm = hexMethodPat.matcher(src);
        while (hm.find()) {
            String m = "FRACTUREISER INJECTION: Method with hex name '_" + hm.group(1).substring(0, 8) +
                        "...' (static initializer injection signature)";
            if (!findings.contains(m)) { findings.add(m); warn(m); }
        }

        // Also check for clinit calling methods with suspicious names
        Pattern clinitCallPat = Pattern.compile("<clinit>[^}]{0,500}_([0-9a-f]{16,})");
        Matcher cm = clinitCallPat.matcher(src);
        if (cm.find()) {
            String m = "FRACTUREISER: <clinit> calls hex-named method '_" + cm.group(1).substring(0, 8) + "...'";
            if (!findings.contains(m)) { findings.add(m); warn(m); }
        }
    }

    /** Detect high density of new String(new byte[]{...}) — hallmark of fractureiser obfuscation */
    static void detectByteArrayStringDensity(String src, List<String> findings) {
        Pattern pat = Pattern.compile("new\\s+String\\s*\\(\\s*new\\s+byte\\s*\\[\\s*\\]\\s*\\{");
        Matcher m = pat.matcher(src);
        int count = 0;
        while (m.find()) count++;

        if (count >= 10) {
            String msg = "Heavy string obfuscation: " + count + " instances of byte[] string construction " +
                "(all string literals encoded as byte arrays — common in obfuscated JARs)";
            if (!findings.contains(msg)) { findings.add(msg); warn(msg); }
        } else if (count >= 5) {
            String msg = "Moderate byte[] string construction density: " + count + " instances";
            if (!findings.contains(msg)) { findings.add(msg); ilog("  [MARKER] " + msg); }
        }
    }

    // Extract ASCII strings >= 8 chars from raw class bytes
    static Set<String> extractRawStrings(Map<String, byte[]> classes) {
        Set<String> result = new LinkedHashSet<>();
        for (byte[] data : classes.values()) {
            StringBuilder cur = new StringBuilder();
            for (byte b : data) {
                char c = (char)(b & 0xFF);
                if (c >= 0x20 && c < 0x7F) { cur.append(c); }
                else {
                    if (cur.length() >= 8) result.add(cur.toString());
                    cur.setLength(0);
                }
            }
            if (cur.length() >= 8) result.add(cur.toString());
        }
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADAMRAT ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    static void analyzeAdamRat(String jarPath, String jarSha256, String src,
                                Map<String, byte[]> classes, List<String> markers,
                                String ts, String[] configEntry, String configRaw,
                                String cfrPath, Path tempDir) throws Exception {

        // XOR key extraction
        step("Extracting XOR key...");
        byte[] xorKey = extractXorKey(src, classes);
        if (xorKey == null) {
            fail("Could not find XOR key");
            writeUnknownConfigLog(jarPath, jarSha256, ts, markers, "XOR key not found");
            exportGenericIocsJson(jarPath, jarSha256, "adamrat_unknown", markers, new ArrayList<>(), new LinkedHashMap<>());
            return;
        }
        ok("XOR key found (" + xorKey.length + " bytes): " + hexSnippet(xorKey));

        // Byte arrays
        step("Extracting encrypted byte arrays...");
        Map<String, byte[]> byteArrays = extractByteArrays(src, classes);
        ok("Found " + byteArrays.size() + " byte array(s)");

        // N candidates
        step("Computing candidate n values from XOR chains...");
        List<Integer> nCandidates = buildNCandidates(src);
        ok("Built " + nCandidates.size() + " candidate n value(s)");

        // Decrypted string URLs
        step("Scanning decrypted strings for URLs...");
        List<String> extraUrls = scanDecryptedStrings(byteArrays, xorKey, nCandidates);
        if (extraUrls.isEmpty()) ok("No additional URLs found in decrypted strings");
        else { ok("Found " + extraUrls.size() + " URL(s):"); extraUrls.forEach(u -> ilog("  URL: " + u)); }

        // AES key
        step("Recovering AES key string...");
        String aesKeyStr = findAesKey(byteArrays, xorKey, nCandidates, configRaw);
        if (aesKeyStr == null) { fail("Could not recover AES key"); }
        else { ok("AES key recovered: \"" + aesKeyStr + "\""); }

        // Decrypt
        String json = null;
        if (configRaw != null && aesKeyStr != null) {
            step("Decrypting config...");
            json = decryptConfig(configRaw, aesKeyStr);
            if (json != null) {
                ok("Config decrypted successfully");
                Map<String, String> unknownFields = dynamicFieldDiscovery(json);
                if (!unknownFields.isEmpty()) {
                    ok("Discovered " + unknownFields.size() + " unknown field(s):");
                    unknownFields.forEach((k, v) -> ilog("  [UNKNOWN] \"" + k + "\" => " + v));
                }
                String webhook = findWebhook(json);
                String webhookStatus = webhook != null ? checkWebhookStatus(webhook) : null;
                printConfig(json, unknownFields, webhook, webhookStatus);
                writeConfigLog(jarPath, configEntry[0], aesKeyStr, xorKey, json, ts, jarSha256, unknownFields, extraUrls, webhook, webhookStatus);
                exportAdamRatIocsJson(jarPath, jarSha256, json, extraUrls, markers, webhook, webhookStatus);
            } else {
                fail("AES decryption failed — key or IV mismatch");
                writeUnknownConfigLog(jarPath, jarSha256, ts, markers, "AES decryption failed");
            }
        }

        if (json == null) exportGenericIocsJson(jarPath, jarSha256, "adamrat", markers, extraUrls, new LinkedHashMap<>());

        ilog(""); ilog("RESULT: " + (json != null ? "SUCCESS" : "PARTIAL") + " — config.log written");
        System.out.println("    ══════════════════════════════════════════");
        System.out.println("    RESULT: " + (json != null ? "SUCCESS" : "PARTIAL") + " — config.log written");
        System.out.println("    ══════════════════════════════════════════");
    }

    // ─────────────────────────────────────────────────────────────────────
    // WEEDHACK DROPPER ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    static void analyzeDropper(String jarPath, String jarSha256, String src,
                                Map<String, byte[]> classes, List<String> markers,
                                String ts, boolean hasCasino) {
        step("Analyzing Weedhack dropper variant...");

        // Campaign UUID
        String fabricJson  = readFabricApiJson(jarPath);
        String campaignId  = null;
        if (fabricJson != null) {
            Matcher m = Pattern.compile("\"api_version\"\\s*:\\s*\"([^\"]+)\"").matcher(fabricJson);
            if (m.find()) campaignId = m.group(1);
            ilog("  fabric.api.json: " + fabricJson.trim());
        }
        // Fallback: scan raw class bytes for UUID pattern
        if (campaignId == null) {
            Pattern uuidPat = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
            for (String s : extractRawStrings(classes)) {
                Matcher um = uuidPat.matcher(s);
                if (um.find()) { campaignId = um.group(); ilog("  Campaign UUID (raw): " + campaignId); break; }
            }
        }

        String campaignName = campaignId != null ? CAMPAIGN_MAP.getOrDefault(campaignId, "Unknown") : "Unknown";
        ok("Campaign UUID: " + (campaignId != null ? campaignId : "not found") + " [" + campaignName + "]");

        // Detect ETH contract from decompiled source (future-proof: may change)
        String ethContract = detectEthContract(src, classes);
        if (ethContract == null) ethContract = DROPPER_ETH_CONTRACT(); // fallback to known
        ilog("  ETH Contract: " + ethContract);

        // Detect stage2 class/method from decompiled source
        String stage2Class  = detectStage2Class(src, classes);
        String stage2Method = detectStage2Method(src);
        if (stage2Class  == null) stage2Class  = DROPPER_STAGE2_CLASS();
        if (stage2Method == null) stage2Method = DROPPER_STAGE2_METHOD();

        // Detect execution environment
        String execEnv = detectExecEnvironment(src);

        // Casino sub-type
        if (hasCasino) {
            ilog("  Sub-type: CASINO_BUNDLED — contains net.aseity.optimization rig classes");
            ilog("    LegitRigController: digit-rigging casino cheat with overlay deception");
        }

        // Detect custom exfil/stage2 paths from source
        String exfilPath  = detectUrlPath(src, "/api/", DROPPER_EXFIL_PATH());
        String stage2Path = detectUrlPath(src, "/files/", DROPPER_STAGE2_PATH());

        // Fetch live C2
        step("Querying Ethereum contract for live C2 URL...");
        String c2Base   = fetchEthC2Url(ethContract);
        String c2Exfil  = c2Base != null ? c2Base + exfilPath  : null;
        String c2Stage2 = c2Base != null ? c2Base + stage2Path : null;

        if (c2Base != null) {
            ok("Live C2 URL: " + c2Base);
            warn("  Exfil endpoint : " + c2Exfil);
            warn("  Stage2 DL URL  : " + c2Stage2);
        } else {
            warn("Could not resolve C2 URL from Ethereum contract");
        }

        // Console output
        System.out.println();
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + GREEN + "  DROPPER CONFIG (Weedhack/Blockchain C2)" + RESET);
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(YELLOW + "  Variant       : Weedhack (Ethereum blockchain C2)" + RESET);
        System.out.println(YELLOW + "  Sub-type      : " + (hasCasino ? "CASINO_BUNDLED" : "standard") + RESET);
        System.out.println(YELLOW + "  Campaign UUID : " + (campaignId != null ? campaignId : "unknown") + RESET);
        System.out.println(YELLOW + "  Campaign Name : " + campaignName + RESET);
        System.out.println(YELLOW + "  ETH Contract  : " + ethContract + RESET);
        System.out.println(YELLOW + "  C2 Base URL   : " + (c2Base != null ? c2Base : "(could not fetch)") + RESET);
        System.out.println(YELLOW + "  Exfil URL     : " + (c2Exfil != null ? c2Exfil : exfilPath + " (relative)") + RESET);
        System.out.println(YELLOW + "  Stage2 DL URL : " + (c2Stage2 != null ? c2Stage2 : stage2Path + " (relative)") + RESET);
        System.out.println(YELLOW + "  Stage2 Class  : " + stage2Class + RESET);
        System.out.println(YELLOW + "  Stage2 Method : " + stage2Method + "(String jsonContext)" + RESET);
        System.out.println(YELLOW + "  Exec Env      : " + (execEnv != null ? execEnv : "Fabric (default)") + RESET);
        System.out.println(YELLOW + "  Data Stolen   : username, UUID, accessToken, executionEnvironment" + RESET);
        System.out.println(GREEN  + "════════════════════════════════════════" + RESET);

        writeDropperConfigLog(jarPath, jarSha256, campaignId, campaignName, ethContract,
            c2Base, c2Exfil, c2Stage2, stage2Class, stage2Method, execEnv, hasCasino, ts, markers);
        exportDropperIocsJson(jarPath, jarSha256, campaignId, ethContract, c2Base, c2Exfil, c2Stage2,
            stage2Class, stage2Method, hasCasino, markers);

        ilog(""); ilog("RESULT: SUCCESS (dropper) — config.log written");
        System.out.println("    ══════════════════════════════════════════");
        System.out.println("    RESULT: SUCCESS — config.log written");
        System.out.println("    ══════════════════════════════════════════");
    }

    // ─────────────────────────────────────────────────────────────────────
    // SESSION HARVESTER ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    static void analyzeSessionHarvester(String jarPath, String jarSha256, String src,
                                         Map<String, byte[]> classes, List<String> markers, String ts) {
        step("Analyzing Weedhack Session Harvester...");

        // Extract API endpoints from decompiled source
        List<String> apiEndpoints = new ArrayList<>();
        Pattern urlPat = Pattern.compile("\"(https?://[^\"]+)\"");
        Matcher um = urlPat.matcher(src);
        Set<String> seen = new LinkedHashSet<>();
        while (um.find()) {
            String u = um.group(1);
            if (seen.add(u)) apiEndpoints.add(u);
        }

        // Detect what it can do from source
        boolean canGetProfile  = src.contains("getProfileInfo") || src.contains("/minecraft/profile");
        boolean canValidate    = src.contains("validateSession");
        boolean canChangeSkin  = src.contains("changeSkin")     || src.contains("/minecraft/profile/skins");
        boolean hasLoginScreen = src.contains("LoginScreen");
        boolean hasEditScreen  = src.contains("EditAccountScreen");

        ilog("  Package      : dev.majanito");
        ilog("  Can steal session token : " + hasLoginScreen);
        ilog("  Can validate token      : " + canValidate);
        ilog("  Can get profile info    : " + canGetProfile);
        ilog("  Can change skin         : " + canChangeSkin);
        ilog("  Has EditAccountScreen   : " + hasEditScreen);

        System.out.println();
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + GREEN + "  SESSION HARVESTER (dev.majanito)" + RESET);
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(YELLOW + "  Variant         : Weedhack Session Token Harvester" + RESET);
        System.out.println(YELLOW + "  Package         : dev.majanito" + RESET);
        System.out.println(YELLOW + "  LoginScreen     : " + hasLoginScreen + " (presents fake login UI to collect token)" + RESET);
        System.out.println(YELLOW + "  validateSession : " + canValidate   + " (verifies stolen token against Minecraft API)" + RESET);
        System.out.println(YELLOW + "  getProfileInfo  : " + canGetProfile + " (extracts IGN + UUID from token)" + RESET);
        System.out.println(YELLOW + "  changeSkin      : " + canChangeSkin + " (can silently modify account skin)" + RESET);
        System.out.println(YELLOW + "  Data stolen     : Minecraft session token, IGN, UUID" + RESET);
        if (!apiEndpoints.isEmpty()) {
            System.out.println(YELLOW + "  API endpoints   :" + RESET);
            apiEndpoints.stream().limit(10).forEach(u -> System.out.println(YELLOW + "    " + u + RESET));
        }
        System.out.println(GREEN  + "════════════════════════════════════════" + RESET);

        // Config log
        String line = "=".repeat(50);
        clog(line); clog("  Session Harvester — Weedhack"); clog("  " + ts); clog(line); clog("");
        clog("Sample          : " + jarPath);
        clog("SHA-256         : " + jarSha256);
        clog("Variant         : Session Token Harvester (dev.majanito)");
        clog("");
        clog("-- CAPABILITIES -----------------------------------------");
        clog("  LoginScreen     : " + hasLoginScreen + " — fake UI steals session token from user");
        clog("  validateSession : " + canValidate);
        clog("  getProfileInfo  : " + canGetProfile + " — GET api.minecraftservices.com/minecraft/profile");
        clog("  changeSkin      : " + canChangeSkin + " — POST minecraft/profile/skins");
        clog("  EditAccountScreen: " + hasEditScreen);
        clog("");
        clog("-- API ENDPOINTS ----------------------------------------");
        apiEndpoints.forEach(u -> clog("  " + u));
        clog("");
        clog("-- BEHAVIORAL MARKERS -----------------------------------");
        markers.forEach(m -> clog("  - " + m));
        clog("");
        clog("-- INDICATORS OF COMPROMISE (IOCs) ----------------------");
        apiEndpoints.stream().filter(u -> !u.contains("mojang") && !u.contains("minecraft")).forEach(u -> clog("  URL: " + u));
        clog(""); clog(line);

        // IOCs JSON
        exportGenericIocsJson(jarPath, jarSha256, "session_harvester", markers, apiEndpoints, new LinkedHashMap<>());

        ilog(""); ilog("RESULT: SUCCESS (session harvester) — config.log written");
        System.out.println("    ══════════════════════════════════════════");
        System.out.println("    RESULT: SUCCESS — config.log written");
        System.out.println("    ══════════════════════════════════════════");
    }

    // ─────────────────────────────────────────────────────────────────────
    // UNKNOWN VARIANT — GENERIC BEST-EFFORT ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    static void analyzeUnknown(String jarPath, String jarSha256, String src,
                                Map<String, byte[]> classes, List<String> markers,
                                String ts, String[] configEntry, String configRaw,
                                String cfrPath, Path tempDir) throws Exception {
        warn("Unknown variant — attempting generic extraction");

        List<String> extractedUrls = new ArrayList<>();
        Pattern urlPat = Pattern.compile("\"(https?://[^\"]+)\"");
        Matcher um = urlPat.matcher(src);
        while (um.find()) extractedUrls.add(um.group(1));

        // Try XOR + AES path anyway
        byte[] xorKey = extractXorKey(src);
        String json   = null;
        if (xorKey != null && configRaw != null) {
            Map<String, byte[]> byteArrays = extractByteArrays(src);
            List<Integer> nCandidates = buildNCandidates(src);
            String aesKey = findAesKey(byteArrays, xorKey, nCandidates, configRaw);
            if (aesKey != null) {
                json = decryptConfig(configRaw, aesKey);
                if (json != null) {
                    ok("Config decrypted (unknown variant): " + aesKey);
                    Map<String, String> unknownFields = dynamicFieldDiscovery(json);
                    String webhook = findWebhook(json);
                    String webhookStatus = webhook != null ? checkWebhookStatus(webhook) : null;
                    printConfig(json, unknownFields, webhook, webhookStatus);
                    writeConfigLog(jarPath, configEntry[0], aesKey, xorKey, json, ts, jarSha256, unknownFields, extractedUrls, webhook, webhookStatus);
                    exportAdamRatIocsJson(jarPath, jarSha256, json, extractedUrls, markers, webhook, webhookStatus);
                    ilog("RESULT: SUCCESS (unknown variant, decrypted) — config.log written");
                    return;
                }
            }
        }

        // Fallback: write what we know
        writeUnknownConfigLog(jarPath, jarSha256, ts, markers, "No known malware config found");
        exportGenericIocsJson(jarPath, jarSha256, "unknown", markers, extractedUrls, new LinkedHashMap<>());
        warn("RESULT: PARTIAL — config.log has partial info");
    }

    // ─────────────────────────────────────────────────────────────────────
    // SOURCE-BASED DETECTION HELPERS (future-proof)
    // ─────────────────────────────────────────────────────────────────────

    /** Scan decompiled source + raw class bytes for Ethereum contract addresses. */
    static String detectEthContract(String src, Map<String, byte[]> classes) {
        Pattern ethPat = Pattern.compile("0x[0-9a-fA-F]{40}");
        // Check decompiled source first
        Matcher m = ethPat.matcher(src);
        while (m.find()) {
            String addr = m.group();
            if (!addr.equalsIgnoreCase("0x0000000000000000000000000000000000000000")) return addr;
        }
        // Fall back to raw class bytes
        for (String s : extractRawStrings(classes)) {
            Matcher rm = ethPat.matcher(s);
            if (rm.find()) {
                String addr = rm.group();
                if (!addr.equalsIgnoreCase("0x0000000000000000000000000000000000000000")) return addr;
            }
        }
        return null;
    }

    /** Detect the Stage 2 class name from decompiled source or raw strings. */
    static String detectStage2Class(String src, Map<String, byte[]> classes) {
        // Look for loadClass / forName calls with a dotted class name string
        Pattern p = Pattern.compile("\"([a-z][a-z0-9.]+\\.[A-Z][a-zA-Z0-9]+)\"");
        Matcher m = p.matcher(src);
        while (m.find()) {
            String cls = m.group(1);
            if (cls.contains("Main") || cls.contains("Loader") || cls.contains("Init")) return cls;
        }
        // Raw string fallback
        for (String s : extractRawStrings(classes)) {
            if (s.matches("[a-z][a-z0-9.]+\\.[A-Z][a-zA-Z0-9]+") && s.contains("majanito")) return s;
        }
        return null;
    }

    /** Detect the Stage 2 method name from decompiled source. */
    static String detectStage2Method(String src) {
        // Look for method invocations via reflection: invoke(null, ...) preceded by getDeclaredMethod
        Pattern p = Pattern.compile("getDeclaredMethod\\(\"([a-zA-Z][a-zA-Z0-9]+)\"");
        Matcher m = p.matcher(src);
        if (m.find()) return m.group(1);
        // Or literal string that matches camelCase method
        Pattern p2 = Pattern.compile("\"(initialize[A-Z][a-zA-Z0-9]+|init[A-Z][a-zA-Z0-9]+|load[A-Z][a-zA-Z0-9]+)\"");
        Matcher m2 = p2.matcher(src);
        if (m2.find()) return m2.group(1);
        return null;
    }

    /** Detect the execution environment string (Fabric, DoubleClick, etc.) */
    static String detectExecEnvironment(String src) {
        Pattern p = Pattern.compile("executionEnvironment\\s*=\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(src);
        if (m.find()) return m.group(1);
        // Also check string literals for known values
        for (String env : new String[]{"Fabric", "DoubleClick", "Forge", "NeoForge"}) {
            if (src.contains("\"" + env + "\"")) return env;
        }
        return null;
    }

    /** Detect a URL path pattern from decompiled source with a default fallback. */
    static String detectUrlPath(String src, String prefix, String defaultPath) {
        Pattern p = Pattern.compile("\"(" + Pattern.quote(prefix) + "[^\"]+)\"");
        Matcher m = p.matcher(src);
        if (m.find()) return m.group(1);
        return defaultPath;
    }

    // ─────────────────────────────────────────────────────────────────────
    // ETHEREUM C2 FETCH
    // ─────────────────────────────────────────────────────────────────────

    static String fetchEthC2Url(String ethContract) {
        String body = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\""
            + ethContract + "\",\"data\":\"" + DROPPER_ETH_METHOD() + "\"},\"latest\"],\"id\":1}";
        for (String rpc : DROPPER_ETH_RPCS()) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(rpc))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofSeconds(8))
                    .build();
                String resp = SHARED_HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body();
                int idx = resp.indexOf("\"result\":\"");
                if (idx == -1) continue;
                String hex  = resp.substring(idx + 10, resp.indexOf("\"", idx + 10));
                String data = hex.startsWith("0x") ? hex.substring(2) : hex;
                if (data.length() < 128) continue;
                long lengthL = Long.parseUnsignedLong(data.substring(64 + 48, 128), 16); // last 16 hex chars (safe range)
                int length = (lengthL > 10000) ? 10000 : (int) lengthL; // cap at 10k chars
                if (length == 0) continue;
                String strHex = data.substring(128, Math.min(128 + length * 2, data.length()));
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < strHex.length() - 1; i += 2) {
                    int c = Integer.parseInt(strHex.substring(i, i + 2), 16);
                    if (c != 0) sb.append((char) c);
                }
                String raw = sb.toString().trim();
                String url = raw.contains("|") ? raw.substring(0, raw.lastIndexOf('|')) : raw;
                if (!url.isEmpty() && url.startsWith("http")) {
                    ilog("  ETH C2 URL fetched from: " + rpc);
                    return url;
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // LOG WRITERS
    // ─────────────────────────────────────────────────────────────────────

    static void writeDropperConfigLog(String jarPath, String sha256, String campaignId,
                                       String campaignName, String ethContract,
                                       String c2Base, String c2Exfil, String c2Stage2,
                                       String stage2Class, String stage2Method,
                                       String execEnv, boolean hasCasino,
                                       String ts, List<String> markers) {
        String line = "=".repeat(50);
        clog(line); clog("  Decrypted Config — Weedhack Dropper Variant"); clog("  " + ts); clog(line); clog("");
        clog("Sample        : " + jarPath);
        clog("SHA-256       : " + sha256);
        clog("Variant       : Weedhack (Ethereum blockchain C2)");
        clog("Sub-type      : " + (hasCasino ? "CASINO_BUNDLED (contains casino cheat rig)" : "standard"));
        clog("");
        clog("-- CAMPAIGN INFO --------------------------------------------");
        clog("  Campaign UUID : " + (campaignId != null ? campaignId : "unknown"));
        clog("  Campaign Name : " + campaignName);
        clog("");
        clog("-- C2 INFRASTRUCTURE ----------------------------------------");
        clog("  ETH Contract  : " + ethContract);
        clog("  ETH Method    : " + DROPPER_ETH_METHOD() + " (getText - ABI string return)");
        clog("  C2 Base URL   : " + (c2Base != null ? c2Base : "(unavailable - queried " + DROPPER_ETH_RPCS().length + " RPC nodes)"));
        clog("  Exfil URL     : " + (c2Exfil != null ? c2Exfil : "(base)" + DROPPER_EXFIL_PATH()));
        clog("  Stage2 URL    : " + (c2Stage2 != null ? c2Stage2 : "(base)" + DROPPER_STAGE2_PATH()));
        clog("  ETH RPC nodes : " + DROPPER_ETH_RPCS().length + " public endpoints");
        clog("");
        clog("-- STAGE 2 --------------------------------------------------");
        clog("  Class  : " + stage2Class);
        clog("  Method : " + stage2Method + "(String jsonContext)");
        clog("  Env    : " + (execEnv != null ? execEnv : "Fabric"));
        clog("  Notes  : Stage 2 JAR downloaded in-memory via custom ClassLoader");
        clog("           Player context (username/UUID/accessToken) passed to Stage 2");
        clog("");
        clog("-- DATA EXFILTRATED -----------------------------------------");
        clog("  - username (Minecraft username)");
        clog("  - uuid (Minecraft UUID)");
        clog("  - accessToken (session token for account theft)");
        clog("  - executionEnvironment (" + (execEnv != null ? execEnv : "Fabric") + ")");
        clog("");
        if (hasCasino) {
            clog("-- CASINO CHEAT MODULE --------------------------------------");
            clog("  LegitRigController: manipulates item NBT digits in dispenser grids");
            clog("  PaperGameDispenserOverlay: hides rigged slot from victim's view");
            clog("  Hotkeys: G=toggle rig, H=switch side, O=overlay, P=settings");
        }
        clog("");
        clog("-- BEHAVIORAL MARKERS ----------------------------------------");
        markers.forEach(m -> clog("  - " + m));
        clog(""); clog(line);
    }

    static void writeUnknownConfigLog(String jarPath, String sha256, String ts,
                                       List<String> markers, String reason) {
        String line = "=".repeat(50);
        clog(line); clog("  Analysis Result — Unknown/Partial"); clog("  " + ts); clog(line); clog("");
        clog("Sample  : " + jarPath);
        clog("SHA-256 : " + sha256);
        clog("Reason  : " + reason);
        clog("");
        clog("-- BEHAVIORAL MARKERS ----------------------------------------");
        markers.forEach(m -> clog("  - " + m));
        clog(""); clog(line);
    }

    // ─────────────────────────────────────────────────────────────────────
    // IOC EXPORTERS
    // ─────────────────────────────────────────────────────────────────────

    static void exportDropperIocsJson(String jarPath, String sha256, String campaignId,
                                       String ethContract, String c2Base,
                                       String c2Exfil, String c2Stage2,
                                       String stage2Class, String stage2Method,
                                       boolean hasCasino, List<String> markers) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"sha256\": \"").append(escJson(sha256)).append("\",\n");
            sb.append("  \"file\": \"").append(escJson(java.nio.file.Paths.get(jarPath).getFileName().toString())).append("\",\n");
            sb.append("  \"analyzed\": \"").append(escJson(java.time.Instant.now().toString())).append("\",\n");
            sb.append("  \"variant\": \"weedhack\",\n");
            sb.append("  \"subtype\": \"").append(hasCasino ? "casino_bundled" : "standard").append("\",\n");
            sb.append("  \"campaignId\": \"").append(escJson(campaignId != null ? campaignId : "")).append("\",\n");
            sb.append("  \"campaignName\": \"").append(escJson(campaignId != null ? CAMPAIGN_MAP.getOrDefault(campaignId, "Unknown") : "Unknown")).append("\",\n");
            sb.append("  \"ethContract\": \"").append(escJson(ethContract)).append("\",\n");
            sb.append("  \"ethMethod\": \"").append(DROPPER_ETH_METHOD()).append("\",\n");
            sb.append("  \"c2Base\": \"").append(escJson(c2Base != null ? c2Base : "")).append("\",\n");
            sb.append("  \"exfilUrl\": \"").append(escJson(c2Exfil != null ? c2Exfil : "")).append("\",\n");
            sb.append("  \"stage2Url\": \"").append(escJson(c2Stage2 != null ? c2Stage2 : "")).append("\",\n");
            sb.append("  \"stage2Class\": \"").append(escJson(stage2Class)).append("\",\n");
            sb.append("  \"stage2Method\": \"").append(escJson(stage2Method)).append("\",\n");
            sb.append("  \"behavioralMarkers\": [");
            for (int i = 0; i < markers.size(); i++) {
                sb.append("\"").append(escJson(markers.get(i))).append("\"");
                if (i < markers.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            appendMarkerDetails(sb);
            sb.append("\n}\n");
            Files.writeString(out(jarName + "_iocs.json"), sb.toString());
        } catch (Exception e) { warn("Could not write iocs.json: " + e.getMessage()); }
    }

    static void exportAdamRatIocsJson(String jarPath, String sha256, String json,
                                       List<String> extraUrls, List<String> markers,
                                       String webhook, String webhookStatus) {
        try {
            String userId  = findSnowflake(json);
            String premium = findPremiumBool(json);
            List<String> urls = new ArrayList<>();
            if (webhook != null) urls.add(webhook);
            // Value-based URL extraction — field-name-independent
            Pattern urlValPat = Pattern.compile("\"(https?://[^\"]+)\"");
            Matcher uvm = urlValPat.matcher(json);
            while (uvm.find()) { String u = uvm.group(1); if (!urls.contains(u)) urls.add(u); }

            // Extract domains from URLs
            Set<String> domains = new LinkedHashSet<>();
            for (String u : urls) {
                Matcher dm = Pattern.compile("https?://([^/]+)").matcher(u);
                if (dm.find()) domains.add(dm.group(1));
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"sha256\": \"").append(escJson(sha256)).append("\",\n");
            sb.append("  \"file\": \"").append(escJson(java.nio.file.Paths.get(jarPath).getFileName().toString())).append("\",\n");
            sb.append("  \"analyzed\": \"").append(escJson(java.time.Instant.now().toString())).append("\",\n");
            sb.append("  \"variant\": \"adamrat\",\n");
            sb.append("  \"webhook\": \"").append(escJson(webhook != null ? webhook : "")).append("\",\n");
            sb.append("  \"webhookStatus\": \"").append(escJson(webhookStatus != null ? webhookStatus : "")).append("\",\n");
            sb.append("  \"userId\": \"").append(escJson(userId != null ? userId : "")).append("\",\n");
            sb.append("  \"premium\": ").append("true".equals(premium)).append(",\n");
            sb.append("  \"decryptedConfig\": \"").append(escJson(json)).append("\",\n");
            sb.append("  \"domains\": [");
            int di = 0;
            for (String d : domains) { sb.append("\"").append(escJson(d)).append("\""); if (++di < domains.size()) sb.append(", "); }
            sb.append("],\n");
            sb.append("  \"urls\": [");
            for (int i = 0; i < urls.size(); i++) {
                sb.append("\"").append(escJson(urls.get(i))).append("\"");
                if (i < urls.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            sb.append("  \"extraUrls\": [");
            for (int i = 0; i < extraUrls.size(); i++) {
                sb.append("\"").append(escJson(extraUrls.get(i))).append("\"");
                if (i < extraUrls.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            sb.append("  \"behavioralMarkers\": [");
            for (int i = 0; i < markers.size(); i++) {
                sb.append("\"").append(escJson(markers.get(i))).append("\"");
                if (i < markers.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            appendMarkerDetails(sb);
            sb.append("\n}\n");
            Files.writeString(out(jarName + "_iocs.json"), sb.toString());
        } catch (Exception e) { warn("Could not write iocs.json: " + e.getMessage()); }
    }

    static void exportGenericIocsJson(String jarPath, String sha256, String variant,
                                       List<String> markers, List<String> urls,
                                       Map<String, String> extra) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            sb.append("  \"sha256\": \"").append(escJson(sha256)).append("\",\n");
            sb.append("  \"file\": \"").append(escJson(java.nio.file.Paths.get(jarPath).getFileName().toString())).append("\",\n");
            sb.append("  \"analyzed\": \"").append(escJson(java.time.Instant.now().toString())).append("\",\n");
            sb.append("  \"variant\": \"").append(escJson(variant)).append("\",\n");
            sb.append("  \"urls\": [");
            for (int i = 0; i < urls.size(); i++) {
                sb.append("\"").append(escJson(urls.get(i))).append("\"");
                if (i < urls.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            sb.append("  \"behavioralMarkers\": [");
            for (int i = 0; i < markers.size(); i++) {
                sb.append("\"").append(escJson(markers.get(i))).append("\"");
                if (i < markers.size() - 1) sb.append(", ");
            }
            sb.append("],\n");
            // Mod loader metadata — helps scoring understand legitimate mod patterns
            if (!detectedModLoaders.isEmpty()) {
                sb.append("  \"modLoaders\": [");
                int mli = 0;
                for (String ml : detectedModLoaders) {
                    sb.append("\"").append(escJson(ml)).append("\"");
                    if (++mli < detectedModLoaders.size()) sb.append(", ");
                }
                sb.append("],\n");
            }
            appendMarkerDetails(sb);
            sb.append("\n}\n");
            Files.writeString(out(jarName + "_iocs.json"), sb.toString());
        } catch (Exception e) { warn("Could not write iocs.json: " + e.getMessage()); }
    }

    /** Append the markerDetails JSON object to a StringBuilder. */
    static void appendMarkerDetails(StringBuilder sb) {
        sb.append("  \"markerDetails\": {");
        int mi = 0;
        for (Map.Entry<String, List<Map<String, String>>> me : markerDetails.entrySet()) {
            sb.append("\n    \"").append(escJson(me.getKey())).append("\": [");
            List<Map<String, String>> locs = me.getValue();
            for (int i = 0; i < locs.size(); i++) {
                Map<String, String> loc = locs.get(i);
                sb.append("{\"file\":\"").append(escJson(loc.getOrDefault("file", "")))
                  .append("\",\"line\":").append(loc.getOrDefault("line", "0"))
                  .append(",\"context\":\"").append(escJson(loc.getOrDefault("context", "")))
                  .append("\"}");
                if (i < locs.size() - 1) sb.append(",");
            }
            sb.append("]");
            if (++mi < markerDetails.size()) sb.append(",");
        }
        sb.append("\n  }");
    }

    // ─────────────────────────────────────────────────────────────────────
    // ZIP / CLASS EXTRACTION
    // ─────────────────────────────────────────────────────────────────────

    static Map<String, byte[]> extractClasses(String jarPath, Path outDir) throws Exception {
        Map<String, byte[]> result = new LinkedHashMap<>();

        // Single ZipFile handle for both passes (avoids double open)
        try (ZipFile zf = new ZipFile(jarPath)) {
            // Pass 1: fake-directory ZIP trick (entries named *.class/ with data)
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() && entry.getSize() > 0 && name.endsWith(".class/")) {
                    if (entry.getSize() > 50_000_000) { ilog("  SKIP: " + name + " too large (" + entry.getSize() + ")"); continue; }
                    try (InputStream is = zf.getInputStream(entry)) {
                        byte[] data = readBounded(is, 50_000_000);
                        if (isClassMagic(data)) {
                            String safe = name.replaceAll("[/\\\\]", "_").replaceAll("/$", "");
                            result.put(safe, data);
                            ilog("  + " + name + " (" + data.length + " bytes)");
                        }
                    } catch (Exception ignored) {}
                }
            }

            // Pass 2: standard .class files (always run to catch normal classes too)
            if (result.isEmpty()) {
                ilog("  Falling back to standard class extraction");
                System.out.println("    Falling back to standard class extraction");
            }
            Enumeration<? extends ZipEntry> entries2 = zf.entries();
            while (entries2.hasMoreElements()) {
                ZipEntry entry = entries2.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) continue;
                if (entry.getSize() > 50_000_000) { ilog("  SKIP: " + entry.getName() + " too large"); continue; }
                try (InputStream is = zf.getInputStream(entry)) {
                    byte[] data = readBounded(is, 50_000_000);
                    if (isClassMagic(data)) {
                        String safe = entry.getName().replaceAll("[/\\\\]", "_");
                        if (result.containsKey(safe)) safe = safe + "_std"; // avoid collision with pass 1
                        result.put(safe, data);
                        ilog("  + [std] " + entry.getName() + " (" + data.length + " bytes)");
                        System.out.println("    + [std] " + entry.getName() + " (" + data.length + " bytes)");
                    }
                } catch (Exception ignored) {}
            }
        }

        return result;
    }

    /** Read from stream while counting actual bytes; throws if limit exceeded (protects against zip bombs). */
    static byte[] readBounded(InputStream is, long limit) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        long total = 0;
        int n;
        while ((n = is.read(tmp)) != -1) {
            total += n;
            if (total > limit) throw new IOException("ZipEntry exceeds safe size limit (" + limit + " bytes)");
            buf.write(tmp, 0, n);
        }
        return buf.toByteArray();
    }

    static boolean isClassMagic(byte[] data) {
        return data.length >= 4
            && (data[0] & 0xFF) == 0xCA && (data[1] & 0xFF) == 0xFE
            && (data[2] & 0xFF) == 0xBA && (data[3] & 0xFF) == 0xBE;
    }

    /** Skip known library packages to speed up decompilation (prefixes from CFG). */
    static boolean isLibraryClass(String name) {
        String n = name.replace('_', '/').replace('\\', '/').toLowerCase();
        for (String prefix : cfgArr("library.class.prefixes")) {
            if (!prefix.isEmpty()) {
                String p = prefix.toLowerCase();
                // Match both underscore and slash variants
                if (n.startsWith(p) || n.startsWith(p.replace('_', '/'))) return true;
            }
        }
        // Gson heuristic: skip any class containing "gson" unless it's clearly from the payload author
        return n.contains("gson") && !n.contains("majanito") && !n.contains("example");
    }

    // ─────────────────────────────────────────────────────────────────────
    // CONFIG FILE DETECTION
    // ─────────────────────────────────────────────────────────────────────

    static String[] findConfigFile(String jarPath) throws Exception {
        try (ZipFile zf = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || entry.getSize() <= 0) continue;
                String name = entry.getName();
                // Skip known non-config resources
                String nameLower = name.toLowerCase();
                if (nameLower.endsWith(".json") || nameLower.endsWith(".mf") || nameLower.endsWith(".png")
                        || nameLower.endsWith(".class") || nameLower.endsWith(".class/")
                        || nameLower.endsWith(".md") || (nameLower.endsWith(".txt") && name.contains("CHANGELOG"))
                        || nameLower.endsWith(".ttf") || nameLower.endsWith(".otf") || nameLower.endsWith(".woff")
                        || nameLower.endsWith(".woff2") || nameLower.endsWith(".jpg") || nameLower.endsWith(".jpeg")
                        || nameLower.endsWith(".gif") || nameLower.endsWith(".svg") || nameLower.endsWith(".ico")
                        || nameLower.endsWith(".properties") || nameLower.endsWith(".xml") || nameLower.endsWith(".yml")
                        || nameLower.endsWith(".yaml") || nameLower.endsWith(".toml") || nameLower.endsWith(".cfg")
                        || name.startsWith("META-INF/padding/") || name.startsWith("META-INF/junk/")
                        || (name.startsWith("META-INF/") && !name.equals("META-INF/a1b2c3d4"))
                        || name.contains("mixin") || name.contains("LICENSE")) continue;
                try (InputStream is = zf.getInputStream(entry)) {
                    byte[] data = readBounded(is, 1_000_000); // 1MB cap for config files
                    if (data.length < 4) continue;
                    String content = new String(data, StandardCharsets.US_ASCII).trim();

                    // Format 1: hex:hex (IV:ciphertext)
                    if (content.matches("[0-9a-fA-F]+:[0-9a-fA-F]+")) {
                        ilog("  Config format: hex:hex in " + name);
                        return new String[]{name, content, "hex"};
                    }
                    // Format 2: Base64
                    try {
                        byte[] dec = Base64.getDecoder().decode(data);
                        String ds = new String(dec, StandardCharsets.US_ASCII);
                        if (ds.contains("{") && ds.contains("http")) {
                            ilog("  Config format: base64 in " + name);
                            return new String[]{name, ds, "base64"};
                        }
                    } catch (Exception ignored) {}
                    // Format 3: pure hex >= 64 chars, no colon
                    if (content.matches("[0-9a-fA-F]+") && content.length() >= 64) {
                        int mid = content.length() / 2;
                        ilog("  Config format: pure hex (split) in " + name);
                        return new String[]{name, content.substring(0, mid) + ":" + content.substring(mid), "hex-split"};
                    }
                    // Format 4: raw bytes containing keyword markers
                    if (content.contains("webhook") || content.contains("discord")
                            || content.contains("http") || content.contains("token")) {
                        ilog("  Config format: raw-keyword in " + name);
                        return new String[]{name, content, "raw-keyword"};
                    }
                } catch (Exception ignored) {}
            }
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // FABRIC API JSON
    // ─────────────────────────────────────────────────────────────────────

    static String readFabricApiJson(String jarPath) {
        try (ZipFile zf = new ZipFile(jarPath)) {
            ZipEntry e = zf.getEntry("fabric.api.json");
            if (e == null) return null;
            try (InputStream is = zf.getInputStream(e)) {
                return new String(readBounded(is, 1_000_000), StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) { return null; }
    }

    // ─────────────────────────────────────────────────────────────────────
    // XOR KEY & BYTE ARRAY EXTRACTION
    // ─────────────────────────────────────────────────────────────────────

    static byte[] extractXorKey(String src) { return extractXorKey(src, null); }

    static byte[] extractXorKey(String src, Map<String, byte[]> classes) {
        Pattern all = Pattern.compile(
            "private static byte\\[\\]\\s+([\\w$]+)\\(\\)\\s*\\{\\s*return new byte\\[\\]\\{([^}]+)\\};");
        int primaryMin  = cfgInt("xor.key.primary.min");
        int primaryMax  = cfgInt("xor.key.primary.max");
        int fallbackMin = cfgInt("xor.key.fallback.min");
        int fallbackMax = cfgInt("xor.key.fallback.max");
        // Primary pass: preferred size range
        Matcher am = all.matcher(src);
        while (am.find()) {
            byte[] arr = parseByteArray(am.group(2));
            if (arr != null && arr.length >= primaryMin && arr.length <= primaryMax) {
                ilog("  XOR key (primary heuristic " + primaryMin + "-" + primaryMax + "): "
                    + am.group(1) + "() len=" + arr.length);
                return arr;
            }
        }
        // Fallback pass: broader range
        am.reset();
        while (am.find()) {
            byte[] arr = parseByteArray(am.group(2));
            if (arr != null && arr.length >= fallbackMin && arr.length <= fallbackMax) {
                ilog("  XOR key (fallback " + fallbackMin + "-" + fallbackMax + "): "
                    + am.group(1) + "() len=" + arr.length);
                return arr;
            }
        }
        // Bytecode-level fallback: extract byte[] literals directly from raw class bytes
        // when decompilation fails (e.g. heavy control-flow obfuscation)
        if (classes != null) {
            ilog("  Source-level XOR key not found — trying bytecode extraction...");
            byte[] best = null;
            String bestClass = null;
            for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                String cname = e.getKey();
                // Focus on ExampleModClient or similar main classes
                if (!cname.toLowerCase().contains("examplemod") && !cname.toLowerCase().contains("client")
                    && !cname.contains("$")) continue;
                List<byte[]> arrays = extractByteArraysFromBytecode(e.getValue());
                for (byte[] arr : arrays) {
                    if (arr.length >= primaryMin && arr.length <= primaryMax) {
                        ilog("  XOR key (bytecode primary " + primaryMin + "-" + primaryMax
                            + ") from " + cname + " len=" + arr.length);
                        return arr;
                    }
                    if (arr.length >= fallbackMin && arr.length <= fallbackMax) {
                        if (best == null || Math.abs(arr.length - 46) < Math.abs(best.length - 46)) {
                            best = arr;
                            bestClass = cname;
                        }
                    }
                }
            }
            if (best != null) {
                ilog("  XOR key (bytecode fallback " + fallbackMin + "-" + fallbackMax
                    + ") from " + bestClass + " len=" + best.length);
                return best;
            }
        }
        return null;
    }

    /**
     * Extract byte[] literals from JVM bytecode.
     * Looks for: bipush/sipush N, newarray T_BYTE(8), then dup+index+value+bastore sequences.
     */
    static List<byte[]> extractByteArraysFromBytecode(byte[] classBytes) {
        List<byte[]> results = new ArrayList<>();
        // JVM opcodes
        final int BIPUSH = 0x10, SIPUSH = 0x11, ICONST_M1 = 0x02, ICONST_0 = 0x03, ICONST_5 = 0x08;
        final int NEWARRAY = 0xBC, DUP = 0x59, BASTORE = 0x54, ARETURN = 0xB0;
        final int T_BYTE = 8;

        for (int i = 0; i < classBytes.length - 4; i++) {
            int op = classBytes[i] & 0xFF;
            int arrayLen = -1;
            int next = i + 1;

            // Read array size push
            if (op == BIPUSH && i + 2 < classBytes.length) {
                arrayLen = classBytes[i + 1]; // signed byte
                if (arrayLen < 0) arrayLen += 256; // treat as unsigned for sizes
                next = i + 2;
            } else if (op == SIPUSH && i + 3 < classBytes.length) {
                arrayLen = ((classBytes[i + 1] & 0xFF) << 8) | (classBytes[i + 2] & 0xFF);
                next = i + 3;
            } else if (op >= ICONST_0 && op <= ICONST_5) {
                arrayLen = op - ICONST_0;
                next = i + 1;
            } else {
                continue;
            }

            if (arrayLen < 10 || arrayLen > 200 || next >= classBytes.length) continue;
            if ((classBytes[next] & 0xFF) != NEWARRAY || next + 1 >= classBytes.length) continue;
            if ((classBytes[next + 1] & 0xFF) != T_BYTE) continue;

            // Found: push N, newarray T_BYTE — now extract the byte values
            byte[] arr = new byte[arrayLen];
            boolean[] filled = new boolean[arrayLen];
            int pos = next + 2;
            int filledCount = 0;

            while (pos < classBytes.length && filledCount < arrayLen) {
                int b = classBytes[pos] & 0xFF;
                if (b == DUP) {
                    // Expected: dup, index_push, value_push, bastore
                    pos++;
                    if (pos >= classBytes.length) break;
                    // Read index
                    int idx = -1;
                    b = classBytes[pos] & 0xFF;
                    if (b == BIPUSH && pos + 1 < classBytes.length) {
                        idx = classBytes[pos + 1]; if (idx < 0) idx += 256;
                        pos += 2;
                    } else if (b == SIPUSH && pos + 2 < classBytes.length) {
                        idx = ((classBytes[pos + 1] & 0xFF) << 8) | (classBytes[pos + 2] & 0xFF);
                        pos += 3;
                    } else if (b >= ICONST_0 && b <= ICONST_5) {
                        idx = b - ICONST_0;
                        pos++;
                    } else if (b == ICONST_M1) {
                        break; // shouldn't have -1 index
                    } else {
                        break; // unexpected opcode
                    }
                    if (idx < 0 || idx >= arrayLen) break;

                    // Read value
                    if (pos >= classBytes.length) break;
                    int val;
                    b = classBytes[pos] & 0xFF;
                    if (b == BIPUSH && pos + 1 < classBytes.length) {
                        val = classBytes[pos + 1]; // signed byte value
                        pos += 2;
                    } else if (b == SIPUSH && pos + 2 < classBytes.length) {
                        val = (short)(((classBytes[pos + 1] & 0xFF) << 8) | (classBytes[pos + 2] & 0xFF));
                        pos += 3;
                    } else if (b >= ICONST_M1 && b <= ICONST_5) {
                        val = b - ICONST_0; // ICONST_M1=0x02 → -1, ICONST_0=0x03 → 0, etc.
                        pos++;
                    } else {
                        break;
                    }

                    // Expect bastore
                    if (pos >= classBytes.length || (classBytes[pos] & 0xFF) != BASTORE) break;
                    pos++;

                    arr[idx] = (byte) val;
                    filled[idx] = true;
                    filledCount++;
                } else if (b == ARETURN || b == 0x4C || b == 0x4D || b == 0xB3) {
                    // areturn or astore or putstatic — end of array init
                    break;
                } else {
                    // Other opcode — might be control flow obfuscation interleaved
                    // Skip up to 20 bytes looking for next DUP
                    boolean foundDup = false;
                    for (int skip = 1; skip <= 20 && pos + skip < classBytes.length; skip++) {
                        if ((classBytes[pos + skip] & 0xFF) == DUP) {
                            pos += skip;
                            foundDup = true;
                            break;
                        }
                    }
                    if (!foundDup) break;
                }
            }

            // Accept if we filled most of the array (>80%)
            if (filledCount >= arrayLen * 0.8 && filledCount >= 10) {
                results.add(arr);
            }
        }
        return results;
    }

    static Map<String, byte[]> extractByteArrays(String src) { return extractByteArrays(src, null); }

    static Map<String, byte[]> extractByteArrays(String src, Map<String, byte[]> classes) {
        Map<String, byte[]> result = new LinkedHashMap<>();
        Pattern p = Pattern.compile(
            "(?:private |public )?static byte\\[\\]\\s+([\\w$]+)\\(\\)\\s*\\{\\s*return new byte\\[\\]\\{([^}]*)\\}");
        Matcher m = p.matcher(src);
        while (m.find()) {
            byte[] arr = parseByteArray(m.group(2));
            if (arr != null && arr.length > 0) result.put(m.group(1), arr);
        }
        // Bytecode fallback when source extraction found nothing
        if (result.isEmpty() && classes != null) {
            ilog("  Source-level byte arrays not found — trying bytecode extraction...");
            int idx = 0;
            for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                String cname = e.getKey();
                if (!cname.toLowerCase().contains("examplemod") && !cname.toLowerCase().contains("client")
                    && !cname.contains("$")) continue;
                List<byte[]> arrays = extractByteArraysFromBytecode(e.getValue());
                for (byte[] arr : arrays) {
                    result.put("bytecode_" + cname + "_" + (idx++), arr);
                }
            }
            if (!result.isEmpty()) {
                ilog("  Found " + result.size() + " byte array(s) from bytecode extraction");
            }
        }
        return result;
    }

    static byte[] parseByteArray(String csv) {
        try {
            String[] parts = csv.trim().split(",");
            byte[] r = new byte[parts.length];
            for (int i = 0; i < parts.length; i++) r[i] = (byte) Integer.parseInt(parts[i].trim());
            return r;
        } catch (Exception e) { return null; }
    }

    // ─────────────────────────────────────────────────────────────────────
    // N CANDIDATES & XOR DECRYPT
    // ─────────────────────────────────────────────────────────────────────

    static List<Integer> buildNCandidates(String src) {
        Set<Integer> cands = new LinkedHashSet<>();

        // Pattern 1: [int] n2 = 0x... ^ (0x... ^ 0x...) — 'int' prefix is optional for reassignments
        Pattern init3 = Pattern.compile(
            "(?:int\\s+)?n2?\\s*=\\s*(0x[0-9a-fA-F]+)\\s*\\^\\s*\\(\\s*(0x[0-9a-fA-F]+)\\s*\\^\\s*(0x[0-9a-fA-F]+)\\s*\\)");
        List<Integer> inits = new ArrayList<>();
        Matcher m3 = init3.matcher(src);
        while (m3.find()) inits.add(parseHex(m3.group(1)) ^ parseHex(m3.group(2)) ^ parseHex(m3.group(3)));

        // Collect ALL XOR operations: n = 0x... ^ n
        Pattern xorN = Pattern.compile("n2?\\s*=\\s*(0x[0-9a-fA-F]+)\\s*\\^\\s*n2?");
        List<Integer> xors = new ArrayList<>();
        Matcher mx = xorN.matcher(src);
        while (mx.find()) xors.add(parseHex(mx.group(1)));

        // Also match: n ^= 0x...
        Pattern xorAssign = Pattern.compile("n2?\\s*\\^=\\s*(0x[0-9a-fA-F]+|\\d+)");
        Matcher mxa = xorAssign.matcher(src);
        while (mxa.find()) {
            try {
                String val = mxa.group(1);
                xors.add(val.startsWith("0x") ? parseHex(val) : Integer.parseUnsignedInt(val));
            } catch (Exception ignored) {}
        }

        // Build candidates: for each init, apply EVERY xor individually and also chain up to 20 deep
        for (int init : inits) {
            cands.add(init);
            // Apply each XOR value individually from init (each method may use a different XOR)
            for (int xv : xors) { cands.add(init ^ xv); }
            // Chain: apply XORs sequentially up to 20 deep
            int n = init;
            for (int i = 0; i < Math.min(xors.size(), 20); i++) { n = xors.get(i) ^ n; cands.add(n); }
        }

        // Pattern 2: int n = decimal ^ decimal ^ decimal (some samples use decimal instead of hex)
        Pattern initDec = Pattern.compile("int n2?\\s*=\\s*(\\d{6,10})\\s*\\^\\s*\\(\\s*(\\d{6,10})\\s*\\^\\s*(\\d{6,10})\\s*\\)");
        Matcher mdec = initDec.matcher(src);
        while (mdec.find()) {
            try {
                int init2 = Integer.parseUnsignedInt(mdec.group(1)) ^
                             Integer.parseUnsignedInt(mdec.group(2)) ^
                             Integer.parseUnsignedInt(mdec.group(3));
                cands.add(init2);
                for (int xv : xors) { cands.add(init2 ^ xv); }
                int n2 = init2;
                for (int i = 0; i < Math.min(xors.size(), 20); i++) { n2 = xors.get(i) ^ n2; cands.add(n2); }
            } catch (Exception ignored) {}
        }

        // Pattern 3: Method-local XOR chains — find init + sequential XOR in close proximity
        // Find blocks like: n2 = init; ... n2 = 0x... ^ n2; (within ~500 chars)
        for (int init : inits) {
            int startIdx = src.indexOf(Integer.toHexString(init).toUpperCase());
            if (startIdx < 0) startIdx = src.indexOf("0x" + Integer.toHexString(init));
            if (startIdx < 0) continue;
            // Extract the next 2000 chars and find local XOR chain
            String localBlock = src.substring(startIdx, Math.min(src.length(), startIdx + 2000));
            Matcher localXor = xorN.matcher(localBlock);
            int n = init;
            while (localXor.find()) { n = parseHex(localXor.group(1)) ^ n; cands.add(n); }
        }

        ilog("  Candidate n values: " + cands.size());
        return new ArrayList<>(cands);
    }

    static String xorDecrypt(byte[] data, int n, byte[] key) {
        if (data == null || data.length == 0) return null;
        byte[] copy = data.clone();
        byte[] k1 = Integer.toString(n).getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < copy.length; i++) { copy[i] ^= k1[i % k1.length]; copy[i] ^= key[i % key.length]; }
        try { return new String(copy, StandardCharsets.UTF_16); } catch (Exception e) { return null; }
    }

    // ─────────────────────────────────────────────────────────────────────
    // AES KEY RECOVERY
    // ─────────────────────────────────────────────────────────────────────

    static String findAesKey(Map<String, byte[]> arrays, byte[] xorKey,
                              List<Integer> nCandidates, String configRaw) {
        // Pass 1: try with the primary XOR key
        String result = tryAesKeyWithXorKey(arrays, xorKey, nCandidates, configRaw);
        if (result != null) return result;

        // Pass 2: try every other byte array as a potential alternate XOR key
        // (some variants use a different XOR key per class/method)
        ilog("  Primary XOR key failed, trying alternate XOR keys from byte array pool...");
        for (Map.Entry<String, byte[]> ke : arrays.entrySet()) {
            byte[] altKey = ke.getValue();
            if (altKey.length < 20 || altKey.length > 120) continue;
            if (Arrays.equals(altKey, xorKey)) continue; // skip the one we already tried
            result = tryAesKeyWithXorKey(arrays, altKey, nCandidates, configRaw);
            if (result != null) {
                ilog("  Found AES key using alternate XOR key: " + ke.getKey() + " (" + altKey.length + " bytes)");
                return result;
            }
        }

        // Pass 3: Algebraic n-recovery with primary XOR key
        ilog("  Widening to algebraic n-recovery...");
        System.out.println("    Widening to algebraic n-recovery...");
        return algebraicRecover(arrays, xorKey, xorKey.length, configRaw);
    }

    static String tryAesKeyWithXorKey(Map<String, byte[]> arrays, byte[] xorKey,
                                       List<Integer> nCandidates, String configRaw) {
        for (Map.Entry<String, byte[]> e : arrays.entrySet()) {
            byte[] data = e.getValue();
            if (data.length < 20 || data.length > 200) continue;
            if (Arrays.equals(data, xorKey)) continue; // don't try XOR key against itself
            for (int n : nCandidates) {
                String r = xorDecrypt(data, n, xorKey);
                if (!isAsciiPrintable(r) || r.length() < 12 || r.length() > 64) continue;
                if (configRaw == null || decryptConfig(configRaw, r) != null) {
                    ilog("  AES key: " + e.getKey() + " [n=" + n + "] => \"" + r + "\"");
                    System.out.println("    AES key: " + e.getKey() + " [n=" + n + "] => \"" + r + "\"");
                    return r;
                }
            }
        }
        return null;
    }

    static String algebraicRecover(Map<String, byte[]> arrays, byte[] xorKey,
                                    int xorLen, String configRaw) {
        for (Map.Entry<String, byte[]> e : arrays.entrySet()) {
            byte[] arr = e.getValue();
            int len = arr.length;
            if (len < 20 || len > 200 || len % 2 != 0) continue;
            for (int ndl = 1; ndl <= 10; ndl++) {
                for (int mode = 0; mode <= 3; mode++) {
                    int[] known = new int[ndl];
                    Arrays.fill(known, -1);
                    boolean conflict = false;
                    if (mode >= 2) {
                        int bom0 = (mode == 2) ? 0xFF : 0xFE, bom1 = (mode == 2) ? 0xFE : 0xFF;
                        int req0 = (arr[0] & 0xFF) ^ (xorKey[0 % xorLen] & 0xFF) ^ bom0;
                        int req1 = (arr[1] & 0xFF) ^ (xorKey[1 % xorLen] & 0xFF) ^ bom1;
                        if (req0 < '0' || req0 > '9' || req1 < '0' || req1 > '9') { conflict = true; }
                        else {
                            int dp0 = 0 % ndl, dp1 = 1 % ndl;
                            if (known[dp0] == -1) known[dp0] = req0 - '0'; else if (known[dp0] != req0 - '0') conflict = true;
                            if (!conflict) { if (known[dp1] == -1) known[dp1] = req1 - '0'; else if (known[dp1] != req1 - '0') conflict = true; }
                        }
                    }
                    int start = (mode >= 2) ? 2 : 0;
                    for (int i = start; i < len && !conflict; i++) {
                        boolean isZero = (mode == 0) ? (i % 2 == 0) : (mode == 1) ? (i % 2 == 1)
                                       : (mode == 2) ? ((i - 2) % 2 == 1) : ((i - 2) % 2 == 0);
                        if (!isZero) continue;
                        int req = (arr[i] & 0xFF) ^ (xorKey[i % xorLen] & 0xFF);
                        if (req < '0' || req > '9') { conflict = true; break; }
                        int dp = i % ndl;
                        if (known[dp] == -1) known[dp] = req - '0';
                        else if (known[dp] != req - '0') { conflict = true; break; }
                    }
                    if (conflict) continue;
                    int freeCount = 0; int[] freePos = new int[ndl];
                    for (int p2 = 0; p2 < ndl; p2++) if (known[p2] == -1) freePos[freeCount++] = p2;
                    long enumSize = 1;
                    for (int f = 0; f < freeCount; f++) { enumSize *= 10; if (enumSize > 200_000) break; }
                    if (enumSize > 200_000) continue;
                    int[] freeVals = new int[freeCount];
                    for (long combo = 0; combo < enumSize; combo++) {
                        long tmp = combo;
                        for (int f = freeCount - 1; f >= 0; f--) { freeVals[f] = (int)(tmp % 10); tmp /= 10; }
                        int[] digits = known.clone();
                        for (int f = 0; f < freeCount; f++) digits[freePos[f]] = freeVals[f];
                        long nVal = 0; boolean overflow = false;
                        for (int d : digits) { nVal = nVal * 10 + d; if (nVal > Integer.MAX_VALUE) { overflow = true; break; } }
                        if (overflow || nVal < 0) continue;
                        String r = xorDecrypt(arr, (int) nVal, xorKey);
                        if (!isAsciiPrintable(r) || r.length() < 12 || r.length() > 64) continue;
                        if (configRaw == null || decryptConfig(configRaw, r) != null) {
                            ilog("  AES key (algebraic): " + e.getKey() + " [n=" + nVal + " mode=" + mode + "] => \"" + r + "\"");
                            return r;
                        }
                    }
                }
            }
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // AES DECRYPTION (CBC, GCM, ECB)
    // ─────────────────────────────────────────────────────────────────────

    static String decryptConfig(String raw, String aesKeyStr) {
        try {
            String[] parts = raw.split(":");
            if (parts.length < 2) return null;
            byte[] cipher = hexToBytes(parts[1]);
            byte[] fileIv = (parts[0].matches("[0-9a-fA-F]+") && parts[0].length() == 32) ? hexToBytes(parts[0]) : null;
            byte[] keyB   = aesKeyStr.getBytes(StandardCharsets.UTF_8);
            List<byte[]> keySizes = new ArrayList<>();
            if (keyB.length == 16 || keyB.length == 24 || keyB.length == 32) keySizes.add(keyB);
            for (int sz : new int[]{16, 24, 32}) keySizes.add(Arrays.copyOf(keyB, sz));

            // AES-CBC
            if (cipher.length >= 16) {
                byte[] iv = Arrays.copyOfRange(cipher, 0, 16);
                byte[] dt = Arrays.copyOfRange(cipher, 16, cipher.length);
                for (byte[] tryKey : keySizes) {
                    for (String mode : new String[]{"AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"}) {
                        List<byte[]> ivCands = new ArrayList<>(Arrays.asList(iv,
                            Arrays.copyOfRange(tryKey, 0, Math.min(16, tryKey.length)), new byte[16]));
                        if (fileIv != null) ivCands.add(0, fileIv);
                        for (byte[] tryIv : ivCands) {
                            byte[] tryData = (fileIv != null && tryIv == fileIv) ? cipher
                                           : (Arrays.equals(tryIv, iv) ? dt : cipher);
                            try {
                                SecretKeySpec ks = new SecretKeySpec(tryKey, "AES");
                                Cipher c = Cipher.getInstance(mode);
                                c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(tryIv));
                                String s = new String(c.doFinal(tryData), StandardCharsets.UTF_8).trim();
                                if (looksLikeJson(s)) return s;
                            } catch (Exception ignored) {}
                        }
                    }
                }
            }
            // AES-GCM
            if (cipher.length >= 12) {
                byte[] gcmIv = Arrays.copyOfRange(cipher, 0, 12);
                byte[] gcmDt = Arrays.copyOfRange(cipher, 12, cipher.length);
                for (byte[] tryKey : keySizes) {
                    try {
                        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tryKey, "AES"), new GCMParameterSpec(128, gcmIv));
                        String s = new String(c.doFinal(gcmDt), StandardCharsets.UTF_8).trim();
                        if (looksLikeJson(s)) return s;
                    } catch (Exception ignored) {}
                }
            }
            // AES-ECB
            for (byte[] tryKey : keySizes) {
                try {
                    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tryKey, "AES"));
                    String s = new String(c.doFinal(cipher), StandardCharsets.UTF_8).trim();
                    if (looksLikeJson(s)) return s;
                } catch (Exception ignored) {}
            }
        } catch (Exception e) { warn("Decrypt error: " + e.getMessage()); }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // FIELD-NAME-INDEPENDENT VALUE EXTRACTORS
    // ─────────────────────────────────────────────────────────────────────

    static String findWebhook(String json) {
        Matcher m = Pattern.compile("https?://discord\\.com/api/webhooks/[^\"\\s]+").matcher(json);
        if (m.find()) return m.group(0);
        return null;
    }

    /**
     * Check if a Discord webhook is still active.
     * GET the webhook URL — Discord returns 200 if alive, 404 if deleted.
     * Returns "ACTIVE", "DEAD", or "UNKNOWN (HTTP <code>)".
     */
    static String checkWebhookStatus(String webhookUrl) {
        // Only connect to Discord — never follow attacker URLs
        if (!webhookUrl.startsWith("https://discord.com/api/webhooks/")) return "SKIP (non-Discord URL)";
        try {
            // POST an intentionally empty payload — Discord returns 400 "Cannot send an
            // empty message" (code 50006) for live webhooks, and 404/403/401 for dead ones.
            // This confirms the webhook can actually receive messages without sending one.
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .header("Content-Type", "application/json")
                .header("User-Agent", "Mozilla/5.0")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
            HttpResponse<String> resp = SHARED_HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            int code = resp.statusCode();
            String body = resp.body() != null ? resp.body() : "";
            if (code == 400 && body.contains("50006")) return "ACTIVE";
            if (code == 401) return "DEAD (token invalid)";
            if (code == 403) return "DEAD (forbidden/disabled)";
            if (code == 404) return "DEAD (deleted/reported)";
            if (code == 429) return "DEAD (rate limited — recheck manually)";
            // 204 = message actually sent (shouldn't happen with {} but handle it)
            if (code == 204 || code == 200) return "ACTIVE";
            String bodySnippet = body.replaceAll("\\s+", " ");
            return "UNKNOWN (HTTP " + code + " — " + bodySnippet.substring(0, Math.min(80, bodySnippet.length())) + ")";
        } catch (Exception e) {
            return "UNKNOWN (error: " + e.getMessage() + ")";
        }
    }

    /** Appends a confirmed active webhook to webhook.log in the working directory.
     *  If the webhook URL already exists in the log, the source JAR name is appended
     *  to that line so all source files are recorded per unique webhook. */
    static synchronized void appendWebhookLog(String sourceJar, String webhookUrl) {
        try {
            Path log = Paths.get("webhook.log");
            if (Files.exists(log)) {
                List<String> lines = new ArrayList<>(Files.readAllLines(log, StandardCharsets.UTF_8));
                for (int i = 0; i < lines.size(); i++) {
                    if (lines.get(i).contains(webhookUrl)) {
                        // Append this JAR name to the existing line if not already listed
                        if (!lines.get(i).contains(sourceJar)) {
                            lines.set(i, lines.get(i) + ", " + sourceJar);
                            Files.write(log, lines, StandardCharsets.UTF_8,
                                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
                        }
                        return;
                    }
                }
            }
            // New webhook — write a new line: "JAR1 | https://..."
            String line = sourceJar + " | " + webhookUrl;
            Files.write(log, (line + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {}
    }

    static String findSnowflake(String json) {
        Matcher m = Pattern.compile("\"(\\d{17,20})\"").matcher(json);
        while (m.find()) {
            try {
                long id = Long.parseUnsignedLong(m.group(1));
                long ts = (id >> 22) + 1420070400000L;
                if (ts > 1420070400000L && ts < 2051222400000L) return m.group(1);
            } catch (Exception ignored) {}
        }
        return null;
    }

    static String findPremiumBool(String json) {
        Matcher m = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(true|false)").matcher(json);
        while (m.find()) { if (!m.group(1).equals("enabled")) return m.group(2); }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DYNAMIC FIELD DISCOVERY (unknown obfuscated field names)
    // ─────────────────────────────────────────────────────────────────────

    static Map<String, String> dynamicFieldDiscovery(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        Pattern p = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|([^,}\\]]+))");
        Matcher m = p.matcher(json);
        while (m.find()) {
            String key = m.group(1);
            if (FIELD_MAP.containsKey(key)) continue;
            String val = m.group(2) != null ? m.group(2) : (m.group(3) != null ? m.group(3).trim() : "");
            String label;
            if (val.matches("https?://discord\\.com/api/webhooks/.*")) label = "Discord Webhook URL";
            else if (val.matches("https?://.*"))     label = "URL";
            else if (val.matches("\\d{17,20}"))      label = "Discord Snowflake ID";
            else if (val.equals("true") || val.equals("false")) label = "Boolean flag";
            else if (val.matches("\\d+"))            label = "Numeric value";
            else if (val.isEmpty() || val.equals("-")) label = "Empty/disabled";
            else if (val.startsWith("{"))            label = "Nested object";
            else                                     label = "Unknown string";
            result.put(key, label + " [value: " + val + "]");
        }
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DECRYPTED STRING URL SCAN
    // ─────────────────────────────────────────────────────────────────────

    static List<String> scanDecryptedStrings(Map<String, byte[]> arrays, byte[] xorKey, List<Integer> nCandidates) {
        Set<String> found = new LinkedHashSet<>();
        Pattern urlPat = Pattern.compile("https?://[^\\s\"'<>]+");
        for (Map.Entry<String, byte[]> e : arrays.entrySet()) {
            for (int n : nCandidates) {
                String r = xorDecrypt(e.getValue(), n, xorKey);
                if (r == null) continue;
                Matcher m = urlPat.matcher(r);
                while (m.find()) { String u = m.group(); if (found.add(u)) ilog("  [URL] " + u); }
            }
        }
        return new ArrayList<>(found);
    }

    // ─────────────────────────────────────────────────────────────────────
    // CONFIG PRINT (console + info.log)
    // ─────────────────────────────────────────────────────────────────────

    static void printConfig(String json, Map<String, String> unknownFields, String webhook, String webhookStatus) {
        String pretty = prettyJson(json);
        System.out.println(); System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + GREEN + "  DECRYPTED CONFIG" + RESET);
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(pretty);
        System.out.println(GREEN + "════════════════════════════════════════" + RESET);
        llog(""); llog("== DECRYPTED CONFIG ====================================");
        llog(pretty); llog("========================================================");

        System.out.println(); System.out.println(BOLD + CYAN + "-- Field Meanings --------------------------------------" + RESET);
        llog(""); llog("-- Field Meanings ---");
        for (Map.Entry<String, String> e : FIELD_MAP.entrySet()) {
            if (!json.contains("\"" + e.getKey() + "\"")) continue;
            String val = extractJsonValue(json, e.getKey());
            System.out.println(YELLOW + "  \"" + e.getKey() + "\"" + RESET + "  ->  " + CYAN + (val != null ? val : "") + RESET + "  (" + e.getValue() + ")");
            llog(String.format("  %-10s  ->  %-28s  %s", "\"" + e.getKey() + "\"", val != null ? val : "", e.getValue()));
        }
        if (!unknownFields.isEmpty()) {
            System.out.println(BOLD + CYAN + "-- UNKNOWN FIELDS (possible new version) ---------------" + RESET);
            llog("-- UNKNOWN FIELDS ---");
            unknownFields.forEach((k, v) -> {
                System.out.println(YELLOW + "  \"" + k + "\"  =>  " + v + RESET);
                llog("  \"" + k + "\"  =>  " + v);
            });
        }
        System.out.println(CYAN + "--------------------------------------------------------" + RESET);
        llog("----------------------------------------------------");

        if (webhook != null) {
            boolean alive = webhookStatus != null && webhookStatus.equals("ACTIVE");
            String statusColor = alive ? GREEN : RED;
            System.out.println(YELLOW + "  Discord Webhook  ->  " + webhook + RESET);
            System.out.println(statusColor + "  Webhook Status   ->  " + (webhookStatus != null ? webhookStatus : "UNKNOWN") + RESET);
            llog("  Discord Webhook  ->  " + webhook);
            llog("  Webhook Status   ->  " + (webhookStatus != null ? webhookStatus : "UNKNOWN"));
            if (alive) appendWebhookLog(jarName, webhook);
        }
        Pattern sf = Pattern.compile("\"(\\d{17,20})\""); Matcher sm = sf.matcher(json);
        while (sm.find()) {
            try {
                long id = Long.parseUnsignedLong(sm.group(1));
                long ts = (id >> 22) + 1420070400000L;
                String ln = "  Snowflake " + sm.group(1) + "  ->  created ~" + java.time.Instant.ofEpochMilli(ts);
                System.out.println(YELLOW + ln + RESET); llog(ln);
            } catch (Exception ignored) {}
        }
        Pattern tp = Pattern.compile("\"timestamp\"\\s*:\\s*(\\d{13})"); Matcher tm = tp.matcher(json);
        if (tm.find()) {
            String ln = "  Config timestamp  ->  " + java.time.Instant.ofEpochMilli(Long.parseLong(tm.group(1)));
            System.out.println(YELLOW + ln + RESET); llog(ln);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // CONFIG LOG WRITER (AdamRat)
    // ─────────────────────────────────────────────────────────────────────

    static void writeConfigLog(String jarPath, String configFilename, String aesKey,
                                byte[] xorKey, String json, String ts, String sha256,
                                Map<String, String> unknownFields, List<String> extraUrls,
                                String webhook, String webhookStatus) {
        String pretty = prettyJson(json);
        String line   = "=".repeat(50);
        clog(line); clog("  Decrypted Config"); clog("  " + ts); clog(line); clog("");
        clog("Sample      : " + jarPath); clog("SHA-256     : " + sha256);
        clog("Config file : " + configFilename); clog("AES key     : " + aesKey);
        clog("XOR key     : " + hexFull(xorKey)); clog("");
        clog("-- RAW JSON -------------------------------------------------"); clog(pretty); clog("");
        clog("-- DECODED FIELDS -------------------------------------------");
        boolean any = false;
        for (Map.Entry<String, String> e : FIELD_MAP.entrySet()) {
            if (!json.contains("\"" + e.getKey() + "\"")) continue;
            String val = extractJsonValue(json, e.getKey());
            clog(String.format("  %-14s  %-30s  %s", e.getValue().split(" ")[0], val != null ? val : "(not found)", e.getValue()));
            any = true;
        }
        if (!any) clog("  (no known field mappings matched)");
        clog("");
        if (!unknownFields.isEmpty()) {
            clog("-- UNKNOWN FIELDS (possible new version) --------------------");
            unknownFields.forEach((k, v) -> clog("  \"" + k + "\"  =>  " + v));
            clog("");
        }
        clog("-- INDICATORS OF COMPROMISE (IOCs) --------------------------");
        String webhookId = null;
        if (webhook != null) {
            clog("  Discord Webhook  : " + webhook);
            clog("  Webhook Status   : " + (webhookStatus != null ? webhookStatus : "UNKNOWN"));
            Matcher wm = Pattern.compile("webhooks/(\\d+)/").matcher(webhook);
            if (wm.find()) { webhookId = wm.group(1); clog("  Webhook ID       : " + webhookId); }
            if (webhookStatus != null && webhookStatus.equals("ACTIVE")) appendWebhookLog(jarName, webhook);
        }
        String userId = findSnowflake(json);
        if (userId != null) {
            clog("  Attacker User ID : " + userId);
            try { long id = Long.parseUnsignedLong(userId); clog("  Account Created  : " + java.time.Instant.ofEpochMilli((id >> 22) + 1420070400000L)); }
            catch (Exception ignored) {}
        }
        // Value-based URL extraction — independent of field name obfuscation
        Pattern urlValPat = Pattern.compile("\"(https?://[^\"]+)\"");
        Matcher uvm = urlValPat.matcher(json);
        Set<String> seenUrls = new LinkedHashSet<>();
        while (uvm.find()) {
            String u = uvm.group(1);
            if (seenUrls.add(u)) {
                clog("  URL              : " + u);
                Matcher dm = Pattern.compile("https?://([^/]+)").matcher(u);
                if (dm.find()) clog("  Domain           : " + dm.group(1));
            }
        }
        Matcher tm2 = Pattern.compile("\"timestamp\"\\s*:\\s*(\\d{13})").matcher(json);
        if (tm2.find()) clog("  Config Timestamp : " + java.time.Instant.ofEpochMilli(Long.parseLong(tm2.group(1))));
        String prem = findPremiumBool(json);
        if (prem != null) clog("  Premium Build    : " + prem);

        // AutoPay — field-name-independent: look for nested object with enabled + numeric fields
        Matcher apM = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\\{([^}]+)\\}").matcher(json);
        while (apM.find()) {
            String sub = apM.group(2);
            if (sub.contains("false") || sub.contains("true")) {
                if (sub.matches("[^{]*\"[^\"]+\"\\s*:\\s*(true|false)[^{]*")) {
                    clog(""); clog("-- AUTOPAY CONFIG -------------------------------------------");
                    Matcher fm = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(?:\"([^\"]*)\"|([^,}]+))").matcher(sub);
                    while (fm.find()) {
                        String k = fm.group(1), v = fm.group(2) != null ? fm.group(2) : fm.group(3).trim();
                        String label = FIELD_MAP.getOrDefault(k, k);
                        clog("  " + label.split(" ")[0] + " : " + v);
                    }
                    break;
                }
            }
        }

        if (!extraUrls.isEmpty()) {
            clog(""); clog("-- EXTRA URLs (from decrypted strings) ----------------------");
            extraUrls.forEach(u -> clog("  " + u));
        }

        // Blocklist check
        Set<String> blocklist = loadBlocklist();
        if (!blocklist.isEmpty()) {
            clog(""); clog("-- BLOCKLIST CHECK ------------------------------------------");
            Set<String> allCheck = new LinkedHashSet<>(seenUrls); allCheck.addAll(extraUrls);
            if (webhookId != null) allCheck.add(webhookId); if (userId != null) allCheck.add(userId);
            boolean anyHit = false;
            for (String candidate : allCheck) {
                for (String entry : blocklist) {
                    if (candidate.contains(entry) || entry.contains(candidate)) {
                        clog("  [KNOWN BAD] matched: " + entry); warn("BLOCKLIST HIT: " + entry); anyHit = true;
                    }
                }
            }
            if (!anyHit) clog("  No blocklist matches found");
        }
        clog(""); clog(line);
    }

    // ─────────────────────────────────────────────────────────────────────
    // EXTERNAL CONFIG LOADERS
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Load config.properties and merge into CFG (overrides built-in defaults).
     * Any key present in config.properties replaces the corresponding default.
     */
    static void loadConfig() {
        Path f = Paths.get("config.properties");
        if (!Files.exists(f)) f = Paths.get("tools", "config.properties");
        if (!Files.exists(f)) return;
        try {
            java.util.Properties overrides = new java.util.Properties();
            try (java.io.Reader r = Files.newBufferedReader(f)) { overrides.load(r); }
            for (String key : overrides.stringPropertyNames()) {
                CFG.setProperty(key, overrides.getProperty(key));
            }
            System.out.println(GREEN + "[+] " + RESET
                + "Loaded " + overrides.size() + " override(s) from config.properties");
        } catch (Exception e) {
            System.err.println("Could not read config.properties: " + e.getMessage());
        }
    }

    /** Load extra campaign UUIDs from campaigns.properties (UUID=Name per line). */
    static void loadCampaigns() {
        Path f = Paths.get("campaigns.properties");
        if (!Files.exists(f)) f = Paths.get("tools", "campaigns.properties");
        if (!Files.exists(f)) return;
        try {
            for (String line : Files.readAllLines(f)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq > 0) CAMPAIGN_MAP.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
            System.out.println(GREEN + "[+] " + RESET + "Loaded " + CAMPAIGN_MAP.size() + " campaigns from campaigns.properties");
        } catch (Exception e) { System.err.println("Could not read campaigns.properties: " + e.getMessage()); }
    }

    /** Load extra field mappings from field_map.properties (jsonKey=Label per line). */
    static void loadExtraFieldMap() {
        Path f = Paths.get("field_map.properties");
        if (!Files.exists(f)) f = Paths.get("tools", "field_map.properties");
        if (!Files.exists(f)) return;
        try {
            for (String line : Files.readAllLines(f)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq > 0) FIELD_MAP.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
            System.out.println(GREEN + "[+] " + RESET + "Loaded extra field mappings from field_map.properties");
        } catch (Exception e) { System.err.println("Could not read field_map.properties: " + e.getMessage()); }
    }

    /** Check if an IP (v4 or v6) is private, loopback, link-local, or otherwise non-routable. */
    static boolean isPrivateOrInvalidIP(String ip) {
        // IPv6 detection
        if (ip.contains(":")) {
            String lower = ip.toLowerCase();
            if (lower.equals("::1")) return true;                        // loopback
            if (lower.equals("::")) return true;                         // unspecified
            if (lower.startsWith("fe80:") || lower.startsWith("fe80%")) return true;  // link-local
            if (lower.startsWith("fc") || lower.startsWith("fd")) return true;        // unique local (fc00::/7)
            if (lower.startsWith("ff")) return true;                     // multicast
            if (lower.startsWith("::ffff:")) {                           // IPv4-mapped IPv6
                String v4 = lower.substring(7);
                if (v4.contains(".")) return isPrivateOrInvalidIP(v4);
            }
            return false;
        }
        // IPv4
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return true;
        try {
            int[] o = new int[4];
            for (int i = 0; i < 4; i++) { o[i] = Integer.parseInt(parts[i]); if (o[i] < 0 || o[i] > 255) return true; }
            if (o[0] == 0 || o[0] == 127) return true;                 // loopback/unspecified
            if (o[0] == 10) return true;                                // 10.0.0.0/8
            if (o[0] == 192 && o[1] == 168) return true;               // 192.168.0.0/16
            if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;  // 172.16.0.0/12
            if (o[0] == 169 && o[1] == 254) return true;               // link-local
            if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return true; // CGNAT
            if (o[0] >= 224) return true;                               // multicast + reserved
            if (ip.equals("255.255.255.255")) return true;              // broadcast
        } catch (NumberFormatException e) { return true; }
        return false;
    }

    static Set<String> cachedBlocklist = null;

    static Set<String> loadBlocklist() {
        if (cachedBlocklist != null) return cachedBlocklist;
        Set<String> entries = new LinkedHashSet<>();
        Path bl = Paths.get("blocklist.txt");
        if (!Files.exists(bl)) bl = Paths.get("tools", "blocklist.txt");
        if (!Files.exists(bl)) { cachedBlocklist = entries; return entries; }
        try {
            for (String line : Files.readAllLines(bl)) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) entries.add(line);
            }
        } catch (Exception ignored) {}
        cachedBlocklist = entries;
        return entries;
    }

    // ─────────────────────────────────────────────────────────────────────
    // DECOMPILER MANAGEMENT
    // ─────────────────────────────────────────────────────────────────────

    /** Find a decompiler tool by name pattern (vineflower.jar, jadx, cfr-*.jar) */
    static String findDecompiler(String hint) {
        try {
            String self = JarAnalyzer.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            Path dir = Paths.get(self).getParent();
            if (dir != null) {
                if (hint.equals("jadx")) {
                    Path jadxAll = dir.resolve("jadx/lib/jadx-1.5.1-all.jar");
                    if (Files.exists(jadxAll)) return jadxAll.toString();
                    // Try glob
                    try (var s = Files.list(dir.resolve("jadx/lib"))) {
                        var found = s.filter(p -> p.getFileName().toString().startsWith("jadx-") && p.getFileName().toString().endsWith("-all.jar")).findFirst();
                        if (found.isPresent()) return found.get().toString();
                    } catch (Exception ignored) {}
                } else {
                    Path p = dir.resolve(hint);
                    if (Files.exists(p)) return p.toString();
                }
            }
        } catch (Exception ignored) {}
        // Check CWD and tools/ subdirectory
        for (String base : new String[]{"", "tools/"}) {
            if (hint.equals("jadx")) {
                // Try glob first to find any jadx version
                try (var s = Files.list(Paths.get(base + "jadx/lib"))) {
                    var found = s.filter(p -> p.getFileName().toString().startsWith("jadx-")
                            && p.getFileName().toString().endsWith("-all.jar")).findFirst();
                    if (found.isPresent()) return found.get().toString();
                } catch (Exception ignored) {}
                // Fall back to hardcoded name
                Path jadxAll = Paths.get(base + "jadx/lib/jadx-1.5.1-all.jar");
                if (Files.exists(jadxAll)) return jadxAll.toString();
            } else {
                Path p = Paths.get(base + hint);
                if (Files.exists(p)) return p.toString();
            }
        }
        return null;
    }

    /** Repackage a JAR, fixing entries with trailing "/" on .class files */
    /** Build a stripped JAR containing only non-library classes + resources.
     *  This dramatically speeds up decompilation by excluding bundled dependencies
     *  (Gson, Apache, Kotlin, Minecraft internals, etc.). Also fixes trailing / entries. */
    static Path buildStrippedJar(String jarPath, Path tempDir, boolean fixTrailingSlash) throws Exception {
        Path stripped = tempDir.resolve("stripped.jar");
        int kept = 0, skipped = 0;
        try (ZipFile zf = new ZipFile(jarPath);
             java.util.jar.JarOutputStream jos = new java.util.jar.JarOutputStream(
                 new FileOutputStream(stripped.toFile()))) {
            var entries = zf.entries();
            Set<String> written = new HashSet<>();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                // Fix trailing / on class entries
                if (fixTrailingSlash && name.endsWith(".class/")) {
                    name = name.substring(0, name.length() - 1);
                }
                // Sanitize path traversal
                if (name.contains("..") || name.startsWith("/") || name.startsWith("\\")) continue;
                if (written.contains(name)) continue;
                // Skip library classes
                if (name.endsWith(".class")) {
                    String underscore = name.replace('/', '_').replace('\\', '_');
                    if (isLibraryClass(underscore)) {
                        skipped++;
                        continue;
                    }
                }
                written.add(name);
                ZipEntry newEntry = new ZipEntry(name);
                jos.putNextEntry(newEntry);
                if (!entry.isDirectory() || entry.getSize() > 0) {
                    try (InputStream is = zf.getInputStream(entry)) {
                        is.transferTo(jos);
                    }
                }
                jos.closeEntry();
                if (name.endsWith(".class")) kept++;
            }
        }
        if (skipped > 0)
            clog("  Stripped " + skipped + " library class(es), kept " + kept + " for analysis");
        return stripped;
    }

    static Path repackageCleanJar(String jarPath, Path tempDir) throws Exception {
        Path cleanJar = tempDir.resolve("clean.jar");
        try (ZipFile zf = new ZipFile(jarPath);
             java.util.jar.JarOutputStream jos = new java.util.jar.JarOutputStream(
                 new FileOutputStream(cleanJar.toFile()))) {
            var entries = zf.entries();
            Set<String> written = new HashSet<>();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                // Fix: strip trailing / from .class/ entries
                if (name.endsWith(".class/")) {
                    name = name.substring(0, name.length() - 1);
                }
                // Sanitize: prevent path traversal via ../
                if (name.contains("..") || name.startsWith("/") || name.startsWith("\\")) continue;
                if (written.contains(name)) continue;
                written.add(name);
                ZipEntry newEntry = new ZipEntry(name);
                jos.putNextEntry(newEntry);
                if (!entry.isDirectory() || entry.getSize() > 0) {
                    try (InputStream is = zf.getInputStream(entry)) {
                        is.transferTo(jos);
                    }
                }
                jos.closeEntry();
            }
        }
        return cleanJar;
    }

    /** Drain a process's stdout/stderr in a daemon thread to prevent deadlocks.
     *  Returns immediately — the thread runs in the background. */
    static void drainProcessOutput(Process p) {
        Thread t = new Thread(() -> {
            try { p.getInputStream().transferTo(OutputStream.nullOutputStream()); }
            catch (Exception ignored) {}
        });
        t.setDaemon(true);
        t.start();
    }

    /** Run a decompiler process with proper timeout handling.
     *  Returns true if the process completed within the timeout. */
    static boolean runDecompilerProcess(Process p, int timeoutSeconds) throws InterruptedException {
        drainProcessOutput(p);
        boolean done = p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
        if (!done) {
            p.destroyForcibly();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
        } else {
            p.destroyForcibly();
        }
        return done;
    }

    /** Decompile a full JAR using cascade: Vineflower -> JADX -> Procyon -> CFR.
     *  After each decompiler, checks that critical files actually decompiled
     *  (not just error stubs). Falls through if key files have "Couldn't be decompiled". */
    static String decompileFullJar(String jarPath, Path sourceDir, String vineflower, String jadx, String procyon, String cfr, long classCount) {
        // Scale timeout and heap based on class count
        // Base: 120s / 512m for ≤50 classes. Scale up for larger JARs.
        int decompileTimeout = (int) Math.min(600, Math.max(120, classCount * 2));
        String heap = classCount > 500 ? "-Xmx2g" : classCount > 100 ? "-Xmx1g" : "-Xmx512m";
        clog("  Decompile budget: " + classCount + " classes, timeout=" + decompileTimeout + "s, heap=" + heap);

        // Try Vineflower first (best output quality)
        if (vineflower != null) {
            try {
                step("  Trying Vineflower...");
                Process p = new ProcessBuilder("java", heap, "-jar", vineflower,
                        "-ren=1", "-thr=4", "-dgs=1", "-lit=1",
                        jarPath, sourceDir.toString())
                    .redirectErrorStream(true).start();
                boolean done = runDecompilerProcess(p, decompileTimeout);
                if (!done) warn("  Vineflower timed out after " + decompileTimeout + "s");
                long fileCount = countJavaFiles(sourceDir);
                long failedCount = countFailedDecompiles(sourceDir);
                if (fileCount > 0 && failedCount == 0) {
                    ok("  Vineflower produced " + fileCount + " .java file(s)");
                    return "Vineflower";
                } else if (fileCount > 0 && failedCount > 0) {
                    warn("  Vineflower produced " + fileCount + " file(s) but " + failedCount + " failed to decompile — trying other decompilers for failed files");
                    // Keep Vineflower output but supplement with other decompilers
                    String supplement = supplementFailedFiles(jarPath, sourceDir, jadx, procyon, cfr, decompileTimeout, heap);
                    return "Vineflower+" + supplement;
                }
            } catch (Exception e) {
                warn("  Vineflower failed: " + e.getMessage());
            }
        }

        // Try JADX (good deobfuscation)
        if (jadx != null) {
            try {
                step("  Trying JADX...");
                Process p = new ProcessBuilder("java", heap, "-jar", jadx, "--deobf", "-d", sourceDir.toString(), jarPath)
                    .redirectErrorStream(true).start();
                boolean done = runDecompilerProcess(p, decompileTimeout);
                if (!done) warn("  JADX timed out after " + decompileTimeout + "s");
                long fileCount = countJavaFiles(sourceDir);
                if (fileCount > 0) {
                    ok("  JADX produced " + fileCount + " .java file(s)");
                    return "JADX";
                }
            } catch (Exception e) {
                warn("  JADX failed: " + e.getMessage());
            }
        }

        // Try Procyon (handles complex control flow well)
        if (procyon != null) {
            try {
                step("  Trying Procyon...");
                Process p = new ProcessBuilder("java", heap, "-jar", procyon,
                        "-jar", jarPath, "-o", sourceDir.toString())
                    .redirectErrorStream(true).start();
                boolean done = runDecompilerProcess(p, decompileTimeout);
                if (!done) warn("  Procyon timed out after " + decompileTimeout + "s");
                long fileCount = countJavaFiles(sourceDir);
                if (fileCount > 0) {
                    ok("  Procyon produced " + fileCount + " .java file(s)");
                    return "Procyon";
                }
            } catch (Exception e) {
                warn("  Procyon failed: " + e.getMessage());
            }
        }

        // Fallback: CFR per-class
        if (cfr != null) {
            try {
                step("  Falling back to CFR per-class...");
                Process p = new ProcessBuilder("java", heap, "-jar", cfr, jarPath,
                        "--outputdir", sourceDir.toString(), "--renameillegalidents", "true")
                    .redirectErrorStream(true).start();
                boolean done = runDecompilerProcess(p, decompileTimeout);
                if (!done) warn("  CFR timed out after " + decompileTimeout + "s");
                long fileCount = countJavaFiles(sourceDir);
                if (fileCount > 0) return "CFR";
            } catch (Exception e) {
                warn("  CFR failed: " + e.getMessage());
            }
        }
        return "none";
    }

    /** Count .java files that contain "Couldn't be decompiled" or are empty/stub */
    static long countFailedDecompiles(Path dir) {
        try (var walker = Files.walk(dir)) {
            return walker
                .filter(p -> p.toString().endsWith(".java"))
                .filter(p -> {
                    try {
                        long size = Files.size(p);
                        if (size == 0) return true; // 0-byte file = decompiler created it but wrote nothing
                        String content = Files.readString(p);
                        return content.contains("Couldn't be decompiled")
                            || content.contains("// Failed to decompile")
                            || content.trim().isEmpty()
                            || (size < 50 && !content.contains("class ") && !content.contains("interface ")); // stub file
                    } catch (Exception e) { return false; }
                })
                .count();
        } catch (Exception e) { return 0; }
    }

    /** Re-decompile files that Vineflower failed on using JADX, Procyon, or CFR */
    static String supplementFailedFiles(String jarPath, Path sourceDir, String jadx, String procyon, String cfr) { return supplementFailedFiles(jarPath, sourceDir, jadx, procyon, cfr, 120, "-Xmx512m"); }
    static String supplementFailedFiles(String jarPath, Path sourceDir, String jadx, String procyon, String cfr, int timeout, String heap) {
        try {
            // Find which .java files failed
            List<Path> failedFiles;
            try (var walker = Files.walk(sourceDir)) {
                failedFiles = new ArrayList<>(walker.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> {
                        try {
                            long size = Files.size(p);
                            if (size == 0) return true; // 0-byte = decompiler failed silently
                            String content = Files.readString(p);
                            return content.contains("Couldn't be decompiled")
                                || content.contains("// Failed to decompile")
                                || content.trim().isEmpty();
                        } catch (Exception e) { return false; }
                    })
                    .collect(java.util.stream.Collectors.toList()));
            }

            if (failedFiles.isEmpty()) return "none";

            List<String> supplementsUsed = new ArrayList<>();

            // Try JADX for failed files (good deobfuscation)
            if (jadx != null && !failedFiles.isEmpty()) {
                Path jadxTmp = Files.createTempDirectory("jadx_supplement_");
                try {
                    step("  Supplementing " + failedFiles.size() + " failed file(s) with JADX...");
                    Process p = new ProcessBuilder("java", heap, "-jar", jadx, "--deobf", "-d", jadxTmp.toString(), jarPath)
                        .redirectErrorStream(true).start();
                    runDecompilerProcess(p, timeout);

                    int replaced = 0;
                    List<Path> stillFailed = new ArrayList<>();
                    for (Path failed : failedFiles) {
                        String rel = sourceDir.relativize(failed).toString();
                        Path jadxFile = jadxTmp.resolve(rel);
                        if (Files.exists(jadxFile)) {
                            String jadxContent = Files.readString(jadxFile);
                            if (!jadxContent.contains("Couldn't be decompiled") && !jadxContent.contains("// Failed to decompile")) {
                                Files.copy(jadxFile, failed, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                                replaced++;
                            } else {
                                stillFailed.add(failed);
                            }
                        } else {
                            stillFailed.add(failed);
                        }
                    }
                    if (replaced > 0) {
                        ok("  JADX supplemented " + replaced + " of " + failedFiles.size() + " failed file(s)");
                        supplementsUsed.add("JADX");
                    }
                    failedFiles.clear();
                    failedFiles.addAll(stillFailed);
                    cleanUp(jadxTmp);
                } catch (Exception e) {
                    warn("  JADX supplement failed: " + e.getMessage());
                    cleanUp(jadxTmp);
                }
            }

            // Try Procyon for remaining failed files (handles complex control flow)
            if (procyon != null && !failedFiles.isEmpty()) {
                Path procTmp = Files.createTempDirectory("procyon_supplement_");
                try {
                    step("  Supplementing " + failedFiles.size() + " failed file(s) with Procyon...");
                    Process p = new ProcessBuilder("java", heap, "-jar", procyon,
                            "-jar", jarPath, "-o", procTmp.toString())
                        .redirectErrorStream(true).start();
                    runDecompilerProcess(p, timeout);

                    int replaced = 0;
                    List<Path> stillFailed = new ArrayList<>();
                    for (Path failed : failedFiles) {
                        String rel = sourceDir.relativize(failed).toString();
                        Path procFile = procTmp.resolve(rel);
                        if (Files.exists(procFile)) {
                            String procContent = Files.readString(procFile);
                            if (!procContent.contains("Couldn't be decompiled") && !procContent.contains("// Failed to decompile")) {
                                Files.copy(procFile, failed, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                                replaced++;
                            } else {
                                stillFailed.add(failed);
                            }
                        } else {
                            stillFailed.add(failed);
                        }
                    }
                    if (replaced > 0) {
                        ok("  Procyon supplemented " + replaced + " of " + failedFiles.size() + " failed file(s)");
                        supplementsUsed.add("Procyon");
                    }
                    failedFiles.clear();
                    failedFiles.addAll(stillFailed);
                    cleanUp(procTmp);
                } catch (Exception e) {
                    warn("  Procyon supplement failed: " + e.getMessage());
                    cleanUp(procTmp);
                }
            }

            // Try CFR for remaining failed files
            if (cfr != null && !failedFiles.isEmpty()) {
                Path cfrTmp = Files.createTempDirectory("cfr_supplement_");
                try {
                    step("  Supplementing " + failedFiles.size() + " failed file(s) with CFR...");
                    Process p = new ProcessBuilder("java", heap, "-jar", cfr, jarPath,
                            "--outputdir", cfrTmp.toString(), "--renameillegalidents", "true")
                        .redirectErrorStream(true).start();
                    runDecompilerProcess(p, timeout);

                    int replaced = 0;
                    for (Path failed : failedFiles) {
                        String rel = sourceDir.relativize(failed).toString();
                        Path cfrFile = cfrTmp.resolve(rel);
                        if (Files.exists(cfrFile)) {
                            String cfrContent = Files.readString(cfrFile);
                            if (!cfrContent.contains("Couldn't be decompiled") && !cfrContent.contains("// Failed to decompile")) {
                                Files.copy(cfrFile, failed, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                                replaced++;
                            }
                        }
                    }
                    if (replaced > 0) {
                        ok("  CFR supplemented " + replaced + " of " + failedFiles.size() + " failed file(s)");
                        supplementsUsed.add("CFR");
                    }
                    cleanUp(cfrTmp);
                } catch (Exception e) {
                    warn("  CFR supplement failed: " + e.getMessage());
                    cleanUp(cfrTmp);
                }
            }

            return supplementsUsed.isEmpty() ? "none" : String.join("+", supplementsUsed);
        } catch (Exception e) {
            warn("  Supplement failed: " + e.getMessage());
        }
        return "none";
    }

    static long countJavaFiles(Path dir) {
        try (var walker = Files.walk(dir)) { return walker.filter(p -> p.toString().endsWith(".java")).count(); }
        catch (Exception e) { return 0; }
    }

    // ─────────────────────────────────────────────────────────────────────
    // NEW VARIANT ANALYZERS
    // ─────────────────────────────────────────────────────────────────────

    /** Analyze VAPE_CURIUM variant — hex-encoded XOR strings, stage2 download, worm */
    static void analyzeVapeCurium(String jarPath, String jarSha256, String src,
                                   Map<String, byte[]> classes, List<String> markers,
                                   String ts, Path sourceDir) throws Exception {
        clog("═══════════════════════════════════════════════════════");
        clog("VAPE CURIUM ANALYSIS");
        clog("═══════════════════════════════════════════════════════");
        clog("Variant: VAPE_CURIUM (stage2 loader + worm)");
        clog("JAR: " + jarPath);
        clog("SHA-256: " + jarSha256);
        clog("Time: " + ts);
        clog("");

        // Extract hex-encoded strings from source
        Pattern hexPat = Pattern.compile("\"([0-9a-fA-F]{32,})\"");
        Matcher hm = hexPat.matcher(src);
        List<String> hexStrings = new ArrayList<>();
        while (hm.find()) hexStrings.add(hm.group(1));
        clog("Found " + hexStrings.size() + " hex-encoded string(s)");

        // Extract 16-byte key arrays from source
        Pattern keyPat = Pattern.compile("new\\s+byte\\[\\]\\s*\\{([^}]{30,120})\\}");
        Matcher km = keyPat.matcher(src);
        List<byte[]> candidateKeys = new ArrayList<>();
        while (km.find()) {
            try {
                String[] parts = km.group(1).split(",");
                if (parts.length == 16) {
                    byte[] key = new byte[16];
                    for (int i = 0; i < 16; i++) key[i] = (byte)Integer.parseInt(parts[i].trim());
                    candidateKeys.add(key);
                }
            } catch (Exception ignored) {}
        }
        clog("Found " + candidateKeys.size() + " candidate 16-byte key(s)");

        // Try XOR combinations to decrypt hex strings
        List<String> decryptedStrings = new ArrayList<>();
        if (!candidateKeys.isEmpty() && !hexStrings.isEmpty()) {
            // Build master key by XORing all candidate keys
            byte[] masterKey = new byte[16];
            for (byte[] k : candidateKeys) {
                for (int i = 0; i < 16; i++) masterKey[i] ^= k[i];
            }
            clog("Master XOR key: " + hexFull(masterKey));

            for (String hex : hexStrings) {
                try {
                    byte[] data = hexToBytes(hex);
                    // Decrypt: subtract 95, subtract index, then XOR with key
                    byte[] dec = new byte[data.length];
                    for (int i = 0; i < data.length; i++) {
                        dec[i] = (byte)((data[i] - 95 - i) ^ masterKey[i % 16]);
                    }
                    String result = new String(dec, StandardCharsets.UTF_8);
                    if (isAsciiPrintable(result)) {
                        decryptedStrings.add(result);
                        clog("  Decrypted: " + result);
                    }
                } catch (Exception ignored) {}
            }
        }

        // Extract URLs and IOCs from decrypted strings
        List<String> urls = new ArrayList<>();
        for (String s : decryptedStrings) {
            if (s.startsWith("http://") || s.startsWith("https://")) urls.add(s);
        }

        clog("");
        clog("──── Decrypted C2/Config Strings ────");
        for (String s : decryptedStrings) clog("  " + s);

        clog("");
        clog("──── URLs ────");
        for (String u : urls) {
            clog("  " + u);
            System.out.println(YELLOW + "  C2 URL: " + u + RESET);
        }

        // Write IOCs
        writeIOCs(jarPath, jarSha256, "VAPE_CURIUM", markers, urls, null, null, decryptedStrings, ts);

        // Print console summary
        System.out.println();
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + GREEN + "  VAPE CURIUM ANALYSIS COMPLETE" + RESET);
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(YELLOW + "  Variant       : VAPE_CURIUM (stage2 loader + worm)" + RESET);
        System.out.println(YELLOW + "  Hex strings   : " + hexStrings.size() + RESET);
        System.out.println(YELLOW + "  Decrypted     : " + decryptedStrings.size() + RESET);
        System.out.println(YELLOW + "  C2 URLs       : " + urls.size() + RESET);
        System.out.println(GREEN  + "════════════════════════════════════════" + RESET);
    }

    /** Analyze SILENT_NET variant — Polygon blockchain C2, per-class XOR */
    static void analyzeSilentNet(String jarPath, String jarSha256, String src,
                                  Map<String, byte[]> classes, List<String> markers,
                                  String ts, Path sourceDir) throws Exception {
        clog("═══════════════════════════════════════════════════════");
        clog("SILENT NET ANALYSIS");
        clog("═══════════════════════════════════════════════════════");
        clog("Variant: SILENT_NET (Polygon blockchain C2)");
        clog("JAR: " + jarPath);
        clog("SHA-256: " + jarSha256);
        clog("Time: " + ts);
        clog("");
        clog("Detection: com.libmod package with Polygon smart contract C2");
        clog("Technique: Per-class XOR key + numeric key (n) + UTF-16 string encryption");
        clog("C2 Method: Queries Polygon smart contract to dynamically resolve C2 domain");
        clog("");

        // Extract per-class XOR key arrays (byte arrays 10-130 bytes)
        // Lowered minimum from 80 to 10 to catch Core.java's 21-byte key (cvfwkoianc)
        Pattern keyPat = Pattern.compile("new\\s+byte\\[\\]\\s*\\{([^}]{20,800})\\}");
        Matcher km = keyPat.matcher(src);
        List<byte[]> xorKeys = new ArrayList<>();
        while (km.find()) {
            try {
                String[] parts = km.group(1).split(",");
                if (parts.length >= 10 && parts.length <= 130) {
                    byte[] key = new byte[parts.length];
                    for (int i = 0; i < parts.length; i++) key[i] = (byte)Integer.parseInt(parts[i].trim());
                    xorKeys.add(key);
                }
            } catch (Exception ignored) {}
        }
        clog("Found " + xorKeys.size() + " per-class XOR key(s)");

        // Extract encrypted byte arrays (smaller, often start with negative values)
        Pattern encPat = Pattern.compile("new\\s+byte\\[\\]\\s*\\{([^}]{8,2000})\\}");
        Matcher em = encPat.matcher(src);
        List<byte[]> encArrays = new ArrayList<>();
        while (em.find()) {
            try {
                String[] parts = em.group(1).split(",");
                if (parts.length >= 4 && parts.length <= 500) {
                    byte[] arr = new byte[parts.length];
                    boolean hasNegative = false;
                    for (int i = 0; i < parts.length; i++) {
                        arr[i] = (byte)Integer.parseInt(parts[i].trim());
                        if (arr[i] < 0) hasNegative = true;
                    }
                    // Encrypted arrays typically contain negative values (BOM artifact or signed bytes)
                    // Raised cap from 75 to 500 to catch long encrypted URLs (RPC endpoints with API keys)
                    if (hasNegative) {
                        // Skip XOR key arrays (already captured)
                        boolean isKey = false;
                        for (byte[] k : xorKeys) if (Arrays.equals(k, arr)) { isKey = true; break; }
                        if (!isKey) encArrays.add(arr);
                    }
                }
            } catch (Exception ignored) {}
        }
        clog("Found " + encArrays.size() + " encrypted byte array(s)");

        // Try to decrypt using BOM recovery technique (Schemes 2/3/4: two-layer XOR)
        List<String> decryptedStrings = new ArrayList<>();
        for (byte[] enc : encArrays) {
            boolean decrypted = false;
            for (byte[] xorKey : xorKeys) {
                List<Integer> nCandidates = recoverNFromBOM(enc, xorKey);
                for (int n : nCandidates) {
                    String result = silentNetXorDecrypt(enc, xorKey, n);
                    if (result != null && isAsciiPrintable(result) && result.length() >= 2) {
                        decryptedStrings.add(result);
                        clog("  Decrypted (n=" + n + "): " + result);
                        decrypted = true;
                    }
                }
            }
            // Fallback: try single-layer XOR (Scheme 1 uses only str(n).getBytes())
            if (!decrypted && enc.length >= 10) {
                for (int n = -5000; n <= 5000; n++) {
                    String result = silentNetSingleXorDecrypt(enc, n);
                    if (result != null && isAsciiPrintable(result) && result.length() >= 2) {
                        decryptedStrings.add(result);
                        clog("  Decrypted single-XOR (n=" + n + "): " + result);
                        break;
                    }
                }
            }
        }

        // Fallback: extract constant pool strings from raw class bytes when decompilation fails
        // These catch strings that decompilers couldn't handle (opaque predicate methods)
        clog("");
        clog("──── Constant Pool String Extraction (fallback) ────");
        int cpStringsFound = 0;
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            String className = entry.getKey();
            byte[] classData = entry.getValue();
            // Extract UTF8 constant pool entries that look like IOCs
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            for (String pattern : new String[]{"polygon", "sltnnt", "prefireMc", "0x9c0a",
                    "NtProfileIndex", "_bootstrap", "method_1674", "method_1676", "method_44717",
                    "ktfdumxluduvzmma", "azmssbnclpvvzpam", "bzwkkgywwylfhgzl"}) {
                if (ascii.contains(pattern)) {
                    String marker = "Constant pool hit: '" + pattern + "' in " + className;
                    if (!markers.contains(marker)) {
                        markers.add(marker);
                        clog("  [CPSTR] " + marker);
                        cpStringsFound++;
                    }
                }
            }
        }
        if (cpStringsFound > 0) clog("  Found " + cpStringsFound + " constant pool string hit(s)");
        else clog("  (no additional IOC strings in constant pool)");

        // Extract smart contract address from source/decrypted strings
        Pattern contractPat = Pattern.compile("0x[0-9a-fA-F]{40}");
        Matcher cm = contractPat.matcher(src);
        List<String> contracts = new ArrayList<>();
        while (cm.find()) contracts.add(cm.group());
        for (String s : decryptedStrings) {
            Matcher cm2 = contractPat.matcher(s);
            while (cm2.find()) contracts.add(cm2.group());
        }

        // Extract URLs from decrypted strings
        List<String> urls = new ArrayList<>();
        Pattern urlPat = Pattern.compile("https?://[\\w.\\-/?=&%+:@]+");
        for (String s : decryptedStrings) {
            Matcher um = urlPat.matcher(s);
            while (um.find()) urls.add(um.group());
        }
        // Also extract URLs from decompiled source (catches partially visible URLs)
        Matcher srcUrlMatcher = urlPat.matcher(src);
        while (srcUrlMatcher.find()) {
            String u = srcUrlMatcher.group();
            if (!urls.contains(u) && !u.contains("minecraft.net") && !u.contains("mojang.com")
                    && !u.contains("fabricmc.net")) {
                urls.add(u);
            }
        }
        // Fallback: extract URLs from raw class constant pool bytes
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            Matcher rawUrlMatcher = urlPat.matcher(ascii);
            while (rawUrlMatcher.find()) {
                String u = rawUrlMatcher.group();
                if (!urls.contains(u) && !u.contains("minecraft.net") && !u.contains("mojang.com")
                        && !u.contains("fabricmc.net") && !u.contains("java.sun.com")) {
                    urls.add(u);
                }
            }
        }

        // Fallback: extract contract addresses from raw class bytes
        for (byte[] classData : classes.values()) {
            String ascii = new String(classData, StandardCharsets.US_ASCII);
            Matcher rawContractMatcher = contractPat.matcher(ascii);
            while (rawContractMatcher.find()) {
                String c = rawContractMatcher.group();
                if (!contracts.contains(c)) contracts.add(c);
            }
        }

        // Extract buyer UUID from lang.dat
        String buyerUUID = null;
        try (ZipFile zf = new ZipFile(jarPath)) {
            ZipEntry langEntry = zf.getEntry("lang.dat");
            if (langEntry != null) {
                try (InputStream is = zf.getInputStream(langEntry)) {
                    String langContent = new String(readBounded(is, 1_000_000), StandardCharsets.UTF_8).trim();
                    if (langContent.matches("[0-9a-f\\-]{36}")) buyerUUID = langContent;
                }
            }
        } catch (Exception ignored) {}

        clog("");
        clog("──── Polygon Smart Contract C2 ────");
        for (String c : contracts) clog("  Contract: " + c);
        clog("");
        clog("──── Decrypted URLs (RPC mirrors & C2) ────");
        for (String u : urls) clog("  " + u);
        if (buyerUUID != null) clog("\n  Buyer UUID: " + buyerUUID);
        clog("");

        // Log findings
        for (String c : contracts) {
            System.out.println(YELLOW + "  Polygon Contract: " + c + RESET);
        }
        for (String u : urls) {
            System.out.println(YELLOW + "  C2/RPC URL: " + u + RESET);
        }
        if (buyerUUID != null) {
            System.out.println(YELLOW + "  Buyer UUID: " + buyerUUID + RESET);
        }

        writeIOCs(jarPath, jarSha256, "SILENT_NET", markers, urls, contracts, buyerUUID, decryptedStrings, ts);
    }

    /** Analyze MSHTA_DROPPER variant — mshta command execution */
    static void analyzeMshtaDropper(String jarPath, String jarSha256, String src,
                                     Map<String, byte[]> classes, List<String> markers,
                                     String ts) throws Exception {
        clog("═══════════════════════════════════════════════════════");
        clog("MSHTA DROPPER ANALYSIS");
        clog("═══════════════════════════════════════════════════════");
        clog("Variant: MSHTA_DROPPER");
        clog("JAR: " + jarPath);
        clog("SHA-256: " + jarSha256);
        clog("Time: " + ts);
        clog("");
        clog("Technique: Executes mshta.exe to download and run remote payload");
        clog("");

        // Extract mshta commands from source and raw bytes
        List<String> mshtaUrls = new ArrayList<>();
        Pattern mshtaPat = Pattern.compile("mshta\\s+(https?://[^\"'\\s]+)", Pattern.CASE_INSENSITIVE);
        Matcher mm = mshtaPat.matcher(src);
        while (mm.find()) mshtaUrls.add(mm.group(1));

        // Also check raw class bytes
        for (byte[] data : classes.values()) {
            String ascii = new String(data, StandardCharsets.US_ASCII);
            Matcher mm2 = mshtaPat.matcher(ascii);
            while (mm2.find()) {
                if (!mshtaUrls.contains(mm2.group(1))) mshtaUrls.add(mm2.group(1));
            }
        }

        // Extract any other URLs
        Pattern urlPat = Pattern.compile("https?://[\\w.\\-/?=&%+:@]+");
        Matcher um = urlPat.matcher(src);
        while (um.find()) {
            String u = um.group();
            if (!mshtaUrls.contains(u) && !u.contains("minecraft") && !u.contains("mojang")) {
                mshtaUrls.add(u);
            }
        }

        clog("──── MSHTA Payload URLs ────");
        for (String u : mshtaUrls) {
            clog("  " + u);
            System.out.println(RED + "  MSHTA Payload URL: " + u + RESET);
        }

        writeIOCs(jarPath, jarSha256, "MSHTA_DROPPER", markers, mshtaUrls, null, null, ts);
    }

    /** Generic malware analyzer for FRACTUREISER, SKYRAGE, etc. */
    // ─────────────────────────────────────────────────────────────────────
    // SERVER CRASHER ANALYZER (2Packets / xynis / similar attack clients)
    // ─────────────────────────────────────────────────────────────────────
    static void analyzeServerCrasher(String jarPath, String jarSha256, String src,
                                      Map<String, byte[]> classes, List<String> markers,
                                      String ts) throws Exception {
        clog("═══════════════════════════════════════════════════════");
        clog("SERVER CRASHER / EXPLOIT CLIENT ANALYSIS");
        clog("═══════════════════════════════════════════════════════");
        clog("JAR: " + jarPath);
        clog("SHA-256: " + jarSha256);
        clog("Time: " + ts);
        clog("");

        // Detect client name and version from source
        String clientName = "Unknown";
        String clientVersion = "Unknown";
        Matcher vnMat = Pattern.compile("\"(\\d+Packets\\s*Client|xynis)\"", Pattern.CASE_INSENSITIVE).matcher(src);
        if (vnMat.find()) clientName = vnMat.group(1);
        else {
            // Try raw strings
            for (byte[] data : classes.values()) {
                String ascii = new String(data, StandardCharsets.US_ASCII);
                if (ascii.contains("2PacketsClient") || ascii.contains("2Packets Client")) { clientName = "2Packets Client"; break; }
                if (ascii.contains("xynis")) { clientName = "xynis"; break; }
            }
        }
        // Look for version near client name references
        Pattern verNear = Pattern.compile("(?:version|VERSION|Version)\\s*[=:]\\s*\"([^\"]+)\"");
        Matcher verNearMat = verNear.matcher(src);
        if (verNearMat.find()) clientVersion = verNearMat.group(1);

        clog("Client: " + clientName);
        clog("Version: " + clientVersion);
        System.out.println(BOLD + RED + "  Client: " + clientName + " v" + clientVersion + RESET);

        // Count crasher classes
        List<String> crasherClasses = new ArrayList<>();
        List<String> exploitClasses = new ArrayList<>();
        List<String> commandClasses = new ArrayList<>();
        for (String name : classes.keySet()) {
            String lower = name.toLowerCase();
            if (lower.contains("crasher") || (lower.contains("crash") && lower.contains("impl"))) crasherClasses.add(name);
            else if (lower.contains("exploit") && lower.contains("impl")) exploitClasses.add(name);
            else if (lower.contains("command") && lower.contains("impl")) commandClasses.add(name);
        }

        // Also scan the JAR entries for inner classes
        try (ZipFile zf = new ZipFile(jarPath)) {
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String n = e.getName();
                if (n.contains("crashers/impl/") && n.endsWith(".class") && !n.contains("$")) {
                    String cn = n.substring(n.lastIndexOf('/') + 1).replace(".class", "");
                    if (!crasherClasses.contains(cn)) crasherClasses.add(cn);
                }
                if (n.contains("exploits/impl/") && n.endsWith(".class") && !n.contains("$")) {
                    String cn = n.substring(n.lastIndexOf('/') + 1).replace(".class", "");
                    if (!exploitClasses.contains(cn)) exploitClasses.add(cn);
                }
            }
        } catch (Exception ignored) {}

        clog("");
        clog("──── CRASHER MODULES (" + crasherClasses.size() + ") ────");
        for (String c : crasherClasses) {
            String name = c.contains("/") ? c.substring(c.lastIndexOf('/') + 1) : c;
            name = name.replace(".class", "");
            clog("  - " + name);
        }
        System.out.println(YELLOW + "  Crasher modules: " + crasherClasses.size() + RESET);

        clog("");
        clog("──── EXPLOIT MODULES (" + exploitClasses.size() + ") ────");
        for (String c : exploitClasses) {
            String name = c.contains("/") ? c.substring(c.lastIndexOf('/') + 1) : c;
            name = name.replace(".class", "");
            clog("  - " + name);
            // Flag especially dangerous exploits
            String nl = name.toLowerCase();
            if (nl.contains("forceop")) System.out.println(RED + "  Exploit: " + name + " (privilege escalation)" + RESET);
            else if (nl.contains("log4j")) System.out.println(RED + "  Exploit: " + name + " (Log4Shell RCE)" + RESET);
            else System.out.println(YELLOW + "  Exploit: " + name + RESET);
        }

        clog("");
        clog("──── COMMANDS (" + commandClasses.size() + ") ────");
        for (String c : commandClasses) {
            String name = c.contains("/") ? c.substring(c.lastIndexOf('/') + 1) : c;
            clog("  - " + name.replace(".class", ""));
        }

        // Extract Discord app ID
        Matcher discordId = Pattern.compile("\"(\\d{17,20})\"").matcher(src);
        List<String> discordAppIds = new ArrayList<>();
        while (discordId.find()) {
            String id = discordId.group(1);
            // Check if it's near DiscordRPC/discordInitialize
            int pos = discordId.start();
            int start = Math.max(0, pos - 200);
            String context = src.substring(start, pos);
            if (context.contains("discord") || context.contains("Discord") || context.contains("RPC")
                || context.contains("discordInitialize") || context.contains("DiscordRP")) {
                if (!discordAppIds.contains(id)) discordAppIds.add(id);
            }
        }
        if (!discordAppIds.isEmpty()) {
            clog("");
            clog("──── DISCORD INTEGRATION ────");
            for (String id : discordAppIds) {
                clog("  Discord Application ID: " + id);
                System.out.println(CYAN + "  Discord App ID: " + id + RESET);
            }
        }

        // Extract URLs (external IPs, auth endpoints, etc.)
        List<String> urls = new ArrayList<>();
        Pattern urlPat = Pattern.compile("\"(https?://[^\"]+)\"");
        Matcher um = urlPat.matcher(src);
        Set<String> seenUrls = new LinkedHashSet<>();
        while (um.find()) {
            String u = um.group(1);
            // Skip Minecraft library/asset URLs
            if (u.contains("libraries.minecraft.net") || u.contains("piston-data.mojang.com")
                || u.contains("launcher.mojang.com") || u.contains("launchermeta.mojang.com")) continue;
            if (seenUrls.add(u)) urls.add(u);
        }

        if (!urls.isEmpty()) {
            clog("");
            clog("──── EXTERNAL URLS ────");
            for (String u : urls) {
                clog("  " + u);
                String ul = u.toLowerCase();
                if (ul.contains("xboxlive") || ul.contains("login.live") || ul.contains("minecraftservices"))
                    System.out.println(RED + "  Auth URL: " + u + RESET);
                else if (ul.contains("ipify") || ul.contains("ifconfig"))
                    System.out.println(YELLOW + "  IP Lookup: " + u + RESET);
                else
                    System.out.println(YELLOW + "  URL: " + u + RESET);
            }
        }

        // Check for account storage paths
        Pattern accPath = Pattern.compile("\"([^\"]*acc[^\"]*\\.ser)\"", Pattern.CASE_INSENSITIVE);
        Matcher accMat = accPath.matcher(src);
        if (accMat.find()) {
            clog("");
            clog("──── ACCOUNT STORAGE ────");
            clog("  Account file: " + accMat.group(1));
            System.out.println(RED + "  Account storage: " + accMat.group(1) + RESET);
        }

        // Check for cookie-based auth chain (AccountHelper pattern)
        boolean hasCookieAuth = src.contains("login.live.com") || src.contains("sisu.xboxlive.com");
        boolean hasTokenChain = src.contains("XBL3.0") || src.contains("login_with_xbox");
        if (hasCookieAuth || hasTokenChain) {
            clog("");
            clog("──── ACCOUNT THEFT CAPABILITY ────");
            clog("  Cookie-based Xbox Live auth chain: " + hasCookieAuth);
            clog("  MC token exchange via XBL: " + hasTokenChain);
            System.out.println(RED + BOLD + "  WARNING: Cookie-based MC account theft capability detected" + RESET);
        }

        // VPN/proxy detection
        boolean hasWarp = src.contains("warp-cli");
        boolean hasProxy = src.contains("Proxy") && src.contains("SOCKS");
        if (hasWarp || hasProxy) {
            clog("");
            clog("──── ANONYMIZATION ────");
            if (hasWarp) { clog("  Cloudflare WARP integration"); System.out.println(YELLOW + "  VPN: Cloudflare WARP integration" + RESET); }
            if (hasProxy) { clog("  SOCKS proxy support"); System.out.println(YELLOW + "  Proxy: SOCKS proxy support" + RESET); }
        }

        clog("");
        clog("──── BEHAVIORAL MARKERS ────");
        for (String m : markers) clog("  - " + m);

        // Total file count
        int totalFiles = 0;
        try (ZipFile zf = new ZipFile(jarPath)) {
            totalFiles = Collections.list(zf.entries()).size();
        } catch (Exception ignored) {}

        // Write IOCs JSON
        writeIOCsEnhanced(jarPath, jarSha256, "SERVER_CRASHER", markers, urls,
            new ArrayList<>(), new LinkedHashMap<>(), new ArrayList<>(), ts);

        System.out.println();
        System.out.println(BOLD + RED + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + RED + "  SERVER CRASHER ANALYSIS COMPLETE" + RESET);
        System.out.println(BOLD + RED + "════════════════════════════════════════" + RESET);
        System.out.println(CYAN  + "  Client         : " + clientName + " v" + clientVersion + RESET);
        System.out.println(YELLOW + "  Crasher modules: " + crasherClasses.size() + RESET);
        System.out.println(YELLOW + "  Exploit modules: " + exploitClasses.size() + RESET);
        System.out.println(YELLOW + "  Commands       : " + commandClasses.size() + RESET);
        System.out.println(YELLOW + "  Total JAR files: " + totalFiles + RESET);
        System.out.println(YELLOW + "  External URLs  : " + urls.size() + RESET);
        if (hasCookieAuth) System.out.println(RED + "  Account theft  : YES (cookie-based Xbox Live auth)" + RESET);
        System.out.println(RED + BOLD + "  Classification : Attack/griefing tool (NOT a RAT)" + RESET);
        System.out.println(BOLD + RED + "════════════════════════════════════════" + RESET);
    }

    static void analyzeGenericMalware(String jarPath, String jarSha256, String src,
                                       Map<String, byte[]> classes, List<String> markers,
                                       String ts, String variant, String description) throws Exception {
        clog("═══════════════════════════════════════════════════════");
        clog(variant + " ANALYSIS");
        clog("═══════════════════════════════════════════════════════");
        clog("Variant: " + variant);
        clog("JAR: " + jarPath);
        clog("SHA-256: " + jarSha256);
        clog("Time: " + ts);
        clog("");
        clog("Description: " + description);
        clog("");

        // Extract all URLs from source
        List<String> urls = new ArrayList<>();
        Pattern urlPat = Pattern.compile("\"(https?://[^\"]+)\"");
        Matcher um = urlPat.matcher(src);
        Set<String> seen = new LinkedHashSet<>();
        while (um.find()) { String u = um.group(1); if (seen.add(u)) urls.add(u); }

        // Extract IPs
        List<String> ips = new ArrayList<>();
        Pattern ipPat = Pattern.compile("\"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?::(\\d+))?\"");
        Matcher ipm = ipPat.matcher(src);
        while (ipm.find()) {
            String ip = ipm.group(1);
            if (!isPrivateOrInvalidIP(ip)) {
                String full = ipm.group(2) != null ? ip + ":" + ipm.group(2) : ip;
                if (!ips.contains(full)) ips.add(full);
            }
        }
        // Also check raw bytes for IPs
        for (byte[] data : classes.values()) {
            String ascii = new String(data, StandardCharsets.US_ASCII);
            Matcher im2 = ipPat.matcher(ascii);
            while (im2.find()) {
                String ip = im2.group(1);
                if (!isPrivateOrInvalidIP(ip)) {
                    if (!ips.contains(ip)) ips.add(ip);
                }
            }
        }

        // Extract Discord webhooks from source and raw bytes
        List<String> webhooks = new ArrayList<>();
        Pattern webhookPat = Pattern.compile("https://discord\\.com/api/webhooks/\\d+/[A-Za-z0-9_\\-]+");
        Matcher wm = webhookPat.matcher(src);
        while (wm.find()) { if (!webhooks.contains(wm.group())) webhooks.add(wm.group()); }
        // Also check raw class bytes for webhooks
        for (byte[] data : classes.values()) {
            Matcher wm2 = webhookPat.matcher(new String(data, StandardCharsets.US_ASCII));
            while (wm2.find()) { if (!webhooks.contains(wm2.group())) webhooks.add(wm2.group()); }
        }

        // Decode Base64 LDC constants from raw bytes (common in WeirdUtils, Comet)
        List<String> decodedBase64 = new ArrayList<>();
        for (byte[] data : classes.values()) {
            Set<String> rawStrings = new LinkedHashSet<>();
            StringBuilder cur = new StringBuilder();
            for (byte b : data) {
                char c = (char)(b & 0xFF);
                if (c >= 0x20 && c < 0x7F) cur.append(c);
                else { if (cur.length() >= 20) rawStrings.add(cur.toString()); cur.setLength(0); }
            }
            if (cur.length() >= 20) rawStrings.add(cur.toString());
            for (String s : rawStrings) {
                if (s.matches("[A-Za-z0-9+/]{20,}={0,2}") && !s.contains(" ")) {
                    try {
                        byte[] dec = Base64.getDecoder().decode(s);
                        String decoded = new String(dec, StandardCharsets.UTF_8);
                        if (decoded.length() >= 6 && decoded.chars().allMatch(c -> c >= 0x20 && c < 0x7F)) {
                            decodedBase64.add(decoded);
                            if (decoded.startsWith("http") && !urls.contains(decoded)) urls.add(decoded);
                        }
                    } catch (Exception ignored) {}
                }
            }
        }

        // Detect embedded files and known-bad resources
        List<String> embeddedFiles = new ArrayList<>();
        List<String> knownBadResources = new ArrayList<>();
        Map<String, String> embeddedHashes = new LinkedHashMap<>();
        try (ZipFile zf = new ZipFile(jarPath)) {
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                String basename = name.contains("/") ? name.substring(name.lastIndexOf('/') + 1) : name;

                if (name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".exe")
                    || name.endsWith(".bat") || name.endsWith(".ps1") || name.endsWith(".jar")
                    || name.endsWith(".hta") || name.endsWith(".vbs") || name.endsWith(".bin")) {
                    embeddedFiles.add(name + " (" + e.getSize() + " bytes)");
                    // Hash embedded executables for IOCs
                    try (InputStream is = zf.getInputStream(e)) {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] eData = readBounded(is, 50_000_000);
                        String eHash = hexFull(md.digest(eData));
                        embeddedHashes.put(name, eHash);
                    } catch (Exception ignored) {}
                }

                for (String bad : KNOWN_BAD_RESOURCES) {
                    if (basename.equals(bad) || name.endsWith(bad)) {
                        knownBadResources.add(name);
                    }
                }
            }
        } catch (Exception ignored) {}

        // Extract plugin.yml data (Bukkit/Spigot plugins — Comet, Ectasy)
        String pluginYml = null;
        try (ZipFile zf = new ZipFile(jarPath)) {
            ZipEntry pyEntry = zf.getEntry("plugin.yml");
            if (pyEntry == null) pyEntry = zf.getEntry("bungee.yml");
            if (pyEntry != null) {
                try (InputStream is = zf.getInputStream(pyEntry)) {
                    pluginYml = new String(readBounded(is, 1_000_000), StandardCharsets.UTF_8);
                }
            }
        } catch (Exception ignored) {}

        // Log findings
        clog("──── URLs ────");
        for (String u : urls) { clog("  " + u); System.out.println(YELLOW + "  URL: " + u + RESET); }
        if (!ips.isEmpty()) {
            clog(""); clog("──── IP Addresses ────");
            for (String ip : ips) { clog("  " + ip); System.out.println(RED + "  IP: " + ip + RESET); }
        }
        if (!webhooks.isEmpty()) {
            clog(""); clog("──── Discord Webhooks ────");
            for (String w : webhooks) {
                String status = checkWebhookStatus(w);
                clog("  " + w + " [" + status + "]");
                System.out.println((status.equals("ACTIVE") ? GREEN : RED) + "  Webhook: " + w + " [" + status + "]" + RESET);
                if (status.equals("ACTIVE")) appendWebhookLog(jarName, w);
            }
        }
        if (!decodedBase64.isEmpty()) {
            clog(""); clog("──── Decoded Base64 LDC Constants ────");
            for (String d : decodedBase64) {
                clog("  " + d);
                System.out.println(YELLOW + "  Base64→ " + d + RESET);
            }
        }
        if (!embeddedFiles.isEmpty()) {
            clog(""); clog("──── Embedded Executables/Libraries ────");
            for (String f : embeddedFiles) {
                clog("  " + f);
                System.out.println(RED + "  Embedded: " + f + RESET);
            }
            for (Map.Entry<String, String> eh : embeddedHashes.entrySet()) {
                clog("    SHA-256: " + eh.getValue());
            }
        }
        if (!knownBadResources.isEmpty()) {
            clog(""); clog("──── KNOWN MALICIOUS RESOURCES ────");
            for (String r : knownBadResources) {
                clog("  *** " + r);
                System.out.println(RED + BOLD + "  KNOWN BAD: " + r + RESET);
            }
        }
        if (pluginYml != null) {
            clog(""); clog("──── Plugin Metadata (plugin.yml) ────");
            clog(pluginYml);
            // Extract plugin name, author, commands
            Matcher nameMat = Pattern.compile("name:\\s*(.+)").matcher(pluginYml);
            if (nameMat.find()) System.out.println(CYAN + "  Plugin Name: " + nameMat.group(1).trim() + RESET);
            Matcher authMat = Pattern.compile("(?:author|authors):\\s*(.+)").matcher(pluginYml);
            if (authMat.find()) System.out.println(CYAN + "  Author: " + authMat.group(1).trim() + RESET);
            Matcher cmdMat = Pattern.compile("commands:\\s*\\n((?:\\s+.+\\n)*)").matcher(pluginYml);
            if (cmdMat.find()) {
                Matcher cmdNames = Pattern.compile("^\\s{2,4}(\\w+):", Pattern.MULTILINE).matcher(cmdMat.group(1));
                while (cmdNames.find()) {
                    System.out.println(YELLOW + "  Command: /" + cmdNames.group(1) + RESET);
                    clog("  Command: /" + cmdNames.group(1));
                }
            }
        }

        clog(""); clog("──── Behavioral Markers ────");
        for (String m : markers) clog("  - " + m);

        // Combine all IOC URLs
        List<String> allUrls = new ArrayList<>(urls);
        allUrls.addAll(ips);
        allUrls.addAll(webhooks);

        // Enhanced IOC export with embedded hashes and webhooks
        writeIOCsEnhanced(jarPath, jarSha256, variant, markers, allUrls, webhooks, embeddedHashes, decodedBase64, ts);

        System.out.println();
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(BOLD + GREEN + "  " + variant + " ANALYSIS COMPLETE" + RESET);
        System.out.println(BOLD + GREEN + "════════════════════════════════════════" + RESET);
        System.out.println(YELLOW + "  URLs found    : " + urls.size() + RESET);
        System.out.println(YELLOW + "  IPs found     : " + ips.size() + RESET);
        System.out.println(YELLOW + "  Embedded files: " + embeddedFiles.size() + RESET);
        System.out.println(GREEN + "════════════════════════════════════════" + RESET);

        ilog(""); ilog("RESULT: SUCCESS (" + variant.toLowerCase() + ") — config.log written");
        System.out.println("    RESULT: SUCCESS — config.log written");
    }

    /** Write IOCs JSON for new variant types */
    static void writeIOCs(String jarPath, String jarSha256, String variant,
                           List<String> markers, List<String> urls,
                           List<String> contracts, String buyerUUID, String ts) {
        writeIOCs(jarPath, jarSha256, variant, markers, urls, contracts, buyerUUID, null, ts);
    }

    static void writeIOCs(String jarPath, String jarSha256, String variant,
                           List<String> markers, List<String> urls,
                           List<String> contracts, String buyerUUID,
                           List<String> decryptedStrings, String ts) {
        try {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"jar\": \"").append(escJson(Paths.get(jarPath).getFileName().toString())).append("\",\n");
            json.append("  \"sha256\": \"").append(escJson(jarSha256)).append("\",\n");
            json.append("  \"variant\": \"").append(variant).append("\",\n");
            json.append("  \"timestamp\": \"").append(ts).append("\",\n");
            if (buyerUUID != null)
                json.append("  \"buyerUUID\": \"").append(escJson(buyerUUID)).append("\",\n");
            if (contracts != null && !contracts.isEmpty()) {
                json.append("  \"contracts\": [");
                for (int i = 0; i < contracts.size(); i++) {
                    json.append("\"").append(escJson(contracts.get(i))).append("\"");
                    if (i < contracts.size()-1) json.append(",");
                }
                json.append("],\n");
            }
            if (decryptedStrings != null && !decryptedStrings.isEmpty()) {
                json.append("  \"decryptedStrings\": [");
                for (int i = 0; i < decryptedStrings.size(); i++) {
                    json.append("\"").append(escJson(decryptedStrings.get(i))).append("\"");
                    if (i < decryptedStrings.size()-1) json.append(",");
                }
                json.append("],\n");
            }
            json.append("  \"urls\": [");
            if (urls != null) for (int i = 0; i < urls.size(); i++) {
                json.append("\"").append(escJson(urls.get(i))).append("\"");
                if (i < urls.size()-1) json.append(",");
            }
            json.append("],\n");
            json.append("  \"markers\": [");
            for (int i = 0; i < markers.size(); i++) {
                json.append("\"").append(escJson(markers.get(i))).append("\"");
                if (i < markers.size()-1) json.append(",");
            }
            json.append("],\n");
            if (!detectedModLoaders.isEmpty()) {
                json.append("  \"modLoaders\": [");
                int mli = 0;
                for (String ml : detectedModLoaders) {
                    json.append("\"").append(escJson(ml)).append("\"");
                    if (++mli < detectedModLoaders.size()) json.append(",");
                }
                json.append("]\n");
            } else {
                // Remove trailing comma from markers line
                json.setLength(json.length() - 2);
                json.append("\n");
            }
            json.append("}\n");
            Files.writeString(out(jarName + "_iocs.json"), prettyJson(json.toString()));
        } catch (Exception e) {
            warn("Failed to write IOCs: " + e.getMessage());
        }
    }

    /** Enhanced IOC writer with webhooks, embedded file hashes, and decoded Base64 strings */
    static void writeIOCsEnhanced(String jarPath, String jarSha256, String variant,
                                   List<String> markers, List<String> urls,
                                   List<String> webhooks, Map<String, String> embeddedHashes,
                                   List<String> decodedBase64, String ts) {
        try {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"jar\": \"").append(escJson(Paths.get(jarPath).getFileName().toString())).append("\",\n");
            json.append("  \"sha256\": \"").append(escJson(jarSha256)).append("\",\n");
            json.append("  \"variant\": \"").append(variant).append("\",\n");
            json.append("  \"timestamp\": \"").append(ts).append("\",\n");

            // URLs
            json.append("  \"urls\": [");
            if (urls != null) for (int i = 0; i < urls.size(); i++) {
                json.append("\"").append(escJson(urls.get(i))).append("\"");
                if (i < urls.size()-1) json.append(", ");
            }
            json.append("],\n");

            // Domains
            Set<String> domains = new LinkedHashSet<>();
            if (urls != null) for (String u : urls) {
                Matcher dm = Pattern.compile("https?://([^/:]+)").matcher(u);
                if (dm.find()) domains.add(dm.group(1));
            }
            json.append("  \"domains\": [");
            int di = 0;
            for (String d : domains) { json.append("\"").append(escJson(d)).append("\""); if (++di < domains.size()) json.append(", "); }
            json.append("],\n");

            // Webhooks
            if (webhooks != null && !webhooks.isEmpty()) {
                json.append("  \"webhooks\": [");
                for (int i = 0; i < webhooks.size(); i++) {
                    json.append("\"").append(escJson(webhooks.get(i))).append("\"");
                    if (i < webhooks.size()-1) json.append(", ");
                }
                json.append("],\n");
            }

            // Embedded file hashes
            if (embeddedHashes != null && !embeddedHashes.isEmpty()) {
                json.append("  \"embeddedFiles\": {\n");
                int ei = 0;
                for (Map.Entry<String, String> e : embeddedHashes.entrySet()) {
                    json.append("    \"").append(escJson(e.getKey())).append("\": \"").append(e.getValue()).append("\"");
                    if (++ei < embeddedHashes.size()) json.append(",");
                    json.append("\n");
                }
                json.append("  },\n");
            }

            // Decoded Base64 strings
            if (decodedBase64 != null && !decodedBase64.isEmpty()) {
                json.append("  \"decodedBase64\": [");
                for (int i = 0; i < decodedBase64.size(); i++) {
                    json.append("\"").append(escJson(decodedBase64.get(i))).append("\"");
                    if (i < decodedBase64.size()-1) json.append(", ");
                }
                json.append("],\n");
            }

            // Markers
            json.append("  \"markers\": [");
            for (int i = 0; i < markers.size(); i++) {
                json.append("\"").append(escJson(markers.get(i))).append("\"");
                if (i < markers.size()-1) json.append(", ");
            }
            json.append("]\n");
            json.append("}\n");
            Files.writeString(out(jarName + "_iocs.json"), prettyJson(json.toString()));
        } catch (Exception e) {
            warn("Failed to write IOCs: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // SILENT_NET CRYPTO HELPERS
    // ─────────────────────────────────────────────────────────────────────

    /** Recover possible n values from BOM constraint (UTF-16 decryption) */
    static List<Integer> recoverNFromBOM(byte[] data, byte[] xorKey) {
        List<Integer> results = new ArrayList<>();
        if (data.length < 4) return results;

        for (int keyLen = 1; keyLen <= 11; keyLen++) {
            byte[] key = new byte[keyLen];
            boolean[] set = new boolean[keyLen];
            boolean valid = true;

            for (int i = 0; i < Math.min(data.length, keyLen * 4); i++) {
                int plain = -1;
                if (i == 0) plain = 0xFE;
                else if (i == 1) plain = 0xFF;
                else if (i >= 2 && i % 2 == 0) plain = 0x00;
                if (plain < 0) continue;

                int pos = i % keyLen;
                int needed = (data[i] & 0xFF) ^ (xorKey[i % xorKey.length] & 0xFF) ^ plain;

                if (set[pos]) {
                    if ((key[pos] & 0xFF) != needed) { valid = false; break; }
                } else {
                    key[pos] = (byte) needed;
                    set[pos] = true;
                }
            }
            if (!valid) continue;

            boolean allSet = true;
            for (int i = 0; i < keyLen; i++) {
                if (!set[i]) { allSet = false; break; }
                int b = key[i] & 0xFF;
                if (b < 0x2D || b > 0x39 || (b > 0x2D && b < 0x30)) { valid = false; break; }
            }
            if (!valid || !allSet) continue;

            try {
                int n = Integer.parseInt(new String(key));
                if (Integer.toString(n).length() == keyLen) results.add(n);
            } catch (NumberFormatException ignored) {}
        }
        return results;
    }

    /** XOR decrypt for Silent NET: data ^ keyStr ^ xorKey, result as UTF-16 (Schemes 2/3/4) */
    static String silentNetXorDecrypt(byte[] data, byte[] xorKey, int n) {
        byte[] copy = data.clone();
        String keyStr = Integer.toString(n);
        byte[] keyBytes = keyStr.getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < copy.length; i++) {
            copy[i] = (byte)(copy[i] ^ keyBytes[i % keyBytes.length]);
            copy[i] = (byte)(copy[i] ^ xorKey[i % xorKey.length]);
        }
        return new String(copy, StandardCharsets.UTF_16);
    }

    /** Single-layer XOR decrypt for Silent NET Scheme 1: data ^ str(n).getBytes(), result as UTF-16BE */
    static String silentNetSingleXorDecrypt(byte[] data, int n) {
        if (data.length < 10) return null;
        byte[] copy = data.clone();
        String keyStr = Integer.toString(n);
        byte[] keyBytes = keyStr.getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < copy.length; i++) {
            copy[i] = (byte)(copy[i] ^ keyBytes[i % keyBytes.length]);
        }
        // Check for UTF-16 BOM (FE FF) after single-layer XOR
        if (copy.length >= 2 && (copy[0] & 0xFF) == 0xFE && (copy[1] & 0xFF) == 0xFF) {
            return new String(copy, StandardCharsets.UTF_16);
        }
        // Also try UTF-16BE interpretation (no BOM)
        String result = new String(copy, java.nio.charset.Charset.forName("UTF-16BE"));
        // Quick validity check: should contain mostly printable chars
        int printable = 0;
        for (char c : result.toCharArray()) {
            if (c >= 0x20 && c < 0x7F) printable++;
        }
        if (result.length() > 0 && printable * 100 / result.length() > 80) return result;
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // OUTPUT STRUCTURE: main/ and main/important/
    // ─────────────────────────────────────────────────────────────────────

    static void copyMainFiles(Path sourceDir, Path mainDir, Path importantDir,
                               Variant variant, Map<String, byte[]> classes, String src) {
        try {
            // Define which packages are "main" vs library for each variant
            Set<String> mainPatterns = new LinkedHashSet<>();
            Set<String> importantPatterns = new LinkedHashSet<>();

            switch (variant) {
                case ADAMRAT:
                    mainPatterns.add("com/example"); mainPatterns.add("com\\example");
                    importantPatterns.add("vubsyodfkejzllnk"); importantPatterns.add("upokyqklsolkxbys");
                    importantPatterns.add("ExampleModClient"); importantPatterns.add("c0nfig");
                    break;
                case WEEDHACK:
                    mainPatterns.add("FabricAdapter"); mainPatterns.add("Helper");
                    importantPatterns.add("FabricAdapter"); importantPatterns.add("Helper");
                    break;
                case SESSION_HARVESTER:
                    mainPatterns.add("dev/majanito"); mainPatterns.add("dev\\majanito");
                    importantPatterns.add("LoginScreen"); importantPatterns.add("APIUtils");
                    break;
                case SILENT_NET:
                    mainPatterns.add("com/libmod"); mainPatterns.add("com\\libmod");
                    importantPatterns.add("RpcHelper"); importantPatterns.add("Libmod");
                    importantPatterns.add("Main"); importantPatterns.add("Core");
                    break;
                case VAPE_CURIUM:
                    mainPatterns.add("com/curium"); mainPatterns.add("com\\curium");
                    mainPatterns.add("TextureAtlas"); mainPatterns.add("Shader");
                    mainPatterns.add("ChunkMesh"); mainPatterns.add("StateTracker");
                    importantPatterns.add("NetworkManager"); importantPatterns.add("TextureAtlas");
                    importantPatterns.add("StateTracker");
                    break;
                case MSHTA_DROPPER:
                    // Copy everything non-library
                    mainPatterns.add("/"); // match all
                    importantPatterns.add("mshta"); importantPatterns.add("Runtime");
                    importantPatterns.add("ProcessBuilder");
                    break;
                case SERVER_CRASHER:
                    mainPatterns.add("us/whitedev"); mainPatterns.add("us\\whitedev");
                    importantPatterns.add("Exploit"); importantPatterns.add("Crasher");
                    importantPatterns.add("CrashManager"); importantPatterns.add("ExploitManager");
                    importantPatterns.add("AccountHelper"); importantPatterns.add("DiscordRP");
                    importantPatterns.add("Main2Packets"); importantPatterns.add("VpnHelper");
                    importantPatterns.add("PacketHelper"); importantPatterns.add("ForceOp");
                    importantPatterns.add("Log4J");
                    break;
                case MCLAUNCHER_LOADER:
                    mainPatterns.add("me/mclauncher"); mainPatterns.add("me\\mclauncher");
                    importantPatterns.add("IMCL"); importantPatterns.add("MEntrypoint");
                    importantPatterns.add("LoaderClient"); importantPatterns.add("StagingHelper");
                    break;
                case PACKUTIL_RAT:
                    mainPatterns.add("com/example/addon"); mainPatterns.add("com\\example\\addon");
                    importantPatterns.add("PackUtil"); importantPatterns.add("ExampleModClient");
                    break;
                default:
                    mainPatterns.add("/"); // match all non-library
                    importantPatterns.add("webhook"); importantPatterns.add("discord");
                    importantPatterns.add("Runtime.exec"); importantPatterns.add("HttpURL");
                    break;
            }

            try (var walker = Files.walk(sourceDir)) {
                walker.filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> {
                        try {
                            String rel = sourceDir.relativize(p).toString();
                            String content = Files.readString(p);
                            boolean isLib = isLibraryClass(rel.replace(".java", ".class"));

                            // Check if it matches main patterns
                            boolean isMain = false;
                            for (String pat : mainPatterns) {
                                if (rel.contains(pat) || pat.equals("/")) { isMain = true; break; }
                            }
                            if (isMain && !isLib) {
                                Path dest = mainDir.resolve(rel);
                                Files.createDirectories(dest.getParent());
                                Files.copy(p, dest, StandardCopyOption.REPLACE_EXISTING);

                                // Check if it also matches important patterns
                                boolean isImportant = false;
                                for (String pat : importantPatterns) {
                                    if (rel.contains(pat) || content.contains(pat)) { isImportant = true; break; }
                                }
                                if (isImportant) {
                                    Path impDest = importantDir.resolve(rel);
                                    Files.createDirectories(impDest.getParent());
                                    Files.copy(p, impDest, StandardCopyOption.REPLACE_EXISTING);
                                }
                            }
                        } catch (Exception ignored) {}
                    });
            }
        } catch (Exception e) {
            warn("Error copying main files: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // ANALYSIS REPORT
    // ─────────────────────────────────────────────────────────────────────

    static void writeAnalysisTxt(Path outDir, String jarPath, String jarSha256,
                                  Variant variant, List<String> markers,
                                  String decompilerUsed, String src, String configRaw,
                                  boolean hasTrailingSlash) {
        try (PrintWriter w = new PrintWriter(new FileWriter(outDir.resolve(jarName + "_analysis.txt").toFile()))) {
            w.println("═══════════════════════════════════════════════════════════");
            w.println("FILE ANALYSIS REPORT");
            w.println("═══════════════════════════════════════════════════════════");
            w.println();
            w.println("File: " + Paths.get(jarPath).getFileName());
            w.println("SHA-256: " + jarSha256);
            w.println("Variant: " + variant);
            w.println("Analysis Date: " + java.time.Instant.now());
            w.println();

            w.println("──── WHAT WAS DETECTED ────");
            w.println();
            switch (variant) {
                case ADAMRAT:
                    w.println("This JAR is an ADAMRAT malware sample. ADAMRAT is a Minecraft Fabric mod");
                    w.println("RAT (Remote Access Trojan) that uses AES-encrypted configuration stored in");
                    w.println("the JAR's resources. It exfiltrates stolen data via Discord webhooks.");
                    w.println("Detection: Identified by obfuscated class names (vubsyodfkejzllnk pattern)");
                    w.println("and ExampleModClient entry point with inner config classes.");
                    break;
                case WEEDHACK:
                    w.println("This JAR is a WEEDHACK DROPPER. It uses Ethereum smart contracts (EtherHiding)");
                    w.println("to dynamically resolve its C2 domain, downloads a native DLL stage2 payload,");
                    w.println("and invokes it via JNIC (Java Native Interface Compiler).");
                    w.println("Detection: FabricAdapter class + eth_call RPC patterns.");
                    break;
                case SESSION_HARVESTER:
                    w.println("This JAR is a SESSION HARVESTER targeting Minecraft authentication tokens.");
                    w.println("It steals session tokens from the Minecraft launcher and exfiltrates them.");
                    w.println("Detection: dev.majanito package + LoginScreen/APIUtils classes.");
                    break;
                case VAPE_CURIUM:
                    w.println("This JAR is a VAPE CURIUM malware sample. It is a sophisticated stage2 loader");
                    w.println("and worm that downloads arbitrary JARs from a C2 URL, executes them via");
                    w.println("NetworkManager.start(), and self-replicates to all Minecraft launcher mod");
                    w.println("folders (CurseForge, PrismLauncher, Modrinth, .minecraft, etc.).");
                    w.println("Detection: TextureAtlasCache/ShaderCompileCache/ChunkMeshPool key classes");
                    w.println("with hex-encoded XOR string encryption.");
                    break;
                case SILENT_NET:
                    w.println("This JAR is a SILENT NET malware sample. It uses BLOCKCHAIN-BASED C2 RESOLUTION");
                    w.println("via a Polygon smart contract to dynamically resolve its C2 domain. This makes");
                    w.println("the C2 infrastructure resilient to takedowns since the attacker can update the");
                    w.println("domain by writing to the blockchain.");
                    w.println("Detection: com.libmod package + Polygon RPC endpoints + opaque predicate");
                    w.println("obfuscation (cwmhwqsenglvcost.glcqksioqxlglmmb dispatcher class).");
                    break;
                case MSHTA_DROPPER:
                    w.println("This JAR is an MSHTA DROPPER. It uses the Windows mshta.exe utility to");
                    w.println("download and execute a remote HTA payload, which typically drops additional");
                    w.println("malware. The technique bypasses many security controls.");
                    w.println("Detection: mshta command string in class bytecode.");
                    break;
                case FRACTUREISER:
                    w.println("This JAR is infected with FRACTUREISER, a multi-stage Minecraft mod infector");
                    w.println("that propagates through CurseForge and BukkitDev. Stage 0 uses URLClassLoader");
                    w.println("to download from hardcoded IPs. Stage 1 creates system properties and downloads");
                    w.println("lib.jar/libWebGL64.jar. Stage 2/3 (dev.neko) steals browser credentials,");
                    w.println("Discord tokens, crypto wallets, and Minecraft session tokens.");
                    w.println("Detection: dev.neko/nekoclient classes or known C2 IPs in constant pool.");
                    break;
                case SKYRAGE:
                    w.println("This JAR is a SKYRAGE variant. It connects to skyrage.de C2 servers,");
                    w.println("creates persistence via scheduled tasks (MicrosoftEdgeUpdateTaskMachineVM)");
                    w.println("and Windows services (vmd-gnu), and drops discord_rpc.dll for Discord");
                    w.println("token theft. Also steals browser and Minecraft credentials.");
                    w.println("Detection: skyrage.de domain or discord_rpc.dll in JAR resources.");
                    break;
                case WEIRDUTILS:
                    w.println("This JAR is a WEIRDUTILS backdoor. It uses AES/CBC encrypted payloads");
                    w.println("with Base64-encoded LDC (load constant) instructions to hide C2 URLs.");
                    w.println("Masquerades under org.spongepowered.tools.obfuscation namespace.");
                    w.println("Fetches C2 config from Pastebin, exfiltrates to owouwu.tk.");
                    w.println("Uses custom ObfuscatedClassloader for dynamic class loading.");
                    w.println("Detection: owouwu.tk domain, ObfuscatedClassloader class, or known");
                    w.println("Base64 Pastebin URL in LDC constant pool.");
                    break;
                case COMET:
                    w.println("This JAR is a COMET backdoor targeting Bukkit/Spigot servers.");
                    w.println("Registers '*auth' chat command with default password 'test'");
                    w.println("(MD5: 81dc9bdb52d04dc20036dbd8313ed055). C2 hosted on Replit.");
                    w.println("Provides remote command execution, OP escalation, and plugin management.");
                    w.println("Detection: *auth command pattern, MD5 hash, or replit.dev/replit.app C2.");
                    break;
                case ECTASY:
                    w.println("This JAR is an ECTASY backdoor targeting BungeeCord/Spigot servers.");
                    w.println("Uses '*' as command prefix. Downloads second-stage 'bungee.jar' to");
                    w.println("plugins/PluginMetrics/ directory. C2: ectasy.club.");
                    w.println("Features TranslatableComponentDeserializer for obfuscation, remote");
                    w.println("shell, file manager, and full server takeover capabilities.");
                    w.println("Detection: ectasy.club domain, PluginMetrics/bungee.jar path, or");
                    w.println("TranslatableComponentDeserializer class.");
                    break;
                case SERVER_CRASHER:
                    w.println("This JAR is a SERVER CRASHER / EXPLOIT CLIENT. It is a weaponized Minecraft");
                    w.println("client bundled with server crashing tools, plugin exploits, and attack modules.");
                    w.println("Unlike RATs, this tool is designed for the operator to attack Minecraft servers");
                    w.println("rather than steal data from the user running it.");
                    w.println("Capabilities: server DoS via malformed packets, plugin exploitation (ForceOp,");
                    w.println("Log4J, LuckPerms, WorldEdit, BungeeCord/Velocity), account management via");
                    w.println("cookie theft, VPN/proxy integration, and Discord Rich Presence.");
                    w.println("Detection: us.whitedev package, CrashManager/ExploitManager classes,");
                    w.println("or 2PacketsClient/xynis identifiers.");
                    break;
                case MCLAUNCHER_LOADER:
                    w.println("This JAR contains the MCLAUNCHER LOADER — a malicious mod loader that uses");
                    w.println("the me/mclauncher package to inject and execute arbitrary code.");
                    w.println("IMCL class uses ClassLoader.defineClass for runtime bytecode injection.");
                    w.println("MEntrypoint uses ProcessBuilder for system command execution.");
                    w.println("StagingHelper uses reflective invocation + System.load for native library loading.");
                    w.println("Often bundled with legitimate mods (Meteor Client, AppleSkin, NoChatReports, etc.)");
                    w.println("as a trojanized wrapper — the legitimate mod works normally while the loader");
                    w.println("silently downloads and executes a second-stage payload.");
                    w.println("Detection: me/mclauncher package with IMCL/MEntrypoint/LoaderClient/StagingHelper classes.");
                    break;
                case PACKUTIL_RAT:
                    w.println("This JAR is a PACKUTIL RAT — a trojanized Minecraft Fabric mod that masquerades");
                    w.println("as a legitimate addon (e.g. 'YungLightUI') while hiding a full-featured RAT");
                    w.println("in the com.example.addon package using PackUtil* utility classes.");
                    w.println("Capabilities: Minecraft session theft (UUID/access token), screen capture,");
                    w.println("command execution (Runtime.exec), native library loading (System.load),");
                    w.println("sun.misc.Unsafe memory manipulation, dynamic class loading, and reflection.");
                    w.println("Uses control-flow obfuscation (switch dispatchers) and braille art ASCII arrays");
                    w.println("as string table padding to evade static analysis.");
                    w.println("Detection: com/example/addon package with 3+ PackUtil* class names.");
                    break;
                default:
                    w.println("This JAR's variant could not be definitively classified. It was analyzed");
                    w.println("using generic extraction and behavioral analysis.");
                    break;
            }
            w.println();

            w.println("──── WHAT WAS DONE ────");
            w.println();
            w.println("1. Extracted all class files from JAR (" + (hasTrailingSlash ? "including .class/ trick entries" : "standard extraction") + ")");
            if (hasTrailingSlash)
                w.println("   - JAR uses trailing '/' trick on .class entries to evade decompilers");
            w.println("2. Decompiled using " + decompilerUsed + " decompiler");
            w.println("   - Full source written to source/ directory");
            w.println("   - Main application code copied to main/ directory");
            w.println("   - C2/config code highlighted in main/important/ directory");
            if (configRaw != null)
                w.println("3. Found and decrypted embedded configuration file");
            w.println("3. Scanned for behavioral markers and IOCs");
            w.println("4. Extracted and decrypted obfuscated strings (variant-specific)");
            w.println();

            w.println("──── WHY THIS ANALYSIS ────");
            w.println();
            w.println("Decompiler choice: " + decompilerUsed);
            if (decompilerUsed.contains("Vineflower")) {
                w.println("  Vineflower was used because it produces the cleanest output and handles");
                w.println("  obfuscated control flow better than CFR for most patterns.");
            }
            if (decompilerUsed.contains("JADX")) {
                w.println("  JADX was used because Vineflower failed. JADX has built-in deobfuscation");
                w.println("  that renames obfuscated identifiers to readable names.");
            }
            if (decompilerUsed.contains("CFR")) {
                w.println("  CFR was used as fallback or supplement. It handles some obfuscation");
                w.println("  patterns that other decompilers miss, but may fail on opaque predicates.");
            }
            w.println();

            if (!markers.isEmpty()) {
                w.println("──── BEHAVIORAL MARKERS ────");
                w.println();
                for (String m : markers) {
                    w.println("  - " + m);
                    // Include file/line details if available
                    List<Map<String, String>> details = markerDetails.get(m);
                    if (details != null) {
                        for (Map<String, String> d : details) {
                            String file = d.getOrDefault("file", "");
                            String line = d.getOrDefault("line", "0");
                            String ctx = d.getOrDefault("context", "");
                            if (!file.isEmpty()) {
                                w.print("      @ " + file);
                                if (!"0".equals(line)) w.print(":" + line);
                                if (!ctx.isEmpty()) w.print("  →  " + ctx.trim());
                                w.println();
                            }
                        }
                    }
                }
                w.println();
            }

            w.println("──── OUTPUT FILES ────");
            w.println();
            w.println("  source/           Full decompiled Java source code");
            w.println("  main/             Main application source files (non-library)");
            w.println("  main/important/   C2, config, and crypto code specifically");
            w.println("  *_analysis.txt    This report");
            w.println("  *_info.log        Detailed analysis log");
            w.println("  *_config.log      Extracted configuration data");
            w.println("  *_iocs.json       Machine-readable IOCs (URLs, hashes, webhooks)");
        } catch (Exception e) {
            warn("Failed to write analysis.txt: " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // JAR METADATA EXTRACTION
    // ─────────────────────────────────────────────────────────────────────

    /** Extract and log comprehensive metadata from the JAR */
    static void extractJarMetadata(String jarPath, Map<String, byte[]> classes) {
        // 1. MANIFEST.MF
        try (ZipFile zf = new ZipFile(jarPath)) {
            ZipEntry manifest = zf.getEntry("META-INF/MANIFEST.MF");
            if (manifest != null) {
                String content;
                try (InputStream mis = zf.getInputStream(manifest)) { content = new String(readBounded(mis, 1_000_000), StandardCharsets.UTF_8); }
                ilog("  MANIFEST.MF:");
                for (String line : content.split("\n")) {
                    line = line.trim();
                    if (!line.isEmpty()) ilog("    " + line);
                }
                // Extract Main-Class
                java.util.jar.Manifest mf = new java.util.jar.Manifest(
                    new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
                String mainClass = mf.getMainAttributes().getValue("Main-Class");
                if (mainClass != null) {
                    ok("Main-Class: " + mainClass);
                    ilog("  Main-Class: " + mainClass);
                }
                // Check for Java agent attributes (Premain-Class, Agent-Class)
                String premainClass = mf.getMainAttributes().getValue("Premain-Class");
                if (premainClass != null) {
                    warn("Java agent: Premain-Class found (" + premainClass + ")");
                    ilog("  Premain-Class: " + premainClass);
                }
                String agentClass = mf.getMainAttributes().getValue("Agent-Class");
                if (agentClass != null) {
                    warn("Java agent: Agent-Class found (" + agentClass + ")");
                    ilog("  Agent-Class: " + agentClass);
                }
            }
        } catch (Exception e) { ilog("  MANIFEST.MF: (error: " + e.getMessage() + ")"); }

        // 2. Mod metadata files (fabric.mod.json, quilt.mod.json, mods.toml, plugin.yml)
        String[] modMetas = {"fabric.mod.json", "quilt.mod.json", "META-INF/mods.toml",
                             "plugin.yml", "bungee.yml", "paper-plugin.yml"};
        try (ZipFile zf = new ZipFile(jarPath)) {
            for (String meta : modMetas) {
                ZipEntry e = zf.getEntry(meta);
                if (e != null) {
                    // Track which mod loader this JAR targets
                    if (meta.equals("fabric.mod.json")) detectedModLoaders.add("fabric");
                    else if (meta.equals("quilt.mod.json")) detectedModLoaders.add("quilt");
                    else if (meta.equals("META-INF/mods.toml")) detectedModLoaders.add("forge");
                    else if (meta.equals("plugin.yml") || meta.equals("paper-plugin.yml")) detectedModLoaders.add("bukkit");
                    else if (meta.equals("bungee.yml")) detectedModLoaders.add("bungee");

                    String content;
                    try (InputStream metaIs = zf.getInputStream(e)) { content = new String(readBounded(metaIs, 1_000_000), StandardCharsets.UTF_8); }
                    ilog("  " + meta + ":");
                    // Extract key fields
                    for (String field : new String[]{"id", "name", "version", "description", "authors",
                            "contact", "homepage", "main", "entrypoints"}) {
                        Pattern p = Pattern.compile("\"" + field + "\"\\s*:\\s*(?:\"([^\"]*)\"|\\[([^\\]]*)\\]|([^,}]+))");
                        Matcher m = p.matcher(content);
                        if (m.find()) {
                            String val = m.group(1) != null ? m.group(1) : (m.group(2) != null ? m.group(2) : m.group(3));
                            ilog("    " + field + ": " + val.trim());
                            if (field.equals("id") || field.equals("name"))
                                ok("Mod " + field + ": " + val.trim());
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        // 3. Non-.class resource inventory (find hidden files, embedded JARs, suspicious resources)
        List<String> resources = new ArrayList<>();
        List<String> suspiciousResources = new ArrayList<>();
        try (ZipFile zf = new ZipFile(jarPath)) {
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                if (e.isDirectory() && e.getSize() <= 0) continue;
                if (name.endsWith(".class") || name.endsWith(".class/")) continue;
                resources.add(name + " (" + e.getSize() + " bytes)");
                // Flag suspicious entries
                if (name.endsWith(".jar") || name.endsWith(".dll") || name.endsWith(".so")
                    || name.endsWith(".exe") || name.endsWith(".bat") || name.endsWith(".sh")
                    || name.endsWith(".ps1") || name.endsWith(".vbs") || name.endsWith(".hta")
                    || name.endsWith(".dat") || name.endsWith(".bin")) {
                    suspiciousResources.add(name + " (" + e.getSize() + " bytes)");
                }
                // Check for hidden dotfiles
                String basename = name.contains("/") ? name.substring(name.lastIndexOf('/') + 1) : name;
                if (basename.startsWith(".") && !basename.equals(".") && !basename.equals("..")) {
                    suspiciousResources.add("[dotfile] " + name);
                }
            }
        } catch (Exception ignored) {}
        if (!resources.isEmpty()) {
            ilog("  Non-class resources (" + resources.size() + "):");
            for (String r : resources) ilog("    " + r);
        }
        if (!suspiciousResources.isEmpty()) {
            for (String r : suspiciousResources) warn("Suspicious resource: " + r);
        }

        // 3b. JNIC blob detection — check binary resources for JNIC native obfuscation
        try (ZipFile zf2 = new ZipFile(jarPath)) {
            var entries2 = zf2.entries();
            while (entries2.hasMoreElements()) {
                ZipEntry e = entries2.nextElement();
                String name = e.getName().toLowerCase();
                if (e.isDirectory() || e.getSize() <= 0) continue;
                if (name.endsWith(".bin") || name.endsWith(".dat")) {
                    try (InputStream is = zf2.getInputStream(e)) {
                        byte[] header = new byte[(int)Math.min(e.getSize(), 64)];
                        int read = is.read(header);
                        if (read >= 4) {
                            // Check for "JNIC" string in first 64 bytes
                            String headerStr = new String(header, 0, read, StandardCharsets.US_ASCII);
                            boolean hasJnic = headerStr.contains("JNIC");
                            // Check for CAFEBABE at non-standard offset (offset > 0)
                            boolean hasCafeBabe = false;
                            for (int off = 4; off < read - 3; off++) {
                                if ((header[off] & 0xFF) == 0xCA && (header[off+1] & 0xFF) == 0xFE
                                    && (header[off+2] & 0xFF) == 0xBA && (header[off+3] & 0xFF) == 0xBE) {
                                    hasCafeBabe = true;
                                    break;
                                }
                            }
                            if (hasJnic || hasCafeBabe) {
                                String msg = "JNIC native obfuscation blob detected (" + e.getSize() + " bytes): " + e.getName();
                                warn(msg);
                                ilog("  [JNIC] " + msg);
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}

        // 3c. META-INF/services/ detection (ServiceLoader exploitation)
        try (ZipFile zf3 = new ZipFile(jarPath)) {
            var entries3 = zf3.entries();
            boolean hasServices = false;
            while (entries3.hasMoreElements()) {
                ZipEntry e = entries3.nextElement();
                if (e.getName().startsWith("META-INF/services/") && !e.isDirectory()) {
                    hasServices = true;
                    break;
                }
            }
            if (hasServices) {
                warn("META-INF/services/ entries found (potential ServiceLoader exploitation)");
                ilog("  [SERVICES] META-INF/services/ entries detected");
            }
        } catch (Exception ignored) {}

        // 4. Java class file version detection (compile target)
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            byte[] data = e.getValue();
            if (data.length >= 8 && isClassMagic(data)) {
                int minor = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
                int major = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
                String javaVer;
                if      (major <= 45) javaVer = "Java 1.1";
                else if (major == 46) javaVer = "Java 1.2";
                else if (major == 47) javaVer = "Java 1.3";
                else if (major == 48) javaVer = "Java 1.4";
                else if (major == 49) javaVer = "Java 5";
                else if (major == 50) javaVer = "Java 6";
                else if (major == 51) javaVer = "Java 7";
                else if (major == 52) javaVer = "Java 8";
                else if (major == 53) javaVer = "Java 9";
                else if (major == 54) javaVer = "Java 10";
                else if (major == 55) javaVer = "Java 11";
                else if (major == 56) javaVer = "Java 12";
                else if (major == 57) javaVer = "Java 13";
                else if (major == 58) javaVer = "Java 14";
                else if (major == 59) javaVer = "Java 15";
                else if (major == 60) javaVer = "Java 16";
                else if (major == 61) javaVer = "Java 17";
                else if (major == 62) javaVer = "Java 18";
                else if (major == 63) javaVer = "Java 19";
                else if (major == 64) javaVer = "Java 20";
                else if (major == 65) javaVer = "Java 21";
                else if (major == 66) javaVer = "Java 22";
                else if (major == 67) javaVer = "Java 23";
                else                  javaVer = "Java " + (major - 44);
                ok("Class version: " + major + "." + minor + " (" + javaVer + ") [" + e.getKey() + "]");
                ilog("  Class version: " + major + "." + minor + " (" + javaVer + ")");
                break; // Only report once (first class)
            }
        }

        // 5. Certificate/signing detection
        try (ZipFile zf = new ZipFile(jarPath)) {
            var entries = zf.entries();
            boolean signed = false;
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName().toUpperCase();
                if (name.startsWith("META-INF/") && (name.endsWith(".SF") || name.endsWith(".RSA")
                    || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    signed = true;
                    ilog("  Signing file: " + e.getName());
                }
            }
            if (signed) ok("JAR is signed (has META-INF/*.SF/*.RSA)");
            else ilog("  JAR is not signed");
        } catch (Exception ignored) {}

        // 6. Constant pool string extraction (extract ALL strings > 4 chars from class constant pools)
        Set<String> constantPoolStrings = new LinkedHashSet<>();
        for (byte[] data : classes.values()) {
            extractConstantPoolStrings(data, constantPoolStrings);
        }
        // Filter for interesting strings
        List<String> interestingStrings = new ArrayList<>();
        Pattern ipPat = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        Pattern domainPat = Pattern.compile("[a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,}");
        Pattern pathPat = Pattern.compile("[A-Z]:\\\\|/home/|/tmp/|/etc/|%APPDATA%|%TEMP%|%USERPROFILE%");
        Pattern b64Pat = Pattern.compile("^[A-Za-z0-9+/]{20,}={0,2}$");
        for (String s : constantPoolStrings) {
            Matcher ipM = ipPat.matcher(s);
            if (ipM.find() && !s.contains("version")) {
                interestingStrings.add("[IP] " + s);
                continue;
            }
            if (s.startsWith("http://") || s.startsWith("https://")) {
                interestingStrings.add("[URL] " + s);
                continue;
            }
            Matcher pathM = pathPat.matcher(s);
            if (pathM.find()) {
                interestingStrings.add("[PATH] " + s);
                continue;
            }
            if (b64Pat.matcher(s).matches() && s.length() >= 24) {
                // Try decode
                try {
                    byte[] dec = Base64.getDecoder().decode(s);
                    String decoded = new String(dec, StandardCharsets.UTF_8);
                    if (isAsciiPrintable(decoded) && decoded.length() >= 4) {
                        interestingStrings.add("[B64] " + s + " => " + decoded);
                    }
                } catch (Exception ignored) {}
                continue;
            }
            // Check for Discord tokens, API keys, etc. (skip known-safe library strings)
            if (s.matches("[A-Za-z0-9._\\-]{50,}") || s.contains("token") || s.contains("api_key")
                || s.contains("password") || s.contains("secret")) {
                // Skip single-word programming terms and common library references
                String lower = s.toLowerCase();
                if (lower.contains("tokenize") || lower.contains("tokenizer") || lower.contains("tokenclass")
                    || lower.contains("tokentype") || lower.contains("tokenvalue") || lower.contains("nexttoken")
                    || lower.contains("peektoken") || lower.contains("gettoken") || lower.contains("parsetoken")
                    || lower.contains("token_") || lower.contains("_token") || lower.contains("tokenfactory")
                    || lower.equals("token") || lower.equals("password") || lower.equals("secret")
                    || lower.startsWith("com.google.") || lower.startsWith("com.fasterxml.")
                    || lower.startsWith("org.json.") || lower.startsWith("com.formdev.")
                    || lower.contains("expected") || lower.contains("invalid json")
                    || lower.contains("keyword")) continue;
                interestingStrings.add("[SENSITIVE] " + s);
            }
        }
        if (!interestingStrings.isEmpty()) {
            ok("Found " + interestingStrings.size() + " interesting constant pool string(s):");
            for (String s : interestingStrings) {
                ilog("    " + s);
                if (s.startsWith("[IP]") || s.startsWith("[URL]") || s.startsWith("[SENSITIVE]"))
                    warn("  " + s);
            }
        }

        // 6b. Collect constant pool URLs and domains as pipeline IOCs
        // These are stored as static fields on the metadata extraction pass so variant analyzers can use them
        cpUrlsCollected.clear();
        cpDomainsCollected.clear();
        for (String s : interestingStrings) {
            if (s.startsWith("[URL] ")) {
                String url = s.substring(6).trim();
                cpUrlsCollected.add(url);
            }
        }
        // Extract domains from constant pool strings
        for (String s : constantPoolStrings) {
            if (domainPat.matcher(s).matches() && s.contains(".") && !s.contains("/")
                && !s.endsWith(".class") && !s.endsWith(".java") && !s.endsWith(".json")
                && !s.endsWith(".xml") && !s.endsWith(".yml") && !s.endsWith(".properties")
                && s.length() <= 80) {
                // Skip common Java/library package-like strings
                if (!s.startsWith("java.") && !s.startsWith("javax.") && !s.startsWith("com.google.")
                    && !s.startsWith("org.apache.") && !s.startsWith("com.sun.")
                    && !s.startsWith("sun.") && !s.startsWith("com.fasterxml.")
                    && !s.startsWith("org.slf4j.") && !s.startsWith("io.netty.")) {
                    cpDomainsCollected.add(s);
                }
            }
        }
        if (!cpUrlsCollected.isEmpty())
            ilog("  [CP-PIPELINE] Collected " + cpUrlsCollected.size() + " URL(s) from constant pool");
        if (!cpDomainsCollected.isEmpty())
            ilog("  [CP-PIPELINE] Collected " + cpDomainsCollected.size() + " domain pattern(s) from constant pool");

        // 7. Dangerous API import analysis
        Map<String, String> dangerousApis = new LinkedHashMap<>();
        dangerousApis.put("java/lang/Runtime", "Runtime.exec() — command execution");
        dangerousApis.put("java/lang/ProcessBuilder", "ProcessBuilder — process spawning");
        dangerousApis.put("java/net/URLClassLoader", "URLClassLoader — dynamic class loading from URLs");
        dangerousApis.put("java/lang/reflect/Method", "Reflection — method invocation (anti-analysis/dynamic calls)");
        dangerousApis.put("javax/crypto/Cipher", "Crypto API — encryption/decryption");
        dangerousApis.put("java/net/HttpURLConnection", "HTTP networking");
        dangerousApis.put("java/net/Socket", "Raw socket networking");
        dangerousApis.put("java/io/FileOutputStream", "File writing capability");
        dangerousApis.put("java/awt/Robot", "Screen capture / input simulation");
        dangerousApis.put("java/awt/Toolkit", "Clipboard access");
        dangerousApis.put("java/lang/ClassLoader", "Custom ClassLoader — dynamic code loading");
        dangerousApis.put("java/util/prefs/Preferences", "Registry/preferences access (persistence)");
        dangerousApis.put("java/lang/instrument", "Java agent instrumentation");
        dangerousApis.put("sun/misc/Unsafe", "Unsafe API — low-level memory manipulation");
        dangerousApis.put("javax/script/ScriptEngine", "Script engine — eval() execution");

        Set<String> detectedApis = new LinkedHashSet<>();
        for (String cpStr : constantPoolStrings) {
            for (Map.Entry<String, String> api : dangerousApis.entrySet()) {
                if (cpStr.contains(api.getKey()) && detectedApis.add(api.getKey())) {
                    ilog("  [API] " + api.getValue());
                }
            }
        }
        // Also check raw class bytes for API refs
        for (byte[] data : classes.values()) {
            String ascii = new String(data, StandardCharsets.US_ASCII);
            for (Map.Entry<String, String> api : dangerousApis.entrySet()) {
                if (ascii.contains(api.getKey()) && detectedApis.add(api.getKey())) {
                    ilog("  [API] " + api.getValue());
                }
            }
        }
        if (!detectedApis.isEmpty()) {
            ok("Detected " + detectedApis.size() + " dangerous API reference(s)");
        }
    }

    /** Extract UTF-8 strings from class file constant pool */
    static void extractConstantPoolStrings(byte[] data, Set<String> out) {
        if (data.length < 10 || !isClassMagic(data)) return;
        try {
            int cpCount = ((data[8] & 0xFF) << 8) | (data[9] & 0xFF);
            int pos = 10;
            for (int i = 1; i < cpCount && pos < data.length; i++) {
                int tag = data[pos] & 0xFF;
                pos++;
                switch (tag) {
                    case 1: // CONSTANT_Utf8
                        if (pos + 2 > data.length) return;
                        int len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                        pos += 2;
                        if (pos + len > data.length) return;
                        if (len >= 4) {
                            String s = new String(data, pos, len, StandardCharsets.UTF_8);
                            out.add(s);
                        }
                        pos += len;
                        break;
                    case 3: case 4: pos += 4; break; // Integer, Float
                    case 5: case 6: pos += 8; i++; break; // Long, Double (takes 2 slots)
                    case 7: case 8: case 16: case 19: case 20: pos += 2; break; // Class, String, MethodType, Module, Package
                    case 9: case 10: case 11: case 12: case 17: case 18: pos += 4; break; // Field, Method, InterfaceMethod, NameAndType, Dynamic, InvokeDynamic
                    case 15: pos += 3; break; // MethodHandle
                    default: return; // Unknown tag, bail out
                }
            }
        } catch (Exception ignored) {}
    }

    // ─────────────────────────────────────────────────────────────────────
    // CFR AUTO-LOCATION
    // ─────────────────────────────────────────────────────────────────────

    static String findCFR() {
        String[] names = {"cfr-0.152.jar", "cfr.jar"};
        try {
            String self = JarAnalyzer.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            Path dir = Paths.get(self).getParent();
            if (dir != null) for (String n : names) if (Files.exists(dir.resolve(n))) return dir.resolve(n).toString();
        } catch (Exception ignored) {}
        for (String n : names) if (Files.exists(Paths.get(n))) return n;
        for (String n : names) if (Files.exists(Paths.get("tools", n))) return Paths.get("tools", n).toString();
        for (String p : new String[]{
                System.getProperty("user.home") + "/cfr-0.152.jar",
                System.getProperty("user.home") + "/cfr.jar",
                System.getProperty("user.home") + "/Downloads/cfr-0.152.jar"}) {
            if (Files.exists(Paths.get(p))) return p;
        }
        throw new RuntimeException("cfr-0.152.jar not found — place it in the same folder");
    }

    // ─────────────────────────────────────────────────────────────────────
    // JSON HELPERS
    // ─────────────────────────────────────────────────────────────────────

    static String prettyJson(String json) {
        StringBuilder sb = new StringBuilder();
        int indent = 0; boolean inStr = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && inStr) { sb.append(c); if (i + 1 < json.length()) sb.append(json.charAt(++i)); continue; }
            if (c == '"') inStr = !inStr;
            if (!inStr) {
                if (c == '{' || c == '[') { sb.append(c).append('\n').append("  ".repeat(++indent)); continue; }
                else if (c == '}' || c == ']') { sb.append('\n').append("  ".repeat(Math.max(0, --indent))).append(c); continue; }
                else if (c == ',') { sb.append(c).append('\n').append("  ".repeat(Math.max(0, indent))); continue; }
                else if (c == ':') { sb.append(": "); continue; }
                else if (c == ' ' || c == '\n' || c == '\r') continue;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    static String extractJsonValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(?:\"([^\"]*)\"|([^,}\\]]+))");
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        return m.group(1) != null ? m.group(1) : m.group(2).trim();
    }

    // ─────────────────────────────────────────────────────────────────────
    // CFR DECOMPILATION
    // ─────────────────────────────────────────────────────────────────────

    static String runCFR(String cfrPath, String classPath) {
        java.util.concurrent.ExecutorService exec = java.util.concurrent.Executors.newSingleThreadExecutor();
        try {
            Process p = new ProcessBuilder("java", "-jar", cfrPath, classPath)
                .redirectErrorStream(true).start();
            // Read output concurrently to avoid deadlock if buffer fills
            java.util.concurrent.Future<byte[]> outputFuture =
                exec.submit(() -> readBounded(p.getInputStream(), 50_000_000));
            if (!p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                outputFuture.cancel(true);
                return "/* CFR timed out after 120s */";
            }
            byte[] out = outputFuture.get(10, java.util.concurrent.TimeUnit.SECONDS);
            p.destroyForcibly();
            return new String(out, StandardCharsets.UTF_8);
        } catch (Exception e) { return "/* CFR failed: " + e.getMessage() + " */"; }
        finally { exec.shutdownNow(); }
    }

    // ─────────────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────────────

    static String sha256(String path) { return hash(path, "SHA-256"); }

    static String hash(String path, String algo) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            try (InputStream is = new BufferedInputStream(new FileInputStream(path))) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) md.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return "ERROR: " + e.getMessage(); }
    }

    static boolean isAsciiPrintable(String s) {
        if (s == null || s.isEmpty()) return false;
        for (char c : s.toCharArray()) if (c < 0x20 || c > 0x7E) return false;
        return s.length() >= 2;
    }

    static boolean looksLikeJson(String s) {
        if (s == null || s.length() < 5) return false;
        if (!s.startsWith("{") && !s.startsWith("[")) return false;
        if (!s.contains("\"")) return false;
        int printable = 0;
        for (char c : s.toCharArray()) if (c >= 0x20 && c <= 0x7E) printable++;
        return (printable * 100L / s.length()) >= 80;
    }

    static int    parseHex(String h)  { return Integer.parseUnsignedInt(h.substring(2), 16); }
    static byte[] hexToBytes(String h) {
        if (h.length() % 2 != 0) h = "0" + h;
        byte[] o = new byte[h.length()/2];
        for (int i=0;i<h.length();i+=2) o[i/2]=(byte)Integer.parseInt(h.substring(i,i+2),16);
        return o;
    }
    static String hexSnippet(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (int i=0;i<Math.min(b.length,8);i++) s.append(String.format("%02x",b[i]));
        return b.length>8?s+"...":s.toString();
    }
    static String hexFull(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte v : b) s.append(String.format("%02x",v));
        return s.toString();
    }
    static String escJson(String s) {
        if (s == null) return "";
        s = s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")
             .replace("\b","\\b").replace("\f","\\f");
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }
    static void cleanUp(Path d) {
        try (var walker = Files.walk(d)) { walker.sorted(Comparator.reverseOrder()).forEach(p->{ try { Files.deleteIfExists(p); } catch(Exception e){} }); }
        catch(Exception ignored){}
    }
    static void closeLogs() { if (infoLog!=null) infoLog.close(); if (configLog!=null) configLog.close(); }

    // ─────────────────────────────────────────────────────────────────────
    // LOGGING
    // ─────────────────────────────────────────────────────────────────────

    static void banner() {
        String[] lines = {
            "  ╔══════════════════════════════════════╗",
            "  ║      Jar Config Extractor            ║",
            "  ║   Minecraft Malware Analyzer         ║",
            "  ╚══════════════════════════════════════╝"
        };
        System.out.println(BOLD + CYAN);
        for (String l : lines) { System.out.println(l); infoLog.println(l); }
        System.out.println(RESET); infoLog.println();
    }

    static void step(String m) { System.out.println(CYAN  +"[*] "+RESET+m); infoLog.println("[*] "+m); }
    static void ok  (String m) { System.out.println(GREEN +"[+] "+RESET+m); infoLog.println("[+] "+m); }
    static void warn(String m) { System.out.println(YELLOW+"[!] "+RESET+m); infoLog.println("[!] "+m); }
    static void fail(String m) { System.out.println(RED   +"[-] "+RESET+m); infoLog.println("[-] "+m); }
    static void ilog(String m) { System.out.println("    "+m);              infoLog.println(m); }
    static void clog(String m) { configLog.println(m); }
    static void llog(String m) { infoLog.println(m); }
}
