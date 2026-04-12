import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

/**
 * BackdoorDetector — Bukkit/Spigot/Paper plugin backdoor scanner
 *
 * Detects common backdoor patterns in Minecraft server plugins by analyzing
 * class constant pools and decompiled source for dangerous API combinations.
 *
 * Patterns detected:
 *   1.  Chat event → console command execution (e.g., "#console op Player")
 *   2.  Chat event → OP escalation (e.g., ".op" in chat gives OP)
 *   3.  Command preprocessor hijacking (intercept commands, re-dispatch as console)
 *   4.  Join event → auto-OP for specific players
 *   5.  ServerCommandEvent manipulation
 *   6.  BungeeCord/plugin message channel backdoor
 *   7.  Sign/book/anvil text triggers
 *   8.  Inventory click → privilege escalation
 *   9.  Block placement triggers
 *  10.  Player interact → OP
 *  11.  Hardcoded UUID + privilege escalation
 *  12.  Remote class loading + privileged execution
 *  13.  Unpermissioned console dispatch from any event
 *  14.  Known trigger string detection (source + raw bytes)
 *  15.  ops.json / whitelist.json / server.properties file manipulation
 *
 * Called from JarAnalyzer.detectBehavioralMarkers().
 */
public class BackdoorDetector {

    /**
     * Main entry point — scans for all backdoor patterns.
     *
     * @param classes       Map of class filename → raw bytecode
     * @param findings      Shared findings list (behavioral markers)
     * @param sourceFiles   Map of source filename → decompiled Java source
     * @param modLoaders    Detected mod loaders (e.g., "bukkit", "fabric")
     * @param markerDetails Shared marker detail map for per-file location tracking
     */
    static void scan(Map<String, byte[]> classes, List<String> findings,
                     Map<String, String> sourceFiles, Set<String> modLoaders,
                     Map<String, List<Map<String, String>>> markerDetails) {

        // Only run if this looks like a Bukkit/Spigot/Paper plugin
        boolean isBukkitPlugin = modLoaders.contains("bukkit");
        if (!isBukkitPlugin) {
            for (byte[] data : classes.values()) {
                String ascii = new String(data, StandardCharsets.US_ASCII);
                if (ascii.contains("org/bukkit/") || ascii.contains("JavaPlugin")) {
                    isBukkitPlugin = true;
                    break;
                }
            }
        }
        if (!isBukkitPlugin) return;

        JarAnalyzer.ilog("  [BACKDOOR] Running Bukkit plugin backdoor scan...");

        scanKnownBackdoorSignatures(classes, findings, markerDetails);
        scanPerClassPatterns(classes, findings, sourceFiles, markerDetails);
        scanTriggerStrings(classes, findings, sourceFiles, markerDetails);
        scanFileManipulation(classes, findings, markerDetails);
        scanInjectedAuxiliaryClasses(classes, findings, sourceFiles, markerDetails);
        scanStructuralAnomalies(classes, findings, sourceFiles, markerDetails);
        scanReflectionAbuse(classes, findings, sourceFiles, markerDetails);
        scanNetworkC2(classes, findings, sourceFiles, markerDetails);
        scanScriptEngines(classes, findings, markerDetails);
        scanProcessExecution(classes, findings, markerDetails);
        scanStringObfuscation(classes, findings, sourceFiles, markerDetails);
        scanObfuscatorSignatures(classes, findings, markerDetails);
        scanEncodedPayloads(classes, findings, sourceFiles, markerDetails);
    }

    // ─────────────────────────────────────────────────────────────────────
    // KNOWN BACKDOOR FRAMEWORK SIGNATURES
    // ─────────────────────────────────────────────────────────────────────

    private static void scanKnownBackdoorSignatures(Map<String, byte[]> classes, List<String> findings,
                                                     Map<String, List<Map<String, String>>> markerDetails) {
        Set<String> classNames = classes.keySet();

        // Check for known malicious packages
        for (String pkg : KNOWN_BACKDOOR_PACKAGES) {
            for (String cls : classNames) {
                if (cls.contains(pkg)) {
                    String m = "KNOWN BACKDOOR FRAMEWORK: Package \"" + pkg + "\" detected (class: " + cls + ")";
                    if (!findings.contains(m)) {
                        findings.add(m); JarAnalyzer.warn(m);
                        addDetail(markerDetails, m, cls, 0, "Known malicious package from backdoor framework");
                    }
                }
            }
        }

        // Check for known malicious class names
        for (String badClass : KNOWN_BACKDOOR_CLASSES) {
            for (String cls : classNames) {
                if (cls.contains(badClass)) {
                    String m = "KNOWN BACKDOOR FRAMEWORK: Class \"" + badClass + "\" detected (in " + cls + ")";
                    if (!findings.contains(m)) {
                        findings.add(m); JarAnalyzer.warn(m);
                        addDetail(markerDetails, m, cls, 0, "Known malicious class from backdoor framework");
                    }
                }
            }
        }

        // Check raw bytes for backdoor tool signatures
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);
            String cn = classEntry.getKey();

            // BeanShell (used by MCBackDoor for script execution)
            if (ascii.contains("bsh.Interpreter") || ascii.contains("bsh/Interpreter")) {
                String m = "SUSPICIOUS: BeanShell script interpreter (used by MCBackDoor) in " + cn;
                if (!findings.contains(m)) {
                    findings.add(m); JarAnalyzer.ilog("  [BACKDOOR] " + m);
                    addDetail(markerDetails, m, cn, 0, "BeanShell interpreter reference");
                }
            }

            // Meterpreter (reverse shell, used by MCBackDoor)
            if (ascii.contains("Meterpreter") || ascii.contains("meterpreter") || ascii.contains("metasploit")) {
                String m = "BACKDOOR: Meterpreter/Metasploit reverse shell component in " + cn;
                if (!findings.contains(m)) {
                    findings.add(m); JarAnalyzer.warn(m);
                    addDetail(markerDetails, m, cn, 0, "Meterpreter/Metasploit reference");
                }
            }

            // org.bukkit.debugger — fake Bukkit package used by Robthekilla backdoor
            if (ascii.contains("org.bukkit.debugger") || ascii.contains("org/bukkit/debugger")) {
                String m = "BACKDOOR: Fake org.bukkit.debugger package (Robthekilla/Backdoor-Plugin) in " + cn;
                if (!findings.contains(m)) {
                    findings.add(m); JarAnalyzer.warn(m);
                    addDetail(markerDetails, m, cn, 0, "Fake Bukkit package — Bukkit has no 'debugger' package");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // INJECTED AUXILIARY CLASS DETECTION (OpenBukloit pattern)
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Detects the OpenBukloit injection pattern: a non-main class with
     * `public static void <name>(JavaPlugin)` called from onEnable().
     * Also detects book edit event triggers.
     */
    private static void scanInjectedAuxiliaryClasses(Map<String, byte[]> classes, List<String> findings,
                                                      Map<String, String> sourceFiles,
                                                      Map<String, List<Map<String, String>>> markerDetails) {
        // Scan decompiled source for the injection pattern
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String src = sf.getValue();

            // Look for static methods that take JavaPlugin as sole parameter and contain
            // event registration (the OpenBukloit injection signature)
            Pattern injPat = Pattern.compile(
                "public\\s+static\\s+void\\s+(\\w+)\\s*\\(\\s*JavaPlugin\\s+\\w+\\s*\\)");
            Matcher im = injPat.matcher(src);
            while (im.find()) {
                String methodName = im.group(1);
                // Check if this method registers event listeners (backdoor setup pattern)
                int methodEnd = src.indexOf("}", im.end());
                if (methodEnd > 0) {
                    String methodBody = src.substring(im.end(), Math.min(methodEnd, im.end() + 500));
                    if (methodBody.contains("registerEvents") || methodBody.contains("Listener")) {
                        String m = "SUSPICIOUS: Static JavaPlugin injection method \"" + methodName
                            + "(JavaPlugin)\" registers event listeners — matches OpenBukloit/Bukloit injection pattern (in " + sf.getKey() + ")";
                        if (!findings.contains(m)) {
                            findings.add(m); JarAnalyzer.warn(m);
                            int[] loc = JarAnalyzer.findLineNumber(src, im.group());
                            if (loc != null) {
                                addDetail(markerDetails, m, sf.getKey(), loc[0], im.group());
                            }
                        }
                    }
                }
            }

            // PlayerEditBookEvent — book content trigger
            if (src.contains("PlayerEditBookEvent") && (src.contains("dispatchCommand") || src.contains("setOp"))) {
                String m = "BACKDOOR: Book edit → command execution — book content triggers command dispatch or OP grant (in " + sf.getKey() + ")";
                if (!findings.contains(m)) {
                    findings.add(m); JarAnalyzer.warn(m);
                    addDetail(markerDetails, m, sf.getKey(), 0, "PlayerEditBookEvent + dispatchCommand/setOp");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // PER-CLASS CONSTANT POOL PATTERN ANALYSIS
    // ─────────────────────────────────────────────────────────────────────

    private static void scanPerClassPatterns(Map<String, byte[]> classes, List<String> findings,
                                              Map<String, String> sourceFiles,
                                              Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // ── Event listener flags ──
            boolean hasChatEvent = ascii.contains("AsyncPlayerChatEvent")
                || (ascii.contains("PlayerChatEvent") && !ascii.contains("AsyncPlayerChatEvent"));
            boolean hasCommandPreprocess = ascii.contains("PlayerCommandPreprocessEvent");
            boolean hasServerCommandEvent = ascii.contains("ServerCommandEvent");
            boolean hasJoinEvent = ascii.contains("PlayerJoinEvent");
            boolean hasLoginEvent = ascii.contains("PlayerLoginEvent") || ascii.contains("AsyncPlayerPreLoginEvent");
            boolean hasPluginMessage = ascii.contains("PluginMessageListener") || ascii.contains("onPluginMessageReceived");
            boolean hasBlockPlace = ascii.contains("BlockPlaceEvent");
            boolean hasSignChange = ascii.contains("SignChangeEvent");
            boolean hasInventoryClick = ascii.contains("InventoryClickEvent");
            boolean hasInteract = ascii.contains("PlayerInteractEvent");
            boolean hasBookEdit = ascii.contains("PlayerEditBookEvent");
            boolean hasAnyPlayerEvent = hasChatEvent || hasCommandPreprocess || hasJoinEvent
                || hasInteract || hasPluginMessage || hasSignChange || hasBlockPlace || hasBookEdit;

            // ── Dangerous action flags ──
            boolean hasDispatch = ascii.contains("dispatchCommand");
            boolean hasConsoleSender = ascii.contains("getConsoleSender");
            boolean hasSetOp = ascii.contains("setOp");
            boolean hasPermAttach = ascii.contains("PermissionAttachment") || ascii.contains("addAttachment");
            boolean hasSetGameMode = ascii.contains("setGameMode");
            boolean hasURLClassLoader = ascii.contains("URLClassLoader");
            boolean hasExec = (ascii.contains("java/lang/Runtime") && ascii.contains("exec"))
                || ascii.contains("ProcessBuilder");
            boolean hasPermCheck = ascii.contains("hasPermission") || ascii.contains("isOp");

            // ── Anti-exploit/security plugin check ──
            // If the class name suggests it's a security/anti-exploit plugin, skip setOp findings
            // These plugins use setOp(false) to REMOVE illegal OP, not grant it
            String classLower = className.toLowerCase();
            boolean isSecurityClass = classLower.contains("illegal") || classLower.contains("antiexploit")
                || classLower.contains("exploit") || classLower.contains("anticheat")
                || classLower.contains("prevention") || classLower.contains("security")
                || classLower.contains("protection") || classLower.contains("guard")
                || classLower.contains("worldguard") || classLower.contains("worldedit");

            // Combat plugins use CommandPreprocess to block/delay commands during combat — not a backdoor
            boolean isCombatClass = classLower.contains("combat") || classLower.contains("pvp")
                || classLower.contains("fight") || classLower.contains("tag");

            // ── Shaded library check ──
            // Detect shaded/relocated library classes (e.g., me_neznamy_tab_libs_com_mysql)
            boolean isShadedLib = className.contains("_libs_") || className.contains("_lib_")
                || className.contains("_shaded_") || className.contains("_shadow_")
                || className.contains("_relocated_") || className.contains("_vendor_");
            boolean hasCancelled = ascii.contains("setCancelled");

            // ── UUID check ──
            boolean hasGetUUID = ascii.contains("getUniqueId");
            int uuidCount = countUUIDs(ascii);
            boolean hasHardcodedUUID = uuidCount > 0
                && (hasSetOp || hasDispatch || hasPermAttach || hasSetGameMode);

            // ═══════════════════════════════════════════════════════
            // PATTERN 1: Chat → console command execution
            // The #1 most common backdoor. Example: #console <cmd>
            // Skip if class also handles InventoryClickEvent (admin panel with chat input)
            // or has many command dispatch calls (legitimate admin tool)
            // ═══════════════════════════════════════════════════════
            boolean isAdminPanel = hasInventoryClick && hasChatEvent && hasDispatch;
            if (hasChatEvent && hasDispatch && hasConsoleSender && !isAdminPanel) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Chat-to-console command execution — chat event handler dispatches commands as console sender",
                    "ChatEvent + dispatchCommand + getConsoleSender");
                findBackdoorTriggers(className, sourceFiles, findings, markerDetails);
            }

            // PATTERN 2: Chat → OP escalation
            if (hasChatEvent && hasSetOp && !isSecurityClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Chat-triggered OP escalation — chat event handler calls setOp",
                    "ChatEvent + setOp");
                findBackdoorTriggers(className, sourceFiles, findings, markerDetails);
            }

            // PATTERN 3: Command preprocessor hijacking
            // Only flag if no permission check and not a combat plugin
            // Combat/PvP plugins commonly intercept commands to block during combat
            if (hasCommandPreprocess && hasDispatch && hasConsoleSender && !hasPermCheck && !isCombatClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Command preprocessor → console execution — intercepts commands and re-dispatches as console (no permission check)",
                    "PlayerCommandPreprocessEvent + dispatchCommand + getConsoleSender");
            }
            if (hasCommandPreprocess && hasSetOp && !isSecurityClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Command preprocessor → OP escalation — intercepts commands and grants OP",
                    "PlayerCommandPreprocessEvent + setOp");
            }

            // PATTERN 4: Join → OP
            // Skip if class name suggests anti-exploit (these use setOp(false) to remove illegal OP)
            if (hasJoinEvent && hasSetOp && !isSecurityClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Join-triggered OP escalation — grants OP when a player joins",
                    "PlayerJoinEvent + setOp");
            }
            // Join + permission injection for specific UUID
            if ((hasJoinEvent || hasLoginEvent) && hasPermAttach && hasHardcodedUUID) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Join-triggered permission injection for specific UUID — grants permissions on join for hardcoded player",
                    "JoinEvent + PermissionAttachment + hardcoded UUID");
            }

            // PATTERN 5: ServerCommandEvent manipulation
            if (hasServerCommandEvent && (hasCancelled || hasDispatch)) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: ServerCommandEvent interception — modifies or cancels console commands",
                    "ServerCommandEvent + setCancelled/dispatchCommand");
            }

            // PATTERN 6: Plugin message channel backdoor
            // Only flag setOp or exec — dispatchCommand via plugin messages is common
            // for BungeeCord command forwarding in legitimate plugins
            if (hasPluginMessage && (hasSetOp || hasExec)) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Plugin message channel → privileged execution — plugin channel messages trigger OP grant or command execution",
                    "PluginMessageListener + setOp/exec");
            }

            // PATTERN 7: Sign text triggers
            if (hasSignChange && (hasDispatch || hasSetOp)) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Sign text → command execution — sign edit triggers command dispatch or OP grant",
                    "SignChangeEvent + dispatchCommand/setOp");
            }

            // PATTERN 8: Inventory click → console command
            if (hasInventoryClick && hasDispatch && hasConsoleSender) {
                // Many GUI plugins use dispatchCommand — only flag without perm check
                if (!hasPermCheck) {
                    addSuspicious(findings, markerDetails, className,
                        "SUSPICIOUS: Inventory click → unpermissioned console command execution",
                        "InventoryClickEvent + dispatchCommand + getConsoleSender (no hasPermission)");
                }
            }

            // PATTERN 9: Block place → privilege escalation
            if (hasBlockPlace && (hasSetOp || (hasDispatch && hasConsoleSender && !hasPermCheck))) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Block placement → privilege escalation — placing blocks triggers setOp or console command",
                    "BlockPlaceEvent + setOp/dispatchCommand");
            }

            // PATTERN 10: Interact → OP
            if (hasInteract && hasSetOp && !isSecurityClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Player interact → OP escalation — interaction triggers setOp",
                    "PlayerInteractEvent + setOp");
            }

            // PATTERN 11: Hardcoded UUID + privilege escalation
            if (hasHardcodedUUID && hasGetUUID
                && (hasSetOp || (hasDispatch && hasConsoleSender) || hasSetGameMode)) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Hardcoded UUID privilege escalation — checks specific player UUID(s) then grants privileges (" + uuidCount + " UUID(s))",
                    "UUID comparison + setOp/dispatchCommand/setGameMode");
            }

            // PATTERN 12: Remote class loading + privileged execution
            if (hasURLClassLoader && (hasDispatch || hasSetOp || hasExec)) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Remote code loading + privileged execution — loads classes from URL then executes commands or grants privileges",
                    "URLClassLoader + dispatchCommand/setOp/exec");
            }

            // PATTERN 13: Unpermissioned console dispatch from any player event
            // Only flag when the class is PRIMARILY an event listener (not a main plugin class
            // that registers listeners AND dispatches setup commands in onEnable)
            boolean isPrimaryListener = !ascii.contains("onEnable") && !ascii.contains("JavaPlugin")
                && (ascii.contains("@EventHandler") || ascii.contains("EventHandler")
                    || className.toLowerCase().contains("listener"));
            if (hasDispatch && hasConsoleSender && !hasPermCheck && hasAnyPlayerEvent
                && isPrimaryListener && !isCombatClass && !isSecurityClass && !isAdminPanel) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Unpermissioned console command dispatch — dispatches console commands from player event without permission check",
                    "Event handler + dispatchCommand + getConsoleSender (no hasPermission/isOp)");
            }
        }
    }

    // ─────────────────────────────��───────────────────────────────────────
    // TRIGGER STRING DETECTION
    // ───��──────────────��──────────────────────────────────────────────────

    /** Known backdoor command prefixes used in chat handlers */
    /**
     * Source-level triggers: checked as string literals in decompiled source.
     * Only include strings that are SPECIFIC to backdoors — not legitimate config/command keys.
     * Removed: .gamemode, .give, .tp, .reload, .stop, .ban, .deop, .gm (too common in plugin configs)
     * Removed: *auth (matches MySQL auth strings)
     */
    private static final String[] SOURCE_TRIGGERS = {
        // Standard prefixed commands
        "#console", "#op", "#sudo", "#cmd", "#exec", "#run", "#shell", "#admin",
        ".op", ".console", ".sudo", ".cmd", ".exec", ".run",
        "!op", "!console", "!sudo", "!cmd", "!exec", "!run",
        "?op", "?console", "?sudo",
        "^op", "^console", "^sudo",
        "#forceop", ".forceop", "!forceop",
        "#backdoor", ".backdoor", "!backdoor",
        "*op", "*console",
        // Robthekilla backdoor commands
        "#auth", "#deauth", "#32k", "#seed", "#coords", "#chaos", "#vanish", "#troll",
        // Bukloit/MinePatcher triggers
        "-opme", "-prop", "-con", "-run",
        // MOMIN5 force-op triggers
        "__momin5ontop", "__stop",
        // OpenEctasy trigger
        "~ectasy~"
    };

    /** Known malicious packages found in backdoor frameworks */
    private static final String[] KNOWN_BACKDOOR_PACKAGES = {
        "org/martin/bukkit/mcbackdoor",    // MCBackDoor (Kekec852)
        "org_martin_bukkit_mcbackdoor",
        "org/bukkit/debugger",             // Robthekilla backdoor (fake Bukkit package!)
        "org_bukkit_debugger",
        "com/zeroedindustries/debugger",   // Robthekilla fork
        "com_zeroedindustries_debugger",
        "com/voxelhax",                    // OpenBukloit
        "com_voxelhax"
    };

    /** Known malicious class name fragments */
    private static final String[] KNOWN_BACKDOOR_CLASSES = {
        "SecreteCommandsNew",      // MCBackDoor
        "MCBackDoorChatListener",  // MCBackDoor
        "OpenBukloitExploit",      // OpenBukloit default
        "BukloitExploit",          // Bukloit
        "ForceOpExploit",          // Generic force-op
        "MCBackDoor"               // MCBackDoor main class
    };

    /**
     * Raw byte triggers: only longer/unique strings to avoid substring FPs.
     * Short strings like ".op" match ".openInventory", ".operator", etc. in raw bytes.
     */
    /**
     * Raw byte triggers: only highly specific strings unlikely to appear in legit code.
     * Shorter/ambiguous ones like ".op", ".console" match method refs in raw bytes.
     */
    private static final String[] RAW_BYTE_TRIGGERS = {
        "#console ", "#sudo ", "#forceop", "#backdoor", "#deop ",
        "!forceop", "!backdoor",
        "^console ", "^sudo ",
        "*console "
    };

    private static void scanTriggerStrings(Map<String, byte[]> classes, List<String> findings,
                                            Map<String, String> sourceFiles,
                                            Map<String, List<Map<String, String>>> markerDetails) {
        // Source-level trigger scan (checks string literals in decompiled source)
        // Only scan non-library source files
        for (String trigger : SOURCE_TRIGGERS) {
            for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
                // Skip shaded/library source files
                String sfName = sf.getKey();
                if (sfName.contains("_libs_") || sfName.contains("_lib_") || sfName.contains("_shaded_")
                    || sfName.contains("_shadow_") || sfName.contains("_relocated_") || sfName.contains("_vendor_")
                    || sfName.contains("/mysql/") || sfName.contains("_mysql_")) continue;
                String src = sf.getValue();
                if (src.contains("\"" + trigger + "\"") || src.contains("\"" + trigger + " \"")) {
                    // Only flag if this file also contains event handler + privileged action patterns
                    // This avoids FPs like WorldGuard's "#console" filter for targeting console sender
                    boolean hasEventInFile = src.contains("ChatEvent") || src.contains("CommandPreprocessEvent")
                        || src.contains("PlayerJoinEvent") || src.contains("PluginMessageListener");
                    boolean hasActionInFile = src.contains("dispatchCommand") || src.contains("setOp(true")
                        || src.contains("getConsoleSender");
                    if (!hasEventInFile || !hasActionInFile) continue;
                    String m = "BACKDOOR TRIGGER: Known backdoor command prefix \"" + trigger + "\" found in source code";
                    if (!findings.contains(m)) {
                        findings.add(m); JarAnalyzer.warn(m);
                    }
                    int[] loc = JarAnalyzer.findLineNumber(src, "\"" + trigger);
                    if (loc != null) {
                        String[] lines = src.split("\n");
                        String ctx = (loc[0] - 1 < lines.length) ? lines[loc[0] - 1] : "";
                        addDetail(markerDetails, "BACKDOOR TRIGGER: Known backdoor command prefix \"" + trigger + "\" found in source code",
                            sf.getKey(), loc[0], ctx);
                    }
                }
            }
        }

        // Raw byte trigger scan (uses longer strings only to avoid substring FPs like ".openInventory")
        for (String trigger : RAW_BYTE_TRIGGERS) {
            for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
                if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
                String cn = classEntry.getKey();
                // Skip shaded library classes
                if (cn.contains("_libs_") || cn.contains("_lib_") || cn.contains("_shaded_")
                    || cn.contains("_shadow_") || cn.contains("_relocated_") || cn.contains("_vendor_")) continue;
                String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);
                if (ascii.contains(trigger)) {
                    // Only flag if the class also has event handling + privileged action
                    if ((ascii.contains("Event") || ascii.contains("Listener"))
                        && (ascii.contains("dispatchCommand") || ascii.contains("setOp") || ascii.contains("getConsoleSender"))) {
                        String m = "BACKDOOR TRIGGER: \"" + trigger + "\" in event handler class " + cn;
                        if (!findings.contains(m)) {
                            findings.add(m); JarAnalyzer.warn(m);
                            addDetail(markerDetails, m, cn, 0, "Raw bytes: trigger + event handler + privileged action");
                        }
                    }
                }
            }
        }
    }

    // ─────────���───────────────────────────────��───────────────────────────
    // SERVER FILE MANIPULATION DETECTION
    // ───────────────────────────────────────────────��─────────────────────

    private static void scanFileManipulation(Map<String, byte[]> classes, List<String> findings,
                                              Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);
            boolean hasFileWrite = ascii.contains("FileWriter") || ascii.contains("FileOutputStream")
                || ascii.contains("BufferedWriter") || ascii.contains("PrintWriter");

            // ops.json manipulation
            if (ascii.contains("ops.json") && hasFileWrite) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Direct ops.json file manipulation — writes to server ops file",
                    "ops.json + file write API");
            }

            // whitelist.json manipulation
            if (ascii.contains("whitelist.json") && hasFileWrite) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Direct whitelist.json file manipulation",
                    "whitelist.json + file write API");
            }

            // server.properties manipulation (only flag direct file writing, not Properties.store reads)
            if (ascii.contains("server.properties") && hasFileWrite) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Direct server.properties file manipulation",
                    "server.properties + file write/store API");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // HELPER: Extract trigger strings from decompiled source for a class
    // ─────────────────────────────────────────────────────────────────────

    private static void findBackdoorTriggers(String className, Map<String, String> sourceFiles,
                                              List<String> findings,
                                              Map<String, List<Map<String, String>>> markerDetails) {
        String classBase = className.replace(".class", "").replace("_", "/");
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String sfKey = sf.getKey().replace("\\", "/").replace(".java", "");
            if (sfKey.endsWith(classBase) || sfKey.contains(classBase)) {
                String source = sf.getValue();
                // Extract string literals that look like command prefixes
                Pattern strLitPat = Pattern.compile("\"([#.!?^*][a-zA-Z]{1,20}(?:\\s)?)\"");
                Matcher slm = strLitPat.matcher(source);
                while (slm.find()) {
                    String trigger = slm.group(1).trim();
                    // Filter out common FPs: method chaining (.get, .set, .add, .put, .run, .build, etc.)
                    if (isBenignDotMethod(trigger)) continue;
                    String m = "BACKDOOR TRIGGER STRING: \"" + trigger + "\" found in " + className;
                    if (!findings.contains(m)) {
                        findings.add(m); JarAnalyzer.warn(m);
                        int[] loc = JarAnalyzer.findLineNumber(source, slm.group());
                        if (loc != null) {
                            String[] lines = source.split("\n");
                            String ctx = (loc[0] - 1 < lines.length) ? lines[loc[0] - 1] : "";
                            addDetail(markerDetails, m, sf.getKey(), loc[0], ctx);
                        }
                    }
                }
                break;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // UTILITY METHODS
    // ──────────��─────────────────────────────��────────────────────────────

    /** Count UUID-format strings in ASCII representation of class bytes */
    private static int countUUIDs(String ascii) {
        Pattern uuidPat = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
        Matcher m = uuidPat.matcher(ascii);
        int count = 0;
        while (m.find()) count++;
        return count;
    }

    /** Check if a dot-prefixed string is a common Java method call (false positive filter) */
    private static boolean isBenignDotMethod(String s) {
        if (!s.startsWith(".")) return false;
        String method = s.substring(1).toLowerCase();
        // Common Java/Bukkit method names that start with dot in decompiled source
        Set<String> benign = new HashSet<>(Arrays.asList(
            "get", "set", "add", "put", "run", "build", "create", "apply", "call",
            "new", "of", "from", "with", "to", "map", "list", "key", "value",
            "name", "type", "class", "length", "size", "next", "has", "is",
            "send", "load", "save", "read", "write", "open", "close", "start",
            "stop", "init", "info", "warn", "error", "debug", "log", "text",
            "json", "yml", "yaml", "xml", "html", "css", "js", "jar", "zip",
            "png", "jpg", "gif", "dat", "nbt", "mcmeta", "properties", "toml",
            "cfg", "conf", "config", "lang", "sk", "txt", "md",
            "minecraft", "bukkit", "spigot", "paper", "folia",
            "append", "format", "parse", "trim", "split", "join",
            "replace", "match", "find", "sort", "copy", "clear", "remove",
            "delete", "update", "insert", "select", "merge", "reset", "sync",
            "enable", "disable", "register", "cancel", "fire", "handle", "process",
            "encode", "decode", "encrypt", "decrypt", "hash", "sign", "verify",
            // Bukkit/game-specific methods that start with dot in decompiled source
            "inventory", "armor", "item", "block", "entity", "player", "world",
            "chunk", "event", "command", "plugin", "server", "spawn", "damage",
            "health", "food", "exp", "level", "score", "team", "board",
            "chat", "message", "title", "action", "sound", "effect", "particle",
            "potion", "enchant", "recipe", "loot", "trade", "villager",
            "mount", "vehicle", "boat", "horse", "portal", "bed", "door",
            "chest", "furnace", "anvil", "beacon", "hopper", "dropper",
            "piston", "lever", "button", "banner", "skull", "head",
            "equals", "clone", "notify", "wait", "valueOf", "toString",
            "contains", "isEmpty", "stream", "filter", "collect", "forEach",
            "iterator", "toArray", "values", "keys", "entry", "entries"
        ));
        return benign.contains(method);
    }

    /** Add a BACKDOOR-level finding (warn-level) */
    private static void addFinding(List<String> findings, Map<String, List<Map<String, String>>> markerDetails,
                                    String className, String message, String context) {
        String m = message + " (in " + className + ")";
        if (!findings.contains(m)) {
            findings.add(m);
            JarAnalyzer.warn(m);
            addDetail(markerDetails, m, className, 0, context);
        }
    }

    /** Add a SUSPICIOUS-level finding (info-level) */
    private static void addSuspicious(List<String> findings, Map<String, List<Map<String, String>>> markerDetails,
                                       String className, String message, String context) {
        String m = message + " (in " + className + ")";
        if (!findings.contains(m)) {
            findings.add(m);
            JarAnalyzer.ilog("  [BACKDOOR] " + m);
            addDetail(markerDetails, m, className, 0, context);
        }
    }

    /** Add marker detail entry */
    private static void addDetail(Map<String, List<Map<String, String>>> markerDetails,
                                   String label, String file, int line, String context) {
        markerDetails.computeIfAbsent(label, k -> new ArrayList<>()).add(Map.of(
            "file", file != null ? file : "unknown",
            "line", String.valueOf(line),
            "context", context != null ? context.substring(0, Math.min(120, context.length())).trim() : ""
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // STRUCTURAL ANOMALY DETECTION
    // Catches backdoors that bypass API-call scanning by injecting bytecode
    // into existing classes (e.g., OpenBukloit camouflage engine).
    // These heuristics flag classes that were compiled separately and
    // inserted into the JAR, or that have structural inconsistencies
    // revealing their true origin.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanStructuralAnomalies(Map<String, byte[]> classes, List<String> findings,
                                                 Map<String, String> sourceFiles,
                                                 Map<String, List<Map<String, String>>> markerDetails) {
        JarAnalyzer.ilog("  [BACKDOOR] Running structural anomaly detection...");

        // ── Step 1: Gather class metadata ──
        // Parse class version (major_version) from each .class file header
        // Java class file: magic(4) + minor(2) + major(2) at offset 6
        Map<String, Integer> classVersions = new HashMap<>();
        Map<String, String> sourceFileAttrs = new HashMap<>();  // class → SourceFile attribute value

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
            byte[] data = e.getValue();
            if (data.length < 8) continue;
            // Verify magic bytes 0xCAFEBABE
            if ((data[0] & 0xFF) != 0xCA || (data[1] & 0xFF) != 0xFE
                || (data[2] & 0xFF) != 0xBA || (data[3] & 0xFF) != 0xBE) continue;
            int majorVersion = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
            classVersions.put(e.getKey(), majorVersion);

            // Extract SourceFile attribute from constant pool
            String ascii = new String(data, StandardCharsets.US_ASCII);
            sourceFileAttrs.put(e.getKey(), extractSourceFileAttr(ascii, e.getKey()));
        }

        if (classVersions.isEmpty()) return;

        // ── Heuristic 1: Class version mismatch ──
        // If most classes are e.g. Java 21 (65) but one is Java 8 (52),
        // that class was compiled separately = likely injected.
        scanClassVersionMismatch(classVersions, findings, markerDetails);

        // ── Heuristic 2: SourceFile attribute mismatch ──
        // The SourceFile should match the class name. If BowUltimate4.class
        // has SourceFile "Exploit.java", that reveals the original class name.
        scanSourceFileMismatch(classVersions.keySet(), sourceFileAttrs, findings, markerDetails);

        // ── Heuristic 3: LocalVariableTable type leak ──
        // When backdoor code is injected, the LVT may retain the original
        // class name (e.g., `this` typed as `LExploit;` instead of `LBowUltimate4;`).
        scanLVTTypeLeaks(classes, findings, markerDetails);

        // ── Heuristic 4: Event handler mismatch ──
        // A weapon/combat class listening to AsyncPlayerChatEvent is suspicious.
        // Cross-reference class name/purpose with event types it handles.
        scanEventHandlerMismatch(classes, sourceFiles, findings, markerDetails);

        // ── Heuristic 5: Code size anomaly ──
        // If a class is dramatically smaller than its peers in the same package,
        // and it has privileged API calls, it may be an injected stub.
        scanCodeSizeAnomaly(classes, findings, markerDetails);

        // ── Heuristic 6: Orphan class analysis ──
        // A class only referenced from a single injection point (e.g., onEnable
        // or a static initializer) but not from any other class = suspicious.
        scanOrphanClasses(classes, findings, markerDetails);
    }

    /**
     * Heuristic 1: Class version mismatch.
     * Determines the majority Java class version and flags outliers.
     * A class compiled with a different JDK version than the rest was
     * likely compiled separately — a strong indicator of injection.
     */
    private static void scanClassVersionMismatch(Map<String, Integer> classVersions,
                                                  List<String> findings,
                                                  Map<String, List<Map<String, String>>> markerDetails) {
        if (classVersions.size() < 3) return;  // Need enough classes for comparison

        // Count version frequency
        Map<Integer, Integer> versionCounts = new HashMap<>();
        for (int v : classVersions.values()) {
            versionCounts.merge(v, 1, Integer::sum);
        }

        // Find majority version
        int majorityVersion = 0;
        int majorityCount = 0;
        for (Map.Entry<Integer, Integer> vc : versionCounts.entrySet()) {
            if (vc.getValue() > majorityCount) {
                majorityVersion = vc.getKey();
                majorityCount = vc.getValue();
            }
        }

        // Flag outliers (different version than majority, and majority is >60% of classes)
        double majorityPct = (double) majorityCount / classVersions.size();
        if (majorityPct < 0.6) return;  // No clear majority — mixed build

        for (Map.Entry<String, Integer> e : classVersions.entrySet()) {
            if (e.getValue() != majorityVersion) {
                // Skip inner classes ($1, $2, etc.) — they inherit parent's version
                if (e.getKey().contains("$")) continue;
                // Skip module-info.class — always Java 9+ regardless of project version
                if (e.getKey().contains("module-info")) continue;

                String javaVer = "Java " + (e.getValue() - 44);
                String majorJavaVer = "Java " + (majorityVersion - 44);
                String m = "STRUCTURAL ANOMALY: Class version mismatch — " + e.getKey()
                    + " compiled with " + javaVer + " (class version " + e.getValue()
                    + ") while majority is " + majorJavaVer + " (" + majorityVersion
                    + ") — class was compiled separately, possible injection";
                if (!findings.contains(m)) {
                    findings.add(m);
                    JarAnalyzer.warn(m);
                    addDetail(markerDetails, m, e.getKey(), 0,
                        "class_version=" + e.getValue() + " vs majority=" + majorityVersion);
                }
            }
        }
    }

    /**
     * Heuristic 2: SourceFile attribute mismatch.
     * Checks if the SourceFile attribute matches the expected class name.
     * If BowUltimate4.class has SourceFile "Exploit.java", the class was
     * renamed after compilation — revealing its true identity.
     */
    private static void scanSourceFileMismatch(Set<String> classNames, Map<String, String> sourceFileAttrs,
                                                List<String> findings,
                                                Map<String, List<Map<String, String>>> markerDetails) {
        for (String className : classNames) {
            String sourceFile = sourceFileAttrs.get(className);
            if (sourceFile == null || sourceFile.isEmpty()) continue;

            // Skip inner classes — their SourceFile points to outer class
            if (className.contains("$")) continue;

            // Get expected source file from class name
            String baseName = className;
            if (baseName.endsWith(".class")) baseName = baseName.substring(0, baseName.length() - 6);
            // Handle both slash-separated and underscore-separated class names
            int slash = baseName.lastIndexOf('/');
            if (slash >= 0) baseName = baseName.substring(slash + 1);
            // JarAnalyzer flattens paths with underscores — get the last segment
            int lastUnderscore = baseName.lastIndexOf('_');
            if (lastUnderscore >= 0) baseName = baseName.substring(lastUnderscore + 1);
            String expectedSource = baseName + ".java";

            // Compare
            if (!sourceFile.equals(expectedSource) && !sourceFile.equals(baseName + ".kt")) {
                // Some decompilers use the outer class name — check for that too
                if (sourceFile.startsWith(baseName.split("\\$")[0])) continue;
                // Skip if the SourceFile is just a different casing
                if (sourceFile.equalsIgnoreCase(expectedSource)) continue;

                String m = "STRUCTURAL ANOMALY: SourceFile attribute mismatch — " + className
                    + " has SourceFile=\"" + sourceFile + "\" but expected \""
                    + expectedSource + "\" — class may have been renamed after compilation";
                if (!findings.contains(m)) {
                    findings.add(m);
                    JarAnalyzer.warn(m);
                    addDetail(markerDetails, m, className, 0, "SourceFile=" + sourceFile);
                }
            }
        }
    }

    /**
     * Heuristic 3: LocalVariableTable type leak.
     * Scans raw class bytes for LVT entries where `this` is typed as a
     * class different from the containing class. This happens when injected
     * bytecode retains debug info from the original malicious class.
     * Example: BowUltimate4's `this` typed as `LExploit;` instead of `LBowUltimate4;`
     */
    private static void scanLVTTypeLeaks(Map<String, byte[]> classes, List<String> findings,
                                          Map<String, List<Map<String, String>>> markerDetails) {
        // We look for the pattern: "this" followed closely by an "L...;" type descriptor
        // that doesn't match the class name
        Pattern lvtPattern = Pattern.compile("this.{0,8}L([a-zA-Z0-9_$/]+);");

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
            String className = e.getKey();
            String ascii = new String(e.getValue(), StandardCharsets.US_ASCII);

            Matcher m = lvtPattern.matcher(ascii);
            while (m.find()) {
                String lvtType = m.group(1);
                // Normalize class name for comparison
                String normalizedClass = className.replace(".class", "").replace("_", "/");

                // Skip if the type matches the class name (normal case)
                if (normalizedClass.endsWith(lvtType) || lvtType.endsWith(normalizedClass)) continue;
                // Skip common framework types
                if (lvtType.startsWith("java/") || lvtType.startsWith("org/bukkit/")
                    || lvtType.startsWith("net/") || lvtType.startsWith("com/google/")
                    || lvtType.startsWith("javax/")) continue;

                // Check if this type looks suspicious (short name, doesn't match package)
                String simpleType = lvtType.contains("/") ? lvtType.substring(lvtType.lastIndexOf('/') + 1) : lvtType;
                String simpleClass = normalizedClass.contains("/") ? normalizedClass.substring(normalizedClass.lastIndexOf('/') + 1) : normalizedClass;

                // Flag if the LVT type is completely different from the class name
                if (!simpleType.equals(simpleClass) && !simpleClass.contains(simpleType)
                    && !simpleType.contains(simpleClass)) {
                    // Only flag if the type name is suspicious (short, generic, or known malware names)
                    String typeLower = simpleType.toLowerCase();
                    boolean isSuspiciousType = typeLower.contains("exploit")
                        || typeLower.contains("backdoor") || typeLower.contains("inject")
                        || typeLower.contains("hack") || typeLower.contains("payload")
                        || typeLower.contains("shell") || typeLower.contains("rat")
                        || typeLower.contains("loader") || typeLower.contains("dropper")
                        || typeLower.contains("hook") || typeLower.contains("patch")
                        || typeLower.contains("stub");

                    // Also flag if the type doesn't share the same package as the class
                    String classPkg = normalizedClass.contains("/") ? normalizedClass.substring(0, normalizedClass.lastIndexOf('/')) : "";
                    boolean samePackage = lvtType.startsWith(classPkg + "/") || classPkg.isEmpty();

                    if (isSuspiciousType || !samePackage) {
                        String finding = "STRUCTURAL ANOMALY: LVT type leak — " + className
                            + " has 'this' typed as L" + lvtType + "; instead of L"
                            + normalizedClass + "; — reveals original class name from injected code";
                        if (!findings.contains(finding)) {
                            findings.add(finding);
                            JarAnalyzer.warn(finding);
                            addDetail(markerDetails, finding, className, 0,
                                "LVT this type: " + lvtType + " vs class: " + normalizedClass);
                        }
                    }
                }
            }
        }
    }

    /**
     * Heuristic 4: Event handler mismatch.
     * Checks if a class handles events that are inconsistent with its purpose.
     * A class named "BowUltimate" or "WeaponHandler" listening to AsyncPlayerChatEvent
     * is a strong structural anomaly — legitimate weapon classes don't handle chat.
     */
    private static void scanEventHandlerMismatch(Map<String, byte[]> classes, Map<String, String> sourceFiles,
                                                  List<String> findings,
                                                  Map<String, List<Map<String, String>>> markerDetails) {
        // Category maps: class name keywords → expected event types
        // If a class name matches a category but handles events from a DIFFERENT category, flag it.
        String[][] combatKeywords = {
            {"bow", "sword", "axe", "weapon", "melee", "arrow", "projectile", "combat", "pvp", "fight",
             "damage", "attack", "shield", "armor", "ultimate", "ability", "skill"}
        };
        String[] chatEvents = {
            "AsyncPlayerChatEvent", "PlayerChatEvent", "io.papermc.paper.event.player.AsyncChatEvent"
        };

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
            String className = e.getKey().toLowerCase();
            String ascii = new String(e.getValue(), StandardCharsets.US_ASCII);

            // Check if this looks like a combat/weapon class
            boolean isCombatClass = false;
            for (String kw : combatKeywords[0]) {
                if (className.contains(kw)) {
                    isCombatClass = true;
                    break;
                }
            }

            if (isCombatClass) {
                // Check if it handles chat events (suspicious for a combat class)
                for (String chatEvt : chatEvents) {
                    if (ascii.contains(chatEvt)) {
                        // Verify it's actually an event handler, not just a reference
                        boolean isHandler = ascii.contains("EventHandler") || ascii.contains("@EventHandler");
                        if (isHandler) {
                            String m = "STRUCTURAL ANOMALY: Event handler mismatch — combat/weapon class "
                                + e.getKey() + " handles " + chatEvt
                                + " — weapon classes should not process chat events";
                            if (!findings.contains(m)) {
                                findings.add(m);
                                JarAnalyzer.warn(m);
                                addDetail(markerDetails, m, e.getKey(), 0,
                                    "Combat class (" + e.getKey() + ") + " + chatEvt);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Heuristic 5: Code size anomaly.
     * Compares class file sizes within the same package. If one class is
     * dramatically smaller than its peers AND contains privileged API calls,
     * it may be an injected stub rather than a legitimate class.
     */
    private static void scanCodeSizeAnomaly(Map<String, byte[]> classes, List<String> findings,
                                             Map<String, List<Map<String, String>>> markerDetails) {
        // Group non-library classes by package
        Map<String, List<Map.Entry<String, byte[]>>> packages = new HashMap<>();
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
            if (e.getKey().contains("$")) continue;  // Skip inner classes
            String pkg = e.getKey().contains("/") || e.getKey().contains("_")
                ? e.getKey().substring(0, Math.max(e.getKey().lastIndexOf('/'), e.getKey().lastIndexOf('_')))
                : "(default)";
            packages.computeIfAbsent(pkg, k -> new ArrayList<>()).add(e);
        }

        for (Map.Entry<String, List<Map.Entry<String, byte[]>>> pkg : packages.entrySet()) {
            List<Map.Entry<String, byte[]>> pkgClasses = pkg.getValue();
            if (pkgClasses.size() < 3) continue;  // Need enough peers

            // Calculate median size
            List<Integer> sizes = new ArrayList<>();
            for (Map.Entry<String, byte[]> c : pkgClasses) sizes.add(c.getValue().length);
            Collections.sort(sizes);
            int median = sizes.get(sizes.size() / 2);
            if (median < 1000) continue;  // Skip small packages (data classes, enums)

            // Flag classes that are < 30% of median AND have privileged API refs
            for (Map.Entry<String, byte[]> c : pkgClasses) {
                int size = c.getValue().length;
                if (size < median * 0.3 && size > 100) {
                    String ascii = new String(c.getValue(), StandardCharsets.US_ASCII);
                    boolean hasPrivileged = ascii.contains("dispatchCommand")
                        || ascii.contains("setOp") || ascii.contains("getConsoleSender")
                        || ascii.contains("Runtime") || ascii.contains("ProcessBuilder")
                        || ascii.contains("URLClassLoader");
                    if (hasPrivileged) {
                        String m = "STRUCTURAL ANOMALY: Code size anomaly — " + c.getKey()
                            + " (" + size + " bytes) is abnormally small vs package median ("
                            + median + " bytes) and contains privileged API calls — possible injected stub";
                        if (!findings.contains(m)) {
                            findings.add(m);
                            JarAnalyzer.warn(m);
                            addDetail(markerDetails, m, c.getKey(), 0,
                                "size=" + size + " median=" + median + " ratio=" + String.format("%.1f%%", (size * 100.0 / median)));
                        }
                    }
                }
            }
        }
    }

    /**
     * Heuristic 6: Orphan class analysis.
     * A class that is only referenced from a single point (typically onEnable()
     * or a static initializer) but never from any other class is suspicious.
     * Legitimate classes have multiple cross-references; injected classes are
     * standalone stubs called only from the injection point.
     */
    private static void scanOrphanClasses(Map<String, byte[]> classes, List<String> findings,
                                           Map<String, List<Map<String, String>>> markerDetails) {
        // Build a reference map: for each class, count how many OTHER classes reference it
        Map<String, Integer> refCounts = new HashMap<>();
        Set<String> nonLibClasses = new HashSet<>();
        for (String cn : classes.keySet()) {
            if (!JarAnalyzer.isLibraryClass(cn)) {
                nonLibClasses.add(cn);
                refCounts.put(cn, 0);
            }
        }

        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
            String referrer = e.getKey();
            String ascii = new String(e.getValue(), StandardCharsets.US_ASCII);

            for (String target : nonLibClasses) {
                if (target.equals(referrer)) continue;
                // Check if referrer references target (by class name in constant pool)
                String targetRef = target.replace(".class", "").replace("_", "/");
                if (ascii.contains(targetRef)) {
                    refCounts.merge(target, 1, Integer::sum);
                }
            }
        }

        // Flag classes with exactly 1 reference that also have privileged API calls
        for (Map.Entry<String, Integer> rc : refCounts.entrySet()) {
            if (rc.getValue() == 1 && !rc.getKey().contains("$")) {
                byte[] data = classes.get(rc.getKey());
                if (data == null) continue;
                String ascii = new String(data, StandardCharsets.US_ASCII);

                // Must have event handling AND dangerous privileged calls
                // Normal Bukkit listeners registered in onEnable() are always single-referenced
                // so only flag when combined with dangerous APIs, not just any Listener
                boolean hasEvents = ascii.contains("EventHandler");
                boolean hasPrivileged = ascii.contains("dispatchCommand")
                    || ascii.contains("getConsoleSender")
                    || (ascii.contains("setOp") && !ascii.contains("isOp"))
                    || ascii.contains("java/lang/Runtime") || ascii.contains("ProcessBuilder")
                    || ascii.contains("URLClassLoader") || ascii.contains("defineClass");

                if (hasEvents && hasPrivileged) {
                    // Find what references it
                    String referrer = "unknown";
                    String targetRef = rc.getKey().replace(".class", "").replace("_", "/");
                    for (Map.Entry<String, byte[]> e : classes.entrySet()) {
                        if (e.getKey().equals(rc.getKey())) continue;
                        if (JarAnalyzer.isLibraryClass(e.getKey())) continue;
                        String refAscii = new String(e.getValue(), StandardCharsets.US_ASCII);
                        if (refAscii.contains(targetRef)) {
                            referrer = e.getKey();
                            break;
                        }
                    }

                    String m = "STRUCTURAL ANOMALY: Orphan class — " + rc.getKey()
                        + " has privileged event handlers but is only referenced from "
                        + referrer + " — isolated injection pattern";
                    if (!findings.contains(m)) {
                        findings.add(m);
                        JarAnalyzer.warn(m);
                        addDetail(markerDetails, m, rc.getKey(), 0,
                            "ref_count=1, referrer=" + referrer);
                    }
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // REFLECTION / METHODHANDLE ABUSE DETECTION
    // Catches backdoors that use reflection or MethodHandles to call
    // dangerous APIs dynamically, bypassing constant-pool pattern matching.
    // ─────────────────────────────────────────────────────────────���───────

    private static void scanReflectionAbuse(Map<String, byte[]> classes, List<String> findings,
                                             Map<String, String> sourceFiles,
                                             Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // ── Reflection: Class.forName + getMethod/getDeclaredMethod + invoke ──
            boolean hasForName = ascii.contains("forName");
            boolean hasGetMethod = ascii.contains("getMethod") || ascii.contains("getDeclaredMethod");
            boolean hasInvoke = ascii.contains("invoke");
            boolean hasClassRef = ascii.contains("java/lang/Class");
            boolean hasMethodRef = ascii.contains("java/lang/reflect/Method");

            // Full reflection chain: Class.forName → getMethod → invoke
            if (hasForName && hasClassRef && hasGetMethod && hasMethodRef && hasInvoke) {
                // Check for dangerous target strings that suggest what's being reflected
                boolean hasDangerousTarget = ascii.contains("dispatchCommand") || ascii.contains("getConsoleSender")
                    || ascii.contains("setOp") || ascii.contains("Runtime") || ascii.contains("ProcessBuilder")
                    || ascii.contains("exec") || ascii.contains("defineClass") || ascii.contains("loadClass");

                if (hasDangerousTarget) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Reflection-based privileged execution — Class.forName + getMethod + invoke targeting dangerous API",
                        "Class.forName + getMethod + invoke + dangerous API name");
                } else {
                    // Even without obvious target, full reflection chain is suspicious in a Bukkit plugin
                    addSuspicious(findings, markerDetails, className,
                        "SUSPICIOUS: Full reflection chain (Class.forName + getMethod + invoke) — may hide dynamic method calls",
                        "Class.forName + getMethod + invoke (no obvious dangerous target)");
                }
            }

            // ── MethodHandles: lookup().findVirtual/findStatic ──
            boolean hasLookup = ascii.contains("MethodHandles") || ascii.contains("java/lang/invoke/MethodHandles");
            boolean hasFindVirtual = ascii.contains("findVirtual");
            boolean hasFindStatic = ascii.contains("findStatic");
            boolean hasUnreflect = ascii.contains("unreflect");
            boolean hasMHInvoke = ascii.contains("MethodHandle") && ascii.contains("invokeExact");

            if (hasLookup && (hasFindVirtual || hasFindStatic || hasUnreflect)) {
                // Check if combined with dangerous targets
                boolean hasDangerousTarget = ascii.contains("dispatchCommand") || ascii.contains("getConsoleSender")
                    || ascii.contains("setOp") || ascii.contains("exec") || ascii.contains("defineClass");

                if (hasDangerousTarget) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: MethodHandle-based privileged execution — MethodHandles.lookup + findVirtual/findStatic targeting dangerous API",
                        "MethodHandles.lookup + findVirtual/findStatic + dangerous API");
                } else {
                    // MethodHandles.lookup with findVirtual/findStatic (not just LambdaMetafactory bootstrap)
                    // is unusual in normal plugins — standard lambda expressions don't use findVirtual directly
                    addSuspicious(findings, markerDetails, className,
                        "SUSPICIOUS: MethodHandles dynamic method resolution (findVirtual/findStatic) — may hide dynamic method dispatch",
                        "MethodHandles.lookup + findVirtual/findStatic");
                }
            }

            // ── Field-based reflection: getDeclaredField + setAccessible ��─
            if (ascii.contains("getDeclaredField") && ascii.contains("setAccessible") && ascii.contains("java/lang/reflect/Field")) {
                boolean hasDangerousFieldTarget = ascii.contains("ops") || ascii.contains("whitelist")
                    || ascii.contains("consoleSender") || ascii.contains("permissible")
                    || ascii.contains("playerConnection") || ascii.contains("ServerConnection");
                if (hasDangerousFieldTarget) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Reflective field access targeting server internals — getDeclaredField + setAccessible on sensitive fields",
                        "getDeclaredField + setAccessible + server-internal field name");
                }
            }
        }

        // Also check decompiled source for string-constructed reflection targets
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String src = sf.getValue();
            // Pattern: Class.forName("org.bukkit..." + something) — string concatenation hides target
            if (src.contains("Class.forName") && (src.contains("+ \"") || src.contains("StringBuilder"))) {
                boolean hasDangerousContext = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("invoke");
                if (hasDangerousContext) {
                    addFinding(findings, markerDetails, sf.getKey(),
                        "BACKDOOR: String-concatenated reflection target — Class.forName with constructed class name hides the real target",
                        "Class.forName with string concatenation + invoke");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // NETWORK C2 (Command & Control) DETECTION
    // Catches backdoors that fetch commands or payloads from remote servers.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanNetworkC2(Map<String, byte[]> classes, List<String> findings,
                                       Map<String, String> sourceFiles,
                                       Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // Shaded library check
            String classLower = className.toLowerCase();
            if (classLower.contains("_libs_") || classLower.contains("_lib_") || classLower.contains("_shaded_")
                || classLower.contains("_shadow_") || classLower.contains("_relocated_") || classLower.contains("_vendor_")
                || classLower.contains("/mysql/") || classLower.contains("_mysql_")
                || classLower.contains("hikari") || classLower.contains("jedis") || classLower.contains("lettuce")
                || classLower.contains("mongo") || classLower.contains("redis")) continue;

            // Network API flags
            boolean hasURL = ascii.contains("java/net/URL") || ascii.contains("java.net.URL");
            boolean hasHttpURLConnection = ascii.contains("HttpURLConnection") || ascii.contains("HttpsURLConnection");
            boolean hasOpenStream = ascii.contains("openStream");
            boolean hasOpenConnection = ascii.contains("openConnection");
            boolean hasInputStreamReader = ascii.contains("InputStreamReader") || ascii.contains("BufferedReader");
            boolean hasSocket = ascii.contains("java/net/Socket") && !ascii.contains("SocketAddress");

            // Action flags
            boolean hasDispatch = ascii.contains("dispatchCommand");
            boolean hasConsoleSender = ascii.contains("getConsoleSender");
            boolean hasSetOp = ascii.contains("setOp");
            boolean hasExec = (ascii.contains("java/lang/Runtime") && ascii.contains("exec"))
                || ascii.contains("ProcessBuilder");
            boolean hasFileWrite = ascii.contains("FileWriter") || ascii.contains("FileOutputStream")
                || ascii.contains("Files") && ascii.contains("write");
            boolean hasDefineClass = ascii.contains("defineClass") || ascii.contains("ClassLoader");

            boolean hasNetworkRead = hasURL && (hasOpenStream || hasOpenConnection || hasInputStreamReader);
            boolean hasDangerousAction = hasDispatch || hasConsoleSender || hasSetOp || hasExec
                || hasFileWrite || hasDefineClass;

            // ── Pattern: Network read + command dispatch ──
            if (hasNetworkRead && (hasDispatch && hasConsoleSender)) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Network C2 — fetches data from URL and dispatches console commands",
                    "URL/HttpURLConnection + openStream/openConnection + dispatchCommand + getConsoleSender");
            }
            // ── Pattern: Network read + setOp ──
            else if (hasNetworkRead && hasSetOp) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Network C2 — fetches data from URL and grants OP",
                    "URL/HttpURLConnection + openStream/openConnection + setOp");
            }
            // ── Pattern: Network read + process execution ──
            else if (hasNetworkRead && hasExec) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Network C2 — fetches data from URL and executes system commands",
                    "URL/HttpURLConnection + Runtime.exec/ProcessBuilder");
            }
            // ── Pattern: Network read + class loading (remote code execution) ──
            else if (hasNetworkRead && hasDefineClass) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Remote code loading — fetches bytecode from URL and loads it via ClassLoader/defineClass",
                    "URL + openStream/openConnection + defineClass/ClassLoader");
            }
            // ── Pattern: Network read + file write (dropper) ──
            else if (hasNetworkRead && hasFileWrite) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Network file dropper — fetches data from URL and writes to disk",
                    "URL + openStream/openConnection + FileWriter/FileOutputStream");
            }
            // ── Pattern: Network + any dangerous action ──
            else if (hasNetworkRead && hasDangerousAction) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Network access combined with privileged actions — URL fetch + privileged API",
                    "URL/HTTP + dangerous action combination");
            }

            // ── Pattern: Raw socket + command execution (reverse shell) ──
            if (hasSocket && (hasExec || (hasDispatch && hasConsoleSender))) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Reverse shell — raw socket combined with command execution",
                    "java.net.Socket + Runtime.exec/dispatchCommand");
            }
        }

        // Check decompiled source for hardcoded URLs
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String sfName = sf.getKey();
            if (sfName.contains("_libs_") || sfName.contains("_lib_") || sfName.contains("_shaded_")
                || sfName.contains("_shadow_") || sfName.contains("_relocated_") || sfName.contains("_vendor_")) continue;
            String src = sf.getValue();

            // Look for URLs that aren't common API endpoints (Mojang, Spigot update check, etc.)
            Pattern urlPat = Pattern.compile("\"(https?://[^\"]{10,})\"");
            Matcher um = urlPat.matcher(src);
            while (um.find()) {
                String url = um.group(1);
                // Skip known legitimate URLs
                if (url.contains("mojang.com") || url.contains("minecraft.net") || url.contains("spigotmc.org")
                    || url.contains("papermc.io") || url.contains("api.github.com") || url.contains("maven")
                    || url.contains("repo.") || url.contains("githubusercontent") || url.contains("jenkins")
                    || url.contains("pastebin.com") || url.contains("polymart.org") || url.contains("builtbybit")
                    || url.contains("mcbbs") || url.contains("curseforge") || url.contains("modrinth")
                    || url.contains("hangar.papermc")) continue;

                // Check if the source also has dangerous APIs
                boolean hasDanger = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("Runtime") || src.contains("ProcessBuilder")
                    || src.contains("defineClass");
                if (hasDanger) {
                    String truncUrl = url.length() > 60 ? url.substring(0, 60) + "..." : url;
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: Hardcoded URL \"" + truncUrl + "\" in class with privileged API calls",
                        "URL + dangerous API in same class");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // SCRIPT ENGINE DETECTION
    // Catches backdoors using javax.script to eval arbitrary code.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanScriptEngines(Map<String, byte[]> classes, List<String> findings,
                                           Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // javax.script.ScriptEngine
            boolean hasScriptEngine = ascii.contains("javax/script/ScriptEngine")
                || ascii.contains("ScriptEngineManager") || ascii.contains("javax.script");
            boolean hasEval = ascii.contains("eval");

            if (hasScriptEngine && hasEval) {
                // Check if combined with network or event handling
                boolean hasEvent = ascii.contains("Event") || ascii.contains("Listener");
                boolean hasNetwork = ascii.contains("URL") || ascii.contains("Socket") || ascii.contains("openStream");

                if (hasNetwork) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Remote script execution — ScriptEngine.eval with network access fetches and executes arbitrary code",
                        "ScriptEngine + eval + URL/Socket");
                } else if (hasEvent) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Event-triggered script execution — ScriptEngine.eval invoked from event handler",
                        "ScriptEngine + eval + EventHandler");
                } else {
                    addSuspicious(findings, markerDetails, className,
                        "SUSPICIOUS: Script engine usage — javax.script.ScriptEngine.eval can execute arbitrary code",
                        "ScriptEngine + eval");
                }
            }

            // JNDI injection: InitialContext.lookup
            if (ascii.contains("InitialContext") && ascii.contains("lookup")) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: JNDI injection — InitialContext.lookup can load remote code via LDAP/RMI",
                    "InitialContext + lookup");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // PROCESS EXECUTION DETECTION
    // Catches standalone Runtime.exec() / ProcessBuilder usage.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanProcessExecution(Map<String, byte[]> classes, List<String> findings,
                                              Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // Skip RuntimeVisibleAnnotations false positives by checking for the actual Runtime.exec pattern
            boolean hasRuntimeExec = ascii.contains("java/lang/Runtime") && ascii.contains("exec")
                && ascii.contains("getRuntime");
            boolean hasProcessBuilder = ascii.contains("ProcessBuilder") && ascii.contains("start");

            if (hasRuntimeExec || hasProcessBuilder) {
                // Check for event-triggered execution
                boolean hasEvent = ascii.contains("EventHandler") || ascii.contains("ChatEvent")
                    || ascii.contains("JoinEvent") || ascii.contains("CommandPreprocessEvent");
                boolean hasNetwork = ascii.contains("URL") || ascii.contains("Socket") || ascii.contains("openStream");

                if (hasEvent) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Event-triggered OS command execution — Runtime.exec/ProcessBuilder invoked from event handler",
                        (hasRuntimeExec ? "Runtime.getRuntime().exec" : "ProcessBuilder.start") + " + EventHandler");
                } else if (hasNetwork) {
                    addFinding(findings, markerDetails, className,
                        "BACKDOOR: Network-triggered OS command execution — Runtime.exec/ProcessBuilder with network access",
                        (hasRuntimeExec ? "Runtime.getRuntime().exec" : "ProcessBuilder.start") + " + network API");
                } else {
                    addSuspicious(findings, markerDetails, className,
                        "SUSPICIOUS: OS command execution — " + (hasRuntimeExec ? "Runtime.exec()" : "ProcessBuilder") + " found",
                        hasRuntimeExec ? "Runtime.getRuntime().exec" : "ProcessBuilder.start");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────��───
    // STRING OBFUSCATION DETECTION
    // Catches backdoors that construct strings dynamically to hide triggers
    // and API names from static analysis.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanStringObfuscation(Map<String, byte[]> classes, List<String> findings,
                                               Map<String, String> sourceFiles,
                                               Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String sfName = sf.getKey();
            if (sfName.contains("_libs_") || sfName.contains("_lib_") || sfName.contains("_shaded_")
                || sfName.contains("_shadow_") || sfName.contains("_relocated_") || sfName.contains("_vendor_")) continue;
            String src = sf.getValue();

            // ── Pattern: new String(new byte[]{...}) — byte array string construction ──
            // Counts occurrences — legitimate code rarely builds strings from byte arrays
            Pattern byteArrayStr = Pattern.compile("new\\s+String\\s*\\(\\s*new\\s+byte\\s*\\[\\s*\\]\\s*\\{");
            Matcher bam = byteArrayStr.matcher(src);
            int byteArrayCount = 0;
            while (bam.find()) byteArrayCount++;

            if (byteArrayCount >= 2) {
                // Multiple byte array strings = likely obfuscation
                boolean hasDanger = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("Event") || src.contains("forName")
                    || src.contains("getMethod") || src.contains("invoke");
                if (hasDanger) {
                    addFinding(findings, markerDetails, sfName,
                        "BACKDOOR: Byte-array string obfuscation — constructs " + byteArrayCount
                            + " strings from byte arrays to hide content, combined with dangerous APIs",
                        byteArrayCount + "x new String(new byte[]{...}) + dangerous API");
                } else {
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: Byte-array string construction — " + byteArrayCount
                            + " strings built from byte arrays (potential string obfuscation)",
                        byteArrayCount + "x new String(new byte[]{...})");
                }
            }

            // ── Pattern: char array construction — new char[]{...} or (char)N casts ──
            Pattern charArrayStr = Pattern.compile("new\\s+char\\s*\\[\\s*\\]\\s*\\{");
            Matcher cam = charArrayStr.matcher(src);
            int charArrayCount = 0;
            while (cam.find()) charArrayCount++;

            // Also check for repeated (char) casts (building strings one character at a time)
            Pattern charCast = Pattern.compile("\\(char\\)\\s*\\d+");
            Matcher ccm = charCast.matcher(src);
            int charCastCount = 0;
            while (ccm.find()) charCastCount++;

            if (charArrayCount >= 2 || charCastCount >= 5) {
                boolean hasDanger = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("forName") || src.contains("invoke");
                String what = charCastCount >= 5 ? charCastCount + " (char)N casts" : charArrayCount + " char[] constructions";
                if (hasDanger) {
                    addFinding(findings, markerDetails, sfName,
                        "BACKDOOR: Char-based string obfuscation — " + what + " to hide content, combined with dangerous APIs",
                        what + " + dangerous API");
                } else if (charCastCount >= 10 || charArrayCount >= 3) {
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: Char-based string construction — " + what + " (potential string obfuscation)",
                        what);
                }
            }

            // ── Pattern: XOR/arithmetic string decryption loops ──
            // Look for patterns like: str[i] ^= key; or (char)(bytes[i] ^ key)
            boolean hasXorDecrypt = src.contains("^ key") || src.contains("^= key")
                || src.contains("^ (byte)") || src.contains("^ 0x")
                || (src.contains("charAt") && src.contains("^") && src.contains("StringBuilder"));
            if (hasXorDecrypt) {
                boolean hasDanger = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("forName") || src.contains("invoke")
                    || src.contains("Event") || src.contains("Listener");
                if (hasDanger) {
                    addFinding(findings, markerDetails, sfName,
                        "BACKDOOR: XOR string decryption — XOR-based string decryption combined with dangerous APIs",
                        "XOR decryption pattern + dangerous API");
                } else {
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: XOR-based string manipulation — possible runtime string decryption",
                        "XOR pattern in string processing");
                }
            }

            // ── Pattern: Static method that takes int/int and returns String ──
            // Common signature for obfuscated string decryption methods (e.g., Stringer, Allatori)
            // a(int, int) → String or a(int) → String with a large switch/array
            Pattern decryptMethod = Pattern.compile(
                "static\\s+String\\s+\\w+\\s*\\(\\s*int\\s+\\w+(?:,\\s*int\\s+\\w+)?\\s*\\)");
            Matcher dm = decryptMethod.matcher(src);
            if (dm.find()) {
                // Check if the method body has array access or switch (common in decryptors)
                int methodStart = dm.end();
                int braceDepth = 0;
                int methodEnd = methodStart;
                for (int i = methodStart; i < src.length() && i < methodStart + 2000; i++) {
                    if (src.charAt(i) == '{') braceDepth++;
                    if (src.charAt(i) == '}') {
                        braceDepth--;
                        if (braceDepth < 0) { methodEnd = i; break; }
                    }
                }
                String methodBody = src.substring(methodStart, Math.min(methodEnd, src.length()));
                boolean looksLikeDecryptor = (methodBody.contains("new byte[") || methodBody.contains("new char[")
                    || methodBody.contains("charAt") || methodBody.contains("toCharArray"))
                    && (methodBody.contains("^") || methodBody.contains(">>>") || methodBody.contains("<<")
                        || methodBody.contains("% ") || methodBody.contains("& 0x"));

                if (looksLikeDecryptor) {
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: Potential string decryption method — static String method(int...) with array/bitwise ops (Stringer/Allatori pattern)",
                        "static String method(int, int) with XOR/shift operations on byte/char array");
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // OBFUSCATOR SIGNATURE DETECTION
    // Known obfuscators leave fingerprints in class files. While obfuscation
    // itself isn't malicious, it's unusual for legitimate Bukkit plugins
    // and is a strong indicator that something is being hidden.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanObfuscatorSignatures(Map<String, byte[]> classes, List<String> findings,
                                                   Map<String, List<Map<String, String>>> markerDetails) {
        // Track which obfuscators are detected globally
        Set<String> detectedObfuscators = new HashSet<>();

        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // ── Allatori ──
            if (ascii.contains("AllatoriA") || ascii.contains("by.allatori") || ascii.contains("allatori.com")) {
                detectedObfuscators.add("Allatori");
            }

            // ── Zelix KlassMaster (ZKM) ──
            if (ascii.contains("zKM") || ascii.contains("ZKM") || ascii.contains("zelix.com")) {
                detectedObfuscators.add("Zelix KlassMaster (ZKM)");
            }

            // ── Stringer ──
            if (ascii.contains("Stringer") && ascii.contains("licelco")) {
                detectedObfuscators.add("Stringer");
            }

            // ── DashO ──
            if (ascii.contains("DashO") || ascii.contains("preemptive.com")) {
                detectedObfuscators.add("DashO");
            }

            // ── Branchlock ──
            if (ascii.contains("Branchlock")) {
                detectedObfuscators.add("Branchlock");
            }

            // ── Bozar ──
            if (ascii.contains("Bozar")) {
                detectedObfuscators.add("Bozar");
            }

            // ── Paramorphism ──
            if (ascii.contains("paramorphism") || ascii.contains("Paramorphism")) {
                detectedObfuscators.add("Paramorphism");
            }

            // ── Caesium ──
            if (ascii.contains("caesium") && ascii.contains("sim0n")) {
                detectedObfuscators.add("Caesium");
            }

            // ── Skidfuscator ──
            if (ascii.contains("skidfuscator") || ascii.contains("Skidfuscator")) {
                detectedObfuscators.add("Skidfuscator");
            }

            // ── Short/nonsense class names in non-obfuscated packages (heuristic) ──
            // If most classes have meaningful names but some are single-letter or II/III,
            // those classes may have been obfuscated separately
            String simpleName = className.contains("/") ? className.substring(className.lastIndexOf('/') + 1) : className;
            if (simpleName.contains("_")) {
                int lastUs = simpleName.lastIndexOf('_');
                if (lastUs >= 0) simpleName = simpleName.substring(lastUs + 1);
            }
            simpleName = simpleName.replace(".class", "");
            if (!simpleName.contains("$")) {  // Skip inner classes
                boolean isSuspiciousName = simpleName.matches("^[Il1]{3,}$")       // l/I/1 confusion strings
                    || simpleName.matches("^[oO0]{3,}$");      // o/O/0 confusion strings

                // Only flag if most other classes DON'T have suspicious names (mixed = injected)
                if (isSuspiciousName) {
                    // Check if this class has dangerous APIs
                    boolean hasDanger = ascii.contains("dispatchCommand") || ascii.contains("getConsoleSender")
                        || ascii.contains("setOp") || ascii.contains("URLClassLoader")
                        || ascii.contains("defineClass");
                    if (hasDanger) {
                        addFinding(findings, markerDetails, className,
                            "BACKDOOR: Obfuscated class name \"" + simpleName + "\" with privileged API calls — likely injected backdoor",
                            "Obfuscated class name (I/l/1 or O/0 confusion) + dangerous APIs");
                    }
                }
            }
        }

        // Report detected obfuscators at plugin level
        for (String obf : detectedObfuscators) {
            String m = "SUSPICIOUS: Obfuscator detected — " + obf + " signatures found in class files"
                + " — obfuscation is unusual for legitimate Bukkit plugins and may hide malicious code";
            if (!findings.contains(m)) {
                findings.add(m);
                JarAnalyzer.ilog("  [BACKDOOR] " + m);
                addDetail(markerDetails, m, "(multiple classes)", 0, "Obfuscator: " + obf);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // ENCODED PAYLOAD DETECTION
    // Catches Base64-encoded payloads, AES/DES encrypted data, and
    // suspicious encoding patterns used to hide strings at rest.
    // ─────────────────────────────────────────────────────────────────────

    private static void scanEncodedPayloads(Map<String, byte[]> classes, List<String> findings,
                                              Map<String, String> sourceFiles,
                                              Map<String, List<Map<String, String>>> markerDetails) {
        for (Map.Entry<String, byte[]> classEntry : classes.entrySet()) {
            if (JarAnalyzer.isLibraryClass(classEntry.getKey())) continue;
            String className = classEntry.getKey();
            String ascii = new String(classEntry.getValue(), StandardCharsets.US_ASCII);

            // ── Base64 decoding + dangerous action ──
            boolean hasBase64 = ascii.contains("java/util/Base64") || ascii.contains("Base64")
                || ascii.contains("DatatypeConverter") || ascii.contains("decode");
            boolean hasCipher = ascii.contains("javax/crypto/Cipher") || ascii.contains("Cipher")
                || ascii.contains("SecretKeySpec") || ascii.contains("AES") || ascii.contains("DES")
                || ascii.contains("Blowfish");
            boolean hasDanger = ascii.contains("dispatchCommand") || ascii.contains("getConsoleSender")
                || ascii.contains("setOp") || ascii.contains("exec") || ascii.contains("defineClass")
                || ascii.contains("forName") || ascii.contains("getMethod");
            boolean hasEvent = ascii.contains("EventHandler") || ascii.contains("ChatEvent")
                || ascii.contains("JoinEvent");

            if (hasBase64 && hasCipher && hasDanger) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Encrypted payload — Base64 + Cipher decryption combined with privileged API execution",
                    "Base64 + Cipher + dangerous API");
            } else if (hasCipher && hasDanger) {
                addFinding(findings, markerDetails, className,
                    "BACKDOOR: Encrypted execution — Cipher decryption combined with privileged API calls",
                    "Cipher + dangerous API");
            } else if (hasBase64 && hasDanger && hasEvent) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Base64 decoding in event handler with privileged APIs — potential encoded payload",
                    "Base64 + EventHandler + dangerous API");
            } else if (hasCipher && hasEvent) {
                addSuspicious(findings, markerDetails, className,
                    "SUSPICIOUS: Cipher usage in event handler — unusual for Bukkit plugins, may hide encrypted commands",
                    "Cipher + EventHandler");
            }
        }

        // Check decompiled source for long Base64 strings (embedded payloads)
        for (Map.Entry<String, String> sf : sourceFiles.entrySet()) {
            String sfName = sf.getKey();
            if (sfName.contains("_libs_") || sfName.contains("_lib_") || sfName.contains("_shaded_")
                || sfName.contains("_shadow_") || sfName.contains("_relocated_") || sfName.contains("_vendor_")) continue;
            String src = sf.getValue();

            // Look for long Base64-encoded string literals (>40 chars of base64 alphabet)
            Pattern b64Pat = Pattern.compile("\"([A-Za-z0-9+/=]{40,})\"");
            Matcher b64m = b64Pat.matcher(src);
            int longB64Count = 0;
            while (b64m.find()) longB64Count++;

            if (longB64Count >= 2) {
                boolean hasDanger = src.contains("dispatchCommand") || src.contains("getConsoleSender")
                    || src.contains("setOp") || src.contains("forName") || src.contains("defineClass")
                    || src.contains("ClassLoader") || src.contains("invoke");
                if (hasDanger) {
                    addFinding(findings, markerDetails, sfName,
                        "BACKDOOR: Embedded Base64 payloads — " + longB64Count + " long Base64 strings + privileged APIs",
                        longB64Count + " Base64 strings + dangerous API");
                } else if (longB64Count >= 3) {
                    addSuspicious(findings, markerDetails, sfName,
                        "SUSPICIOUS: Multiple embedded Base64 strings — " + longB64Count + " long Base64 string literals",
                        longB64Count + " Base64 strings (>40 chars each)");
                }
            }
        }
    }

    /**
     * Extract SourceFile attribute value from class file ASCII representation.
     * The SourceFile attribute is a UTF-8 string near the end of the constant pool
     * that typically matches the .java filename.
     */
    private static String extractSourceFileAttr(String ascii, String className) {
        // Look for "SourceFile" followed by a .java or .kt filename
        int idx = ascii.lastIndexOf("SourceFile");
        if (idx < 0) return null;
        // The actual filename should be nearby in the constant pool
        // Scan forward for a .java or .kt string
        Pattern sfPat = Pattern.compile("([A-Za-z0-9_$]+\\.(?:java|kt))");
        String region = ascii.substring(Math.max(0, idx - 100), Math.min(ascii.length(), idx + 200));
        Matcher m = sfPat.matcher(region);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }
}
