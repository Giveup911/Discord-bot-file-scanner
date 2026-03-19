/*
    Minecraft RAT/Malware YARA Rules
    Drop new .yar files into this directory — they load automatically on bot startup.
*/

rule Weedhack_Dropper
{
    meta:
        description = "Weedhack dropper - EtherHiding C2 resolution via Ethereum blockchain"
        author = "RatScanner"
        severity = "critical"

    strings:
        $eth_call = "eth_call" ascii
        $init_wh = "initializeWeedhack" ascii
        $majanito = "dev/majanito" ascii
        $majanito2 = "dev.majanito" ascii
        $fabric = "FabricAdapter" ascii

    condition:
        $eth_call and ($init_wh or $majanito or $majanito2 or $fabric)
}

rule Weedhack_Stage2_Module
{
    meta:
        description = "Weedhack Stage 2 Module.jar with JNIC native payload"
        author = "RatScanner"
        severity = "critical"

    strings:
        $jnic_dat = /dev\/jnic\/lib\/[a-f0-9\-]+\.dat/ ascii
        $jnic_loader = "JNICLoader" ascii
        $majanito = "dev/majanito" ascii

    condition:
        $jnic_dat and ($jnic_loader or $majanito)
}

rule AdamRAT
{
    meta:
        description = "AdamRAT - Minecraft session stealer with XOR+AES config"
        author = "RatScanner"
        severity = "high"

    strings:
        $adamrat = "adamrat.shop" ascii nocase
        $obf1 = "vubsyodfkejzllnk" ascii
        $obf2 = "upokyqklsolkxbys" ascii
        $obf3 = "pynvtoxahbmzany" ascii
        $example_mod = "ExampleModClient" ascii

    condition:
        $adamrat or ($example_mod and any of ($obf*))
}

rule Discord_Webhook_Exfil
{
    meta:
        description = "Discord webhook URL for data exfiltration"
        author = "RatScanner"
        severity = "high"

    strings:
        $webhook = /discord\.com\/api\/webhooks\/\d+\// ascii
        $webhook2 = /discordapp\.com\/api\/webhooks\/\d+\// ascii

    condition:
        any of them
}

rule Skyrage_RAT
{
    meta:
        description = "Skyrage Minecraft RAT"
        author = "RatScanner"
        severity = "critical"

    strings:
        $skyrage = "skyrage.de" ascii nocase
        $panel = "panel.skyrage" ascii nocase
        $pkg = "de/skyrage" ascii

    condition:
        uint16(0) == 0x4B50 and any of them
}

rule Fractureiser
{
    meta:
        description = "Fractureiser supply chain malware"
        author = "RatScanner"
        severity = "critical"

    strings:
        $fract1 = "fractureiser" ascii nocase
        $stage0_class = "Cosmetics.class" ascii
        $stage0_pkg = "dev/neko" ascii
        $stage1_class = "DungeonzMain" ascii
        $c2_ip1 = "85.217.144.130" ascii
        $c2_ip2 = "107.189.3.101" ascii

    condition:
        uint16(0) == 0x4B50 and ($fract1 or ($stage0_class and $stage0_pkg) or $stage1_class or any of ($c2_ip*))
}

rule MSHTA_Dropper
{
    meta:
        description = "MSHTA-based dropper in Minecraft mod"
        author = "RatScanner"
        severity = "high"

    strings:
        $mshta = "mshta" ascii nocase
        $vbscript = "vbscript" ascii nocase
        $runtime_exec = "Runtime.getRuntime().exec" ascii

    condition:
        $mshta and ($vbscript or $runtime_exec)
}

rule Suspicious_Minecraft_Mod
{
    meta:
        description = "Minecraft mod that reads launcher accounts and exfiltrates via webhook"
        author = "RatScanner"
        severity = "medium"

    strings:
        $launcher_accts = "launcher_accounts" ascii
        $webhook = "discord.com/api/webhooks" ascii

    condition:
        $launcher_accts and $webhook
}

rule Ethereum_Contract_C2
{
    meta:
        description = "EtherHiding - Ethereum/Polygon smart contract used for C2"
        author = "RatScanner"
        severity = "critical"

    strings:
        $known_contract_eth = "0x1280a841Fbc1F883365d3C83122260E0b2995B74" ascii nocase
        $known_contract_poly = "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a" ascii nocase
        $eth_call = "eth_call" ascii
        $jsonrpc = "jsonrpc" ascii
        $eth_method = "0xce6d41de" ascii

    condition:
        any of ($known_contract*) or ($eth_call and $jsonrpc and $eth_method)
}

rule Known_Malicious_Domains
{
    meta:
        description = "Known Weedhack/RAT infrastructure domains"
        author = "RatScanner"
        severity = "critical"

    strings:
        $d1 = "whrc.ru" ascii nocase
        $d2 = "weedhack.to" ascii nocase
        $d3 = "weedhack.cy" ascii nocase
        $d4 = "whreceiver.ru" ascii nocase
        $d5 = "whnewreceive.ru" ascii nocase
        $d6 = "receiver.cy" ascii nocase
        $d7 = "adamrat.shop" ascii nocase

    condition:
        any of them
}

rule Browser_Data_Stealer
{
    meta:
        description = "Browser credential/cookie stealer targeting Chrome/Firefox/Edge"
        author = "RatScanner"
        severity = "high"

    strings:
        $chrome_db1 = "Login Data" ascii
        $chrome_db2 = "Web Data" ascii
        $chrome_db3 = "Local State" ascii
        $chrome_path = "Google/Chrome/User Data" ascii
        $chrome_path2 = "Google\\Chrome\\User Data" ascii
        $firefox_db1 = "logins.json" ascii
        $firefox_db2 = "key4.db" ascii
        $firefox_db3 = "places.sqlite" ascii
        $firefox_path = "Mozilla/Firefox/Profiles" ascii
        $firefox_path2 = "Mozilla\\Firefox\\Profiles" ascii
        $edge_path = "Microsoft/Edge/User Data" ascii
        $edge_path2 = "Microsoft\\Edge\\User Data" ascii
        $brave_path = "BraveSoftware/Brave-Browser" ascii
        $brave_path2 = "BraveSoftware\\Brave-Browser" ascii
        $dpapi = "CryptUnprotectData" ascii
        $exfil_webhook = /discord\.com\/api\/webhooks/ ascii
        $exfil_telegram = "api.telegram.org" ascii

    condition:
        // Require browser path + credential DB + exfil method
        (any of ($chrome_path*) or any of ($firefox_path*) or any of ($edge_path*) or any of ($brave_path*))
        and (any of ($chrome_db*) or any of ($firefox_db*) or $dpapi)
        and (any of ($exfil*))
}

rule Discord_Token_Stealer
{
    meta:
        description = "Discord token stealer targeting app local storage"
        author = "RatScanner"
        severity = "high"

    strings:
        $discord_ls = "discord/Local Storage/leveldb" ascii
        $discord_ls2 = "discord\\Local Storage\\leveldb" ascii
        $discordcanary = "discordcanary" ascii nocase
        $discordptb = "discordptb" ascii nocase
        $api_check = "/api/v9/users/@me" ascii
        $api_check2 = "/api/v10/users/@me" ascii
        $betterdiscord = "BetterDiscord" ascii
        $token_regex = "dQw4w9WgXcQ" ascii

    condition:
        // Require leveldb path access + token validation OR token regex
        (any of ($discord_ls*)) and (any of ($api_check*) or $token_regex)
        or ($token_regex and any of ($api_check*))
        or (any of ($discord_ls*) and 2 of ($discordcanary, $discordptb, $betterdiscord))
}

rule Crypto_Miner_Injection
{
    meta:
        description = "Cryptocurrency miner injected into Minecraft mod/client"
        author = "RatScanner"
        severity = "high"

    strings:
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $xmrig = "xmrig" ascii nocase
        $pool1 = "pool.minexmr.com" ascii
        $pool2 = "pool.hashvault.pro" ascii
        $pool3 = "xmrpool.eu" ascii
        $pool4 = "pool.supportxmr.com" ascii
        $pool5 = "monerohash.com" ascii
        $pool6 = "moneroocean.stream" ascii
        $coinhive = "coinhive" ascii nocase

    condition:
        any of ($stratum*) or any of ($pool*) or $xmrig or $coinhive
}

rule Clipboard_Hijacker
{
    meta:
        description = "Clipboard monitoring and crypto address replacement"
        author = "RatScanner"
        severity = "high"

    strings:
        $clipboard1 = "getSystemClipboard" ascii
        $clipboard2 = "ClipboardOwner" ascii
        $clipboard3 = "lostOwnership" ascii
        $clipboard4 = "StringSelection" ascii
        $clipboard5 = "setContents" ascii

    condition:
        ($clipboard1 or $clipboard2) and ($clipboard3 or $clipboard4 or $clipboard5)
}

rule Keylogger_Injection
{
    meta:
        description = "Keylogger functionality in Minecraft mod"
        author = "RatScanner"
        severity = "high"

    strings:
        $jnativehook = "jnativehook" ascii
        $nkl = "NativeKeyListener" ascii
        $gkl = "GlobalKeyListener" ascii
        $keylogger = "KeyLogger" ascii nocase
        $getasync = "GetAsyncKeyState" ascii
        $sethook = "SetWindowsHookEx" ascii

    condition:
        ($jnativehook or $nkl or $gkl or $keylogger) or ($getasync and $sethook)
}

rule Staged_Payload_Downloader
{
    meta:
        description = "Multi-stage downloader fetching payloads from paste/file hosting"
        author = "RatScanner"
        severity = "medium"

    strings:
        $paste1 = "pastebin.com/raw" ascii
        $paste2 = "hastebin.com/raw" ascii
        $paste3 = "hasteb.in/raw" ascii
        $paste4 = "rentry.co/raw" ascii
        $github_raw = "raw.githubusercontent.com" ascii
        $discord_cdn = "cdn.discordapp.com/attachments" ascii
        $transfer = "transfer.sh" ascii
        $gofile = "gofile.io" ascii
        $anonfiles = "anonfiles.com" ascii
        $urlloader = "URLClassLoader" ascii
        $defineclass = "defineClass" ascii

    condition:
        any of ($paste*, $github_raw, $discord_cdn, $transfer, $gofile, $anonfiles) and ($urlloader or $defineclass)
}

rule AntiAnalysis_Evasion
{
    meta:
        description = "Anti-VM/anti-analysis checks before payload execution"
        author = "RatScanner"
        severity = "medium"

    strings:
        $vbox1 = "VBoxService" ascii
        $vbox2 = "VirtualBox" ascii
        $vmware1 = "vmtoolsd" ascii
        $vmware2 = "vmwaretray" ascii
        $wireshark = "Wireshark" ascii
        $procmon = "procmon" ascii
        $fiddler = "Fiddler" ascii
        $sandbox = "SbieDll" ascii
        $defender_excl = "Add-MpPreference" ascii

    condition:
        3 of ($vbox*, $vmware*, $wireshark, $procmon, $fiddler, $sandbox) or $defender_excl
}

rule Minecraft_Launcher_Token_Stealer
{
    meta:
        description = "Targets multiple Minecraft launcher token files for theft"
        author = "RatScanner"
        severity = "high"

    strings:
        $la = "launcher_accounts" ascii
        $lp = "launcher_profiles" ascii
        $essential = "essential/microsoft_accounts" ascii
        $essential2 = "essential\\microsoft_accounts" ascii
        $feather = "feather/accounts" ascii
        $feather2 = "feather\\accounts" ascii
        $lunar = "lunar/accounts" ascii
        $lunar2 = "lunar\\accounts" ascii
        $webhook = "discord.com/api/webhooks" ascii
        $telegram = "api.telegram.org" ascii

    condition:
        2 of ($la, $lp, $essential*, $feather*, $lunar*) and ($webhook or $telegram)
}

rule Telegram_Bot_Exfil
{
    meta:
        description = "Telegram bot token used for data exfiltration"
        author = "RatScanner"
        severity = "high"

    strings:
        $tg_api = "api.telegram.org" ascii
        $tg_bot = /bot[0-9]{8,10}:[A-Za-z0-9_\-]{35}/ ascii
        $tg_send = "sendDocument" ascii
        $tg_send2 = "sendMessage" ascii

    condition:
        $tg_api and ($tg_bot or $tg_send or $tg_send2)
}

rule BleedingPipe_Deserialization
{
    meta:
        description = "Deserialization RCE pattern (BleedingPipe-style)"
        author = "RatScanner"
        severity = "critical"

    strings:
        $readobj = "readObject" ascii
        $objinput = "ObjectInputStream" ascii
        $socket_recv = "getInputStream" ascii
        $ysoserial = "ysoserial" ascii nocase
        $commons_collect = "commons-collections" ascii
        $transformer = "InvokerTransformer" ascii
        $lazy_map = "LazyMap" ascii

    condition:
        ($ysoserial or $transformer or $lazy_map) or
        ($readobj and $objinput and $socket_recv and ($commons_collect or $transformer))
}

rule JVMTI_Agent_Injection
{
    meta:
        description = "JVMTI agent injection (NeptuneLoader-style)"
        author = "RatScanner"
        severity = "high"

    strings:
        $attach = "VirtualMachine.attach" ascii
        $attach2 = "com.sun.tools.attach" ascii
        $agent_load = "loadAgent" ascii
        $agent_path = "agentmain" ascii
        $instrumentation = "Instrumentation" ascii

    condition:
        ($attach or $attach2) and ($agent_load or $agent_path) and $instrumentation
}

rule Silent_NET_Stealer
{
    meta:
        description = "Silent NET - Minecraft session stealer with Polygon blockchain C2"
        author = "RatScanner"
        severity = "critical"

    strings:
        $pkg1 = "com/libmod" ascii
        $pkg2 = "com.libmod" ascii
        $opaque1 = "ktfdumxluduvzmma" ascii
        $opaque2 = "azmssbnclpvvzpam" ascii
        $opaque3 = "bzwkkgywwylfhgzl" ascii
        $opaque4 = "xnhyeinlaaoruzua" ascii
        $sltnnt = "sltnnt.ru" ascii
        $contract = "0x9c0a5073" ascii nocase
        $prefireMc = "prefireMc" ascii
        $langdat = "lang.dat" ascii
        $libmod_id = "\"id\": \"libmod\"" ascii

    condition:
        uint16(0) == 0x4B50 and (
            (any of ($pkg*) and any of ($opaque*))
            or $sltnnt
            or $contract
            or (any of ($pkg*) and $prefireMc)
            or (any of ($pkg*) and $langdat and $libmod_id)
        )
}

rule Polygon_Contract_C2
{
    meta:
        description = "Polygon blockchain smart contract used for C2 resolution"
        author = "RatScanner"
        severity = "critical"

    strings:
        $known_contract = "0x9c0a507300fd902787bb193d80fca5ce6e1bff9a" ascii nocase
        $polygon_rpc1 = "polygon-rpc.com" ascii
        $polygon_rpc2 = "polygon-bor-rpc.publicnode.com" ascii
        $polygon_rpc3 = "1rpc.io/matic" ascii
        $eth_call = "eth_call" ascii
        $eth_method = "0xce6d41de" ascii

    condition:
        $known_contract or ($eth_call and $eth_method and any of ($polygon_rpc*))
}

rule Reflection_Chain_Execution {
    meta:
        description = "Detects Java reflection chains used to execute hidden payloads"
        severity = "medium"
    strings:
        $forName = "Class.forName" ascii
        $getMethod = "getMethod" ascii
        $invoke = ".invoke(" ascii
        $getDeclared = "getDeclaredMethod" ascii
        $newInstance = "newInstance" ascii
    condition:
        $forName and ($getMethod or $getDeclared) and ($invoke or $newInstance)
}

rule Dynamic_ClassLoader_Injection {
    meta:
        description = "Detects dynamic class loading from byte arrays (runtime code injection)"
        severity = "high"
    strings:
        $defineClass = "defineClass" ascii
        $unsafe1 = "sun/misc/Unsafe" ascii
        $unsafe2 = "sun.misc.Unsafe" ascii
        $urlcl = "URLClassLoader" ascii
        $byteArray = "[B" ascii
        $lookup = "MethodHandles$Lookup" ascii
    condition:
        $defineClass and ($unsafe1 or $unsafe2 or $urlcl or ($byteArray and $lookup))
}

rule DNS_Tunneling_C2 {
    meta:
        description = "Detects DNS resolution APIs used for C2 communication"
        severity = "medium"
    strings:
        $jndi1 = "InitialDirContext" ascii
        $jndi2 = "javax.naming" ascii
        $jndi3 = "DirContext" ascii
        $dns1 = "TXT" ascii
        $dns2 = "dns:" ascii
        $lookup = "lookup" ascii
    condition:
        ($jndi1 or $jndi2 or $jndi3) and ($dns1 or $dns2) and $lookup
}

rule Polymorphic_Discord_Webhook {
    meta:
        description = "Detects Discord webhook URL construction via string building"
        severity = "high"
    strings:
        $hook_path = "/api/webhooks/" ascii
        $hook_url1 = "discord.com/api/webhooks" ascii nocase
        $hook_url2 = "discordapp.com/api/webhooks" ascii nocase
        $builder1 = "StringBuilder" ascii
        $builder2 = "StringBuffer" ascii
        $concat = "concat" ascii
    condition:
        ($hook_path or $hook_url1 or $hook_url2) and ($builder1 or $builder2 or $concat)
}

rule Java_Agent_Instrumentation {
    meta:
        description = "Detects Java agent instrumentation capabilities for bytecode manipulation"
        severity = "high"
    strings:
        $premain = "Premain-Class" ascii
        $agentclass = "Agent-Class" ascii
        $instrument = "java/lang/instrument" ascii
        $retransform = "retransformClasses" ascii
        $redefine = "redefineClasses" ascii
        $attach = "com.sun.tools.attach" ascii
    condition:
        ($premain or $agentclass) and ($instrument or $retransform or $redefine or $attach)
}

rule Scheduled_Delayed_Payload {
    meta:
        description = "Detects scheduled/delayed payload execution combined with dangerous actions"
        severity = "low"
    strings:
        $timer = "java/util/Timer" ascii
        $sched1 = "ScheduledExecutorService" ascii
        $sched2 = "ScheduledThreadPoolExecutor" ascii
        $proc1 = "ProcessBuilder" ascii
        $exec1 = "Runtime.exec" ascii
        $loader1 = "URLClassLoader" ascii
        $loader2 = "defineClass" ascii
        $unsafe = "sun/misc/Unsafe" ascii
    condition:
        ($timer or $sched1 or $sched2) and ($proc1 or $exec1 or $loader1 or $loader2 or $unsafe)
}

rule PyInstaller_PyArmor_Packed {
    meta:
        description = "PyInstaller executable with PyArmor obfuscation — likely Python RAT/stealer"
        author = "RatScanner"
        severity = "high"
    strings:
        $mz = "MZ"
        $pyinst1 = "PYZ-00.pyz" ascii
        $pyinst2 = "MEIPASS" ascii
        $pyinst3 = "pyimod" ascii
        $pyinst4 = "PyInstaller" ascii
        $pyarmor1 = "__pyarmor__" ascii
        $pyarmor2 = "PY000000" ascii
        $pyarmor3 = "pyarmor_runtime" ascii
    condition:
        $mz at 0 and 2 of ($pyinst*) and any of ($pyarmor*)
}

rule PyInstaller_Stealer_Toolkit {
    meta:
        description = "PyInstaller bundle with credential theft and exfiltration modules"
        author = "RatScanner"
        severity = "critical"
    strings:
        $mz = "MZ"
        $pyinst1 = "PYZ-00.pyz" ascii
        $pyinst2 = "MEIPASS" ascii
        $win32crypt = "win32crypt" ascii
        $dpapi = "CryptUnprotectData" ascii
        $cv2 = "cv2" ascii
        $pynput = "pynput" ascii
        $requests = "requests" ascii
        $aiohttp = "aiohttp" ascii
        $psutil = "psutil" ascii
    condition:
        $mz at 0 and any of ($pyinst*) and (
            ($win32crypt or $dpapi) and ($requests or $aiohttp)
            or $pynput
            or ($cv2 and ($requests or $aiohttp))
            or ($psutil and ($win32crypt or $pynput or $cv2))
        )
}

rule Zipbomb_Dropper {
    meta:
        description = "Rust-based zipbomb dropper that deploys disguised executables"
        author = "RatScanner"
        severity = "critical"
    strings:
        $mz = "MZ"
        $fatal_copy = "FATAL: copy payload" ascii
        $fatal_worker = "FATAL: worker" ascii
        $fatal_dirs = "FATAL: no writable dirs" ascii
        $zipbomb_pdb = "zipbomb" ascii nocase
        $updhelper = "updhelper.exe" ascii
        $cfgsync = "cfgsync.exe" ascii
        $logrotate = "logrotate.exe" ascii
    condition:
        $mz at 0 and (
            any of ($fatal*)
            or $zipbomb_pdb
            or 2 of ($updhelper, $cfgsync, $logrotate)
        )
}

rule MSHTA_Settings_Tel_Dropper {
    meta:
        description = "MSHTA dropper using settings.tel hosting for stage2"
        author = "RatScanner"
        severity = "critical"
    strings:
        $mshta = "mshta" ascii nocase
        $settings_tel = "settings.tel" ascii
        $cmd = "cmd.exe" ascii
        $proc1 = "ProcessBuilder" ascii
        $proc2 = "Runtime" ascii
    condition:
        $settings_tel or ($mshta and ($proc1 or $proc2) and $cmd)
}

rule qProtect_Evasion {
    meta:
        description = "qProtect obfuscator with .class/ trailing slash ZIP entry evasion"
        author = "RatScanner"
        severity = "high"
    strings:
        $pk = "PK"
        $qprotect = "qProtect" ascii nocase
        $trailing1 = ".class/" ascii
        $config_marker = "userWebhook" ascii
        $config_marker2 = "ratfileUrl" ascii
        $donut_c2 = "donutsmp.net" ascii
    condition:
        $pk at 0 and (
            $qprotect
            or ($trailing1 and ($config_marker or $config_marker2))
            or $donut_c2
        )
}

rule GambleRig_Casino_RAT {
    meta:
        description = "GambleRigger/4E casino rig RAT family with session theft and auto-pay"
        author = "RatScanner"
        severity = "critical"
    strings:
        $pk = "PK"
        $donut = "donutsmp.net" ascii
        $user_webhook = "userWebhook" ascii
        $ratfile = "ratfileUrl" ascii
        $download_url = "downloadUrl" ascii
        $auto_pay = "/pay " ascii
        $session_token = "accessToken" ascii
        $launcher_accts = "launcher_accounts" ascii
    condition:
        $pk at 0 and (
            $donut
            or ($user_webhook and $ratfile)
            or $download_url
            or ($auto_pay and $session_token and $launcher_accts)
        )
}

rule Dupemate_MSHTA_Stealer {
    meta:
        description = "Dupemate-style stealer using stack-string obfuscation and mshta dropper"
        author = "RatScanner"
        severity = "high"
    strings:
        $pk = "PK"
        $unloadchunk = ".unloadchunk" ascii
        $settings_tel = "settings.tel" ascii
        $mshta = "mshta" ascii
        $texture_names = "loadTextureAtlas" ascii
        $mipmap = "calculateMipmapLevels" ascii
    condition:
        $pk at 0 and (
            $unloadchunk
            or $settings_tel
            or ($mshta and ($texture_names or $mipmap))
        )
}