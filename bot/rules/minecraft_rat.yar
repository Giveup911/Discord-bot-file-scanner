/*
    Minecraft RAT/Malware YARA Rules
    Drop new .yar files into this directory — they load automatically on bot startup.
*/

rule Weedhack_Dropper
{
    meta:
        description = "Weedhack/Majanito dropper - EtherHiding C2 resolution"
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
        uint16(0) == 0x504B and any of them
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
        uint16(0) == 0x504B and ($fract1 or ($stage0_class and $stage0_pkg) or $stage1_class or any of ($c2_ip*))
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
        description = "Minecraft mod with suspicious capabilities"
        author = "RatScanner"
        severity = "medium"

    strings:
        $mc_dir = ".minecraft" ascii
        $launcher_accts = "launcher_accounts" ascii
        $access_token = "accessToken" ascii
        $session = "session" ascii
        $exec1 = "Runtime.getRuntime()" ascii
        $exec2 = "ProcessBuilder" ascii
        $webhook = "discord.com/api/webhooks" ascii

    condition:
        ($mc_dir or $launcher_accts) and ($access_token or $session) and ($exec1 or $exec2 or $webhook)
}

rule Ethereum_Contract_C2
{
    meta:
        description = "EtherHiding - Ethereum smart contract used for C2"
        author = "RatScanner"
        severity = "critical"

    strings:
        $known_contract = "0x1280a841Fbc1F883365d3C83122260E0b2995B74" ascii nocase
        $eth_call = "eth_call" ascii
        $jsonrpc = "jsonrpc" ascii
        $eth_method = "0xce6d41de" ascii

    condition:
        $known_contract or ($eth_call and $jsonrpc and $eth_method)
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
