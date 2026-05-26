/*
    Community Rules — adapted from Neo23x0/signature-base
    =====================================================
    License: Detection Rule License (DRL) 1.1
    Source:  https://github.com/Neo23x0/signature-base
    Authors: Florian Roth (Nextron Systems), John Lambert, Jeff Beley

    Adapted for PyPI package source scanning:
    - Removed uint32be(0) magic-byte checks (extracted files don't always start with "import")
    - Relaxed filesize limits (packages contain many files of varying sizes)
    - Added severity/confidence meta for scanner integration

    Original rule IDs preserved for traceability.
*/


rule sigbase_python_reverse_shell_b64
{
    meta:
        description = "Python base64-encoded reverse shell with socket/connect/recv indicators"
        severity = "critical"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_python_reverse_shell.yara"
        original_id = "dda831ae-d0ca-5d5a-bdb3-e7c146a770b4"

    strings:
        $h1 = "import base64" ascii
        $s1 = "b64decode" fullword ascii
        $s2 = "lambda" fullword ascii
        $s3 = "version_info" fullword ascii

        // Base64-encoded "socket.SOCK_STREAM"
        $enc_x0 = /(b2NrZXQuU09DS19TVFJFQU|c29ja2V0LlNPQ0tfU1RSRUFN|MAbwBjAGsAZQB0AC4AUwBPAEMASwBfAFMAVABSAEUAQQBNA)/ ascii
        // Base64-encoded ".connect(("
        $enc_x1 = /(5jb25uZWN0KC|Y29ubmVjdCgo|LmNvbm5lY3QoK)/ ascii
        // Base64-encoded "time.sleep"
        $enc_x2 = /(aW1lLnNsZWVw|dGltZS5zbGVlc|RpbWUuc2xlZX)/ ascii
        // Base64-encoded ".recv"
        $enc_x3 = /(5yZWN2|cmVjd|LnJlY3)/ ascii

    condition:
        $h1 and all of ($s*) and 2 of ($enc_x*)
}


rule sigbase_python_pty_backconnect
{
    meta:
        description = "Python PTY reverse-connect shell via dup2 + pty.spawn"
        severity = "critical"
        confidence = "high"
        author = "Jeff Beley"
        reference = "https://github.com/infodox/python-pty-shells"
        original_id = "a9a90d67-774b-5b32-97c0-d7e06763f2e9"

    strings:
        $s1 = "os.dup2(s.fileno()" ascii
        $s2 = "pty.spawn(" ascii
        $s3 = "HISTFILE" ascii
        $s4 = "socket.socket(socket.AF_INET" ascii

    condition:
        3 of them
}


rule sigbase_pyminifier_obfuscation
{
    meta:
        description = "Python code obfuscated with pyminifier (zlib + base64 + exec chain)"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2019/08/ESET_Machete.pdf"
        original_id = "d7297e6a-e1c7-57dd-a57f-a3b67face2f3"

    strings:
        $s1 = "exec(zlib.decompress(base64.b64decode(" ascii
        $s2 = "base64" fullword ascii
        $s3 = "zlib" fullword ascii

    condition:
        $s1 and $s2 and $s3
}


rule sigbase_python_encoded_adware
{
    meta:
        description = "Python payload using base64 import + lambda XOR decoding"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://twitter.com/JohnLaTwC/status/949048002466914304"
        original_id = "7b4b422b-c960-5ab3-a6a7-a30e416efdec"

    strings:
        $r1 = "=__import__(\"base64\").b64decode" ascii
        $s1 = "bytes(map(lambda" ascii
        $s2 = "[1]^" ascii

    condition:
        all of them
}


rule sigbase_python_ssh_backdoor
{
    meta:
        description = "Python SSH backdoor using paramiko"
        severity = "critical"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_backdoor_ssh_python.yar"
        original_id = "eccf705b-b2c3-5af6-ab86-70292089812b"

    strings:
        $s0 = "raw_input(\"Enter command:" ascii
        $s1 = "Failed to load moduli" ascii
        $s2 = "Listen/bind/accept failed" ascii

    condition:
        2 of them
}


rule sigbase_evilosx_backdoor
{
    meta:
        description = "EvilOSX Python macOS backdoor — base64-encoded C2 agent"
        severity = "critical"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://github.com/Marten4n6/EvilOSX"
        original_id = "6940e355-53d2-51e3-afd0-13303a311e9a"

    strings:
        $s0 = "import base64" ascii
        $s1 = "b64decode" fullword ascii
        $x0 = "EvilOSX" fullword ascii
        $x1 = "get_launch_agent_directory" fullword ascii

        // Base64-encoded "EvilOSX"
        $enc_x0 = /(dmlsT1NY|RXZpbE9TW|V2aWxPU1)/ ascii
        // Base64-encoded "get_launch_agent_directory"
        $enc_x1 = /(dldF9sYXVuY2hfYWdlbnRfZGlyZWN0b3J5|Z2V0X2xhdW5jaF9hZ2VudF9kaXJlY3Rvcn|UHJvZ3JhbUFyZ3VtZW50c)/ ascii

    condition:
        $s0 and $s1 and (1 of ($x*) or 1 of ($enc_x*))
}


rule sigbase_python_macos_persistence
{
    meta:
        description = "Python agent establishing macOS LaunchAgent persistence"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://ghostbin.com/paste/mz5nf"
        original_id = "9c69af3c-ee85-58ac-8b78-66760addc117"

    strings:
        $h1 = "#!/usr/bin/env python" ascii
        $s1 = "<plist" ascii
        $s2 = "ProgramArguments" ascii
        $s3 = "Library" ascii
        $interval1 = "StartInterval" ascii
        $interval2 = "RunAtLoad" ascii

    condition:
        $h1 and all of ($s*) and 1 of ($interval*)
}


rule sigbase_double_b64_executable
{
    meta:
        description = "Double base64-encoded executable (PE/ELF stub encoded twice)"
        severity = "critical"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
        original_id = "2e714e91-c7e6-5c6f-930a-270ce452ff0c"

    strings:
        // Double-encoded "This program cannot be run in DOS mode"
        $a1 = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii
        $a2 = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii
        $a3 = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii
        // Double-encoded "This program must be run under Win32"
        $b1 = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii
        $b2 = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii
        $b3 = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii

    condition:
        1 of them
}


rule sigbase_reversed_b64_executable
{
    meta:
        description = "Base64-encoded executable with reversed character order (evasion technique)"
        severity = "high"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base"
        original_id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"

    strings:
        $s1 = "AEAAAAEQATpVT" ascii
        $s2 = "AAAAAAAAAAoVT" ascii
        $s3 = "AEAAAAEAAAqVT" ascii
        $s4 = "AEAAAAIAAQpVT" ascii
        $s5 = "AEAAAAMAAQqVT" ascii

        // Reversed base64 of shell strings
        $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
        $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii

    condition:
        1 of them
}


/*
    Community Rules — adapted from Yara-Rules/rules (capabilities.yar)
    ==================================================================
    License: GNU-GPLv2
    Source:  https://github.com/Yara-Rules/rules
    Author:  x0r

    Language-agnostic C2 infrastructure indicators.
*/


rule community_dyndns_c2
{
    meta:
        description = "Dynamic DNS domain used for C2 — common in malware callbacks"
        severity = "medium"
        confidence = "medium"
        author = "x0r (Yara-Rules community)"
        reference = "https://github.com/Yara-Rules/rules/blob/master/capabilities/capabilities.yar"

    strings:
        $s1 = ".no-ip.org" nocase
        $s2 = ".publicvm.com" nocase
        $s3 = ".linkpc.net" nocase
        $s4 = ".dynu.com" nocase
        $s5 = ".dynu.net" nocase
        $s6 = ".afraid.org" nocase
        $s7 = ".chickenkiller.com" nocase
        $s8 = ".crabdance.com" nocase
        $s9 = ".ignorelist.com" nocase
        $s10 = ".jumpingcrab.com" nocase
        $s11 = ".strangled.com" nocase
        $s12 = ".strangled.net" nocase
        $s13 = ".us.to" nocase
        $s14 = ".info.tm" nocase
        $s15 = ".homenet.org" nocase
        $s16 = ".biz.tm" nocase
        $s17 = ".system-ns.com" nocase
        $s18 = ".adultdns.com" nocase
        $s19 = ".ddns01.com" nocase
        $s20 = ".dnsapi.info" nocase
        $s21 = ".dnsd.info" nocase
        $s22 = ".dnsdynamic.com" nocase
        $s23 = ".dnsdynamic.net" nocase
        $s24 = ".dnsget.org" nocase
        $s25 = ".flashserv.net" nocase
        $s26 = ".ftp21.net" nocase

    condition:
        any of them
}


rule community_ip_lookup_recon
{
    meta:
        description = "External IP lookup service — reconnaissance indicator"
        severity = "low"
        confidence = "medium"
        author = "x0r (Yara-Rules community)"
        reference = "https://github.com/Yara-Rules/rules/blob/master/capabilities/capabilities.yar"

    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
        $n6 = "ipinfo.io" nocase
        $n7 = "ifconfig.me" nocase
        $n8 = "api.ipify.org" nocase
        $n9 = "icanhazip.com" nocase
        $n10 = "ipecho.net" nocase
        $n11 = "ip-api.com" nocase

    condition:
        any of them
}
