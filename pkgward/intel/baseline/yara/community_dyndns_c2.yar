/*
    Adapted from Yara-Rules/rules (capabilities.yar) — GNU GPLv2 (author: x0r)
    https://github.com/Yara-Rules/rules — see NOTICE.
    Per-rule author/reference preserved in meta.
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
