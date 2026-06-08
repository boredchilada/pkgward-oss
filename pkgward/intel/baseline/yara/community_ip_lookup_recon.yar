/*
    Adapted from Yara-Rules/rules (capabilities.yar) — GNU GPLv2 (author: x0r)
    https://github.com/Yara-Rules/rules — see NOTICE.
    Per-rule author/reference preserved in meta.
*/

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
