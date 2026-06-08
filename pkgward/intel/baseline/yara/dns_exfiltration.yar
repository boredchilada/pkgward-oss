rule dns_exfiltration
{
    meta:
        description = "DNS-based data exfiltration pattern"
        severity = "high"
        confidence = "medium"
        author = "pkgward"

    strings:
        $dns1 = /socket\.getaddrinfo|socket\.gethostbyname/ ascii
        $dns2 = /dns\.resolver|dnspython/ ascii
        $encode1 = /base64\.b64encode|\.encode\(|\.hex\(/ ascii
        $sensitive = /os\.environ|os\.uname|platform\.|getpass|socket\.gethostname/ ascii

    condition:
        1 of ($dns*) and $encode1 and $sensitive
}
