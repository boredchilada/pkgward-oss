rule ssh_key_exfiltration
{
    meta:
        description = "Reading SSH private keys and exfiltrating them"
        severity = "critical"
        confidence = "high"
        author = "pkgward"

    strings:
        $ssh_path1 = ".ssh/id_rsa" ascii nocase
        $ssh_path2 = ".ssh/id_ed25519" ascii nocase
        $ssh_path3 = ".ssh/id_ecdsa" ascii nocase
        $ssh_path4 = ".ssh/config" ascii nocase
        $read1 = /open\(.+\.ssh/ ascii
        $read2 = /read_bytes|read_text|read\(\)/ ascii
        $exfil1 = /requests\.post|httpx\.post|urllib/ ascii
        $exfil2 = "webhook" ascii nocase
        $exfil3 = /socket\.connect|urlopen/ ascii

    condition:
        2 of ($ssh_path*) and 1 of ($read*) and 1 of ($exfil*)
}
