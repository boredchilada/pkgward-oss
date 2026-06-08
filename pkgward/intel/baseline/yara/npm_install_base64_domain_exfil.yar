rule npm_install_base64_domain_exfil
{
    meta:
        description = "npm install hook that base64-decodes a domain and sends recon data — the fhirproxy-utils exfil pattern. Legitimate packages do not hide their install-time network destinations behind base64 encoding."
        author = "pkgward"
        date = "2026-06-06"
        severity = "critical"
        confidence = "high"
        category = "malware"
        reference = "fhirproxy-utils 1.0.8, Cloudflare Worker C2"

    strings:
        $b64_decode1 = "atob(" ascii
        $b64_decode2 = /Buffer\.from\s*\([^)]+,\s*["']base64["']\s*\)/ ascii
        $b64_decode3 = "base64" ascii

        $net1       = /https?:\/\// ascii
        $net2       = "fetch(" ascii
        $net3       = /require\s*\(\s*["']https?["']\s*\)/ ascii
        $net4       = "XMLHttpRequest" ascii

        $recon1     = "hostname" ascii
        $recon2     = "os.platform" ascii
        $recon3     = "os.homedir" ascii
        $recon4     = "process.env" ascii
        $recon5     = "whoami" ascii
        $recon6     = "os.userInfo" ascii

        $cloud_meta = "169.254.169.254" ascii

    condition:
        filesize < 100KB
        and (1 of ($b64_decode*))
        and (1 of ($net*))
        and ($cloud_meta or 3 of ($recon*))
}
