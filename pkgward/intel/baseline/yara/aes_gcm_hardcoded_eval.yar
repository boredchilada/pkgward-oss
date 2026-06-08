rule aes_gcm_hardcoded_eval
{
    meta:
        description = "AES-GCM decryption with hardcoded hex key/IV feeding eval — the stage-1 decryption pattern from TeamPCP .pth campaigns. Legitimate crypto code does not hardcode symmetric keys alongside eval."
        author = "pkgward"
        date = "2026-06-06"
        severity = "critical"
        confidence = "high"
        category = "malware"
        reference = "cmd2func decoded_stage1.js AES-128-GCM + hardcoded keys"

    strings:
        $aes_gcm    = "aes-128-gcm" ascii nocase
        $aes256_gcm = "aes-256-gcm" ascii nocase

        $decipher   = "createDecipheriv" ascii
        $from_hex   = /Buffer\.from\s*\([^)]{1,64},\s*["']hex["']\s*\)/ ascii
        $auth_tag   = "setAuthTag" ascii

        $eval1      = /\beval\s*\(/ ascii
        $eval2      = /\beval\s*\)/ ascii
        $function   = /\bFunction\s*\(/ ascii

    condition:
        filesize > 1KB
        and ($aes_gcm or $aes256_gcm)
        and $decipher
        and $from_hex
        and $auth_tag
        and (1 of ($eval*) or $function)
}
