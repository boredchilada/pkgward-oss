rule aes_gcm_hardcoded_eval
{
    meta:
        description = "AES-GCM decryption with hardcoded hex key/IV feeding eval — the stage-1 decryption pattern from TeamPCP .pth campaigns. Legitimate crypto code does not hardcode symmetric keys alongside eval."
        author = "pkgward"
        date = "2026-06-06"
        updated = "2026-06-07"
        // 2026-06-07: require an actual hardcoded hex *literal* ($hex_literal). The
        // rule name claims "hardcoded key" but only checked Buffer.from(x,'hex'),
        // which also matches at-rest token encryption keyed by a runtime random
        // key (createDecipheriv("aes-256-gcm", randomBytes(32), Buffer.from(iv,"hex"))).
        // octocode-mcp 15.0.0 FP: 0 hex literals, key = randomBytes. TeamPCP stage-1
        // hardcodes the key/IV as a hex literal — that literal is the discriminator.
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

        // a hardcoded symmetric key/IV: a quoted hex string literal >= 16 bytes.
        // Random/derived keys (randomBytes/scrypt/pbkdf2) never appear this way.
        $hex_literal = /["'][0-9a-fA-F]{32,}["']/ ascii

        $eval1      = /\beval\s*\(/ ascii
        $eval2      = /\beval\s*\)/ ascii
        $function   = /\bFunction\s*\(/ ascii

    condition:
        filesize > 1KB
        and ($aes_gcm or $aes256_gcm)
        and $decipher
        and $from_hex
        and $hex_literal
        and $auth_tag
        and (1 of ($eval*) or $function)
}
