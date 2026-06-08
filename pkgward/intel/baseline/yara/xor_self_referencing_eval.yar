rule xor_self_referencing_eval
{
    meta:
        description = "XOR decryption key derived from a function's own toString() representation feeding eval — the turbo-btns self-referencing obfuscation. This anti-tamper + obfuscation combo does not appear in legitimate code."
        author = "pkgward"
        date = "2026-06-06"
        severity = "critical"
        confidence = "high"
        category = "malware"
        reference = "turbo-btns 1.0.0 gifted.js self-referencing XOR + eval"

    strings:
        $tostring   = ".toString()" ascii
        $eval       = /\beval\s*\(/ ascii
        $charcode   = "charCodeAt" ascii
        $fromchar   = "fromCharCode" ascii
        $tamper     = "tampered" ascii nocase
        $decode_uri = "decodeURI" ascii

    condition:
        filesize > 5KB
        and $tostring and $eval
        and $charcode and $fromchar
        and $decode_uri
        and $tamper
}
