rule caesar_charcode_eval
{
    meta:
        description = "Charcode array decoded via ROT/Caesar cipher then fed into eval — the _index.js obfuscation pattern from the TeamPCP .pth bun dropper. Legitimate JS does not eval the output of a character-substitution cipher over a numeric array."
        author = "pkgward"
        date = "2026-06-06"
        severity = "critical"
        confidence = "high"
        category = "malware"
        reference = "cmd2func/_index.js ROT-5 + charcode eval"

    strings:
        $charcode   = "fromCharCode" ascii
        $charat     = "charCodeAt" ascii
        $eval       = /\beval\s*\(/ ascii
        $try_catch  = /\}catch\s*\(/ ascii

        $rot_math1  = /\)\s*%\s*26\s*\+/ ascii
        $rot_math2  = /charCodeAt\s*\(\s*0\s*\)\s*-\s*(65|97)/ ascii

        $arr_open   = /\[\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,/ ascii

    condition:
        filesize > 10KB
        and $charcode and $charat and $eval
        and (1 of ($rot_math*))
        and ($arr_open or $try_catch)
}
