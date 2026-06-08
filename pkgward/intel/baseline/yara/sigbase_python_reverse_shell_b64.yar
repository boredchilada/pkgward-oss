/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
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
