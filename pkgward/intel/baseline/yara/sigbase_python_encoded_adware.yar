/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_python_encoded_adware
{
    meta:
        description = "Python payload using base64 import + lambda XOR decoding"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://twitter.com/JohnLaTwC/status/949048002466914304"
        original_id = "7b4b422b-c960-5ab3-a6a7-a30e416efdec"

    strings:
        $r1 = "=__import__(\"base64\").b64decode" ascii
        $s1 = "bytes(map(lambda" ascii
        $s2 = "[1]^" ascii

    condition:
        all of them
}
