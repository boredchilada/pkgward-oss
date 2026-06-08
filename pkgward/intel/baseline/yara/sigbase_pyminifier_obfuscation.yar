/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_pyminifier_obfuscation
{
    meta:
        description = "Python code obfuscated with pyminifier (zlib + base64 + exec chain)"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2019/08/ESET_Machete.pdf"
        original_id = "d7297e6a-e1c7-57dd-a57f-a3b67face2f3"

    strings:
        $s1 = "exec(zlib.decompress(base64.b64decode(" ascii
        $s2 = "base64" fullword ascii
        $s3 = "zlib" fullword ascii

    condition:
        $s1 and $s2 and $s3
}
