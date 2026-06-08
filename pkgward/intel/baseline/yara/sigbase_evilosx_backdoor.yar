/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_evilosx_backdoor
{
    meta:
        description = "EvilOSX Python macOS backdoor — base64-encoded C2 agent"
        severity = "critical"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://github.com/Marten4n6/EvilOSX"
        original_id = "6940e355-53d2-51e3-afd0-13303a311e9a"

    strings:
        $s0 = "import base64" ascii
        $s1 = "b64decode" fullword ascii
        $x0 = "EvilOSX" fullword ascii
        $x1 = "get_launch_agent_directory" fullword ascii

        // Base64-encoded "EvilOSX"
        $enc_x0 = /(dmlsT1NY|RXZpbE9TW|V2aWxPU1)/ ascii
        // Base64-encoded "get_launch_agent_directory"
        $enc_x1 = /(dldF9sYXVuY2hfYWdlbnRfZGlyZWN0b3J5|Z2V0X2xhdW5jaF9hZ2VudF9kaXJlY3Rvcn|UHJvZ3JhbUFyZ3VtZW50c)/ ascii

    condition:
        $s0 and $s1 and (1 of ($x*) or 1 of ($enc_x*))
}
