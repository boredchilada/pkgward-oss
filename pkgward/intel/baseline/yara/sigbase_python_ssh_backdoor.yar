/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_python_ssh_backdoor
{
    meta:
        description = "Python SSH backdoor using paramiko"
        severity = "critical"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base/blob/master/yara/apt_backdoor_ssh_python.yar"
        original_id = "eccf705b-b2c3-5af6-ab86-70292089812b"

    strings:
        $s0 = "raw_input(\"Enter command:" ascii
        $s1 = "Failed to load moduli" ascii
        $s2 = "Listen/bind/accept failed" ascii

    condition:
        2 of them
}
