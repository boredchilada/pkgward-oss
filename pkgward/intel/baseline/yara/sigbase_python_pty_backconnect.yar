/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_python_pty_backconnect
{
    meta:
        description = "Python PTY reverse-connect shell via dup2 + pty.spawn"
        severity = "critical"
        confidence = "high"
        author = "Jeff Beley"
        reference = "https://github.com/infodox/python-pty-shells"
        original_id = "a9a90d67-774b-5b32-97c0-d7e06763f2e9"

    strings:
        $s1 = "os.dup2(s.fileno()" ascii
        $s2 = "pty.spawn(" ascii
        $s3 = "HISTFILE" ascii
        $s4 = "socket.socket(socket.AF_INET" ascii

    condition:
        3 of them
}
