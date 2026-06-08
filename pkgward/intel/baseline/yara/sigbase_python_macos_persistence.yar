/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_python_macos_persistence
{
    meta:
        description = "Python agent establishing macOS LaunchAgent persistence"
        severity = "high"
        confidence = "high"
        author = "John Lambert @JohnLaTwC"
        reference = "https://ghostbin.com/paste/mz5nf"
        original_id = "9c69af3c-ee85-58ac-8b78-66760addc117"

    strings:
        $h1 = "#!/usr/bin/env python" ascii
        $s1 = "<plist" ascii
        $s2 = "ProgramArguments" ascii
        $s3 = "Library" ascii
        $interval1 = "StartInterval" ascii
        $interval2 = "RunAtLoad" ascii

    condition:
        $h1 and all of ($s*) and 1 of ($interval*)
}
