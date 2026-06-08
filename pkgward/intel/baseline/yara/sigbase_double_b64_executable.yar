/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_double_b64_executable
{
    meta:
        description = "Double base64-encoded executable (PE/ELF stub encoded twice)"
        severity = "critical"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
        original_id = "2e714e91-c7e6-5c6f-930a-270ce452ff0c"

    strings:
        // Double-encoded "This program cannot be run in DOS mode"
        $a1 = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii
        $a2 = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii
        $a3 = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii
        // Double-encoded "This program must be run under Win32"
        $b1 = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii
        $b2 = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii
        $b3 = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii

    condition:
        1 of them
}
