/*
    Adapted from Neo23x0/signature-base — Detection Rule License (DRL) 1.1
    https://github.com/Neo23x0/signature-base — see NOTICE.
    Per-rule author/reference/original_id preserved in meta.
*/

rule sigbase_reversed_b64_executable
{
    meta:
        description = "Base64-encoded executable with reversed character order (evasion technique)"
        severity = "high"
        confidence = "high"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://github.com/Neo23x0/signature-base"
        original_id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"

    strings:
        $s1 = "AEAAAAEQATpVT" ascii
        $s2 = "AAAAAAAAAAoVT" ascii
        $s3 = "AEAAAAEAAAqVT" ascii
        $s4 = "AEAAAAIAAQpVT" ascii
        $s5 = "AEAAAAMAAQqVT" ascii

        // Reversed base64 of shell strings
        $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
        $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii

    condition:
        1 of them
}
