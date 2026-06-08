rule pyarmor_suspicious_deps
{
    meta:
        description = "setup.py that bundles PyArmor's pytransform runtime alongside stealer-associated dependencies (boto3, cryptography, requests, psutil). Legitimate PyArmor usage rarely combines cloud+crypto+system-info deps. Flags for manual review, not auto-verdict."
        author = "pkgward"
        date = "2026-06-06"
        severity = "high"
        confidence = "medium"
        category = "suspicious"
        reference = "quantum-core-engine v3.0.0"

    strings:
        $setup      = "setup(" ascii
        $pytrans    = "pytransform" ascii
        $pkg_data   = "package_data" ascii

        $dep_boto   = "boto3" ascii
        $dep_crypto = "cryptography" ascii
        $dep_req    = /["']requests[=<>~!]/ ascii
        $dep_psutil = "psutil" ascii

    condition:
        filesize < 50KB
        and $setup and $pytrans and $pkg_data
        and (3 of ($dep_*))
}
