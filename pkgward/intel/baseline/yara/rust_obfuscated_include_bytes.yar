rule rust_obfuscated_include_bytes {
    meta:
        description = "include_bytes! of executable or script file"
        severity = "high"
        confidence = "medium"
        category = "installer"
        author = "pkgward"
    strings:
        $i1 = /include_bytes!\s*\(\s*"[^"]+\.exe"/
        $i2 = /include_bytes!\s*\(\s*"[^"]+\.dll"/
        $i3 = /include_bytes!\s*\(\s*"[^"]+\.so"/
        $i4 = /include_bytes!\s*\(\s*"[^"]+\.sh"/
        $i5 = /include_bytes!\s*\(\s*"[^"]+\.ps1"/
    condition:
        any of them
}
