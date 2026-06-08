rule rust_typosquat_indicator {
    meta:
        description = "Crate name resembles known popular crate typosquat"
        severity = "medium"
        confidence = "low"
        category = "installer"
        author = "pkgward"
    strings:
        $t1 = "serde_jsom" ascii nocase
        $t2 = "serdee" ascii nocase
        $t3 = "tokiio" ascii nocase
        $t4 = "reqwests" ascii nocase
        $t5 = "clappp" ascii nocase
    condition:
        any of them
}
