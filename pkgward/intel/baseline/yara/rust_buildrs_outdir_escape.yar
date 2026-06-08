rule rust_buildrs_outdir_escape {
    meta:
        description = "build.rs writes to paths outside OUT_DIR"
        severity = "high"
        confidence = "medium"
        category = "installer"
        author = "pkgward"
    strings:
        $w1 = /fs::write\s*\(\s*"\/[^"]+"/
        $w2 = /File::create\s*\(\s*"\/[^"]+"/
        $w3 = "$HOME" ascii
        $w4 = /write\s*\(\s*"\/tmp\//
    condition:
        any of them and filename matches /build\.rs$/i
}
