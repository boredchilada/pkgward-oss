rule rust_encoded_payload_buildrs {
    meta:
        description = "Large base64 or hex-encoded payload in build.rs"
        severity = "medium"
        confidence = "medium"
        category = "installer"
        author = "pkgward"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
        $hex = /(\\x[0-9a-fA-F]{2}){50,}/
    condition:
        any of them and filename matches /build\.rs$/i
}
