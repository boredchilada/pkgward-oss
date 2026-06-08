rule rust_buildrs_env_harvest {
    meta:
        description = "build.rs reads 3+ sensitive environment variables"
        severity = "high"
        confidence = "high"
        category = "installer"
        author = "pkgward"
    strings:
        $e1 = "SSH_AUTH_SOCK" ascii
        $e2 = "AWS_SECRET_ACCESS_KEY" ascii
        $e3 = "AWS_ACCESS_KEY_ID" ascii
        $e4 = "GH_TOKEN" ascii
        $e5 = "GITHUB_TOKEN" ascii
        $e6 = "CARGO_REGISTRY_TOKEN" ascii
        $e7 = "PRIVATE_KEY" ascii
        $e8 = "DATABASE_URL" ascii
    condition:
        3 of ($e*) and filename matches /build\.rs$/i
}
