rule rust_buildrs_network_exec {
    meta:
        description = "build.rs contains both network library imports and command execution"
        severity = "critical"
        confidence = "high"
        category = "installer"
        author = "pkgward"
        reference = "crates.io supply-chain attack pattern"
    strings:
        $net1 = "reqwest" ascii
        $net2 = "ureq" ascii
        $net3 = "hyper::Client" ascii
        $net4 = "attohttpc" ascii
        $exec1 = "Command::new" ascii
        $exec2 = "std::process::Command" ascii
    condition:
        any of ($net*) and any of ($exec*) and filename matches /build\.rs$/i
}
