rule cross_ecosystem_python_in_go
{
    meta:
        description = "Go module shipping Python source with setup.py and a runtime execution framework (pytransform, native extensions). Python inside a Go module is a cross-ecosystem mismatch that warrants investigation."
        author = "pkgward"
        date = "2026-06-06"
        severity = "high"
        confidence = "medium"
        category = "suspicious"
        reference = "quantum-core-engine v3.0.0 — Python + PyArmor inside a Go module"

    strings:
        $setup_py   = "from setuptools import" ascii
        $setup_fn   = "setup(" ascii

        $pyarmor1   = "pyarmor_runtime" ascii
        $pyarmor2   = "__pyarmor__" ascii
        $pyarmor3   = "pytransform" ascii

        $native1    = "_pytransform.dll" ascii
        $native2    = "_pytransform.so" ascii
        $native3    = "_pytransform.dylib" ascii

    condition:
        ($setup_py and $setup_fn)
        and (1 of ($pyarmor*) or 2 of ($native*))
}
