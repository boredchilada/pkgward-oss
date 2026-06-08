rule staged_subprocess_shell
{
    meta:
        description = "Downloads content then runs it via subprocess with shell=True"
        severity = "high"
        confidence = "medium"
        author = "pkgward"

    strings:
        $dl1 = /urllib\.request\.urlopen|requests\.get|httpx\.get|urlopen/ nocase
        $dl2 = /wget|curl\s/ nocase
        $shell = /subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/ ascii
        $decode1 = ".read()" ascii
        $decode2 = ".text" ascii
        $decode3 = ".content" ascii
        $decode4 = ".decode(" ascii

    condition:
        1 of ($dl*) and $shell and 1 of ($decode*)
}
