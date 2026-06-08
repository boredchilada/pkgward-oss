rule pth_bun_dropper
{
    meta:
        description = "Python .pth startup file that downloads and executes the Bun JS runtime — TeamPCP/Mini Shai-Hulud dropper pattern. .pth files with import+exec are already flagged by pth_exec_injection; this rule catches the specific Bun download variant."
        author = "pkgward"
        date = "2026-06-06"
        severity = "critical"
        confidence = "high"
        category = "malware"
        reference = "TeamPCP / Mini Shai-Hulud campaign, 15 packages, 27 versions"

    strings:
        $pth_exec   = "exec(" ascii
        $pth_import = "import " ascii

        $bun_url1   = "oven-sh/bun/releases" ascii
        $bun_url2   = "bun-v" ascii

        $marker     = ".bun_ran" ascii
        $index_js   = "_index.js" ascii

    condition:
        filesize < 5KB
        and $pth_exec and $pth_import
        and (1 of ($bun_url*))
        and ($marker or $index_js)
}
