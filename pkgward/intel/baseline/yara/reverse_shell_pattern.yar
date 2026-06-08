rule reverse_shell_pattern
{
    meta:
        description = "Reverse shell indicators in Python code"
        severity = "critical"
        confidence = "high"
        author = "pkgward"

    strings:
        // Python anchor: the socket *constructor* call. JS bundles use net.Socket()/
        // io.connect(), not "socket.socket(", so this no longer matches minified JS
        // where ".connect(" + "/bin/sh" appear incidentally (the @capgo/cli FP).
        $sock = "socket.socket(" ascii
        $connect = ".connect(" ascii
        // The shell path must be QUOTE-ADJACENT — i.e. passed as a subprocess/pty
        // argument ("/bin/sh", '/bin/bash') the way a real reverse shell invokes it.
        // This excludes a "#!/bin/bash" shebang written into a generated launcher and
        // /bin/sh appearing inside a longer string/comment (the @innvisor/conny-ai FP:
        // socket.connect(("8.8.8.8",80)) local-IP detection + nvidia-smi subprocess +
        // a "#!/bin/bash\n..." run.sh template, none of them an actual reverse shell).
        $shell = /["']\/bin\/(sh|bash)|cmd\.exe/ ascii nocase
        $dup2 = "dup2(" ascii
        $fileno = "fileno()" ascii
        $pty = "pty.spawn" ascii
        $subproc = /subprocess\.(call|Popen|run)\s*\(/ ascii

    condition:
        $sock and $connect and
        (
            ($dup2 and $fileno) or       // os.dup2(s.fileno(), 0/1/2) — classic rev shell
            $pty or                      // pty.spawn("/bin/sh")
            ($subproc and $shell)        // subprocess.call(["/bin/sh", "-i"])
        )
}
