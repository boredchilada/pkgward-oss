rule base64_exec_chain
{
    meta:
        description = "Base64 / marshal decode -> exec/eval chain, the canonical PyPI obfuscation pattern"
        severity = "high"
        confidence = "high"
        author = "pkgward"
        reference = "https://blog.phylum.io/python-malware-imitating-popular-libraries/"

    strings:
        $b64_1 = /base64\.b64decode\s*\(/ ascii
        $b64_2 = /codecs\.decode\(.+rot.?13/ ascii nocase
        $b64_3 = "__import__('base64')" ascii
        $exec1 = "exec(" ascii
        $exec2 = "eval(" ascii
        $marshal = "marshal.loads" ascii

    condition:
        1 of ($b64*) and 1 of ($exec*) or ($marshal and 1 of ($exec*))
}
