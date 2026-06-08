rule evasion_media_stego_loader
{
    meta:
        description = "Steganographic media loader: reads audio/image frame bytes, base64/XOR-decodes them, and pipes the result into an interpreter/subprocess (TeamPCP WAV-stego credential harvester). The media-parse + decode + exec chain is the signature, not any one part."
        severity = "high"
        confidence = "high"
        category = "malware"

    strings:
        $media1 = /wave\.open|import\s+wave|readframes/ ascii
        $media2 = /Image\.open|getdata\(\)|tobytes\(\)/ ascii
        $dec1 = "b64decode" ascii
        $dec2 = /\^\s*key|\^=|bytes\(\s*[a-z]\s*\^/ ascii   // XOR decode loop
        $sink1 = /subprocess\.Popen\([^)]*sys\.executable/ ascii
        $sink2 = /sys\.executable[^\n]{0,60}["']-c["']/ ascii
        $sink3 = /\bexec\s*\(/ ascii
        $sink4 = "start_new_session" ascii

    condition:
        (any of ($media*)) and (any of ($dec*)) and (any of ($sink*))
}
