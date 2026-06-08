rule evasion_anti_ci_payload_gate
{
    meta:
        description = "Payload gated to run ONLY outside CI/analysis (if !CI / not GITHUB_ACTIONS) and chained to a network/exec/eval sink — sandbox-evasion gating. Distinguished from the common benign `if(CI)` skip by the NEGATED check around a live payload."
        severity = "high"
        confidence = "medium"
        category = "malware"

    strings:
        // negated CI/analysis gate (run payload when NOT in CI)
        $neg_js  = /![\s(]*process\.env\.(CI|GITHUB_ACTIONS|CONTINUOUS_INTEGRATION)\b/ ascii
        $neg_py1 = /not\s+os\.(environ\.get|getenv)\(\s*['"](CI|GITHUB_ACTIONS|CONTINUOUS_INTEGRATION)/ ascii
        $neg_py2 = /os\.(environ\.get|getenv)\(\s*['"](CI|GITHUB_ACTIONS)['"][^)]*\)\s*(is\s+None|==\s*None|!=\s*['"]?(true|1))/ ascii
        // a live payload sink in the same file
        $sink1 = "child_process" ascii
        $sink2 = /\beval\s*\(/ ascii
        $sink3 = /subprocess\.(Popen|run|call|check_output)/ ascii
        $sink4 = /(https?:\/\/|fetch\s*\(|requests\.(get|post)|urllib)/ ascii
        $sink5 = "start_new_session" ascii

    condition:
        (any of ($neg_*)) and (2 of ($sink*))
}
