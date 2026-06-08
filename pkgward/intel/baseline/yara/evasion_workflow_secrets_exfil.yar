rule evasion_workflow_secrets_exfil
{
    meta:
        description = "GitHub Actions workflow serializes ALL repo secrets and writes/uploads them — secret-exfil-via-CI (IronWorm/Shai-Hulud second path). Legit workflows reference individual secrets, never toJSON(secrets) to an artifact."
        severity = "critical"
        confidence = "high"
        category = "malware"

    strings:
        $all_secrets = "toJSON(secrets)" ascii nocase
        $art = "upload-artifact" ascii nocase
        $post = /curl[^\n]{0,80}(-d|--data|-F)/ ascii nocase
        $redir = /secrets[^\n]{0,40}>[^\n]{0,40}\.(txt|json|env|log)/ ascii nocase
        $on = /on:\s*\[?\s*(push|pull_request)/ ascii nocase

    condition:
        $all_secrets and $on and ($art or $post or $redir)
}
