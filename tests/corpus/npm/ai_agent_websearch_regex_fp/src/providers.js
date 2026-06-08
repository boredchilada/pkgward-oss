// LLM provider endpoints the user configures the agent to talk to. These are
// first-party API hosts, not exfil sinks — iocs.url_suspicious must be
// de-escalated for them (Tier-2 LLM-endpoint allowlist).
export const PROVIDERS = {
  opencode: "https://opencode.ai/zen/v1",
  nvidia: "https://integrate.api.nvidia.com/v1",
  groq: "https://api.groq.com/openai/v1",
  xai: "https://api.x.ai/v1",
  openai: "https://api.openai.com/v1",
  anthropic: "https://api.anthropic.com/v1",
};

export async function chat(provider, apiKey, body) {
  // API key -> the provider's own endpoint as a Bearer token: authentication,
  // not credential exfiltration (the env_to_net false positive).
  return fetch(`${provider.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
}
