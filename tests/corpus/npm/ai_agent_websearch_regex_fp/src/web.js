// Reduced faithful repro of the arise-jinwoo-cli / opencode-fork web-search tool.
// The `resultRegex.exec(html)` below is RegExp.prototype.exec (string matching),
// NOT child_process.exec — js_net_to_exec must not read it as command execution.
const WEB_SEARCH_MAX_RESULTS = 10;

export async function handleWebSearch(query) {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  const html = await res.text();

  const results = [];
  const resultRegex = /<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = resultRegex.exec(html)) !== null && results.length < WEB_SEARCH_MAX_RESULTS) {
    results.push({ url: m[1], title: m[2].replace(/<[^>]+>/g, "").trim() });
  }
  return results;
}

export async function handleWebFetch(targetUrl) {
  const res = await fetch(targetUrl, { signal: AbortSignal.timeout(10_000) });
  return (await res.text()).slice(0, 100_000);
}
