// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package honeytokens is the single source of truth for the decoy credentials
// planted in every detonation sandbox. A large, realistic spread of secrets —
// cloud, AI/LLM, source-control, registries, payments, messaging, databases,
// crypto wallets — is seeded into the guest environment and home directory so an
// environment-aware ("only steal when there's loot") worm actually runs its
// harvest + exfil, which Tetragon can then observe. The per-token Label lets us
// report *which* secrets a worm went after — its shopping list.
//
// Values are GENERATED AT RUNTIME (crypto/rand), once per process, with realistic
// provider prefixes and shapes (correct `ghp_`/`sk_live_`/`AKIA…` forms, no
// "decoy"/"test"/"fake" tell of any kind). There is deliberately NO literal secret
// in this source: the public repo ships the planting mechanism, not a fixed loot
// list that an evasion-aware worm could fetch from the repo and skip. Each
// deployment's decoys are therefore unique and unguessable. The in-memory map is
// the single source of truth — the `dyn_honeytoken_exfil` canary rule matches
// whatever was generated, wherever it surfaces (an exec arg, a written file, a DNS
// label). Each value is long, unique, and random, so it never collides with real
// install traffic.
package honeytokens

import (
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	b62   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	lo36  = "abcdefghijklmnopqrstuvwxyz0123456789"
	up36  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hexlo = "0123456789abcdef"
	digit = "0123456789"
)

// rnd returns n characters drawn uniformly-ish from charset using crypto/rand.
// Modulo bias is irrelevant for decoy material.
func rnd(charset string, n int) string {
	raw := make([]byte, n)
	if _, err := cryptorand.Read(raw); err != nil {
		// crypto/rand should never fail on Linux; degrade to a non-secret
		// deterministic fill rather than panic at startup.
		for i := range raw {
			raw[i] = byte(i*7 + 13)
		}
	}
	out := make([]byte, n)
	for i, c := range raw {
		out[i] = charset[int(c)%len(charset)]
	}
	return string(out)
}

// secretValues maps a short label -> the generated decoy secret. Every value here
// is a canary: if it ever shows up in traced activity, a worm harvested + staged it.
var secretValues = genSecretValues()

func genSecretValues() map[string]string {
	return map[string]string{
		// --- Cloud ---
		"aws_access_key_id":   "AKIA" + rnd(up36, 16),
		"aws_secret":          rnd(b62, 40),
		"aws_session_token":   "FwoGZXIvYXdzE" + rnd(b62, 64),
		"gcp_api_key":         "AIzaSy" + rnd(b62, 33),
		"azure_client_secret": rnd(b62, 3) + "8Q~" + rnd(b62, 34),
		"digitalocean_token":  "dop_v1_" + rnd(hexlo, 64),
		"cloudflare_token":    rnd(b62, 40),
		// --- AI / LLM ---
		"openai_key":      "sk-proj-" + rnd(b62, 48),
		"anthropic_key":   "sk-ant-api03-" + rnd(b62, 93) + "AA",
		"gemini_key":      "AIzaSy" + rnd(b62, 33),
		"huggingface":     "hf_" + rnd(b62, 34),
		"groq_key":        "gsk_" + rnd(b62, 52),
		"openrouter_key":  "sk-or-v1-" + rnd(hexlo, 64),
		"replicate_token": "r8_" + rnd(b62, 37),
		"perplexity_key":  "pplx-" + rnd(b62, 48),
		"mistral_key":     rnd(b62, 32),
		"cohere_key":      rnd(b62, 40),
		"xai_key":         "xai-" + rnd(b62, 80),
		// --- Source control / package registries ---
		"github_pat":    "ghp_" + rnd(b62, 36),
		"github_pat_fg": "github_pat_" + rnd(b62, 22) + "_" + rnd(b62, 59),
		"gitlab_token":  "glpat-" + rnd(b62, 20),
		"npm_token":     "npm_" + rnd(b62, 36),
		"pypi_token":    "pypi-" + rnd(b62, 84),
		"cargo_token":   "cio" + rnd(b62, 32),
		// --- Payments / SaaS ---
		"stripe_key":   "sk_live_" + rnd(b62, 24),
		"sendgrid_key": "SG." + rnd(b62, 22) + "." + rnd(b62, 43),
		"twilio_token": rnd(hexlo, 32),
		// --- Messaging / webhooks ---
		"slack_bot":       "xoxb-" + rnd(digit, 10) + "-" + rnd(digit, 10) + "-" + rnd(b62, 24),
		"slack_webhook":   "https://hooks.slack.com/services/T" + rnd(up36, 10) + "/B" + rnd(up36, 10) + "/" + rnd(b62, 24),
		"discord_token":   rnd(b62, 24) + "." + rnd(b62, 6) + "." + rnd(b62, 38),
		"discord_webhook": "https://discord.com/api/webhooks/" + rnd(digit, 19) + "/" + rnd(b62, 68),
		"telegram_token":  rnd(digit, 10) + ":AA" + rnd(b62, 35),
		// --- Databases / infra ---
		"database_url":  "postgres://app_admin:" + rnd(b62, 20) + "@prod-db.cluster-c" + rnd(lo36, 9) + ".us-east-1.rds.amazonaws.com:5432/appdb",
		"redis_url":     "rediss://default:" + rnd(b62, 20) + "@prod-cache." + rnd(lo36, 6) + ".ng.0001.use1.cache.amazonaws.com:6379",
		"db_password":   rnd(b62, 24),
		"vercel_token":  rnd(b62, 24),
		"netlify_token": "nfp_" + rnd(b62, 40),
		// --- Crypto wallet ---
		"eth_private_key": "0x" + rnd(hexlo, 64),
		"solana_key":      solanaArray(),
		"wallet_mnemonic": mnemonic(12),
	}
}

// Non-canary structured plants generated once per process (kept out of
// secretValues so the canary set / matcher semantics are unchanged). These carry
// the same realism but never need value-matching.
var (
	sshRSABody     = wrapPEM(rnd(b62, 380))
	sshEd25519Body = wrapPEM(rnd(b62, 120))
	dockerHubAuth  = base64ish("ci-deploy:dckr_pat_" + rnd(b62, 24))
	gcloudRefresh  = "1//0" + rnd(b62, 60)
)

// solanaArray returns a 64-byte secret key as the JSON int array a real
// ~/.config/solana/id.json carries.
func solanaArray() string {
	raw := make([]byte, 64)
	_, _ = cryptorand.Read(raw)
	parts := make([]string, 64)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%d", b)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// bip39ish is a clean word pool (no self-identifying tells) for a realistic
// 12-word wallet mnemonic. It need not be the full BIP-39 list — only look like one.
var bip39ish = []string{
	"abandon", "ability", "able", "absorb", "abstract", "access", "acid", "across",
	"action", "actor", "adapt", "adjust", "admit", "adopt", "advance", "advice",
	"aerobic", "afford", "agent", "agree", "ahead", "aim", "alarm", "album",
	"alert", "alien", "alley", "allow", "almost", "alone", "alpha", "alter",
	"always", "amateur", "amazing", "amount", "amused", "anchor", "ancient", "angle",
	"animal", "ankle", "announce", "annual", "answer", "antenna", "antique", "anxiety",
	"apart", "apology", "appear", "apple", "april", "arch", "arctic", "arena",
	"argue", "armor", "army", "around", "arrange", "arrive", "arrow", "artist",
	"artwork", "aspect", "asset", "assist", "assume", "athlete", "atom", "attack",
	"attend", "attract", "auction", "audit", "august", "author", "auto", "autumn",
	"average", "avoid", "awake", "aware", "awesome", "awkward", "axis", "velvet",
	"venture", "verb", "verify", "vessel", "vintage", "violin", "virtual", "vivid",
}

func mnemonic(n int) string {
	idx := make([]byte, n)
	_, _ = cryptorand.Read(idx)
	words := make([]string, n)
	for i := range words {
		words[i] = bip39ish[int(idx[i])%len(bip39ish)]
	}
	return strings.Join(words, " ")
}

// wrapPEM line-wraps a base64-ish body at 70 columns for a PEM block.
func wrapPEM(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 70 {
		end := i + 70
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// envPlants maps a real env-var name to the secret label it carries. Multiple
// env names can share one secret (GITHUB_TOKEN / GH_TOKEN, NPM_TOKEN / NODE_AUTH_TOKEN).
var envPlants = []struct{ Key, Label string }{
	{"AWS_ACCESS_KEY_ID", "aws_access_key_id"},
	{"AWS_SECRET_ACCESS_KEY", "aws_secret"},
	{"AWS_SESSION_TOKEN", "aws_session_token"},
	{"GOOGLE_API_KEY", "gcp_api_key"},
	{"AZURE_CLIENT_SECRET", "azure_client_secret"},
	{"DIGITALOCEAN_TOKEN", "digitalocean_token"},
	{"CLOUDFLARE_API_TOKEN", "cloudflare_token"},
	{"OPENAI_API_KEY", "openai_key"},
	{"ANTHROPIC_API_KEY", "anthropic_key"},
	{"GEMINI_API_KEY", "gemini_key"},
	{"HF_TOKEN", "huggingface"},
	{"HUGGINGFACE_TOKEN", "huggingface"},
	{"GROQ_API_KEY", "groq_key"},
	{"OPENROUTER_API_KEY", "openrouter_key"},
	{"REPLICATE_API_TOKEN", "replicate_token"},
	{"PERPLEXITY_API_KEY", "perplexity_key"},
	{"MISTRAL_API_KEY", "mistral_key"},
	{"COHERE_API_KEY", "cohere_key"},
	{"XAI_API_KEY", "xai_key"},
	{"GITHUB_TOKEN", "github_pat"},
	{"GH_TOKEN", "github_pat"},
	{"GITLAB_TOKEN", "gitlab_token"},
	{"NPM_TOKEN", "npm_token"},
	{"NODE_AUTH_TOKEN", "npm_token"},
	{"CARGO_REGISTRY_TOKEN", "cargo_token"},
	{"STRIPE_SECRET_KEY", "stripe_key"},
	{"STRIPE_API_KEY", "stripe_key"},
	{"SENDGRID_API_KEY", "sendgrid_key"},
	{"TWILIO_AUTH_TOKEN", "twilio_token"},
	{"SLACK_TOKEN", "slack_bot"},
	{"SLACK_BOT_TOKEN", "slack_bot"},
	{"SLACK_WEBHOOK_URL", "slack_webhook"},
	{"DISCORD_TOKEN", "discord_token"},
	{"DISCORD_BOT_TOKEN", "discord_token"},
	{"DISCORD_WEBHOOK_URL", "discord_webhook"},
	{"TELEGRAM_BOT_TOKEN", "telegram_token"},
	{"DATABASE_URL", "database_url"},
	{"REDIS_URL", "redis_url"},
	{"DB_PASSWORD", "db_password"},
	{"VERCEL_TOKEN", "vercel_token"},
	{"NETLIFY_AUTH_TOKEN", "netlify_token"},
	{"ETH_PRIVATE_KEY", "eth_private_key"},
}

// envMarkers plant non-secret context that makes a CI-gated payload fire.
var envMarkers = []struct{ Key, Value string }{
	{"CI", "true"},
	{"GITHUB_ACTIONS", "true"},
	{"GITHUB_REPOSITORY", "acme-corp/internal-platform"},
	{"GITHUB_RUN_ID", "10482637195"},
}

func v(label string) string { return secretValues[label] }

// filePlant is a decoy file written into the guest home before the package runs.
type filePlant struct {
	Path    string // relative to $HOME unless absolute
	Content string
	Label   string // primary secret it carries (for read-attribution context)
}

func filePlants() []filePlant {
	return []filePlant{
		{".npmrc", "//registry.npmjs.org/:_authToken=" + v("npm_token") + "\n//npm.pkg.github.com/:_authToken=" + v("github_pat") + "\n", "npm_token"},
		{".aws/credentials", "[default]\naws_access_key_id=" + v("aws_access_key_id") + "\naws_secret_access_key=" + v("aws_secret") + "\naws_session_token=" + v("aws_session_token") + "\n", "aws_secret"},
		{".aws/config", "[default]\nregion=us-east-1\noutput=json\n", "aws_config"},
		{".pypirc", "[pypi]\nusername=__token__\npassword=" + v("pypi_token") + "\n", "pypi_token"},
		{".config/gh/hosts.yml", "github.com:\n    oauth_token: " + v("github_pat") + "\n    user: ci-deploy-bot\n    git_protocol: https\n", "github_pat"},
		{".git-credentials", "https://x-access-token:" + v("github_pat") + "@github.com\nhttps://oauth2:" + v("gitlab_token") + "@gitlab.com\n", "github_pat"},
		{".netrc", "machine github.com login ci-deploy-bot password " + v("github_pat") + "\nmachine api.openai.com login apikey password " + v("openai_key") + "\n", "github_pat"},
		{".docker/config.json", `{"auths":{"https://index.docker.io/v1/":{"auth":"` + dockerHubAuth + `"},"https://ghcr.io":{"auth":"` + base64ish("ci:"+v("github_pat")) + `"}}}` + "\n", "docker_config"},
		{".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sshRSABody + "\n-----END OPENSSH PRIVATE KEY-----\n", "ssh_key"},
		{".ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sshEd25519Body + "\n-----END OPENSSH PRIVATE KEY-----\n", "ssh_key"},
		{".config/gcloud/application_default_credentials.json", `{"client_id":"764086051850-abc.apps.googleusercontent.com","client_secret":"` + v("gcp_api_key") + `","refresh_token":"` + gcloudRefresh + `","type":"authorized_user"}` + "\n", "gcp_adc"},
		{".kube/config", "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://k8s-prod.internal:6443\n  name: prod\nusers:\n- name: admin\n  user:\n    token: " + v("digitalocean_token") + "\n", "kube_config"},
		{".cargo/credentials.toml", "[registry]\ntoken = \"" + v("cargo_token") + "\"\n", "cargo_token"},
		{".config/solana/id.json", v("solana_key") + "\n", "solana_key"},
		{".ethereum/keystore/UTC--2024-01-15T00-00-00.000Z--a1b2c3", `{"address":"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678","crypto":{"ciphertext":"` + v("eth_private_key")[2:] + `"},"version":3}` + "\n", "eth_keystore"},
		{".env", strings.Join([]string{
			"OPENAI_API_KEY=" + v("openai_key"),
			"ANTHROPIC_API_KEY=" + v("anthropic_key"),
			"STRIPE_SECRET_KEY=" + v("stripe_key"),
			"DATABASE_URL=" + v("database_url"),
			"AWS_SECRET_ACCESS_KEY=" + v("aws_secret"),
			"GITHUB_TOKEN=" + v("github_pat"),
			"SENDGRID_API_KEY=" + v("sendgrid_key"),
			"WALLET_MNEMONIC=" + v("wallet_mnemonic"),
		}, "\n") + "\n", "dotenv"},
	}
}

// base64ish returns a stable base64-looking blob for a docker auth field without
// pulling in encoding/base64 churn — content only needs to look like a cred.
func base64ish(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i, c := range s {
		b.WriteByte(alpha[(int(c)+i*7)%len(alpha)])
	}
	return b.String()
}

// EnvArgs returns `-e KEY=VALUE` docker args planting every decoy secret + marker
// in the guest environment.
func EnvArgs() []string {
	args := make([]string, 0, (len(envPlants)+len(envMarkers))*2)
	for _, p := range envPlants {
		args = append(args, "-e", p.Key+"="+v(p.Label))
	}
	for _, m := range envMarkers {
		args = append(args, "-e", m.Key+"="+m.Value)
	}
	return args
}

// MaterializeHome writes the decoy files under root ONCE on the host. The same
// shared tree is reused across every detonation (the decoys are fixed for the life
// of the process), so it is idempotent — call it once at startup. Files are written
// 0600 so a read-detection of them during install/import is unambiguous. Crucially
// nothing is written *inside* the sandbox, so no decoy value ever appears in a guest
// exec argv (which would otherwise make the value-canary match our own seeding).
func MaterializeHome(root string) error {
	for _, f := range filePlants() {
		p := filepath.Join(root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(f.Content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// FileMounts returns the `-v host:container:ro` docker args that bind-mount each
// decoy file from the shared host tree (root) to its real location in the guest
// home, plus the project-local .env at workDir. Mounting individual files (not
// parent dirs) so a tool that legitimately writes elsewhere in ~/.cargo, ~/.config,
// etc. isn't blocked by a read-only dir mount.
func FileMounts(root, workDir string) []string {
	var args []string
	for _, f := range filePlants() {
		host := filepath.Join(root, filepath.FromSlash(f.Path))
		args = append(args, "-v", host+":/root/"+f.Path+":ro")
	}
	// $PWD-scanning worms: also expose .env in the working dir.
	if workDir != "" {
		args = append(args, "-v", filepath.Join(root, ".env")+":"+strings.TrimRight(workDir, "/")+"/.env:ro")
	}
	return args
}

// Canary is one decoy secret value and the label naming what kind it is.
type Canary struct {
	Value string
	Label string
}

// Canaries returns every decoy secret value + label, longest-value-first so the
// matcher reports the most specific hit. Values shorter than 12 chars are skipped
// (too short to be a low-FP tripwire).
func Canaries() []Canary {
	out := make([]Canary, 0, len(secretValues))
	for label, val := range secretValues {
		if len(val) < 12 {
			continue
		}
		out = append(out, Canary{Value: val, Label: label})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Value) > len(out[j].Value) })
	return out
}

// Describe is a human summary used in evidence strings.
func Describe(c Canary) string {
	return fmt.Sprintf("%s (decoy %s)", c.Label, c.Value[:min(8, len(c.Value))]+"…")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
