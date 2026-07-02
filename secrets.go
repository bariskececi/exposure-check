package main

import (
	"regexp"
	"strings"
)

type secretRule struct {
	name string
	re   *regexp.Regexp
	sev  Severity
}

// Well-known credential patterns. Detection only — values are redacted in output.
var secretRules = []secretRule{
	{"AWS Access Key ID", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), CRITICAL},
	{"AWS Secret Access Key", regexp.MustCompile(`(?i)aws.{0,20}?['"][0-9a-zA-Z/+]{40}['"]`), CRITICAL},
	{"GitHub Token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b`), CRITICAL},
	{"GitHub Fine-grained Token", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{60,}\b`), CRITICAL},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), HIGH},
	{"Slack Token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), HIGH},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), MEDIUM},
	{"Stripe Secret Key", regexp.MustCompile(`\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b`), CRITICAL},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), CRITICAL},
	{"Twilio API Key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), HIGH},
	{"SendGrid API Key", regexp.MustCompile(`\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`), HIGH},
	{"Slack/Generic Bearer", regexp.MustCompile(`(?i)bearer\s+[0-9a-zA-Z._\-]{20,}`), LOW},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), MEDIUM},
	{"Generic API Key Assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][0-9a-zA-Z._\-]{12,}['"]`), MEDIUM},
	{"NPM Token", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`), HIGH},

	// Cloud provider credentials
	{"Azure Storage Account Key", regexp.MustCompile(`(?i)AccountKey\s*=\s*[0-9a-zA-Z/+=]{44,}`), CRITICAL},
	{"Azure Client Secret", regexp.MustCompile(`(?i)(client.?secret|azure.?secret)\s*[:=]\s*['"][0-9a-zA-Z._~\-]{30,}['"]`), CRITICAL},
	{"GCP Service Account Key", regexp.MustCompile(`"private_key_id"\s*:\s*"[0-9a-f]{40}"`), CRITICAL},
	{"GCP OAuth Token", regexp.MustCompile(`\bya29\.[0-9A-Za-z_\-]{50,}`), HIGH},
	{"DigitalOcean Token", regexp.MustCompile(`\b(dop|doo|dor)_v1_[0-9a-f]{64}\b`), CRITICAL},
	{"Heroku API Key", regexp.MustCompile(`(?i)heroku.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), HIGH},

	// SaaS / vendor tokens
	{"Shopify Token", regexp.MustCompile(`\bshp(at|ca|pa|ss)_[0-9a-fA-F]{32,}\b`), HIGH},
	{"Mailgun API Key", regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`), HIGH},
	{"Postmark Server Token", regexp.MustCompile(`(?i)postmark.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), HIGH},
	{"Telegram Bot Token", regexp.MustCompile(`\b[0-9]{8,10}:[0-9A-Za-z_-]{35}\b`), HIGH},
	{"Discord Bot Token", regexp.MustCompile(`(?i)(discord|bot).{0,20}?[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}`), HIGH},
	{"PyPI API Token", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`), HIGH},

	// Database connection strings
	{"MongoDB Connection String", regexp.MustCompile(`mongodb(\+srv)?://[^\s'"]+:[^\s'"]+@[^\s'"]+`), CRITICAL},
	{"PostgreSQL Connection String", regexp.MustCompile(`postgres(ql)?://[^\s'"]+:[^\s'"]+@[^\s'"]+`), CRITICAL},
	{"MySQL Connection String", regexp.MustCompile(`mysql://[^\s'"]+:[^\s'"]+@[^\s'"]+`), CRITICAL},
	{"Redis Connection String", regexp.MustCompile(`redis(s)?://[^\s'"]+:[^\s'"]+@[^\s'"]+`), HIGH},
	{"JDBC Connection String", regexp.MustCompile(`jdbc:[a-z]+://[^\s'"]*password\s*=\s*[^\s&'"]+`), HIGH},

	// Docker / container
	{"Docker Registry Auth", regexp.MustCompile(`(?i)"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"`), MEDIUM},
}

// scannableExt limits secret scanning to likely text/config files.
var scannableExt = map[string]bool{
	".env": true, ".yml": true, ".yaml": true, ".json": true, ".txt": true, ".ini": true,
	".cfg": true, ".conf": true, ".config": true, ".properties": true, ".xml": true,
	".pem": true, ".key": true, ".ppk": true, ".js": true, ".ts": true, ".py": true,
	".go": true, ".rb": true, ".php": true, ".java": true, ".sh": true, ".ps1": true,
	".tf": true, ".tfvars": true, ".sql": true, ".md": true, ".toml": true, "": true,
}

var skipPathParts = []string{"node_modules/", "vendor/", "/dist/", "/build/", ".min.", "test/fixtures", "testdata/"}

func shouldSkipPath(p string) bool {
	lp := strings.ToLower(p)
	for _, s := range skipPathParts {
		if strings.Contains(lp, s) {
			return true
		}
	}
	return false
}

func extOf(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 || strings.Contains(path[i:], "/") {
		return ""
	}
	return strings.ToLower(path[i:])
}

// redact masks a secret so the tool never re-publishes it.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// scanContent runs all rules over file bytes and returns findings.
func scanContent(repoFull, path string, data []byte) []Finding {
	var out []Finding
	text := string(data)
	if strings.Contains(text, "\x00") { // binary
		return out
	}
	lines := strings.Split(text, "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		if len(line) > 500 {
			line = line[:500]
		}
		for _, r := range secretRules {
			if m := r.re.FindString(line); m != "" {
				key := r.name + "|" + path
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Finding{
					Severity: r.sev, Sev: r.sev.String(), Category: "secret",
					Rule:  "secret." + slug(r.name),
					Title: "Possible " + r.name + " in public repository",
					Location: repoFull + "/" + path + ":" + itoa(i+1),
					Detail:   "Matched value (redacted): " + redact(m),
					Remedy:   "Treat as compromised: rotate the credential immediately, purge it from git history, and add it to a secret scanner in CI.",
				})
			}
		}
	}
	return out
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if c == ' ' || c == '-' || c == '_' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
