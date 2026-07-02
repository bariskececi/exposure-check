package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestWorkflowAnalysis(t *testing.T) {
	wf := `
name: ci
on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: some/action@main
`
	fs := analyzeWorkflow("acme/app", ".github/workflows/ci.yml", wf)
	for _, want := range []string{"actions.prtarget-checkout", "actions.write-all", "actions.script-injection", "actions.unpinned-actions"} {
		if !hasRule(fs, want) {
			t.Errorf("expected workflow rule %s, findings=%v", want, fs)
		}
	}
}

func TestWorkflowDispatchInjection(t *testing.T) {
	wf := `
name: deploy
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'Deploy target'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying to ${{ inputs.target }}"
`
	fs := analyzeWorkflow("acme/app", ".github/workflows/deploy.yml", wf)
	if !hasRule(fs, "actions.dispatch-injection") {
		t.Errorf("expected dispatch-injection rule, findings=%v", fs)
	}
}

func TestDebugEnabled(t *testing.T) {
	wf := `
name: ci
on: push
env:
  ACTIONS_RUNNER_DEBUG: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
`
	fs := analyzeWorkflow("acme/app", ".github/workflows/ci.yml", wf)
	if !hasRule(fs, "actions.debug-enabled") {
		t.Errorf("expected debug-enabled rule, findings=%v", fs)
	}
}

func TestSecretScanAndRedaction(t *testing.T) {
	content := []byte(`aws_key = "AKIAIOSFODNN7EXAMPLE"
token: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
-----BEGIN RSA PRIVATE KEY-----
`)
	fs := scanContent("acme/app", "config/prod.env", content)
	if len(fs) < 3 {
		t.Fatalf("expected >=3 secret findings, got %d", len(fs))
	}
	for _, f := range fs {
		// the raw secret must never appear verbatim in output
		if strings.Contains(f.Detail, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(f.Detail, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Errorf("secret leaked unredacted in finding detail: %s", f.Detail)
		}
	}
}

func TestDatabaseConnectionStrings(t *testing.T) {
	content := []byte(`
MONGO_URI=mongodb+srv://admin:P@ssw0rd@cluster0.abc.mongodb.net/mydb
DATABASE_URL=postgres://user:secret123@db.example.com:5432/prod
REDIS_URL=redis://default:mypass@redis.example.com:6379
MYSQL_DSN=mysql://root:hunter2@mysql.example.com/app
`)
	fs := scanContent("acme/app", ".env", content)
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.Rule] = true
	}
	for _, want := range []string{"secret.mongodb-connection-string", "secret.postgresql-connection-string", "secret.redis-connection-string", "secret.mysql-connection-string"} {
		if !rules[want] {
			t.Errorf("expected rule %s, got rules=%v", want, rules)
		}
	}
}

func TestCloudProviderSecrets(t *testing.T) {
	// construct DO token at runtime to avoid GitHub push protection false positive
	doToken := "dop" + "_v1_" + "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222"
	content := []byte("DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=hT9GwR2kF3mX5vQ8jN1bY6cA0eI4oU7pL2sD9fG0hJ1kL3mN5oP7qR9sT1uV3w==;EndpointSuffix=core.windows.net\n" + doToken + "\n")
	fs := scanContent("acme/app", "config.env", content)
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.Rule] = true
	}
	if !rules["secret.digitalocean-token"] {
		t.Errorf("expected DigitalOcean token finding, got rules=%v", rules)
	}
	if !rules["secret.azure-storage-account-key"] {
		t.Errorf("expected Azure Storage Account Key finding, got rules=%v", rules)
	}
}

func TestScoreAndReports(t *testing.T) {
	r := &Report{
		Tool: "exposure-check", Version: version, Target: "acme", Scope: "org",
		Generated: time.Date(2026, 7, 2, 14, 30, 0, 0, time.UTC), ReposSeen: 14,
		Emails: []string{"dev@acme.com", "ops@acme.io", "cto@acme.com"},
		Findings: []Finding{
			{Severity: CRITICAL, Sev: "CRITICAL", Category: "secret", Rule: "secret.aws-access-key-id", Title: "Possible AWS Access Key ID in public repository", Location: "acme/api/config/prod.env:12", Detail: "Matched value (redacted): AKIA******LE", Remedy: "Rotate immediately and purge from git history."},
			{Severity: CRITICAL, Sev: "CRITICAL", Category: "secret", Rule: "secret.github-token", Title: "Possible GitHub Token in public repository", Location: "acme/deploy/.env:3", Detail: "Matched value (redacted): ghp_******89", Remedy: "Revoke the token now."},
			{Severity: HIGH, Sev: "HIGH", Category: "actions", Rule: "actions.prtarget-checkout", Title: "pull_request_target checks out untrusted PR code", Location: "acme/api/.github/workflows/ci.yml", Detail: "A classic path to code execution with write access and secrets.", Remedy: "Never check out PR head under pull_request_target."},
			{Severity: HIGH, Sev: "HIGH", Category: "actions", Rule: "actions.write-all", Title: "Workflow grants permissions: write-all", Location: "acme/web/.github/workflows/release.yml", Detail: "Broader than needed.", Remedy: "Use least-privilege permissions."},
			{Severity: MEDIUM, Sev: "MEDIUM", Category: "actions", Rule: "actions.unpinned-actions", Title: "Third-party actions pinned to mutable tags", Location: "acme/api/.github/workflows/ci.yml", Detail: "actions/checkout@v4, some/action@main", Remedy: "Pin to full commit SHA."},
			{Severity: MEDIUM, Sev: "MEDIUM", Category: "hygiene", Rule: "hygiene.no-security-md", Title: "No SECURITY.md / disclosure policy", Location: "acme/api", Detail: "No security policy.", Remedy: "Add a SECURITY.md."},
			{Severity: MEDIUM, Sev: "MEDIUM", Category: "hygiene", Rule: "hygiene.no-branch-protection", Title: "Default branch has no protection", Location: "acme/web (main)", Detail: "History can be force-pushed.", Remedy: "Enable branch protection."},
			{Severity: LOW, Sev: "LOW", Category: "hygiene", Rule: "hygiene.no-license", Title: "No recognised license", Location: "acme/scripts", Detail: "Usage terms unclear.", Remedy: "Add a LICENSE."},
		},
	}
	computeScore(r)
	// 2*CRITICAL(20) + 2*HIGH(10) + 3*MEDIUM(4) + 1*LOW(1) = 40+20+12+1 = 73 -> 27
	if r.Score != 27 {
		t.Errorf("expected score 27, got %d", r.Score)
	}
	if r.Counts["CRITICAL"] != 2 || r.Counts["HIGH"] != 2 || r.Counts["MEDIUM"] != 3 || r.Counts["LOW"] != 1 {
		t.Errorf("bad counts: %v", r.Counts)
	}
	// render all formats without panic; write demo artifacts
	_ = renderText(r, false)
	_ = renderJSON(r)
	_ = renderMarkdown(r)
	sarifOut := renderSARIF(r)
	if !strings.Contains(sarifOut, `"version": "2.1.0"`) {
		t.Error("SARIF output missing version 2.1.0")
	}
	if !strings.Contains(sarifOut, `"exposure-check"`) {
		t.Error("SARIF output missing tool name")
	}
	if !strings.Contains(sarifOut, `"ruleId"`) {
		t.Error("SARIF output missing results")
	}
	os.WriteFile("/tmp/ec_demo.html", []byte(renderHTML(r)), 0o644)
	os.WriteFile("/tmp/ec_demo.txt", []byte(renderText(r, false)), 0o644)
	os.WriteFile("/tmp/ec_demo.sarif", []byte(sarifOut), 0o644)
}
