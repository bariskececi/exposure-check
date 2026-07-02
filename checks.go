package main

import (
	"regexp"
	"strconv"
	"strings"
)

func itoa(i int) string { return strconv.Itoa(i) }

type scanOptions struct {
	maxRepos int
	maxFiles int
	secrets  bool
	emails   bool
	actions  bool
	hygiene  bool
}

func defaultOptions() scanOptions {
	return scanOptions{maxRepos: 25, maxFiles: 400, secrets: true, emails: true, actions: true, hygiene: true}
}

// ---- GitHub Actions workflow analysis (heuristic, line-based) ----

var reUses = regexp.MustCompile(`(?m)uses:\s*([^\s#]+)`)
var rePinnedSHA = regexp.MustCompile(`@[0-9a-f]{40}$`)
var reEventInRun = regexp.MustCompile(`\$\{\{\s*github\.event\.[^}]*(title|body|message|name|ref|label|comment|head_ref|author)[^}]*\}\}`)

func analyzeWorkflow(repoFull, path, content string) []Finding {
	var out []Finding
	add := func(sev Severity, rule, title, detail, remedy string) {
		out = append(out, Finding{Severity: sev, Sev: sev.String(), Category: "actions",
			Rule: "actions." + rule, Title: title, Location: repoFull + "/" + path, Detail: detail, Remedy: remedy})
	}
	low := strings.ToLower(content)

	if strings.Contains(low, "pull_request_target") {
		detail := "The workflow uses the pull_request_target trigger, which runs with repository write permissions and access to secrets in the context of a fork's pull request."
		if strings.Contains(low, "actions/checkout") && (strings.Contains(low, "head.sha") || strings.Contains(low, "head.ref") || strings.Contains(low, "pull_request.head")) {
			add(CRITICAL, "prtarget-checkout", "pull_request_target checks out untrusted PR code", detail+" It also checks out the PR head — a classic path to code execution with write access and secrets.",
				"Split into a safe pull_request workflow for building/testing untrusted code, and never check out PR head under pull_request_target.")
		} else {
			add(HIGH, "prtarget", "Workflow uses pull_request_target", detail,
				"Prefer pull_request; if pull_request_target is required, do not check out or execute PR-controlled code and scope permissions tightly.")
		}
	}
	if strings.Contains(low, "write-all") || regexp.MustCompile(`permissions:\s*write-all`).MatchString(low) {
		add(HIGH, "write-all", "Workflow grants permissions: write-all", "The workflow requests write-all token permissions, far broader than most jobs need.",
			"Set least-privilege permissions per job (e.g. contents: read) and only elevate the specific scopes required.")
	}
	if reEventInRun.MatchString(content) {
		add(HIGH, "script-injection", "Untrusted github.event data used in a run step", "User-controlled github.event.* values are interpolated into a shell run: block, allowing script injection.",
			"Pass untrusted values through an intermediate env: variable and reference \"$VAR\" instead of inlining ${{ github.event... }}.")
	}
	if strings.Contains(low, "self-hosted") {
		add(MEDIUM, "self-hosted", "Self-hosted runner referenced", "Self-hosted runners on public repositories can be abused by forked pull requests to run attacker code on your infrastructure.",
			"Avoid self-hosted runners for public repos, or gate them behind required approvals and ephemeral, isolated runners.")
	}
	// workflow_dispatch input injection
	if strings.Contains(low, "workflow_dispatch") {
		// check if any input is interpolated into a run: block
		if regexp.MustCompile(`(?i)\$\{\{\s*(?:github\.event\.inputs|inputs)\.[^}]+\}\}`).MatchString(content) &&
			strings.Contains(low, "run:") {
			add(HIGH, "dispatch-injection", "workflow_dispatch input interpolated in run step",
				"User-supplied workflow_dispatch inputs are interpolated into a shell run: block, allowing script injection by anyone who can trigger the workflow.",
				"Pass inputs through an intermediate env: variable and reference \"$VAR\" instead of inlining ${{ inputs.* }}.")
		}
	}
	// ACTIONS_RUNNER_DEBUG left enabled
	if regexp.MustCompile(`(?i)ACTIONS_RUNNER_DEBUG\s*[:=]\s*true`).MatchString(content) {
		add(MEDIUM, "debug-enabled", "ACTIONS_RUNNER_DEBUG is enabled",
			"Debug logging is enabled, which may expose secrets and internal state in workflow logs.",
			"Remove ACTIONS_RUNNER_DEBUG or set it to false for production workflows.")
	}
	// cross-workflow artifact poisoning: download-artifact without specifying a workflow run
	if strings.Contains(low, "actions/download-artifact") && !strings.Contains(low, "run-id") {
		if strings.Contains(low, "pull_request") || strings.Contains(low, "pull_request_target") {
			add(MEDIUM, "artifact-poisoning", "Artifact download in PR workflow without run-id pinning",
				"Downloading artifacts in a PR-triggered workflow without specifying a run-id can allow a malicious PR to poison artifacts from a prior trusted run.",
				"Pin artifact downloads to a specific run-id from the triggering workflow, or validate artifact contents before use.")
		}
	}

	// unpinned action versions (ambiguous versions => supply-chain risk)
	unpinned := map[string]bool{}
	for _, m := range reUses.FindAllStringSubmatch(content, -1) {
		ref := strings.Trim(m[1], `"'`)
		if !strings.Contains(ref, "@") {
			continue
		}
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		if !rePinnedSHA.MatchString(ref) {
			unpinned[ref] = true
		}
	}
	if len(unpinned) > 0 {
		var refs []string
		for r := range unpinned {
			refs = append(refs, r)
		}
		add(MEDIUM, "unpinned-actions", "Third-party actions pinned to mutable tags", "Actions are referenced by tag/branch ("+strings.Join(refs, ", ")+") rather than a full commit SHA. A compromised or re-tagged action would run in your pipeline.",
			"Pin third-party actions to a full-length commit SHA and use Dependabot to keep them current.")
	}
	return out
}

// ---- repo hygiene ----

var securityPaths = []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}

func hygieneChecks(gh *ghClient, r *ghRepo) []Finding {
	var out []Finding
	repoFull := r.FullName
	// SECURITY.md
	found := false
	for _, p := range securityPaths {
		if gh.fileExists(r.Owner.Login, r.Name, p) {
			found = true
			break
		}
	}
	if !found {
		out = append(out, Finding{Severity: MEDIUM, Sev: MEDIUM.String(), Category: "hygiene", Rule: "hygiene.no-security-md",
			Title: "No SECURITY.md / disclosure policy", Location: repoFull,
			Detail: "The repository has no security policy, so researchers have no clear way to report vulnerabilities.",
			Remedy: "Add a SECURITY.md describing how to report vulnerabilities and your disclosure process."})
	}
	// license
	if r.License == nil || r.License.SPDX == "" || r.License.SPDX == "NOASSERTION" {
		out = append(out, Finding{Severity: LOW, Sev: LOW.String(), Category: "hygiene", Rule: "hygiene.no-license",
			Title: "No recognised license", Location: repoFull,
			Detail: "No SPDX license was detected; usage terms are unclear.", Remedy: "Add a LICENSE file with a recognised open-source license if the code is meant to be reused."})
	}
	// branch protection (best-effort)
	if protected, detectable := gh.branchProtected(r.Owner.Login, r.Name, r.DefaultBranch); detectable && !protected {
		out = append(out, Finding{Severity: MEDIUM, Sev: MEDIUM.String(), Category: "hygiene", Rule: "hygiene.no-branch-protection",
			Title: "Default branch has no protection", Location: repoFull + " (" + r.DefaultBranch + ")",
			Detail: "The default branch is not protected, so history can be force-pushed and unreviewed code merged directly.",
			Remedy: "Enable branch protection: require pull-request review, status checks, and block force pushes."})
	}
	return out
}

// ---- email discovery ----

var reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func discoverEmails(gh *ghClient, owner, name string) []string {
	commits, _ := gh.listCommits(owner, name, 3)
	set := map[string]bool{}
	for _, c := range commits {
		for _, e := range []string{c.Commit.Author.Email, c.Commit.Committer.Email} {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" || strings.HasSuffix(e, "@users.noreply.github.com") || !reEmail.MatchString(e) {
				continue
			}
			// skip common bot/no-reply providers
			if strings.Contains(e, "noreply") || strings.HasPrefix(e, "action@") || strings.Contains(e, "dependabot") {
				continue
			}
			set[e] = true
		}
	}
	var out []string
	for e := range set {
		out = append(out, e)
	}
	return out
}

// ---- per-repo scan ----

func scanRepo(gh *ghClient, r *ghRepo, opt scanOptions, budget *int) ([]Finding, []string) {
	var findings []Finding
	var emails []string
	repoFull := r.FullName
	if opt.hygiene {
		findings = append(findings, hygieneChecks(gh, r)...)
	}
	if opt.emails {
		emails = discoverEmails(gh, r.Owner.Login, r.Name)
	}
	if !opt.actions && !opt.secrets {
		return findings, emails
	}
	tree, err := gh.getTree(r.Owner.Login, r.Name, r.DefaultBranch)
	if err != nil {
		return findings, emails
	}
	scanned := 0
	for _, e := range tree.Tree {
		if e.Type != "blob" || shouldSkipPath(e.Path) {
			continue
		}
		isWorkflow := opt.actions && (strings.HasPrefix(e.Path, ".github/workflows/")) && (strings.HasSuffix(e.Path, ".yml") || strings.HasSuffix(e.Path, ".yaml"))
		isSecretCandidate := opt.secrets && scannableExt[extOf(e.Path)] && e.Size <= 400*1024
		if !isWorkflow && !isSecretCandidate {
			continue
		}
		if *budget <= 0 || scanned >= opt.maxFiles {
			break
		}
		data, err := gh.getContent(r.Owner.Login, r.Name, e.Path)
		*budget--
		scanned++
		if err != nil {
			continue
		}
		if isWorkflow {
			findings = append(findings, analyzeWorkflow(repoFull, e.Path, string(data))...)
		}
		if isSecretCandidate {
			findings = append(findings, scanContent(repoFull, e.Path, data)...)
		}
	}
	return findings, emails
}
