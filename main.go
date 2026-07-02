package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "serve", "dashboard":
		runServe(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("exposure-check " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`exposure-check ` + version + ` — find what attackers can see before they do

USAGE
  exposure-check scan --github-org <org> [flags]
  exposure-check scan --repo <owner/repo> [flags]
  exposure-check scan --domain <domain> [flags]
  exposure-check serve [--port 3000] [--host 127.0.0.1]     # web dashboard

FLAGS
  --repo         owner/repo to scan
  --github-org   organisation or user to scan (public repos)
  --domain       domain to scan (subdomains, typosquats, login panels, TLS)
  --token        GitHub token (or set GITHUB_TOKEN) — recommended for rate limits
  --format       text | json | markdown | html | sarif  (default text)
  --output       write report to a file instead of stdout
  --fail-on      none | low | medium | high | critical  (default none) — exit 1 if reached
  --max-repos    max repositories to scan for an org   (default 25)
  --max-files    max files to fetch per repo           (default 400)
  --no-secrets   skip secret detection
  --no-emails    skip email discovery
  --verbose      show detailed progress (files scanned, API calls)
  --quiet        suppress all progress output, print only the report

Educational & defensive use only: scan assets you own or are authorised to assess.`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "bind address (default localhost only)")
	port := fs.Int("port", 3000, "dashboard port")
	token := fs.String("token", "", "GitHub token")
	_ = fs.Parse(args)
	tok := *token
	if tok == "" {
		tok = os.Getenv("GITHUB_TOKEN")
	}
	runDashboard(*host, *port, tok)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	repo := fs.String("repo", "", "owner/repo")
	org := fs.String("github-org", "", "organisation or user")
	domain := fs.String("domain", "", "domain to scan")
	token := fs.String("token", "", "GitHub token")
	format := fs.String("format", "text", "text|json|markdown|html|sarif")
	output := fs.String("output", "", "output file")
	failOn := fs.String("fail-on", "none", "none|low|medium|high|critical")
	maxRepos := fs.Int("max-repos", 25, "max repos for org")
	maxFiles := fs.Int("max-files", 400, "max files per repo")
	noSecrets := fs.Bool("no-secrets", false, "skip secret detection")
	noEmails := fs.Bool("no-emails", false, "skip email discovery")
	noColor := fs.Bool("no-color", false, "disable colour")
	verbose := fs.Bool("verbose", false, "detailed progress")
	quiet := fs.Bool("quiet", false, "suppress progress, report only")
	_ = fs.Parse(args)

	tok := *token
	if tok == "" {
		tok = os.Getenv("GITHUB_TOKEN")
	}
	if *repo == "" && *org == "" && *domain == "" {
		fmt.Fprintln(os.Stderr, "error: provide --repo owner/repo, --github-org <org>, or --domain <domain>")
		os.Exit(2)
	}

	gh := newGH(tok)
	opt := defaultOptions()
	opt.maxRepos, opt.maxFiles = *maxRepos, *maxFiles
	opt.secrets, opt.emails = !*noSecrets, !*noEmails

	// fetch budget to stay friendly with rate limits
	budget := 40
	if tok != "" {
		budget = 4000
	} else if !*quiet {
		fmt.Fprintln(os.Stderr, "note: no token set — running with a small budget (60 req/hr unauthenticated). Set GITHUB_TOKEN for a full scan.")
	}

	rep := &Report{Tool: "exposure-check", Version: version, Generated: time.Now(), Scope: "repo"}

	// domain scan (can run alongside GitHub scan)
	if *domain != "" {
		if *verbose {
			fmt.Fprintf(os.Stderr, "scanning domain %s ...\n", *domain)
		}
		rep.Target = *domain
		rep.Scope = "domain"
		domainFindings := scanDomain(*domain, *verbose)
		rep.Findings = append(rep.Findings, domainFindings...)
		if *verbose {
			fmt.Fprintf(os.Stderr, "domain scan: %d findings\n", len(domainFindings))
		}
	}

	var repos []*ghRepo
	if *repo != "" {
		parts := strings.SplitN(*repo, "/", 2)
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "error: --repo must be owner/repo")
			os.Exit(2)
		}
		r, err := gh.getRepo(parts[0], parts[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		repos = append(repos, r)
		if rep.Target == "" {
			rep.Target = r.FullName
		} else {
			rep.Target += " + " + r.FullName
		}
	} else if *org != "" {
		if rep.Target == "" {
			rep.Target = *org
			rep.Scope = "org"
		} else {
			rep.Target += " + " + *org
			rep.Scope = "domain+org"
		}
		list, err := gh.listOrgRepos(*org, *maxRepos)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		for i := range list {
			r := list[i]
			if r.Fork || r.Archived {
				continue
			}
			rc := r
			repos = append(repos, &rc)
		}
	}

	emailSet := map[string]bool{}
	for _, r := range repos {
		if budget <= 0 {
			if !*quiet {
				fmt.Fprintln(os.Stderr, "note: fetch budget exhausted — scan truncated. Set a token for a complete scan.")
			}
			break
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "scanning %s ...\n", r.FullName)
		}
		f, em := scanRepo(gh, r, opt, &budget)
		rep.Findings = append(rep.Findings, f...)
		for _, e := range em {
			emailSet[e] = true
		}
		rep.ReposSeen++
		if *verbose {
			fmt.Fprintf(os.Stderr, "  %s: %d findings, %d emails, budget remaining: %d\n", r.FullName, len(f), len(em), budget)
		}
	}
	for e := range emailSet {
		rep.Emails = append(rep.Emails, e)
	}

	computeScore(rep)

	// render
	var out string
	color := *format == "text" && *output == "" && !*noColor && os.Getenv("NO_COLOR") == ""
	switch *format {
	case "json":
		out = renderJSON(rep)
	case "markdown", "md":
		out = renderMarkdown(rep)
	case "html":
		out = renderHTML(rep)
	case "sarif":
		out = renderSARIF(rep)
	default:
		out = renderText(rep, color)
	}
	if *output != "" {
		if err := os.WriteFile(*output, []byte(out), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error writing output:", err)
			os.Exit(1)
		}
		if !*quiet {
			fmt.Fprintln(os.Stderr, "report written to", *output)
		}
	} else {
		fmt.Println(out)
	}

	// CI gate
	if *failOn != "none" {
		threshold := parseSeverity(*failOn)
		if rep.worstSeverity() >= threshold {
			os.Exit(1)
		}
	}
}
