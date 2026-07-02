package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed dashboard/static
var staticFS embed.FS

func runDashboard(port int, token string) {
	mux := http.NewServeMux()

	// serve static files
	sub, _ := fs.Sub(staticFS, "dashboard/static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// scan API
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Type    string `json:"type"`
			Target  string `json:"target"`
			Target2 string `json:"target2"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "invalid request: "+err.Error())
			return
		}
		if req.Target == "" {
			jsonErr(w, "target is required")
			return
		}

		gh := newGH(token)
		opt := defaultOptions()
		rep := &Report{Tool: "exposure-check", Version: version, Generated: time.Now()}

		switch req.Type {
		case "domain":
			rep.Target = req.Target
			rep.Scope = "domain"
			rep.Findings = append(rep.Findings, scanDomain(req.Target, false)...)

		case "github-org":
			rep.Target = req.Target
			rep.Scope = "org"
			budget := 4000
			if token == "" {
				budget = 40
			}
			list, err := gh.listOrgRepos(req.Target, opt.maxRepos)
			if err != nil {
				jsonErr(w, "GitHub API error: "+err.Error())
				return
			}
			for i := range list {
				r := list[i]
				if r.Fork || r.Archived {
					continue
				}
				if budget <= 0 {
					break
				}
				rc := r
				f, em := scanRepo(gh, &rc, opt, &budget)
				rep.Findings = append(rep.Findings, f...)
				for _, e := range em {
					rep.Emails = appendUnique(rep.Emails, e)
				}
				rep.ReposSeen++
			}

		case "repo":
			rep.Scope = "repo"
			parts := strings.SplitN(req.Target, "/", 2)
			if len(parts) != 2 {
				jsonErr(w, "repo must be owner/repo")
				return
			}
			budget := 4000
			if token == "" {
				budget = 40
			}
			r, err := gh.getRepo(parts[0], parts[1])
			if err != nil {
				jsonErr(w, "repo not found: "+err.Error())
				return
			}
			rep.Target = r.FullName
			f, em := scanRepo(gh, r, opt, &budget)
			rep.Findings = append(rep.Findings, f...)
			rep.Emails = em
			rep.ReposSeen = 1

		case "full":
			rep.Scope = "domain+org"
			rep.Target = req.Target
			// domain scan
			rep.Findings = append(rep.Findings, scanDomain(req.Target, false)...)
			// org scan
			orgName := req.Target2
			if orgName == "" {
				orgName = req.Target
			}
			budget := 4000
			if token == "" {
				budget = 40
			}
			list, _ := gh.listOrgRepos(orgName, opt.maxRepos)
			for i := range list {
				r := list[i]
				if r.Fork || r.Archived {
					continue
				}
				if budget <= 0 {
					break
				}
				rc := r
				f, em := scanRepo(gh, &rc, opt, &budget)
				rep.Findings = append(rep.Findings, f...)
				for _, e := range em {
					rep.Emails = appendUnique(rep.Emails, e)
				}
				rep.ReposSeen++
			}

		default:
			jsonErr(w, "unknown scan type: "+req.Type)
			return
		}

		computeScore(rep)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rep)
	})

	// export API
	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}
		var req struct {
			Report json.RawMessage `json:"report"`
			Format string          `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var rep Report
		if err := json.Unmarshal(req.Report, &rep); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// re-parse severities from string
		for i := range rep.Findings {
			rep.Findings[i].Severity = parseSeverity(rep.Findings[i].Sev)
		}

		var out string
		var ct string
		switch req.Format {
		case "html":
			out = renderHTML(&rep)
			ct = "text/html"
		case "json":
			out = renderJSON(&rep)
			ct = "application/json"
		case "sarif":
			out = renderSARIF(&rep)
			ct = "application/json"
		case "markdown", "md":
			out = renderMarkdown(&rep)
			ct = "text/markdown"
		default:
			out = renderText(&rep, false)
			ct = "text/plain"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=exposure-report.%s", req.Format))
		w.Write([]byte(out))
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Fprintf(os.Stderr, "\n  exposure-check dashboard\n  http://localhost%s\n\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func jsonErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
