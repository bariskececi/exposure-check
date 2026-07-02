package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---- typosquatting ----

func typosquatVariants(domain string) []string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	name, tld := parts[0], parts[1]
	seen := map[string]bool{domain: true}
	var out []string
	add := func(d string) {
		d = strings.ToLower(d)
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}

	// character substitution (homoglyphs / leet)
	subs := map[byte][]byte{
		'o': {'0'}, '0': {'o'},
		'l': {'1', 'i'}, '1': {'l', 'i'}, 'i': {'1', 'l'},
		'a': {'4', '@'}, '4': {'a'},
		'e': {'3'}, '3': {'e'},
		's': {'5', 'z'}, '5': {'s'},
		'g': {'q'}, 'q': {'g'},
		'u': {'v'}, 'v': {'u'},
		'n': {'m'}, 'm': {'n'},
		'c': {'k'}, 'k': {'c'},
		'd': {'b'}, 'b': {'d'},
		'w': {'v'},
	}
	for i := 0; i < len(name); i++ {
		if reps, ok := subs[name[i]]; ok {
			for _, r := range reps {
				add(name[:i] + string(r) + name[i+1:] + "." + tld)
			}
		}
	}

	// missing character
	for i := 0; i < len(name); i++ {
		add(name[:i] + name[i+1:] + "." + tld)
	}

	// adjacent swap
	for i := 0; i < len(name)-1; i++ {
		swapped := name[:i] + string(name[i+1]) + string(name[i]) + name[i+2:]
		add(swapped + "." + tld)
	}

	// double character
	for i := 0; i < len(name); i++ {
		add(name[:i] + string(name[i]) + string(name[i]) + name[i+1:] + "." + tld)
	}

	// hyphen insertion
	for i := 1; i < len(name); i++ {
		add(name[:i] + "-" + name[i:] + "." + tld)
	}

	// TLD variations
	altTLDs := []string{"com", "net", "org", "io", "co", "dev", "app", "xyz", "info", "biz", "tech"}
	for _, alt := range altTLDs {
		if alt != tld {
			add(name + "." + alt)
		}
	}

	// common prefix/suffix
	for _, fix := range []string{"login-", "my-", "secure-", "-login", "-secure", "-app", "-portal"} {
		if strings.HasPrefix(fix, "-") {
			add(name + fix + "." + tld)
		} else {
			add(fix + name + "." + tld)
		}
	}

	return out
}

func checkTyposquats(domain string) []Finding {
	variants := typosquatVariants(domain)
	var findings []Finding
	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 30)
	resolver := &net.Resolver{PreferGo: true}

	for _, v := range variants {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := ctxTimeout(3 * time.Second)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, d)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				alive = append(alive, d+" ("+addrs[0]+")")
				mu.Unlock()
			}
		}(v)
	}
	wg.Wait()

	if len(alive) > 0 {
		sev := MEDIUM
		if len(alive) >= 5 {
			sev = HIGH
		}
		findings = append(findings, Finding{
			Severity: sev, Sev: sev.String(), Category: "domain",
			Rule:     "domain.typosquat",
			Title:    fmt.Sprintf("%d lookalike domains resolve to live hosts", len(alive)),
			Location: domain,
			Detail:   "Resolving variants: " + strings.Join(alive, ", "),
			Remedy:   "Investigate each domain for phishing or brand impersonation. Consider registering high-risk variants defensively.",
		})
	}
	return findings
}

// ---- subdomain enumeration ----

var commonSubs = []string{
	"admin", "mail", "webmail", "vpn", "dev", "staging", "stage", "api",
	"portal", "login", "dashboard", "internal", "test", "beta", "app",
	"cdn", "docs", "git", "gitlab", "jenkins", "jira", "confluence",
	"grafana", "kibana", "prometheus", "monitor", "sentry", "ci", "cd",
	"deploy", "build", "registry", "docker", "k8s", "kubernetes",
	"phpmyadmin", "db", "database", "mysql", "postgres", "redis",
	"elastic", "es", "search", "mq", "rabbit", "queue", "ftp",
	"sftp", "ssh", "remote", "rdp", "backup", "old", "legacy",
	"demo", "sandbox", "uat", "qa", "preprod", "prod", "ns1", "ns2",
	"mx", "smtp", "pop", "imap", "autodiscover", "exchange",
	"sso", "auth", "oauth", "iam", "vault", "secrets",
	"status", "health", "metrics", "trace", "log", "logs",
	"wiki", "help", "support", "ticket", "crm", "erp",
	"shop", "store", "pay", "billing", "invoice",
	"cdn1", "cdn2", "static", "assets", "media", "img", "images",
	"s3", "storage", "files", "upload",
}

func enumerateSubdomains(domain string) []Finding {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 40)
	resolver := &net.Resolver{PreferGo: true}

	for _, sub := range commonSubs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fqdn := s + "." + domain
			ctx, cancel := ctxTimeout(3 * time.Second)
			defer cancel()
			addrs, err := resolver.LookupHost(ctx, fqdn)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				found = append(found, fqdn+" → "+addrs[0])
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()

	var findings []Finding
	if len(found) > 0 {
		// flag risky subdomains
		risky := []string{}
		for _, f := range found {
			low := strings.ToLower(f)
			for _, keyword := range []string{"admin", "jenkins", "gitlab", "phpmyadmin", "staging", "internal", "test", "debug", "legacy", "old", "backup", "vault", "secrets", "grafana", "kibana", "sentry", "prometheus", "docker", "registry"} {
				if strings.HasPrefix(low, keyword+".") {
					risky = append(risky, f)
					break
				}
			}
		}

		findings = append(findings, Finding{
			Severity: INFO, Sev: INFO.String(), Category: "domain",
			Rule:     "domain.subdomains",
			Title:    fmt.Sprintf("%d subdomains discovered via DNS", len(found)),
			Location: domain,
			Detail:   strings.Join(found, ", "),
			Remedy:   "Review the attack surface. Ensure internal services are not exposed to the internet without authentication.",
		})

		if len(risky) > 0 {
			sev := MEDIUM
			if len(risky) >= 3 {
				sev = HIGH
			}
			findings = append(findings, Finding{
				Severity: sev, Sev: sev.String(), Category: "domain",
				Rule:     "domain.risky-subdomains",
				Title:    fmt.Sprintf("%d potentially sensitive subdomains exposed", len(risky)),
				Location: domain,
				Detail:   "Sensitive services found publicly: " + strings.Join(risky, ", "),
				Remedy:   "Admin panels, CI/CD, monitoring, and internal tools should not be internet-facing without VPN or strong auth.",
			})
		}
	}
	return findings
}

// ---- login panel discovery ----

var panelPaths = []string{
	"/admin", "/login", "/signin", "/wp-admin", "/wp-login.php",
	"/administrator", "/panel", "/dashboard", "/console",
	"/manager", "/phpmyadmin", "/adminer", "/pma",
	"/_config", "/server-status", "/server-info",
	"/actuator", "/actuator/health", "/actuator/env",
	"/.env", "/.git/config", "/.git/HEAD",
	"/api/swagger", "/swagger-ui.html", "/api-docs",
	"/graphql", "/graphiql",
	"/debug", "/trace", "/metrics", "/healthz",
	"/elmah.axd", "/telescope", "/horizon",
	"/solr/", "/kibana", "/grafana",
	"/remote/login", "/vpn", "/citrix",
	"/owa", "/exchange", "/autodiscover",
	"/jenkins", "/jenkins/login",
}

func discoverPanels(domain string) []Finding {
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var panels []string
	var sensitive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	for _, path := range panelPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := "https://" + domain + p
			resp, err := client.Get(url)
			if err != nil {
				// try http
				url = "http://" + domain + p
				resp, err = client.Get(url)
				if err != nil {
					return
				}
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			bodyLow := strings.ToLower(string(body))

			if resp.StatusCode >= 200 && resp.StatusCode < 404 {
				entry := fmt.Sprintf("%s (%d)", url, resp.StatusCode)

				// sensitive exposures
				if strings.Contains(p, ".env") || strings.Contains(p, ".git") {
					if resp.StatusCode == 200 && len(body) > 10 {
						mu.Lock()
						sensitive = append(sensitive, entry)
						mu.Unlock()
					}
					return
				}
				// detect login-like pages
				if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
					isPanel := strings.Contains(bodyLow, "password") ||
						strings.Contains(bodyLow, "login") ||
						strings.Contains(bodyLow, "sign in") ||
						strings.Contains(bodyLow, "username") ||
						resp.StatusCode == 401
					if isPanel || strings.Contains(p, "admin") || strings.Contains(p, "panel") || strings.Contains(p, "dashboard") {
						mu.Lock()
						panels = append(panels, entry)
						mu.Unlock()
					}
				}
			}
		}(path)
	}
	wg.Wait()

	var findings []Finding

	if len(sensitive) > 0 {
		findings = append(findings, Finding{
			Severity: CRITICAL, Sev: CRITICAL.String(), Category: "domain",
			Rule:     "domain.sensitive-exposure",
			Title:    fmt.Sprintf("%d sensitive files publicly accessible", len(sensitive)),
			Location: domain,
			Detail:   strings.Join(sensitive, ", "),
			Remedy:   "These files may expose credentials, source code, or internal configuration. Block access immediately via web server config.",
		})
	}

	if len(panels) > 0 {
		sev := MEDIUM
		if len(panels) >= 3 {
			sev = HIGH
		}
		findings = append(findings, Finding{
			Severity: sev, Sev: sev.String(), Category: "domain",
			Rule:     "domain.login-panels",
			Title:    fmt.Sprintf("%d login/admin panels exposed", len(panels)),
			Location: domain,
			Detail:   strings.Join(panels, ", "),
			Remedy:   "Admin panels should be behind VPN, IP whitelist, or multi-factor authentication — never open to the internet.",
		})
	}

	return findings
}

// ---- TLS/cert check ----

func checkTLS(domain string) []Finding {
	var findings []Finding
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		findings = append(findings, Finding{
			Severity: MEDIUM, Sev: MEDIUM.String(), Category: "domain",
			Rule: "domain.no-tls", Title: "No TLS/HTTPS available",
			Location: domain + ":443", Detail: "Could not establish TLS connection: " + err.Error(),
			Remedy: "Enable HTTPS with a valid certificate.",
		})
		return findings
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft < 0 {
			findings = append(findings, Finding{
				Severity: HIGH, Sev: HIGH.String(), Category: "domain",
				Rule: "domain.cert-expired", Title: "TLS certificate expired",
				Location: domain, Detail: fmt.Sprintf("Certificate expired %d days ago (NotAfter: %s)", -daysLeft, cert.NotAfter.Format("2006-01-02")),
				Remedy: "Renew the certificate immediately.",
			})
		} else if daysLeft < 30 {
			findings = append(findings, Finding{
				Severity: MEDIUM, Sev: MEDIUM.String(), Category: "domain",
				Rule: "domain.cert-expiring", Title: "TLS certificate expiring soon",
				Location: domain, Detail: fmt.Sprintf("Certificate expires in %d days (%s)", daysLeft, cert.NotAfter.Format("2006-01-02")),
				Remedy: "Renew the certificate before expiry.",
			})
		}

		// check if cert matches domain
		if err := cert.VerifyHostname(domain); err != nil {
			findings = append(findings, Finding{
				Severity: HIGH, Sev: HIGH.String(), Category: "domain",
				Rule: "domain.cert-mismatch", Title: "TLS certificate hostname mismatch",
				Location: domain, Detail: "Certificate does not match domain: " + err.Error(),
				Remedy: "Issue a certificate that covers this domain.",
			})
		}
	}

	// check TLS version
	ver := conn.ConnectionState().Version
	if ver < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Severity: HIGH, Sev: HIGH.String(), Category: "domain",
			Rule: "domain.weak-tls", Title: "Weak TLS version",
			Location: domain, Detail: "Server supports TLS version below 1.2.",
			Remedy: "Disable TLS 1.0 and 1.1; require TLS 1.2 or higher.",
		})
	}

	return findings
}

// ---- orchestrator ----

func scanDomain(domain string, verbose bool) []Finding {
	var allFindings []Finding
	type scanResult struct {
		name     string
		findings []Finding
	}
	results := make(chan scanResult, 4)
	var wg sync.WaitGroup

	scans := []struct {
		name string
		fn   func() []Finding
	}{
		{"TLS/certificate", func() []Finding { return checkTLS(domain) }},
		{"typosquatting", func() []Finding { return checkTyposquats(domain) }},
		{"subdomains", func() []Finding { return enumerateSubdomains(domain) }},
		{"login panels", func() []Finding { return discoverPanels(domain) }},
	}

	for _, s := range scans {
		wg.Add(1)
		go func(name string, fn func() []Finding) {
			defer wg.Done()
			if verbose {
				fmt.Fprintf(ioStderr, "  [domain] checking %s ...\n", name)
			}
			results <- scanResult{name, fn()}
		}(s.name, s.fn)
	}

	go func() { wg.Wait(); close(results) }()

	for r := range results {
		allFindings = append(allFindings, r.findings...)
		if verbose {
			fmt.Fprintf(ioStderr, "  [domain] %s: %d findings\n", r.name, len(r.findings))
		}
	}

	return allFindings
}
