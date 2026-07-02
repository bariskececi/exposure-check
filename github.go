package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const apiBase = "https://api.github.com"

type ghClient struct {
	token string
	http  *http.Client
}

func newGH(token string) *ghClient {
	return &ghClient{token: token, http: &http.Client{Timeout: 25 * time.Second}}
}

func (g *ghClient) do(path string, v any) error {
	url := path
	if strings.HasPrefix(path, "/") {
		url = apiBase + path
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "exposure-check")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 403 && strings.Contains(strings.ToLower(string(body)), "rate limit") {
		return fmt.Errorf("github rate limit reached — set a token with --token or GITHUB_TOKEN for higher limits")
	}
	if resp.StatusCode == 404 {
		return errNotFound
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("github api %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if v != nil {
		return json.Unmarshal(body, v)
	}
	return nil
}

var errNotFound = fmt.Errorf("not found")

// ---- API types ----

type ghRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	DefaultBranch string `json:"default_branch"`
	License       *struct {
		SPDX string `json:"spdx_id"`
	} `json:"license"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type ghTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int    `json:"size"`
	SHA  string `json:"sha"`
}

type ghTree struct {
	Tree      []ghTreeEntry `json:"tree"`
	Truncated bool          `json:"truncated"`
}

type ghCommit struct {
	Commit struct {
		Author struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"author"`
		Committer struct {
			Email string `json:"email"`
		} `json:"committer"`
	} `json:"commit"`
}

// ---- calls ----

func (g *ghClient) getRepo(owner, name string) (*ghRepo, error) {
	var r ghRepo
	if err := g.do(fmt.Sprintf("/repos/%s/%s", owner, name), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (g *ghClient) listOrgRepos(org string, max int) ([]ghRepo, error) {
	var out []ghRepo
	for page := 1; page <= 10; page++ {
		var repos []ghRepo
		if err := g.do(fmt.Sprintf("/orgs/%s/repos?per_page=100&type=public&page=%d", org, page), &repos); err != nil {
			// fall back to user repos if org 404
			if err == errNotFound && page == 1 {
				if err2 := g.do(fmt.Sprintf("/users/%s/repos?per_page=100&type=owner&page=%d", org, page), &repos); err2 != nil {
					return nil, err2
				}
			} else {
				return nil, err
			}
		}
		if len(repos) == 0 {
			break
		}
		out = append(out, repos...)
		if max > 0 && len(out) >= max {
			out = out[:max]
			break
		}
		if len(repos) < 100 {
			break
		}
	}
	return out, nil
}

func (g *ghClient) getTree(owner, name, branch string) (*ghTree, error) {
	var t ghTree
	err := g.do(fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", owner, name, branch), &t)
	return &t, err
}

// getContent fetches a file's raw bytes via the contents API.
func (g *ghClient) getContent(owner, name, path string) ([]byte, error) {
	var c struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := g.do(fmt.Sprintf("/repos/%s/%s/contents/%s", owner, name, path), &c); err != nil {
		return nil, err
	}
	if c.Encoding == "base64" {
		return base64.StdEncoding.DecodeString(strings.ReplaceAll(c.Content, "\n", ""))
	}
	return []byte(c.Content), nil
}

func (g *ghClient) fileExists(owner, name, path string) bool {
	err := g.do(fmt.Sprintf("/repos/%s/%s/contents/%s", owner, name, path), nil)
	return err == nil
}

// branchProtected best-effort: needs admin; returns (protected, detectable).
func (g *ghClient) branchProtected(owner, name, branch string) (bool, bool) {
	var p struct {
		Enabled bool `json:"enabled"`
	}
	err := g.do(fmt.Sprintf("/repos/%s/%s/branches/%s/protection", owner, name, branch), &p)
	if err == errNotFound {
		return false, true // detectable: no protection
	}
	if err != nil {
		return false, false // not detectable (needs admin/token)
	}
	return true, true
}

func (g *ghClient) listCommits(owner, name string, pages int) ([]ghCommit, error) {
	var out []ghCommit
	for page := 1; page <= pages; page++ {
		var cs []ghCommit
		if err := g.do(fmt.Sprintf("/repos/%s/%s/commits?per_page=100&page=%d", owner, name, page), &cs); err != nil {
			if err == errNotFound {
				break
			}
			return out, err
		}
		if len(cs) == 0 {
			break
		}
		out = append(out, cs...)
		if len(cs) < 100 {
			break
		}
	}
	return out, nil
}

func (g *ghClient) rateRemaining() int {
	var r struct {
		Rate struct {
			Remaining int `json:"remaining"`
		} `json:"rate"`
	}
	if err := g.do("/rate_limit", &r); err != nil {
		return -1
	}
	return r.Rate.Remaining
}
