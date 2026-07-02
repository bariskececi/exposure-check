package main

import "time"

// Severity levels, ordered.
type Severity int

const (
	INFO Severity = iota
	LOW
	MEDIUM
	HIGH
	CRITICAL
)

func (s Severity) String() string {
	switch s {
	case CRITICAL:
		return "CRITICAL"
	case HIGH:
		return "HIGH"
	case MEDIUM:
		return "MEDIUM"
	case LOW:
		return "LOW"
	default:
		return "INFO"
	}
}

func parseSeverity(s string) Severity {
	switch s {
	case "critical", "CRITICAL":
		return CRITICAL
	case "high", "HIGH":
		return HIGH
	case "medium", "MEDIUM":
		return MEDIUM
	case "low", "LOW":
		return LOW
	default:
		return INFO
	}
}

// Finding is a single exposure result.
type Finding struct {
	Severity Severity `json:"-"`
	Sev      string   `json:"severity"`
	Category string   `json:"category"`
	Rule     string   `json:"rule"`
	Title    string   `json:"title"`
	Location string   `json:"location,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Remedy   string   `json:"remediation,omitempty"`
}

// Report is the full scan result.
type Report struct {
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Target    string           `json:"target"`
	Scope     string           `json:"scope"`
	Generated time.Time        `json:"generated"`
	ReposSeen int              `json:"repositories_scanned"`
	Score     int              `json:"posture_score"`
	Counts    map[string]int   `json:"counts"`
	Emails    []string         `json:"exposed_emails,omitempty"`
	Findings  []Finding        `json:"findings"`
}

// severityRank maps a threshold string to Severity for --fail-on.
func (r *Report) worstSeverity() Severity {
	worst := INFO
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}
