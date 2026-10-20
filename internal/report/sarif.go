package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/faridlamaul/shipguard/internal/finding"
)

const (
	sarifSchema      = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion     = "2.1.0"
	sarifFingerprint = "shipguard/v1"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF renders the findings as a SARIF 2.1.0 log. Rules are sorted by
// id and deduplicated; results keep the input order. Findings without a File
// are included without a location (GitHub code scanning may ignore them).
// Info license findings (allowed licenses) are left out. The caller drops
// findings suppressed by an exception first (see reportable).
func WriteSARIF(w io.Writer, r finding.Result, version string) error {
	var fs []finding.Finding
	for _, f := range r.Findings {
		if reported(f) {
			fs = append(fs, f)
		}
	}
	rules := map[string]*sarifRule{}
	maxSev := map[string]finding.Severity{}
	for _, f := range fs {
		rule, ok := rules[f.ID]
		if !ok {
			rule = &sarifRule{
				ID:               f.ID,
				ShortDescription: sarifText{Text: orID(f.Message, f.ID)},
				Properties:       map[string]any{"tags": []string{"security", string(f.Category)}},
			}
			rules[f.ID] = rule
		}
		if f.Severity > maxSev[f.ID] {
			maxSev[f.ID] = f.Severity
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := make(map[string]int, len(ids))
	driverRules := make([]sarifRule, 0, len(ids))
	for i, id := range ids {
		index[id] = i
		rules[id].Properties["security-severity"] = securitySeverity(maxSev[id])
		driverRules = append(driverRules, *rules[id])
	}

	results := make([]sarifResult, 0, len(fs))
	for _, f := range fs {
		res := sarifResult{
			RuleID:              f.ID,
			RuleIndex:           index[f.ID],
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{Text: orID(f.Message, f.ID)},
			PartialFingerprints: map[string]string{sarifFingerprint: f.Fingerprint},
			Properties:          map[string]string{"status": string(f.Status)},
		}
		if f.File != "" {
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File, URIBaseID: "%SRCROOT%"},
				Region:           sarifRegion{StartLine: max(f.Line, 1)},
			}}}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "shipguard", Version: version, Rules: driverRules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	return nil
}

func orID(s, id string) string {
	if s == "" {
		return id
	}
	return s
}

func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "9.5"
	case finding.High:
		return "8.0"
	case finding.Medium:
		return "5.5"
	case finding.Low:
		return "3.0"
	default:
		return "0.0"
	}
}
