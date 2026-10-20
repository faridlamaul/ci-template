package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// ErrUpload marks a failure to publish results to a CI platform. Callers treat
// it as a warning: the gate decision, not the upload, decides the exit code.
var ErrUpload = errors.New("upload failed")

const (
	defaultBitbucketAPI   = "http://api.bitbucket.org/2.0"
	secureBitbucketAPI    = "https://api.bitbucket.org/2.0"
	defaultBitbucketProxy = "http://localhost:29418"
	reportKey             = "shipguard"
	maxAnnotations        = 1000
	annotationBatch       = 100
	maxDetails            = 2000
	maxAnnotationSummary  = 450
	maxExternalID         = 64
	maxErrBody            = 200
)

// CodeInsights publishes a report and annotations to Bitbucket Cloud.
type CodeInsights struct {
	BaseURL string // default "http://api.bitbucket.org/2.0"
	Proxy   string // Pipelines auth proxy; empty means no proxy; ignored when Token is set
	Token   string // optional Bearer token
	Repo    string // workspace/repo
	Commit  string
	HTTP    *http.Client // default: 30s timeout, Proxy applied
}

type ciData struct {
	Title string `json:"title"`
	Type  string `json:"type"`
	Value int    `json:"value"`
}

type ciReport struct {
	Title      string   `json:"title"`
	Details    string   `json:"details"`
	ReportType string   `json:"report_type"`
	Reporter   string   `json:"reporter"`
	Result     string   `json:"result"`
	Data       []ciData `json:"data"`
}

type ciAnnotation struct {
	ExternalID     string `json:"external_id"`
	AnnotationType string `json:"annotation_type"`
	Summary        string `json:"summary"`
	Severity       string `json:"severity"`
	Path           string `json:"path,omitempty"`
	Line           int    `json:"line,omitempty"`
}

// Publish creates the Code Insights report for the commit and uploads up to
// 1000 annotations in batches of 100, blocking findings first, then by
// severity. Any failure wraps ErrUpload.
func (c CodeInsights) Publish(ctx context.Context, r finding.Result, d policy.Decision) error {
	if c.Repo == "" || c.Commit == "" {
		return fmt.Errorf("%w: bitbucket repository or commit is unknown (BITBUCKET_REPO_FULL_NAME, BITBUCKET_COMMIT)", ErrUpload)
	}
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBitbucketAPI
		if c.Token != "" {
			base = secureBitbucketAPI // never send a token over plain http
		}
	}
	client := c.HTTP
	if client == nil {
		client = c.newClient()
	}
	reportURL := fmt.Sprintf("%s/repositories/%s/commit/%s/reports/%s", base, c.Repo, c.Commit, reportKey)

	result := "PASSED"
	if d.ExitCode() != 0 {
		result = "FAILED"
	}
	body := ciReport{
		Title:      reportKey,
		Details:    cutRunes(firstLine(Summary(r, d, 0)), maxDetails),
		ReportType: "SECURITY",
		Reporter:   reportKey,
		Result:     result,
		Data: []ciData{
			{Title: "New findings", Type: "NUMBER", Value: d.New},
			{Title: "Total findings", Type: "NUMBER", Value: d.Total},
		},
	}
	if err := c.send(ctx, client, http.MethodPut, reportURL, body); err != nil {
		return err
	}
	anns := annotations(r, d)
	for i := 0; i < len(anns); i += annotationBatch {
		end := min(i+annotationBatch, len(anns))
		if err := c.send(ctx, client, http.MethodPost, reportURL+"/annotations", anns[i:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c CodeInsights) newClient() *http.Client {
	tr := &http.Transport{}
	if c.Proxy != "" && c.Token == "" {
		if u, err := url.Parse(c.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

// send marshals body and issues the request. Errors never contain the token.
func (c CodeInsights) send(ctx context.Context, client *http.Client, method, u string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: encode request: %v", ErrUpload, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrUpload, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%w: %s bitbucket: %v", ErrUpload, method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		return fmt.Errorf("%w: %s bitbucket: HTTP %d: %s", ErrUpload, method, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

type annKey struct {
	fp, id, file string
	line         int
}

func keyOf(f finding.Finding) annKey { return annKey{f.Fingerprint, f.ID, f.File, f.Line} }

// annotations orders findings (blocking first, then severity descending) and
// caps them at maxAnnotations.
func annotations(r finding.Result, d policy.Decision) []ciAnnotation {
	blocking := make(map[annKey]bool, len(d.Blocking))
	for _, f := range d.Blocking {
		blocking[keyOf(f)] = true
	}
	fs := append([]finding.Finding(nil), r.Findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		bi, bj := blocking[keyOf(fs[i])], blocking[keyOf(fs[j])]
		if bi != bj {
			return bi
		}
		return fs[i].Severity > fs[j].Severity
	})
	if len(fs) > maxAnnotations {
		fs = fs[:maxAnnotations]
	}
	out := make([]ciAnnotation, 0, len(fs))
	for _, f := range fs {
		out = append(out, ciAnnotation{
			ExternalID:     cutRunes(f.Fingerprint, maxExternalID),
			AnnotationType: "VULNERABILITY",
			Summary:        cutRunes(strings.TrimSpace(f.ID+" "+f.Message), maxAnnotationSummary),
			Severity:       ciSeverity(f.Severity),
			Path:           f.File,
			Line:           f.Line,
		})
	}
	return out
}

func ciSeverity(s finding.Severity) string {
	switch {
	case s >= finding.Critical:
		return "CRITICAL"
	case s == finding.High:
		return "HIGH"
	case s == finding.Medium:
		return "MEDIUM"
	}
	return "LOW"
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(strings.TrimLeft(line, "# "))
}

// cutRunes truncates s to at most n bytes without splitting a rune.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
