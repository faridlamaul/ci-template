// Package policy loads and validates .shipguard.yaml.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// ErrConfig wraps every configuration validation error.
var ErrConfig = errors.New("invalid config")

// Threshold decides which findings of a category fail the gate.
// YAML forms: "any", "<severity>", or {severity, fix_available_only}.
type Threshold struct {
	Any              bool
	Severity         finding.Severity
	FixAvailableOnly bool
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (t *Threshold) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		if s == "any" {
			*t = Threshold{Any: true}
			return nil
		}
		sev, err := finding.ParseSeverity(s)
		if err != nil {
			return err
		}
		*t = Threshold{Severity: sev}
		return nil
	case yaml.MappingNode:
		var raw struct {
			Severity         *string
			FixAvailableOnly bool
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			switch k.Value {
			case "severity":
				var s string
				if err := v.Decode(&s); err != nil {
					return err
				}
				raw.Severity = &s
			case "fix_available_only":
				if err := v.Decode(&raw.FixAvailableOnly); err != nil {
					return err
				}
			default:
				return fmt.Errorf("line %d: unknown key %q in threshold", k.Line, k.Value)
			}
		}
		if raw.Severity == nil {
			return errors.New("threshold object requires severity")
		}
		sev, err := finding.ParseSeverity(*raw.Severity)
		if err != nil {
			return err
		}
		*t = Threshold{Severity: sev, FixAvailableOnly: raw.FixAvailableOnly}
		return nil
	default:
		return errors.New("threshold must be \"any\", a severity, or {severity, fix_available_only}")
	}
}

// Exception suppresses a finding until Expires (00:00 UTC of the given date).
type Exception struct {
	ID      string
	Path    string
	Reason  string
	Expires time.Time
}

// UnmarshalYAML implements yaml.Unmarshaler. expires accepts only YYYY-MM-DD
// (plain or quoted) and is stored at 00:00 UTC of that date.
func (e *Exception) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: exception must be a mapping", n.Line)
	}
	var out Exception
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "id":
			if err := v.Decode(&out.ID); err != nil {
				return err
			}
		case "path":
			if err := v.Decode(&out.Path); err != nil {
				return err
			}
		case "reason":
			if err := v.Decode(&out.Reason); err != nil {
				return err
			}
		case "expires":
			if v.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: expires must be a YYYY-MM-DD date", v.Line)
			}
			if v.Tag == "!!null" {
				continue // reported as missing by validate
			}
			t, err := time.Parse("2006-01-02", v.Value)
			if err != nil {
				return fmt.Errorf("line %d: expires %q must be a YYYY-MM-DD date", v.Line, v.Value)
			}
			out.Expires = t
		default:
			return fmt.Errorf("line %d: unknown key %q in exception", k.Line, k.Value)
		}
	}
	*e = out
	return nil
}

// Config is the parsed .shipguard.yaml.
type Config struct {
	Version int    `yaml:"version"`
	Mode    string `yaml:"mode"`
	Paths   struct {
		Exclude []string `yaml:"exclude"`
	} `yaml:"paths"`
	Scanners struct {
		Secrets struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"secrets"`
		SAST struct {
			Enabled         bool     `yaml:"enabled"`
			Rules           []string `yaml:"rules"`
			DisableRules    []string `yaml:"disable_rules"`
			DefaultExcludes bool     `yaml:"default_excludes"`
		} `yaml:"sast"`
		SCA struct {
			Enabled  bool `yaml:"enabled"`
			Licenses struct {
				Deny []string `yaml:"deny"`
			} `yaml:"licenses"`
		} `yaml:"sca"`
		IaC struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"iac"`
	} `yaml:"scanners"`
	Timeouts struct {
		PerScanner time.Duration `yaml:"per_scanner"`
	} `yaml:"timeouts"`
	Policy struct {
		FailOn map[finding.Category]Threshold `yaml:"fail_on"`
	} `yaml:"policy"`
	Exceptions []Exception `yaml:"exceptions"`
}

// Defaults returns the built-in configuration.
func Defaults() Config {
	var c Config
	c.Version = 1
	c.Mode = "enforce"
	c.Scanners.Secrets.Enabled = true
	c.Scanners.SAST.Enabled = true
	c.Scanners.SAST.DefaultExcludes = true
	c.Scanners.SCA.Enabled = true
	c.Scanners.IaC.Enabled = true
	c.Timeouts.PerScanner = 15 * time.Minute
	c.Policy.FailOn = map[finding.Category]Threshold{
		finding.CategorySecrets: {Any: true},
		finding.CategorySAST:    {Severity: finding.High},
		finding.CategorySCA:     {Severity: finding.High, FixAvailableOnly: true},
		finding.CategoryIaC:     {Severity: finding.High},
	}
	return c
}

// Parse decodes YAML over Defaults() and validates it.
func Parse(data []byte) (Config, error) {
	c := Defaults()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if err := checkNodes(&doc); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	// Later documents must be empty (a trailing "---", comments or null).
	for {
		var next yaml.Node
		err := dec.Decode(&next)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
		}
		if !emptyDocument(&next) {
			return Config{}, fmt.Errorf("%w: multiple YAML documents are not supported", ErrConfig)
		}
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	return c, nil
}

// Load reads path; a missing file yields Defaults().
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Defaults(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// emptyDocument reports whether doc has no content or only a null scalar.
func emptyDocument(doc *yaml.Node) bool {
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return true
		}
		doc = doc.Content[0]
	}
	return doc.Kind == yaml.ScalarNode && doc.Tag == "!!null"
}

// child returns the value node for key in mapping n, or nil.
func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// durationRe is the per_scanner form the schema allows: ms, s, m and h units
// only, with digits before any decimal point (no sign, no ".5s").
var durationRe = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?(ms|s|m|h))+$`)

// checkNodes rejects shapes that would silently disable gating or that the
// typed decode cannot distinguish (null/empty policy, numeric durations).
func checkNodes(doc *yaml.Node) error {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if p := child(root, "policy"); p != nil {
		if p.Tag == "!!null" {
			return errors.New("policy must not be null")
		}
		if f := child(p, "fail_on"); f != nil && (f.Tag == "!!null" || (f.Kind == yaml.MappingNode && len(f.Content) == 0)) {
			return errors.New("policy.fail_on must not be null or empty")
		}
	}
	if d := child(child(root, "timeouts"), "per_scanner"); d != nil && (d.Tag != "!!str" || !durationRe.MatchString(d.Value)) {
		return fmt.Errorf("line %d: timeouts.per_scanner must be a duration string in ms, s, m or h units such as \"15m\" or \"1h30m\"", d.Line)
	}
	return nil
}

func (c Config) validate() error {
	if len(c.Policy.FailOn) == 0 {
		return errors.New("policy.fail_on must not be empty")
	}
	if c.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", c.Version)
	}
	if c.Mode != "enforce" && c.Mode != "audit" {
		return fmt.Errorf("mode must be enforce or audit, got %q", c.Mode)
	}
	if c.Timeouts.PerScanner <= 0 {
		return errors.New("timeouts.per_scanner must be positive")
	}
	for cat := range c.Policy.FailOn {
		switch cat {
		case finding.CategorySecrets, finding.CategorySAST, finding.CategorySCA, finding.CategoryIaC:
		default:
			return fmt.Errorf("policy.fail_on: unknown category %q", cat)
		}
	}
	for i, p := range c.Paths.Exclude {
		// A pattern ending in "/" is a plain prefix (finding.FilterPaths).
		if !strings.HasSuffix(p, "/") && !doublestar.ValidatePattern(p) {
			return fmt.Errorf("paths.exclude[%d]: invalid glob %q", i, p)
		}
	}
	for i, e := range c.Exceptions {
		if e.Path != "" && !doublestar.ValidatePattern(e.Path) {
			return fmt.Errorf("exceptions[%d].path: invalid glob %q", i, e.Path)
		}
		if e.ID == "" {
			return fmt.Errorf("exceptions[%d]: id is required", i)
		}
		if e.Reason == "" {
			return fmt.Errorf("exceptions[%d] (%s): reason is required", i, e.ID)
		}
		if e.Expires.IsZero() {
			return fmt.Errorf("exceptions[%d] (%s): expires is required", i, e.ID)
		}
	}
	return nil
}
