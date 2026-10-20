// Package policy loads and validates .shipguard.yaml.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

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
	ID      string    `yaml:"id"`
	Path    string    `yaml:"path"`
	Reason  string    `yaml:"reason"`
	Expires time.Time `yaml:"expires"`
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
			Enabled      bool     `yaml:"enabled"`
			Rules        []string `yaml:"rules"`
			DisableRules []string `yaml:"disable_rules"`
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
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

func (c Config) validate() error {
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
	for i, e := range c.Exceptions {
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
