package ruby

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

var update = flag.Bool("update", false, "update golden files")

var defaults = map[string]string{"RUBY_DEFAULT": "3.4"}

func project(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for n, c := range files {
		p := filepath.Join(d, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func fakeEnv(dir string) ci.Env {
	return ci.Env{Dir: dir, Defaults: defaults, Tools: func(_ context.Context, n string) (string, error) { return "/tools/" + n, nil }}
}

func lock(gems ...string) string {
	s := "GEM\n  remote: https://rubygems.org/\n  specs:\n"
	for _, g := range gems {
		s += "    " + g + " (1.0.0)\n"
	}
	return s + "\nDEPENDENCIES\n"
}

func TestRubyVersionForms(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
		src   string
	}{
		{"ruby-version", map[string]string{".ruby-version": "# c\n\n3.2.4\n"}, "3.2.4", ".ruby-version"},
		{"ruby- prefix", map[string]string{".ruby-version": "ruby-3.3.1\n"}, "3.3.1", ".ruby-version"},
		{"wins over gemfile", map[string]string{".ruby-version": "3.1", "Gemfile": `ruby "3.3.1"`}, "3.1", ".ruby-version"},
		{"gemfile double", map[string]string{"Gemfile": "source 'x'\nruby \"3.3.1\"\n"}, "3.3.1", "Gemfile"},
		{"gemfile single", map[string]string{"Gemfile": "ruby '3.3'  # c\n"}, "3.3", "Gemfile"},
		{"gemfile file form", map[string]string{"Gemfile": `ruby file: ".ruby-version"`}, "3.4", "default"},
		{"commented", map[string]string{"Gemfile": "# ruby \"3.0\"\n"}, "3.4", "default"},
		{"none", map[string]string{"Gemfile": "source 'x'\n"}, "3.4", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det, err := Ruby{}.Detect(project(t, c.files), defaults)
			if err != nil {
				t.Fatal(err)
			}
			if det.Version != c.want || det.Source != c.src || det.Language != "ruby" {
				t.Fatalf("got %+v", det)
			}
		})
	}
}

func TestRubyTestRunner(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // joined argv, or "" for skip
	}{
		{"rspec", map[string]string{"spec/a_spec.rb": "", "Gemfile.lock": lock("rspec-core", "rake")}, "bundle exec rspec"},
		{"spec dir without rspec-core falls to rake", map[string]string{"spec/a_spec.rb": "", "Gemfile.lock": lock("rake")}, "bundle exec rake test"},
		{"rspec-core without spec dir", map[string]string{"Gemfile.lock": lock("rspec-core", "rake")}, "bundle exec rake test"},
		{"rake", map[string]string{"Gemfile.lock": lock("rake")}, "bundle exec rake test"},
		{"substring is not a match", map[string]string{"Gemfile.lock": lock("rake-compiler")}, ""},
		{"none", map[string]string{"Gemfile.lock": lock("rack")}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			steps, err := Ruby{}.Steps(context.Background(), fakeEnv(project(t, c.files)), ci.Detection{}, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			s := steps[2]
			if s.Name != "test" {
				t.Fatalf("step = %s", s.Name)
			}
			if c.want == "" {
				if s.Skip != "no rspec or rake test found" || len(s.Cmds) != 0 {
					t.Fatalf("step = %+v", s)
				}
				return
			}
			if len(s.Cmds) != 1 || strings.Join(s.Cmds[0].Argv, " ") != c.want || len(s.JUnit) != 0 || s.Coverage != "" {
				t.Fatalf("step = %+v", s)
			}
		})
	}
}

func TestRubyInstallAndBuildErrors(t *testing.T) {
	_, err := Ruby{}.Steps(context.Background(), fakeEnv(project(t, map[string]string{"Gemfile": ""})), ci.Detection{}, policy.CIConfig{})
	if err == nil || !strings.Contains(err.Error(), "Gemfile.lock is missing; commit it (bundle lock)") {
		t.Fatalf("err = %v", err)
	}
	_, err = Ruby{}.Steps(context.Background(), fakeEnv(project(t, map[string]string{"Gemfile.lock": lock(), "a.gemspec": "", "b.gemspec": ""})), ci.Detection{}, policy.CIConfig{})
	if err == nil || !strings.Contains(err.Error(), "a.gemspec") || !strings.Contains(err.Error(), "b.gemspec") {
		t.Fatalf("err = %v", err)
	}
}

type goldenStep struct {
	Name     ci.StepName
	Cmds     []ci.Cmd
	JUnit    []string
	Coverage string
	Skip     string
	Timeout  time.Duration
	HasAfter bool
}

func marshal(t *testing.T, steps []ci.Step) []byte {
	t.Helper()
	var out []goldenStep
	for _, s := range steps {
		out = append(out, goldenStep{s.Name, s.Cmds, s.JUnit, s.Coverage, s.Skip, s.Timeout, s.After != nil})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\ngot:\n%s\nwant:\n%s", name, got, want)
	}
}

func TestStepsRuby(t *testing.T) {
	for _, c := range []string{"rspec", "rake", "bare"} {
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join("testdata", c)
			det, err := Ruby{}.Detect(dir, defaults)
			if err != nil {
				t.Fatal(err)
			}
			steps, err := Ruby{}.Steps(context.Background(), fakeEnv(dir), det, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "steps-"+c+".golden.json", marshal(t, steps))
		})
	}
}

func TestOverrideRuby(t *testing.T) {
	off := false
	var cfg policy.CIConfig
	cfg.Timeouts.PerStep = time.Minute
	cfg.Steps.Lint.Enabled = &off
	cfg.Steps.Test = policy.CIStep{Run: "make t", JUnit: []string{"j/*.xml"}, Coverage: "c.xml"}
	cfg.Steps.Build = policy.CIStep{Run: "make b"}
	// two gemspecs: a run override must not trip the default build's error
	dir := project(t, map[string]string{"Gemfile.lock": lock(), "a.gemspec": "", "b.gemspec": ""})
	steps, err := Ruby{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "steps-override.golden.json", marshal(t, steps))
}

func TestToolchain(t *testing.T) {
	var got []string
	v, err := Ruby{}.Toolchain(context.Background(), func(_ context.Context, argv ...string) (string, error) {
		got = argv
		return "3.3.1\n", nil
	})
	if err != nil || v != "3.3.1" || strings.Join(got, " ") != "ruby -e print RUBY_VERSION" {
		t.Fatalf("%q %v %v", v, err, got)
	}
}
