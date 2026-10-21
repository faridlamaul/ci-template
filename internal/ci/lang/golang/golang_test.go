package golang

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

var update = flag.Bool("update", false, "update golden files")

func writeMod(t *testing.T, content string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestGoVersionFromGoMod(t *testing.T) {
	cases := []struct {
		name, mod, want, source, errSub string
	}{
		{"toolchain", "module m\n\ngo 1.27\n\ntoolchain go1.27.2\n", "1.27.2", "go.mod", ""},
		{"go only", "module m\n\ngo 1.27\n", "1.27", "go.mod", ""},
		{"go with patch", "module m\n\ngo 1.27.1\n", "1.27.1", "go.mod", ""},
		{"toolchain default", "module m\n\ngo 1.27\n\ntoolchain default\n", "1.27", "go.mod", ""},
		{"toolchain local", "module m\n\ngo 1.27.1\n\ntoolchain local\n", "1.27.1", "go.mod", ""},
		{"missing go", "module m\n", "", "default", "go.mod has no go directive"},
		{"malformed", "module m\n\ngo\n", "", "", "go.mod"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det, err := Go{}.Detect(writeMod(t, c.mod), nil)
			if c.errSub != "" {
				if err == nil || !bytes.Contains([]byte(err.Error()), []byte(c.errSub)) {
					t.Fatalf("err = %v, want containing %q", err, c.errSub)
				}
				if c.source != "" && det.Source != c.source {
					t.Fatalf("source = %q", det.Source)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if det.Version != c.want || det.Source != c.source || det.Language != "go" {
				t.Fatalf("got %+v", det)
			}
		})
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

func fakeEnv(dir string) ci.Env {
	return ci.Env{Dir: dir, Tools: func(_ context.Context, n string) (string, error) { return "/tools/" + n, nil }}
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

func TestStepsGo(t *testing.T) {
	dir := filepath.Join("testdata", "basic")
	det, err := Go{}.Detect(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := Go{}.Steps(context.Background(), fakeEnv(dir), det, policy.CIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "steps-basic.golden.json", marshal(t, steps))
}

func TestOverrideGo(t *testing.T) {
	off := false
	var cfg policy.CIConfig
	cfg.Timeouts.PerStep = time.Minute
	cfg.Steps.Lint.Enabled = &off
	cfg.Steps.Test = policy.CIStep{Run: "make t", JUnit: []string{"j/*.xml"}, Coverage: "c.xml"}
	called := []string{}
	env := ci.Env{Dir: "testdata/basic", Tools: func(_ context.Context, n string) (string, error) {
		called = append(called, n)
		return "/tools/" + n, nil
	}}
	steps, err := Go{}.Steps(context.Background(), env, ci.Detection{Language: "go", Version: "1.27"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "steps-override.golden.json", marshal(t, steps))
	for _, s := range steps {
		if s.Name == "test" && (s.After != nil || len(s.JUnit) != 1 || s.JUnit[0] != "j/*.xml" || s.Coverage != "c.xml") {
			t.Fatalf("test step = %+v", s)
		}
	}
	if len(called) != 0 {
		t.Fatalf("tools fetched: %v", called)
	}
}

func TestToolchain(t *testing.T) {
	v, err := Go{}.Toolchain(context.Background(), func(_ context.Context, argv ...string) (string, error) {
		return "go1.27.2\n", nil
	})
	if err != nil || v != "1.27.2" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestCoverToCobertura(t *testing.T) {
	var buf bytes.Buffer
	if err := CoverToCobertura(filepath.Join("testdata", "cover", "cover.out"), filepath.Join("testdata", "cover"), &buf); err != nil {
		t.Fatal(err)
	}
	golden(t, "cobertura.golden.xml", buf.Bytes())
}

func TestAfterMissingProfile(t *testing.T) {
	dir := t.TempDir()
	s := testStep(t, dir)
	if err := s.After(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard/ci/coverage.xml")); err == nil {
		t.Fatal("coverage written")
	}
}

func testStep(t *testing.T, dir string) ci.Step {
	t.Helper()
	steps, err := Go{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Name == "test" {
			if s.After == nil {
				t.Fatal("test step has no After")
			}
			return s
		}
	}
	t.Fatal("no test step")
	return ci.Step{}
}

func TestAfterWritesCoverage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".shipguard/ci"), 0o755); err != nil {
		t.Fatal(err)
	}
	for src, dst := range map[string]string{"go.mod": "go.mod", "cover.out": ".shipguard/ci/cover.out"} {
		b, err := os.ReadFile(filepath.Join("testdata", "cover", src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := testStep(t, dir).After(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".shipguard/ci/coverage.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		LinesValid int `xml:"lines-valid,attr"`
	}
	if err := xml.Unmarshal(b, &v); err != nil || v.LinesValid != 8 {
		t.Fatalf("parse: %v lines-valid=%d", err, v.LinesValid)
	}
}
