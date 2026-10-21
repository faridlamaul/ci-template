package rust

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

var defaults = map[string]string{"RUST_DEFAULT": "stable"}

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

func TestRustVersionForms(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
		src   string
	}{
		{"toml", map[string]string{"rust-toolchain.toml": "[toolchain]\nchannel = \"1.85.0\"\ncomponents = [\"clippy\"]\n"}, "1.85.0", "rust-toolchain.toml"},
		{"toml single quotes and comment", map[string]string{"rust-toolchain.toml": "# c\n[toolchain]\nchannel = 'nightly-2026-01-01' # pin\n"}, "nightly-2026-01-01", "rust-toolchain.toml"},
		{"toml channel outside section", map[string]string{"rust-toolchain.toml": "[other]\nchannel = \"1.0\"\n"}, "stable", "default"},
		{"toml stable", map[string]string{"rust-toolchain.toml": "[toolchain]\nchannel = \"stable\"\n"}, "stable", "rust-toolchain.toml"},
		{"legacy", map[string]string{"rust-toolchain": "\n1.85\n"}, "1.85", "rust-toolchain"},
		{"legacy toml form", map[string]string{"rust-toolchain": "[toolchain]\nchannel = \"1.80\"\n"}, "1.80", "rust-toolchain"},
		{"toml wins", map[string]string{"rust-toolchain.toml": "[toolchain]\nchannel = \"1.85\"\n", "rust-toolchain": "1.70"}, "1.85", "rust-toolchain.toml"},
		{"none", map[string]string{"Cargo.toml": ""}, "stable", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det, err := Rust{}.Detect(project(t, c.files), defaults)
			if err != nil {
				t.Fatal(err)
			}
			if det.Version != c.want || det.Source != c.src || det.Language != "rust" {
				t.Fatalf("got %+v", det)
			}
		})
	}
	if _, err := (Rust{}).Detect(project(t, nil), map[string]string{}); err == nil {
		t.Fatal("want error for empty RUST_DEFAULT")
	}
}

func TestRustLockedFlag(t *testing.T) {
	for _, locked := range []bool{true, false} {
		files := map[string]string{"Cargo.toml": "[package]\n", "src/lib.rs": ""}
		if locked {
			files["Cargo.lock"] = ""
		}
		steps, err := Rust{}.Steps(context.Background(), fakeEnv(project(t, files)), ci.Detection{}, policy.CIConfig{})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			for _, c := range s.Cmds {
				if c.Shell != "" {
					if strings.Contains(c.Shell, "nextest run") && strings.Contains(c.Shell, "--locked") != locked {
						t.Fatalf("locked=%v shell=%q", locked, c.Shell)
					}
					continue
				}
				line := strings.Join(c.Argv, " ")
				if strings.HasPrefix(line, "cargo fmt") {
					continue
				}
				if has := strings.Contains(line, "--locked"); has != locked {
					t.Fatalf("locked=%v %q", locked, line)
				}
			}
		}
	}
}

func TestRustLibTarget(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		doc   bool
	}{
		{"src/lib.rs", map[string]string{"Cargo.toml": "[package]\n", "src/lib.rs": ""}, true},
		{"lib table", map[string]string{"Cargo.toml": "[package]\n\n[lib]\npath = \"x.rs\"\n"}, true},
		{"bin only", map[string]string{"Cargo.toml": "[package]\n", "src/main.rs": ""}, false},
		{"lib in comment", map[string]string{"Cargo.toml": "# [lib]\n[package]\n"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			steps, err := Rust{}.Steps(context.Background(), fakeEnv(project(t, c.files)), ci.Detection{}, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			cmds := steps[2].Cmds
			if c.doc != (len(cmds) == 3) {
				t.Fatalf("cmds = %+v", cmds)
			}
			if c.doc && strings.Join(cmds[2].Argv, " ") != "cargo test --doc" {
				t.Fatalf("doc cmd = %+v", cmds[2])
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

func TestStepsRust(t *testing.T) {
	for _, c := range []string{"lib", "bin", "nolock"} {
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join("testdata", c)
			det, err := Rust{}.Detect(dir, defaults)
			if err != nil {
				t.Fatal(err)
			}
			steps, err := Rust{}.Steps(context.Background(), fakeEnv(dir), det, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "steps-"+c+".golden.json", marshal(t, steps))
		})
	}
}

func TestOverrideRust(t *testing.T) {
	off := false
	var cfg policy.CIConfig
	cfg.Timeouts.PerStep = time.Minute
	cfg.Steps.Lint.Enabled = &off
	cfg.Steps.Test = policy.CIStep{Run: "make t", JUnit: []string{"j/*.xml"}, Coverage: "c.xml"}
	cfg.Steps.Build = policy.CIStep{Run: "make b"}
	tools := 0
	env := fakeEnv(project(t, map[string]string{"Cargo.toml": ""}))
	env.Tools = func(context.Context, string) (string, error) { tools++; return "", nil }
	steps, err := Rust{}.Steps(context.Background(), env, ci.Detection{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tools != 0 {
		t.Fatalf("tools fetched %d times", tools)
	}
	golden(t, "steps-override.golden.json", marshal(t, steps))
}

func TestToolchain(t *testing.T) {
	var got []string
	v, err := Rust{}.Toolchain(context.Background(), func(_ context.Context, argv ...string) (string, error) {
		got = argv
		return "rustc 1.85.0 (4d91de4e4 2025-02-17)\n", nil
	})
	if err != nil || v != "1.85.0" || strings.Join(got, " ") != "rustc --version" {
		t.Fatalf("%q %v %v", v, err, got)
	}
	if _, err := (Rust{}).Toolchain(context.Background(), func(context.Context, ...string) (string, error) { return "x", nil }); err == nil {
		t.Fatal("want error on unparsable output")
	}
}
