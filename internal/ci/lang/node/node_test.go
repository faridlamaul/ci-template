package node

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

var defaults = map[string]string{"NODE_DEFAULT": "24", "COREPACK_VERSION": "0.36.0"}

func project(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

const pkgAll = `{"scripts":{"lint":"l","test":"t","build":"b"}}`

func TestNodeVersionForms(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
		src   string
	}{
		{"v22", map[string]string{".nvmrc": "v22\n", "package.json": "{}"}, "22", ".nvmrc"},
		{"crlf", map[string]string{".nvmrc": "22\r\n", "package.json": "{}"}, "22", ".nvmrc"},
		{"lts star", map[string]string{".nvmrc": "lts/*\n", "package.json": "{}"}, "24", ".nvmrc"},
		{"lts name", map[string]string{".nvmrc": "lts/iron\n", "package.json": "{}"}, "24", ".nvmrc"},
		{"node", map[string]string{".node-version": "node\n", "package.json": "{}"}, "24", ".node-version"},
		{"comment first", map[string]string{".nvmrc": "# hi\n\n v20.1.0 \n", "package.json": "{}"}, "20.1.0", ".nvmrc"},
		{"nvmrc wins", map[string]string{".nvmrc": "22", ".node-version": "20", "package.json": "{}"}, "22", ".nvmrc"},
		{"empty nvmrc falls to node-version", map[string]string{".nvmrc": "\n", ".node-version": "20", "package.json": "{}"}, "20", ".node-version"},
		{"engines", map[string]string{"package.json": `{"engines":{"node":">=20 <23"}}`}, ">=20 <23", "package.json"},
		{"none", map[string]string{"package.json": "{}"}, "24", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det, err := Node{}.Detect(project(t, c.files), defaults)
			if err != nil {
				t.Fatal(err)
			}
			if det.Version != c.want || det.Source != c.src || det.Language != "node" {
				t.Fatalf("got %+v", det)
			}
		})
	}
	if _, err := (Node{}).Detect(project(t, map[string]string{"package.json": "{"}), defaults); err == nil {
		t.Fatal("want error for invalid package.json")
	}
}

func TestNodePackageManager(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		first  []string // expected argv of last install cmd
		ncmds  int
		errSub string
	}{
		{"npm", map[string]string{"package-lock.json": "{}"}, []string{"npm", "ci"}, 1, ""},
		{"pnpm", map[string]string{"pnpm-lock.yaml": ""}, []string{"pnpm", "install", "--frozen-lockfile"}, 3, ""},
		{"yarn classic", map[string]string{"yarn.lock": ""}, []string{"yarn", "install", "--frozen-lockfile"}, 3, ""},
		{"yarn berry yarnrc", map[string]string{"yarn.lock": "", ".yarnrc.yml": "x: y"}, []string{"yarn", "install", "--immutable"}, 3, ""},
		{"yarn berry pm", map[string]string{"yarn.lock": "", "package.json": `{"packageManager":"yarn@4.1.0"}`}, []string{"yarn", "install", "--immutable"}, 3, ""},
		{"yarn classic pm", map[string]string{"yarn.lock": "", "package.json": `{"packageManager":"yarn@1.22.19"}`}, []string{"yarn", "install", "--frozen-lockfile"}, 3, ""},
		{"bun.lock", map[string]string{"bun.lock": ""}, []string{"/tools/bun", "install", "--frozen-lockfile"}, 1, ""},
		{"bun.lockb", map[string]string{"bun.lockb": ""}, []string{"/tools/bun", "install", "--frozen-lockfile"}, 1, ""},
		{"none", map[string]string{}, nil, 0, "lockfile"},
		{"two", map[string]string{"package-lock.json": "{}", "yarn.lock": ""}, nil, 0, "package-lock.json, yarn.lock"},
		{"mismatch", map[string]string{"package-lock.json": "{}", "package.json": `{"packageManager":"pnpm@9.0.0"}`}, nil, 0, "pnpm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"package.json": pkgAll}
			for k, v := range c.files {
				files[k] = v
			}
			dir := project(t, files)
			steps, err := Node{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Fatalf("err = %v, want containing %q", err, c.errSub)
				}
				if c.name == "mismatch" && !strings.Contains(err.Error(), "npm") {
					t.Fatalf("err should name both managers: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cmds := steps[0].Cmds
			if len(cmds) != c.ncmds {
				t.Fatalf("cmds = %+v", cmds)
			}
			got := cmds[len(cmds)-1].Argv
			if strings.Join(got, " ") != strings.Join(c.first, " ") {
				t.Fatalf("argv = %v, want %v", got, c.first)
			}
		})
	}
}

// Node 25 and later ship without corepack: pnpm and yarn installs first
// install the pinned corepack with npm when the image has none.
func TestNodeCorepackBootstrap(t *testing.T) {
	const want = "command -v corepack >/dev/null 2>&1 || npm install -g corepack@0.36.0"
	for lock, pm := range map[string]string{"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"} {
		dir := project(t, map[string]string{"package.json": pkgAll, lock: ""})
		steps, err := Node{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
		if err != nil {
			t.Fatal(err)
		}
		cmds := steps[0].Cmds
		if len(cmds) != 3 || cmds[0].Shell != want || cmds[0].Argv != nil {
			t.Fatalf("%s: first cmd = %+v, want shell %q", pm, cmds, want)
		}
		if got := strings.Join(cmds[1].Argv, " "); got != "corepack enable "+pm {
			t.Fatalf("%s: second cmd = %q", pm, got)
		}
	}
	for name, v := range map[string]string{"missing": "", "unsafe": "1.0.0; rm -rf /"} {
		dir := project(t, map[string]string{"package.json": pkgAll, "pnpm-lock.yaml": ""})
		env := fakeEnv(dir)
		env.Defaults = map[string]string{"NODE_DEFAULT": "24", "COREPACK_VERSION": v}
		if _, err := (Node{}).Steps(context.Background(), env, ci.Detection{}, policy.CIConfig{}); err == nil || !strings.Contains(err.Error(), "COREPACK_VERSION") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// npm and bun need no corepack.
	dir := project(t, map[string]string{"package.json": pkgAll, "package-lock.json": "{}"})
	steps, err := Node{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
	if err != nil || len(steps[0].Cmds) != 1 {
		t.Fatalf("npm: %+v, %v", steps, err)
	}
}

func TestNodeScriptExactMatch(t *testing.T) {
	dir := project(t, map[string]string{"package.json": `{"scripts":{"prelint":"x","test":"t"}}`, "package-lock.json": "{}"})
	steps, err := Node{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[ci.StepName]ci.Step{}
	for _, s := range steps {
		by[s.Name] = s
	}
	if by["lint"].Skip != "no lint script in package.json" || len(by["lint"].Cmds) != 0 {
		t.Fatalf("lint = %+v", by["lint"])
	}
	if by["build"].Skip != "no build script in package.json" {
		t.Fatalf("build = %+v", by["build"])
	}
	if by["test"].Skip != "" || len(by["test"].Cmds) != 1 {
		t.Fatalf("test = %+v", by["test"])
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
	return ci.Env{Dir: dir, Defaults: defaults, Tools: func(_ context.Context, n string) (string, error) { return "/tools/" + n, nil }}
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

func TestStepsNode(t *testing.T) {
	for _, c := range []string{"basic", "pnpm", "bun"} {
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join("testdata", c)
			det, err := Node{}.Detect(dir, defaults)
			if err != nil {
				t.Fatal(err)
			}
			steps, err := Node{}.Steps(context.Background(), fakeEnv(dir), det, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "steps-"+c+".golden.json", marshal(t, steps))
		})
	}
}

func TestOverrideNode(t *testing.T) {
	off := false
	var cfg policy.CIConfig
	cfg.Timeouts.PerStep = time.Minute
	cfg.Steps.Lint.Enabled = &off
	cfg.Steps.Test = policy.CIStep{Run: "make t", JUnit: []string{"j/*.xml"}, Coverage: "c.xml"}
	// no build script in package.json: a run override must not be skipped by the script check
	cfg.Steps.Build = policy.CIStep{Run: "make b"}
	dir := project(t, map[string]string{"package.json": `{"scripts":{"lint":"l"}}`, "bun.lock": ""})
	called := []string{}
	env := ci.Env{Dir: dir, Defaults: defaults, Tools: func(_ context.Context, n string) (string, error) {
		called = append(called, n)
		return "/tools/" + n, nil
	}}
	steps, err := Node{}.Steps(context.Background(), env, ci.Detection{Language: "node", Version: "22"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "steps-override.golden.json", marshal(t, steps))
	if len(called) != 1 || called[0] != "bun" {
		t.Fatalf("tools fetched: %v (only install may fetch bun)", called)
	}
}

func TestToolchain(t *testing.T) {
	v, err := Node{}.Toolchain(context.Background(), func(_ context.Context, argv ...string) (string, error) {
		return "v22.1.0\n", nil
	})
	if err != nil || v != "22.1.0" {
		t.Fatalf("%q %v", v, err)
	}
}
