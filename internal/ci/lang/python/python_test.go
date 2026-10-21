package python

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

var defaults = map[string]string{
	"PYTHON_DEFAULTS": "3.15 3.14 3.13 3.12 3.11",
	"PYTEST_VERSION":  "9.1.1", "COVERAGE_VERSION": "7.16.2", "POETRY_VERSION": "2.5.1",
}

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

func pyproject(req string) string {
	return "[project]\nname = \"x\"\nrequires-python = \"" + req + "\"\n"
}

func TestPythonVersionForms(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		want   string
		src    string
		errSub string
	}{
		{"python-version first line", map[string]string{".python-version": "# c\n\n3.12.4\n3.11\n"}, "3.12.4", ".python-version", ""},
		{"python-version wins", map[string]string{".python-version": "3.10", "pyproject.toml": pyproject(">=3.11")}, "3.10", ".python-version", ""},
		{">=3.11", map[string]string{"pyproject.toml": pyproject(">=3.11")}, "3.15", "pyproject.toml", ""},
		{"~=3.12", map[string]string{"pyproject.toml": pyproject("~=3.12")}, "3.15", "pyproject.toml", ""},
		{"~=3.12.1 style prefix", map[string]string{"pyproject.toml": pyproject("~=3.12.0")}, "3.12", "pyproject.toml", ""},
		{">=3.9,<3.12", map[string]string{"pyproject.toml": pyproject(">=3.9,<3.12")}, "3.11", "pyproject.toml", ""},
		{"spaces", map[string]string{"pyproject.toml": pyproject(">= 3.9 , <= 3.13")}, "3.13", "pyproject.toml", ""},
		{"==3.12.*", map[string]string{"pyproject.toml": pyproject("==3.12.*")}, "3.12", "pyproject.toml", ""},
		{">3.13", map[string]string{"pyproject.toml": pyproject(">3.13")}, "3.15", "pyproject.toml", ""},
		{"single quotes", map[string]string{"pyproject.toml": "[project]\nrequires-python = '<3.13' # c\n"}, "3.12", "pyproject.toml", ""},
		{"other table ignored", map[string]string{"pyproject.toml": "[tool.x]\nrequires-python = \"<3.12\"\n[project]\nname=\"x\"\n"}, "3.15", "default", ""},
		{"none", map[string]string{"requirements.txt": ""}, "3.15", "default", ""},
		{"unsupported !=", map[string]string{"pyproject.toml": pyproject("!=3.10")}, "", "", "!=3.10"},
		{"unsatisfiable", map[string]string{"pyproject.toml": pyproject(">=3.20")}, "", "", ">=3.20"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det, err := Python{}.Detect(project(t, c.files), defaults)
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Fatalf("err = %v, want containing %q", err, c.errSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if det.Version != c.want || det.Source != c.src || det.Language != "python" {
				t.Fatalf("got %+v", det)
			}
		})
	}
}

func fakeEnv(dir string) ci.Env {
	return ci.Env{Dir: dir, Defaults: defaults, Tools: func(_ context.Context, n string) (string, error) { return "/tools/" + n, nil }}
}

func TestPythonInstallModes(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		first  string // joined argv of the first install cmd
		ncmds  int
		env    map[string]string
		errSub string
	}{
		{"uv", map[string]string{"uv.lock": ""}, "/tools/uv sync --frozen", 3, nil, ""},
		{"poetry", map[string]string{"poetry.lock": ""}, "/tools/uv tool run --from poetry==2.5.1 poetry install --sync", 3, map[string]string{"POETRY_VIRTUALENVS_IN_PROJECT": "true"}, ""},
		{"requirements", map[string]string{"requirements.txt": "x"}, "/tools/uv venv .venv", 4, nil, ""},
		{"requirements dev", map[string]string{"requirements.txt": "x", "requirements-dev.txt": "y"}, "/tools/uv venv .venv", 4, nil, ""},
		{"none", map[string]string{"pyproject.toml": "[project]\n"}, "", 0, nil, "lockfile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			steps, err := Python{}.Steps(context.Background(), fakeEnv(project(t, c.files)), ci.Detection{}, policy.CIConfig{})
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Fatalf("err = %v, want containing %q", err, c.errSub)
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
			if got := strings.Join(cmds[0].Argv, " "); got != c.first {
				t.Fatalf("first = %q, want %q", got, c.first)
			}
			if len(c.env) > 0 && cmds[0].Env["POETRY_VIRTUALENVS_IN_PROJECT"] != "true" {
				t.Fatalf("env = %v", cmds[0].Env)
			}
			for _, cm := range cmds {
				if cm.Env["UV_PYTHON"] != "python3" || cm.Env["UV_PYTHON_DOWNLOADS"] != "never" {
					t.Fatalf("uv cmd without UV_PYTHON/UV_PYTHON_DOWNLOADS: %+v", cm)
				}
			}
			last := cmds[len(cmds)-1].Shell
			if !strings.Contains(last, "import coverage") || !strings.Contains(last, "coverage==7.16.2") {
				t.Fatalf("last = %q", last)
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

func TestStepsPython(t *testing.T) {
	for _, c := range []string{"req", "uv", "poetry", "nobuild"} {
		t.Run(c, func(t *testing.T) {
			dir := filepath.Join("testdata", c)
			det, err := Python{}.Detect(dir, defaults)
			if err != nil {
				t.Fatal(err)
			}
			steps, err := Python{}.Steps(context.Background(), fakeEnv(dir), det, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "steps-"+c+".golden.json", marshal(t, steps))
		})
	}
}

func TestOverridePython(t *testing.T) {
	off := false
	var cfg policy.CIConfig
	cfg.Timeouts.PerStep = time.Minute
	cfg.Steps.Lint.Enabled = &off
	cfg.Steps.Test = policy.CIStep{Run: "make t", JUnit: []string{"j/*.xml"}, Coverage: "c.xml"}
	cfg.Steps.Build = policy.CIStep{Run: "make b"}
	dir := project(t, map[string]string{"pyproject.toml": "[project]\nname=\"x\"\n", "uv.lock": ""})
	called := []string{}
	env := ci.Env{Dir: dir, Defaults: defaults, Tools: func(_ context.Context, n string) (string, error) {
		called = append(called, n)
		return "/tools/" + n, nil
	}}
	steps, err := Python{}.Steps(context.Background(), env, ci.Detection{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "steps-override.golden.json", marshal(t, steps))
	if len(called) != 1 || called[0] != "uv" {
		t.Fatalf("tools fetched: %v (only install may fetch uv)", called)
	}
}

func TestToolchain(t *testing.T) {
	v, err := Python{}.Toolchain(context.Background(), func(_ context.Context, argv ...string) (string, error) {
		return "Python 3.12.4\n", nil
	})
	if err != nil || v != "3.12.4" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestRequirementsDevFlag(t *testing.T) {
	dir := project(t, map[string]string{"requirements.txt": "x", "requirements-dev.txt": "y"})
	steps, err := Python{}.Steps(context.Background(), fakeEnv(dir), ci.Detection{}, policy.CIConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(steps[0].Cmds[1].Argv, " "); !strings.HasSuffix(got, "-r requirements.txt -r requirements-dev.txt") {
		t.Fatalf("pip = %q", got)
	}
}

func TestEveryUvCmdPinsInterpreter(t *testing.T) {
	for _, c := range []string{"req", "uv", "poetry"} {
		t.Run(c, func(t *testing.T) {
			steps, err := Python{}.Steps(context.Background(), fakeEnv(filepath.Join("testdata", c)), ci.Detection{}, policy.CIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, s := range steps {
				for _, cm := range s.Cmds {
					if (len(cm.Argv) == 0 || cm.Argv[0] != "/tools/uv") && !strings.Contains(cm.Shell, "/tools/uv") {
						continue
					}
					n++
					if cm.Env["UV_PYTHON"] != "python3" || cm.Env["UV_PYTHON_DOWNLOADS"] != "never" {
						t.Fatalf("%s: uv cmd missing env: %+v", s.Name, cm)
					}
				}
			}
			if n < 4 {
				t.Fatalf("only %d uv cmds found (build step included?)", n)
			}
		})
	}
}
