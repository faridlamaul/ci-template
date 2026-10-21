package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

type fake struct {
	name    string
	markers []string
}

func (f fake) Name() string      { return f.name }
func (f fake) Markers() []string { return f.markers }
func (f fake) Detect(string, map[string]string) (ci.Detection, error) {
	return ci.Detection{Language: f.name, Version: "1.0", Source: f.markers[0]}, nil
}
func (f fake) Toolchain(context.Context, func(context.Context, ...string) (string, error)) (string, error) {
	return "", nil
}
func (f fake) Steps(context.Context, ci.Env, ci.Detection, policy.CIConfig) ([]ci.Step, error) {
	return nil, nil
}

var langs = []ci.Language{
	fake{"go", []string{"go.mod"}},
	fake{"node", []string{"package.json"}},
	fake{"python", []string{"pyproject.toml", "requirements.txt"}},
}

func dirWith(t *testing.T, files ...string) string {
	t.Helper()
	d := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(d, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestDetectSingleMarker(t *testing.T) {
	l, det, err := Detect(dirWith(t, "go.mod"), policy.CIConfig{}, langs, nil)
	if err != nil || l.Name() != "go" || det.Version != "1.0" {
		t.Fatalf("got %v %+v %v", l, det, err)
	}
}

func TestDetectMultipleMarkersOfOneLanguage(t *testing.T) {
	l, _, err := Detect(dirWith(t, "pyproject.toml", "requirements.txt"), policy.CIConfig{}, langs, nil)
	if err != nil || l.Name() != "python" {
		t.Fatalf("got %v %v", l, err)
	}
}

func TestDetectAmbiguousMarkers(t *testing.T) {
	_, _, err := Detect(dirWith(t, "go.mod", "package.json"), policy.CIConfig{}, langs, nil)
	if err == nil {
		t.Fatal("want error")
	}
	for _, s := range []string{"go.mod", "package.json", "ci.language"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q lacks %q", err, s)
		}
	}
}

func TestDetectNoMarker(t *testing.T) {
	_, _, err := Detect(t.TempDir(), policy.CIConfig{}, langs, nil)
	if err == nil {
		t.Fatal("want error")
	}
	for _, s := range []string{"go.mod", "package.json", "pyproject.toml", "requirements.txt"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q lacks %q", err, s)
		}
	}
}

func TestDetectConfigLanguageWins(t *testing.T) {
	cfg := policy.CIConfig{Language: "golang"}
	l, _, err := Detect(dirWith(t, "go.mod", "package.json"), cfg, langs, nil)
	if err != nil || l.Name() != "go" {
		t.Fatalf("got %v %v", l, err)
	}
}

func TestDetectConfigLanguageMissingMarker(t *testing.T) {
	_, _, err := Detect(dirWith(t, "package.json"), policy.CIConfig{Language: "go"}, langs, nil)
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Fatalf("got %v", err)
	}
}

func TestDetectUnknownConfigLanguage(t *testing.T) {
	_, _, err := Detect(dirWith(t, "go.mod"), policy.CIConfig{Language: "cobol"}, langs, nil)
	if err == nil || !strings.Contains(err.Error(), "cobol") {
		t.Fatalf("got %v", err)
	}
}

func TestDetectConfigVersionWins(t *testing.T) {
	cfg := policy.CIConfig{Version: "9.9"}
	_, det, err := Detect(dirWith(t, "go.mod"), cfg, langs, nil)
	if err != nil || det.Version != "9.9" || det.Source != "config" || det.Language != "go" {
		t.Fatalf("got %+v %v", det, err)
	}
}
