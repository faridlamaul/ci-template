package golang

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type xmlLine struct {
	Number int `xml:"number,attr"`
	Hits   int `xml:"hits,attr"`
}

type xmlClass struct {
	Name     string    `xml:"name,attr"`
	Filename string    `xml:"filename,attr"`
	LineRate string    `xml:"line-rate,attr"`
	Branch   string    `xml:"branch-rate,attr"`
	Lines    []xmlLine `xml:"lines>line"`
}

type xmlPackage struct {
	Name     string     `xml:"name,attr"`
	LineRate string     `xml:"line-rate,attr"`
	Branch   string     `xml:"branch-rate,attr"`
	Classes  []xmlClass `xml:"classes>class"`
}

type xmlCoverage struct {
	XMLName      xml.Name     `xml:"coverage"`
	LineRate     string       `xml:"line-rate,attr"`
	BranchRate   string       `xml:"branch-rate,attr"`
	LinesCovered int          `xml:"lines-covered,attr"`
	LinesValid   int          `xml:"lines-valid,attr"`
	Version      string       `xml:"version,attr"`
	Timestamp    string       `xml:"timestamp,attr"`
	Sources      []string     `xml:"sources>source"`
	Packages     []xmlPackage `xml:"packages>package"`
}

func rate(covered, valid int) string {
	if valid == 0 {
		return "0"
	}
	return strconv.FormatFloat(float64(covered)/float64(valid), 'f', 4, 64)
}

func tally(lines []xmlLine) (covered int) {
	for _, l := range lines {
		if l.Hits > 0 {
			covered++
		}
	}
	return covered
}

// CoverToCobertura converts a Go cover profile into Cobertura XML. moduleDir
// holds go.mod; import paths are mapped to files relative to it. Each
// statement block counts every line it spans, and duplicates merge by max hits.
func CoverToCobertura(profile, moduleDir string, w io.Writer) error {
	m, err := parseGoMod(filepath.Join(moduleDir, "go.mod"))
	if err != nil {
		return err
	}
	if m.module == "" {
		return fmt.Errorf("go.mod has no module directive")
	}
	f, err := os.Open(profile)
	if err != nil {
		return fmt.Errorf("open cover profile: %w", err)
	}
	defer f.Close()

	files := map[string]map[int]int{} // module-relative file -> line -> hits
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "mode:") {
			continue
		}
		colon := strings.LastIndex(text, ":")
		fs := strings.Fields(text[colon+1:])
		if colon < 0 || len(fs) != 3 {
			return fmt.Errorf("malformed cover profile line %q", text)
		}
		var sl, sc2, el, ec int
		if _, err := fmt.Sscanf(fs[0], "%d.%d,%d.%d", &sl, &sc2, &el, &ec); err != nil {
			return fmt.Errorf("malformed cover profile range %q: %w", fs[0], err)
		}
		count, err := strconv.Atoi(fs[2])
		if err != nil {
			return fmt.Errorf("malformed cover profile count %q: %w", fs[2], err)
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(text[:colon], m.module), "/")
		lm := files[rel]
		if lm == nil {
			lm = map[int]int{}
			files[rel] = lm
		}
		for l := sl; l <= el; l++ {
			if h, ok := lm[l]; !ok || count > h {
				lm[l] = count
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read cover profile: %w", err)
	}

	byPkg := map[string][]string{}
	for rel := range files {
		d := path.Dir(rel)
		byPkg[d] = append(byPkg[d], rel)
	}
	pkgNames := make([]string, 0, len(byPkg))
	for d := range byPkg {
		pkgNames = append(pkgNames, d)
	}
	sort.Strings(pkgNames)

	cov := xmlCoverage{BranchRate: "0", Version: "1", Timestamp: "0", Sources: []string{moduleDir}}
	totalCov, totalValid := 0, 0
	for _, d := range pkgNames {
		sort.Strings(byPkg[d])
		pkg := xmlPackage{Name: d, Branch: "0"}
		pc, pv := 0, 0
		for _, rel := range byPkg[d] {
			nums := make([]int, 0, len(files[rel]))
			for n := range files[rel] {
				nums = append(nums, n)
			}
			sort.Ints(nums)
			cl := xmlClass{Name: path.Base(rel), Filename: rel, Branch: "0"}
			for _, n := range nums {
				cl.Lines = append(cl.Lines, xmlLine{Number: n, Hits: files[rel][n]})
			}
			c := tally(cl.Lines)
			cl.LineRate = rate(c, len(cl.Lines))
			pc, pv = pc+c, pv+len(cl.Lines)
			pkg.Classes = append(pkg.Classes, cl)
		}
		pkg.LineRate = rate(pc, pv)
		totalCov, totalValid = totalCov+pc, totalValid+pv
		cov.Packages = append(cov.Packages, pkg)
	}
	cov.LinesCovered, cov.LinesValid = totalCov, totalValid
	cov.LineRate = rate(totalCov, totalValid)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(cov); err != nil {
		return fmt.Errorf("encode cobertura: %w", err)
	}
	_, err = io.WriteString(w, "\n")
	return err
}
