package scanner

import (
	"fmt"
	"strings"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// ParseTrivyImage converts a `trivy image --format json` report into SCA
// findings, one per vulnerability and package. image and platform name the
// scanned image in the finding location. An unknown severity is medium, as in
// ParseTrivyConfig.
func ParseTrivyImage(raw []byte, image, platform string) ([]finding.Finding, error) {
	rep, err := decodeTrivy(raw)
	if err != nil {
		return nil, err
	}
	out := []finding.Finding{}
	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			sev, err := finding.ParseSeverity(strings.ToLower(v.Severity))
			if err != nil {
				sev = finding.Medium
			}
			pkg := v.PkgName + "@" + v.InstalledVersion
			loc := fmt.Sprintf("%s (%s) %s", image, platform, pkg)
			msg := fmt.Sprintf("%s is affected by %s", pkg, v.VulnerabilityID)
			if v.Title != "" {
				msg += ": " + finding.NormalizeSnippet(v.Title)
			}
			out = append(out, finding.Finding{
				ID:           v.VulnerabilityID,
				Scanner:      "trivy-image",
				Category:     finding.CategorySCA,
				Severity:     sev,
				File:         loc,
				Message:      msg,
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				FixedVersion: v.FixedVersion,
				FixAvailable: v.FixedVersion != "",
				Fingerprint:  finding.Fingerprint(v.VulnerabilityID, loc, pkg),
			})
		}
	}
	return out, nil
}
