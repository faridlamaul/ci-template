package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint returns a line-independent identity for a finding.
func Fingerprint(ruleID, file, key string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + file + "\x00" + NormalizeSnippet(key)))
	return hex.EncodeToString(sum[:])
}

// NormalizeSnippet collapses all whitespace runs to one space and trims.
func NormalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// SecretKey returns the sha256 hex of a secret; the only form a secret may take.
func SecretKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
