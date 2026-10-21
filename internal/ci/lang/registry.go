// Package lang registers the supported languages.
package lang

import (
	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/ci/lang/golang"
	"github.com/faridlamaul/shipguard/internal/ci/lang/node"
	"github.com/faridlamaul/shipguard/internal/ci/lang/python"
)

// All returns every supported language.
func All() []ci.Language {
	return []ci.Language{golang.Go{}, node.Node{}, python.Python{}}
}
