package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderMatch(t *testing.T) {
	// exact
	exactMatch := Config{
		Providers: []OIDCProvider{
			{
				HeaderMatch: HeaderMatch{
					Name:  "X-Test",
					Exact: "test",
				},
			},
		},
	}
	p := exactMatch.Match("X-Test", "test")
	assert.NotNil(t, p)
	p = exactMatch.Match("X-Test", "foo-bar")
	assert.Nil(t, p)

	// regex
	regexMatch := Config{
		Providers: []OIDCProvider{
			{
				HeaderMatch: HeaderMatch{
					Name:  "X-Test",
					Regex: "^test-.*$",
				},
			},
		},
	}
	p = regexMatch.Match("X-Test", "test-foo-bar")
	assert.NotNil(t, p)
	p = regexMatch.Match("X-Test", "foo-bar")
	assert.Nil(t, p)

	// prefix
	prefixMatch := Config{
		Providers: []OIDCProvider{
			{
				HeaderMatch: HeaderMatch{
					Name:  "X-Test",
					Regex: "test",
				},
			},
		},
	}
	p = prefixMatch.Match("X-Test", "test-foo-bar")
	assert.NotNil(t, p)
	p = prefixMatch.Match("X-Test", "foo-bar")
	assert.Nil(t, p)
}
