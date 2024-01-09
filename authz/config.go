package authz

import (
	"encoding/xml"
	"os"
	"regexp"
	"strings"

	"github.com/shelmangroup/shelman-authz/oidc"
)

type Config struct {
	Providers []OIDCProvider `yaml:"oidc"`
}

type OIDCProvider struct {
	IssuerURL        string   `yaml:"issuer_url"`
	CallbackURI      string   `yaml:"callback_uri"`
	ClientID         string   `yaml:"client_id"`
	ClientSecret     string   `yaml:"client_secret"`
	Scopes           []string `yaml:"scopes"`
	CookieNamePrefix string   `yaml:"cookie_name_prefix"`
	Match            Match    `yaml:"match"`
	p                oidc.UnimplementedAuthProvider
}

type Match struct {
	HeaderName  string `yaml:"header_name"`
	ExactMatch  string `yaml:"exact_match"`
	RegexMatch  string `yaml:"regex_match"`
	PrefixMatch string `yaml:"prefix_match"`
}

func initialize(cfg *Config) (*Config, error) {
	// Create OIDC providers
	for i, c := range cfg.Providers {
		provider, err := oidc.NewOIDCProvider(
			c.ClientID,
			c.ClientSecret,
			c.CallbackURI,
			c.IssuerURL,
			c.Scopes,
		)
		if err != nil {
			return nil, err
		}
		cfg.Providers[i].p = provider
	}
	return cfg, nil
}

func ConfigFromXmlFile(filename string) (*Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := xml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	c, err := initialize(&cfg)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) Match(headerName, headerValue string) *OIDCProvider {
	for _, p := range c.Providers {
		if p.Match.HeaderName == headerName {
			switch {
			case p.Match.ExactMatch == headerValue:
				return &p
			case p.Match.RegexMatch != "" && regexp.MustCompile(p.Match.RegexMatch).MatchString(headerValue):
				return &p
			case p.Match.PrefixMatch != "" && strings.HasPrefix(headerValue, p.Match.PrefixMatch):
				return &p
			}
		}
	}
	return nil
}
