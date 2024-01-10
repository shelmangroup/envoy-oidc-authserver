package authz

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shelmangroup/shelman-authz/oidc"
)

type Config struct {
	Providers []OIDCProvider `yaml:"providers"`
}

type OIDCProvider struct {
	CallbackURI      string   `yaml:"callbackURI"`
	IssuerURL        string   `yaml:"issuerURL"`
	ClientID         string   `yaml:"clientID"`
	ClientSecret     string   `yaml:"clientSecret"`
	Scopes           []string `yaml:"scopes"`
	CookieNamePrefix string   `yaml:"cookieNamePrefix"`
	Match            Match    `yaml:"match"`
	p                oidc.UnimplementedAuthProvider
}

type Match struct {
	HeaderName  string `yaml:"header"`
	ExactMatch  string `yaml:"exact"`
	RegexMatch  string `yaml:"regex"`
	PrefixMatch string `yaml:"prefix"`
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
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
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
