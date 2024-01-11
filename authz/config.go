package authz

import (
	"log/slog"
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
	p oidc.UnimplementedAuthProvider

	IssuerURL        string      `yaml:"issuerURL"`
	CallbackURI      string      `yaml:"callbackURI"`
	ClientID         string      `yaml:"clientID"`
	ClientSecret     string      `yaml:"clientSecret"`
	Scopes           []string    `yaml:"scopes"`
	CookieNamePrefix string      `yaml:"cookieNamePrefix"`
	HeaderMatch      HeaderMatch `yaml:"headerMatch"`
}

type HeaderMatch struct {
	Name   string `yaml:"name"`
	Exact  string `yaml:"exact"`
	Regex  string `yaml:"regex"`
	Prefix string `yaml:"prefix"`
}

func initialize(cfg *Config) (*Config, error) {
	// Create OIDC providers
	for i, c := range cfg.Providers {
		slog.Info("Configuring OIDC provider", slog.String("issuer", c.IssuerURL))
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
		if strings.EqualFold(p.HeaderMatch.Name, headerName) {
			switch {
			case p.HeaderMatch.Exact == headerValue:
				return &p
			case p.HeaderMatch.Regex != "" && regexp.MustCompile(p.HeaderMatch.Regex).MatchString(headerValue):
				return &p
			case p.HeaderMatch.Prefix != "" && strings.HasPrefix(headerValue, p.HeaderMatch.Prefix):
				return &p
			}
		}
	}
	return nil
}
