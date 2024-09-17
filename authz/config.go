package authz

import (
	"log/slog"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shelmangroup/envoy-oidc-authserver/oidc"
	"github.com/shelmangroup/envoy-oidc-authserver/policy"
)

type Config struct {
	SessionExpiration string         `yaml:"sessionExpiration"`
	Providers         []OIDCProvider `yaml:"providers"`
}

type LogoutConfig struct {
	RedirectURI string `yaml:"redirectURI"`
	Path        string `yaml:"path"`
}

type OIDCProvider struct {
	p              oidc.UnimplementedAuthProvider
	preAuthPolicy  *policy.Policy
	postAuthPolicy *policy.Policy

	HeaderMatch                    HeaderMatch  `yaml:"headerMatch"`
	Logout                         LogoutConfig `yaml:"logout"`
	ClientID                       string       `yaml:"clientID"`
	CallbackURI                    string       `yaml:"callbackURI"`
	ClientSecret                   string       `yaml:"clientSecret"`
	CookieNamePrefix               string       `yaml:"cookieNamePrefix"`
	PreAuthPolicy                  string       `yaml:"preAuthPolicy"`
	PostAuthPolicy                 string       `yaml:"postAuthPolicy"`
	IssuerURL                      string       `yaml:"issuerURL"`
	Scopes                         []string     `yaml:"scopes"`
	DisableSecureCookie            bool         `yaml:"disableSecureCookie"`
	DisablePassAuthorizationHeader bool         `yaml:"disablePassAuthorizationHeader"`
	DisableSourceAddressCheck      bool         `yaml:"disableSourceAddressCheck"`
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

		if c.PreAuthPolicy != "" {
			cfg.Providers[i].preAuthPolicy, err = policy.NewPolicy("PreAuth", c.PreAuthPolicy)
			if err != nil {
				return nil, err
			}
			slog.Info("loaded pre-auth policy", slog.String("issuer", c.IssuerURL))
		}
		if c.PostAuthPolicy != "" {
			cfg.Providers[i].postAuthPolicy, err = policy.NewPolicy("PostAuth", c.PostAuthPolicy)
			if err != nil {
				return nil, err
			}
			slog.Info("loaded post-auth policy", slog.String("issuer", c.IssuerURL))
		}
	}
	return cfg, nil
}

func ConfigFromYamlFile(filename string) (*Config, error) {
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
				slog.Debug("header match exact", slog.String("name", headerName), slog.String("value", headerValue))
				return &p
			case p.HeaderMatch.Regex != "" && regexp.MustCompile(p.HeaderMatch.Regex).MatchString(headerValue):
				slog.Debug("header match regex", slog.String("name", headerName), slog.String("value", headerValue))
				return &p
			case p.HeaderMatch.Prefix != "" && strings.HasPrefix(headerValue, p.HeaderMatch.Prefix):
				slog.Debug("header match prefix", slog.String("name", headerName), slog.String("value", headerValue))
				return &p
			}
		}
	}
	return nil
}
