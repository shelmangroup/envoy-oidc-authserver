# Shelman Authz

An implementation of Envoy External Authorization, focused on delivering authN/Z solutions for Kubernetes.

Some of the features it provides:

- Transparent login and logout
  - Retrieves OAuth2 Access tokens, ID tokens, and refresh tokens
  - Compatible with any standard OIDC Provider

- Session management
  - Configuration of session lifetime and idle timeouts
  - Refreshes expired tokens automatically

- Authz server is stateless, all state is stored as encrypted (NaCl) cookie data at the client.

- Open Policy Agent chaining request.
  - Allowing fine grained policy rules per request.
