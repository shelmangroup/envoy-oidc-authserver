# Envoy OIDC Authserver

An implementation of Envoy External Authorization, focused on delivering authN/Z solutions for Envoy L7 proxy.
Compatible with Kubernetes Ingress classes like Projectcontour or Istio.

Some of the features it provides:

- Transparent login

  - Retrieves OAuth2 Access tokens, ID tokens, and refresh tokens
  - Compatible with any standard OIDC Provider

- Session management

  - Refreshes expired tokens automatically

- Open Policy Agent chaining request.
  - Allowing fine grained policy rules per request.
