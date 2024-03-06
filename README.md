# Envoy OIDC Authserver

An implementation of Envoy External Authorization, focused on delivering
authN/Z solutions for Envoy proxy. Compatible with Kubernetes Ingress
classes like [Project Contour](https://projectcontour.io/) or [Istio](https://istio.io).

Some of the features it provides:

- Transparent login

  - Retrieves OAuth2 Access tokens, ID tokens and refresh tokens
  - Compatible with any standard OIDC Provider
  - Supports PKCE flow (public)
  - Logout redirects

- Session management

  - Session tokens and data are cryptographically verifiable.
  - Refreshes expired tokens automatically

- Pre and post authorization policies with Open Policy Agent (OPA) policies.

  - Allowing fine grained policy rules per request.
  - Post authorization token policies (decode JWT and verify claims).
