module github.com/shelmangroup/envoy-oidc-authserver

go 1.21.5

require (
	buf.build/gen/go/envoyproxy/envoy/connectrpc/go v1.14.0-20240103202553-5b59168cb472.1
	buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go v1.32.0-20240103202553-5b59168cb472.1
	connectrpc.com/connect v1.14.0
	connectrpc.com/grpchealth v1.3.0
	connectrpc.com/grpcreflect v1.2.0
	connectrpc.com/otelconnect v0.6.0
	github.com/eko/gocache/lib/v4 v4.1.5
	github.com/eko/gocache/store/redis/v4 v4.2.1
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611
	github.com/gogo/googleapis v1.4.1
	github.com/google/uuid v1.6.0
	github.com/grokify/go-pkce v0.2.3
	github.com/stretchr/testify v1.8.4
	github.com/zitadel/oidc/v3 v3.8.1
	go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace v0.46.1
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.46.1
	go.opentelemetry.io/contrib/zpages v0.46.1
	go.opentelemetry.io/otel v1.23.1
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.21.0
	go.opentelemetry.io/otel/sdk v1.21.0
	golang.org/x/net v0.19.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240221002015-b0ce06bbee7c
	google.golang.org/grpc v1.61.0
)

require (
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/prometheus/client_golang v1.18.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require (
	buf.build/gen/go/cncf/xds/protocolbuffers/go v1.32.0-20231212190141-23263dcfaa96.1 // indirect
	buf.build/gen/go/envoyproxy/protoc-gen-validate/protocolbuffers/go v1.32.0-20231130202533-71881f09a0c5.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/eko/gocache/store/go_cache/v4 v4.2.1
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/lmittmann/tint v1.0.3
	github.com/mattn/go-isatty v0.0.20
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/open-policy-agent/opa v0.61.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/peterbourgon/ff/v4 v4.0.0-alpha.4
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/redis/go-redis/v9 v9.4.0
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/zitadel/logging v0.5.0 // indirect
	github.com/zitadel/schema v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.21.0 // indirect
	go.opentelemetry.io/otel/metric v1.23.1 // indirect
	go.opentelemetry.io/otel/trace v1.23.1
	go.opentelemetry.io/proto/otlp v1.0.0 // indirect
	golang.org/x/crypto v0.17.0
	golang.org/x/exp v0.0.0-20230817173708-d852ddb80c63 // indirect
	golang.org/x/oauth2 v0.15.0
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231106174013-bbf56f31fb17 // indirect
	google.golang.org/protobuf v1.32.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1
)
