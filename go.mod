module github.com/shelmangroup/envoy-oidc-authserver

go 1.22.3

require (
	buf.build/gen/go/envoyproxy/envoy/connectrpc/go v1.16.2-20240617172853-7c298ee915bf.1
	buf.build/gen/go/envoyproxy/envoy/protocolbuffers/go v1.34.2-20240617172853-7c298ee915bf.2
	connectrpc.com/connect v1.16.2
	connectrpc.com/grpchealth v1.3.0
	connectrpc.com/grpcreflect v1.2.0
	connectrpc.com/otelconnect v0.7.0
	github.com/eko/gocache/lib/v4 v4.1.6
	github.com/eko/gocache/store/redis/v4 v4.2.2
	github.com/fernet/fernet-go v0.0.0-20240119011108-303da6aec611
	github.com/gogo/googleapis v1.4.1
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.9.0
	github.com/zitadel/oidc/v3 v3.25.1
	go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace v0.52.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.52.0
	go.opentelemetry.io/otel v1.27.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.27.0
	go.opentelemetry.io/otel/sdk v1.27.0
	golang.org/x/net v0.26.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240617180043-68d350f18fd4
)

require (
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.54.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require (
	buf.build/gen/go/cncf/xds/protocolbuffers/go v1.34.2-20240422202033-c42b0ebe1c45.2 // indirect
	buf.build/gen/go/envoyproxy/protoc-gen-validate/protocolbuffers/go v1.34.2-20240617172848-daf171c6cdb5.2 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/eko/gocache/store/go_cache/v4 v4.2.2
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/lmittmann/tint v1.0.4
	github.com/matthewhartstonge/pkce v0.1.2
	github.com/mattn/go-isatty v0.0.20
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/open-policy-agent/opa v0.65.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/peterbourgon/ff/v4 v4.0.0-alpha.4
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/redis/go-redis/v9 v9.5.3
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/zitadel/logging v0.6.0 // indirect
	github.com/zitadel/schema v1.3.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.27.0 // indirect
	go.opentelemetry.io/otel/metric v1.27.0 // indirect
	go.opentelemetry.io/otel/trace v1.27.0
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	golang.org/x/crypto v0.24.0
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/oauth2 v0.21.0
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240617180043-68d350f18fd4 // indirect
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1
)
