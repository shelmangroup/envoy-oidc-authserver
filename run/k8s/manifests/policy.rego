package envoy.authz

import rego.v1

import input.attributes.request.http

default allow = true

# allow if {
# 	action_allowed
# }
#
# # allow callback path
# action_allowed if {
#     http.headers[":authority"] == "localhost:8000"
#     http.method == "GET"
#     glob.match("/_authz/callback*", ["/"], http.path)
# }
#
# action_allowed if {
#     http.headers[":authority"] == "localhost:8000"
#     http.method == "GET"
#     glob.match("/api/info", ["/"], http.path)
# }
#
# action_allowed if {
#     http.headers[":authority"] == "localhost:8000"
#     http.method == "GET"
#     glob.match("/", ["/"], http.path)
# }
#
