module github.com/decionis/agent-safe-pipeline/verifiers/kong

go 1.22

require (
	github.com/Kong/go-pdk v0.11.2
	github.com/decionis/agent-safe-pipeline/verifiers/envoy v0.0.0
)

require (
	github.com/gowebpki/jcs v1.0.1 // indirect
	github.com/ugorji/go/codec v1.2.14 // indirect
	google.golang.org/protobuf v1.36.2 // indirect
)

// The verifier library beside this module: the two Go hops verify identically.
replace github.com/decionis/agent-safe-pipeline/verifiers/envoy => ../envoy
