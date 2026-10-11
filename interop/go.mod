// Test-only module: github.com/cB-Sigma/mbus against the published test
// data of other M-Bus implementations (see doc.go). Not part of the
// published module; nothing here is imported by it.
module github.com/cB-Sigma/mbus/interop

go 1.27.1

require github.com/cB-Sigma/mbus v0.0.0

require (
	github.com/cB-Sigma/dlms v0.1.0 // indirect
	github.com/cB-Sigma/iotcrypto v0.1.1 // indirect
	github.com/cB-Sigma/tlsx v0.6.0 // indirect
	github.com/goburrow/serial v0.1.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cB-Sigma/mbus => ../
