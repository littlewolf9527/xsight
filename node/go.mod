module github.com/littlewolf9527/xsight/node

go 1.24.0

toolchain go1.24.4

require (
	github.com/cilium/ebpf v0.21.0
	github.com/littlewolf9527/xsight/shared v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/littlewolf9527/xsight/shared => ../shared

require (
	github.com/gopacket/gopacket v1.5.0 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/netsampler/goflow2/v2 v2.2.6 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
