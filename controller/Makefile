# xSight Controller — Build targets

GO ?= go

BIN := bin/xsight-controller

PROTO_DIR := ../proto
PB_DIR    := internal/pb

.PHONY: all build proto migrate clean help

all: build

## Build — xsight-controller binary
build:
	$(GO) build -o $(BIN) .

## Proto — generate Go code from shared protobuf definition
proto:
	@mkdir -p $(PB_DIR)
	protoc -I $(PROTO_DIR) \
		--go_out=$(PB_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PB_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/xsight.proto
	@# Fix package path: replace node package with controller package
	@sed -i 's|github.com/littlewolf9527/xsight/node/internal/pb|github.com/littlewolf9527/xsight/controller/internal/pb|g' \
		$(PB_DIR)/xsight.pb.go $(PB_DIR)/xsight_grpc.pb.go

## Migrate — run DB migrations (embedded in binary, just starts and exits)
migrate:
	$(GO) run . -config config.yaml -migrate

## Clean
clean:
	rm -f $(BIN)
	rm -f $(PB_DIR)/*.pb.go

## Help
help:
	@echo "Targets:"
	@echo "  all      — build (default)"
	@echo "  build    — build xsight-controller binary"
	@echo "  proto    — generate Go code from protobuf"
	@echo "  migrate  — run database migrations"
	@echo "  clean    — remove build artifacts"
