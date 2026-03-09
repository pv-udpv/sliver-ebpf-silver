# Silver Plugin — Makefile
# Builds eBPF objects, generates Go bindings (bpf2go), compiles loader
# Supports both standalone daemon and Sliver c-shared extension modes

CLANG      ?= clang
GO         ?= go
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
GOARCH     := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
VMLINUX    ?= vmlinux.h
OUTPUT     := .output
BINARY     := silver-plugin
SHARED_LIB := silver-plugin-linux-$(GOARCH)
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

INCLUDES := -I. -Ibpf -I$(OUTPUT) -I/usr/include

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all clean proto bpf generate standalone shared armory-pkg

all: proto bpf standalone

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT):
	mkdir -p $(OUTPUT)

bpf: bpf/silver.bpf.c bpf/silver_types.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c bpf/silver.bpf.c -o $(OUTPUT)/silver.bpf.o

proto:
	protoc --go_out=. --go-grpc_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_opt=paths=source_relative \
		proto/network.proto

generate: bpf
	cd cmd && $(GO) generate ./...

# Standalone daemon binary
standalone: generate
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/...

# Sliver C2 shared library (sideload extension)
shared: generate
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared \
		-ldflags="$(LDFLAGS)" \
		-o $(SHARED_LIB) ./cmd/...

# Package for Sliver Armory distribution
armory-pkg: shared
	mkdir -p armory-pkg
	cp extension.json armory-pkg/
	cp $(SHARED_LIB) armory-pkg/
	tar -czf silver-extension.tar.gz -C armory-pkg .
	@echo "Package: silver-extension.tar.gz"
	@echo "Sign with: minisign -Sm silver-extension.tar.gz"

clean:
	rm -rf $(OUTPUT) $(VMLINUX) $(BINARY) $(SHARED_LIB)
	rm -f *.pb.go *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o
	rm -rf armory-pkg silver-extension.tar.gz
