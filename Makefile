# Silver Plugin — Makefile
# Builds eBPF objects, generates Go bindings (bpf2go), compiles loader
# Supports: standalone daemon, Sliver c-shared extension, nDPI integration

CLANG      ?= clang
GO         ?= go
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
GOARCH     := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
VMLINUX    ?= vmlinux.h
OUTPUT     := .output
BINARY     := silver-plugin
SHARED_LIB := silver-plugin-linux-$(GOARCH)
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
NDPI_DIR   := third_party/nDPI

INCLUDES := -I. -Ibpf -I$(OUTPUT) -I/usr/include

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all clean proto bpf bpf-xsk generate standalone shared armory-pkg ndpi-lib

all: proto bpf standalone

# ---- nDPI third-party build ----

$(NDPI_DIR)/src/lib/.libs/libndpi.a:
	@echo "=== Building nDPI from source ==="
	@if [ ! -d $(NDPI_DIR) ]; then \
		git clone --depth=1 https://github.com/ntop/nDPI.git $(NDPI_DIR); \
	fi
	cd $(NDPI_DIR) && ./autogen.sh && ./configure --with-only-ndpi && make -j$$(nproc)

ndpi-lib: $(NDPI_DIR)/src/lib/.libs/libndpi.a

# ---- Kernel-side BPF ----

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT):
	mkdir -p $(OUTPUT)

bpf: bpf/silver.bpf.c bpf/silver_types.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c bpf/silver.bpf.c -o $(OUTPUT)/silver.bpf.o

bpf-xsk: bpf/silver_xsk.bpf.c bpf/silver_types.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c bpf/silver_xsk.bpf.c -o $(OUTPUT)/silver_xsk.bpf.o

proto:
	protoc --go_out=. --go-grpc_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_opt=paths=source_relative \
		proto/network.proto

generate: bpf bpf-xsk
	cd cmd && $(GO) generate ./...

# Standalone daemon binary (no nDPI, no CGo)
standalone: generate
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -tags no_ndpi -o $(BINARY) ./cmd/...

# Standalone with nDPI (CGo required)
standalone-ndpi: generate ndpi-lib
	CGO_ENABLED=1 $(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY)-ndpi ./cmd/...

# Sliver C2 shared library without nDPI
shared: generate
	CGO_ENABLED=1 $(GO) build -buildmode=c-shared \
		-ldflags="$(LDFLAGS)" -tags no_ndpi \
		-o $(SHARED_LIB) ./cmd/...

# Sliver C2 shared library WITH nDPI statically linked
shared-ndpi: generate ndpi-lib
	CGO_ENABLED=1 CGO_LDFLAGS="-L$(PWD)/$(NDPI_DIR)/src/lib/.libs -Wl,-Bstatic -lndpi -Wl,-Bdynamic -lm -lpthread" \
		$(GO) build -buildmode=c-shared \
		-ldflags="$(LDFLAGS)" \
		-o $(SHARED_LIB) ./cmd/...

# Package for Sliver Armory distribution
armory-pkg: shared-ndpi
	mkdir -p armory-pkg
	cp extension.json armory-pkg/
	cp $(SHARED_LIB) armory-pkg/
	tar -czf silver-extension.tar.gz -C armory-pkg .
	@echo "Package: silver-extension.tar.gz"
	@echo "Sign with: minisign -Sm silver-extension.tar.gz"

clean:
	rm -rf $(OUTPUT) $(VMLINUX) $(BINARY) $(BINARY)-ndpi $(SHARED_LIB)
	rm -f *.pb.go *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o
	rm -rf armory-pkg silver-extension.tar.gz
