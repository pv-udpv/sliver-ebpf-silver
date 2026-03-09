# Silver Plugin — Makefile
# Builds the eBPF object, generates skeleton, compiles Go loader

CLANG      ?= clang
BPFTOOL    ?= bpftool
GO         ?= go
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX    ?= vmlinux.h
OUTPUT     := .output
BPF_OBJ    := $(OUTPUT)/silver.bpf.o
SKEL_H     := $(OUTPUT)/silver.skel.h
BINARY     := silver-plugin

INCLUDES := -I. -Ibpf -I$(OUTPUT) -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean proto bpf skeleton go

all: proto bpf go

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf: $(BPF_OBJ)

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(BPF_OBJ): bpf/silver.bpf.c bpf/silver_types.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-c $< -o $@

skeleton: $(SKEL_H)

$(SKEL_H): $(BPF_OBJ) | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

proto:
	protoc --go_out=. --go-grpc_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_opt=paths=source_relative \
		proto/network.proto

go: bpf
	$(GO) generate ./...
	$(GO) build -o $(BINARY) ./cmd/...

clean:
	rm -rf $(OUTPUT) $(VMLINUX) $(BINARY)
	rm -f *.pb.go *_bpfel.go *_bpfeb.go *_bpfel.o *_bpfeb.o
