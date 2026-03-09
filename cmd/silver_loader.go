// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// silver_loader.go — Userspace loader + Sliver extension entrypoint
//
// Two modes:
//   1. Sliver extension: compiled with -buildmode=c-shared, loaded via sideload
//   2. Standalone: compiled normally, runs as a daemon with gRPC
//
// Build (Sliver):   go build -buildmode=c-shared -o silver-plugin-linux-amd64 ./cmd/...
// Build (Standalone): go build -o silver-plugin ./cmd/...

package main

/*
#include <stdint.h>
#include <stdlib.h>

// Sliver extension callback type
typedef int (*goCallback)(const char *, int);
*/
import "C"

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" Silver ../bpf/silver.bpf.c -- -I../bpf -I/usr/include

var (
	version string = "dev"

	silverMu    sync.Mutex
	silverState *SilverRuntime
)

// SilverRuntime holds all BPF links and state for cleanup
type SilverRuntime struct {
	objs       SilverObjects
	links      []link.Link
	rd         *ringbuf.Reader
	grpcSrv    *grpc.Server
	eventsCh   chan []byte
	shutdownCh chan struct{}
}

// =================================================================
// MODE 1: SLIVER C2 EXTENSION ENTRYPOINT
// =================================================================

//export SilverEntry
func SilverEntry(argsBuffer *C.char, bufferSize C.uint32_t, callback C.goCallback) C.int {
	args := C.GoBytes(unsafe.Pointer(argsBuffer), C.int(bufferSize))

	cmd := "flows"
	if len(args) > 0 {
		cmd = string(bytes.TrimRight(args, "\x00"))
	}

	result, err := handleCommand(cmd)
	if err != nil {
		errMsg := fmt.Sprintf("error: %v", err)
		cStr := C.CString(errMsg)
		defer C.free(unsafe.Pointer(cStr))
		return C.int(C.goCallback(callback)(cStr, C.int(len(errMsg))))
	}

	cResult := C.CString(result)
	defer C.free(unsafe.Pointer(cResult))
	return C.int(C.goCallback(callback)(cResult, C.int(len(result))))
}

func handleCommand(cmd string) (string, error) {
	silverMu.Lock()
	defer silverMu.Unlock()

	switch cmd {
	case "start":
		return startSilver()
	case "stop":
		return stopSilver()
	case "flows":
		return dumpFlows()
	case "stats":
		return dumpStats()
	case "dns":
		return dumpDNS()
	case "stream":
		return "streaming mode: events forwarded via callback", nil
	case "policy":
		return dumpPolicy()
	case "version":
		return fmt.Sprintf("Silver %s", version), nil
	default:
		return "", fmt.Errorf("unknown command: %s (available: start, stop, flows, stats, dns, stream, policy, version)", cmd)
	}
}

func startSilver() (string, error) {
	if silverState != nil {
		return "Silver already running", nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return "", fmt.Errorf("remove memlock: %w", err)
	}

	rt := &SilverRuntime{
		eventsCh:   make(chan []byte, 4096),
		shutdownCh: make(chan struct{}),
	}

	if err := LoadSilverObjects(&rt.objs, nil); err != nil {
		return "", fmt.Errorf("load BPF objects: %w", err)
	}

	cgroupPath := "/sys/fs/cgroup"

	// Program 1: cgroup/sock_create
	l1, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: rt.objs.SilverSockCreate,
	})
	if err != nil {
		rt.objs.Close()
		return "", fmt.Errorf("attach cgroup/sock_create: %w", err)
	}
	rt.links = append(rt.links, l1)

	// Program 2: cgroup/connect4
	l2, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: rt.objs.SilverConnect4,
	})
	if err != nil {
		rt.cleanup()
		return "", fmt.Errorf("attach cgroup/connect4: %w", err)
	}
	rt.links = append(rt.links, l2)

	// Program 3: sock_ops
	l3, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: rt.objs.SilverSockOps,
	})
	if err != nil {
		rt.cleanup()
		return "", fmt.Errorf("attach sockops: %w", err)
	}
	rt.links = append(rt.links, l3)

	// Program 4: XDP
	iface := os.Getenv("SILVER_IFACE")
	if iface == "" {
		iface = "eth0"
	}
	ifIdx, err := net.InterfaceByName(iface)
	if err != nil {
		rt.cleanup()
		return "", fmt.Errorf("get interface %s: %w", iface, err)
	}

	l4, err := link.AttachXDP(link.XDPOptions{
		Program:   rt.objs.SilverXdp,
		Interface: ifIdx.Index,
	})
	if err != nil {
		rt.cleanup()
		return "", fmt.Errorf("attach XDP on %s: %w", iface, err)
	}
	rt.links = append(rt.links, l4)

	// Programs 5 & 6: TC ingress/egress via TCX (kernel >=6.6)
	l5, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIdx.Index,
		Program:   rt.objs.SilverTcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Printf("TCX ingress attach failed (kernel <6.6?): %v", err)
	} else {
		rt.links = append(rt.links, l5)
	}

	l6, err := link.AttachTCX(link.TCXOptions{
		Interface: ifIdx.Index,
		Program:   rt.objs.SilverTcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("TCX egress attach failed (kernel <6.6?): %v", err)
	} else {
		rt.links = append(rt.links, l6)
	}

	// Ring buffer reader
	rt.rd, err = ringbuf.NewReader(rt.objs.Events)
	if err != nil {
		rt.cleanup()
		return "", fmt.Errorf("open ringbuf: %w", err)
	}

	go rt.readEvents()

	silverState = rt
	return fmt.Sprintf("Silver %s started: XDP+TCX on %s, cgroup %s, %d programs attached",
		version, iface, cgroupPath, len(rt.links)), nil
}

func stopSilver() (string, error) {
	if silverState == nil {
		return "Silver not running", nil
	}
	close(silverState.shutdownCh)
	silverState.cleanup()
	silverState = nil
	return "Silver stopped, all BPF programs detached", nil
}

func (rt *SilverRuntime) readEvents() {
	for {
		select {
		case <-rt.shutdownCh:
			return
		default:
		}
		record, err := rt.rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}
		select {
		case rt.eventsCh <- record.RawSample:
		default:
		}
	}
}

func (rt *SilverRuntime) cleanup() {
	if rt.rd != nil {
		rt.rd.Close()
	}
	for _, l := range rt.links {
		l.Close()
	}
	rt.objs.Close()
}

// =================================================================
// MAP DUMP HELPERS
// =================================================================

type FlowRecord struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	L4Proto   string `json:"l4_proto"`
	L7Proto   string `json:"l7_proto"`
	Direction string `json:"direction"`
	State     string `json:"state"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	CgroupID  uint64 `json:"cgroup_id"`
	DNSName   string `json:"dns_name,omitempty"`
	PktsIn    uint64 `json:"packets_in"`
	PktsOut   uint64 `json:"packets_out"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
}

func dumpFlows() (string, error) {
	if silverState == nil {
		return "", fmt.Errorf("Silver not running -- use 'silver start' first")
	}
	// TODO: iterate flow_table map and marshal to JSON
	return `{"status": "flow_table dump -- implement with MapIterator"}`, nil
}

func dumpStats() (string, error) {
	if silverState == nil {
		return "", fmt.Errorf("Silver not running")
	}
	return `{"status": "decision_stats dump -- implement with PerCPU lookup"}`, nil
}

func dumpDNS() (string, error) {
	if silverState == nil {
		return "", fmt.Errorf("Silver not running")
	}
	return `{"status": "dns_cache dump -- implement with MapIterator"}`, nil
}

func dumpPolicy() (string, error) {
	if silverState == nil {
		return "", fmt.Errorf("Silver not running")
	}
	return `{"status": "policy_rules dump -- implement with Array lookup"}`, nil
}

// =================================================================
// MODE 2: STANDALONE DAEMON
// =================================================================

func main() {
	log.Printf("Silver plugin %s -- standalone mode", version)

	result, err := startSilver()
	if err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
	log.Println(result)

	grpcAddr := os.Getenv("SILVER_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = "0.0.0.0:50052"
	}
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", grpcAddr, err)
	}

	srv := grpc.NewServer()
	// pb.RegisterNetworkServer(srv, NewSilverNetworkServer(silverState))
	log.Printf("gRPC server listening on %s", grpcAddr)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down Silver...")
		stopSilver()
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("gRPC serve: %v", err)
	}
}
