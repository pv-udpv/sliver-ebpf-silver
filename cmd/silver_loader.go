// silver_loader.go — Userspace loader and gRPC server for the Silver plugin
// Mirrors Sliver's extension pattern: reflectively loaded shared lib on Linux.
// Also works standalone for E2B sandbox deployment.
//
// Build: go generate && go build -o silver-plugin .
//go:generate bpftool gen skeleton .output/silver.bpf.o > silver_bpf_skel.h
//go:generate protoc --go_out=. --go-grpc_out=. proto/network.proto

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" Silver ../bpf/silver.bpf.c -- -I../bpf -I/usr/include

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := SilverObjects{}
	if err := LoadSilverObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	cgroupPath := "/sys/fs/cgroup"

	// Program 1: cgroup/sock_create
	sockCreateLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.SilverSockCreate,
	})
	if err != nil {
		log.Fatalf("attach cgroup/sock_create: %v", err)
	}
	defer sockCreateLink.Close()

	// Program 2: cgroup/connect4
	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.SilverConnect4,
	})
	if err != nil {
		log.Fatalf("attach cgroup/connect4: %v", err)
	}
	defer connect4Link.Close()

	// Program 3: sock_ops
	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SilverSockOps,
	})
	if err != nil {
		log.Fatalf("attach sockops: %v", err)
	}
	defer sockOpsLink.Close()

	// Program 4: XDP
	iface := os.Getenv("SILVER_IFACE")
	if iface == "" {
		iface = "eth0"
	}
	ifIdx, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("get interface %s: %v", iface, err)
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.SilverXdp,
		Interface: ifIdx.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP on %s: %v", iface, err)
	}
	defer xdpLink.Close()

	// Programs 5 & 6: TC ingress/egress
	log.Printf("TC ingress/egress: use tc CLI or TCX API for %s", iface)

	// Ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("ringbuf read error: %v", err)
				continue
			}
			_ = record.RawSample // TODO: deserialize and fan-out to gRPC stream clients
		}
	}()

	// gRPC server
	grpcAddr := os.Getenv("SILVER_GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = "0.0.0.0:50052"
	}
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", grpcAddr, err)
	}

	srv := grpc.NewServer()
	// TODO: Register Network service from generated proto code
	// pb.RegisterNetworkServer(srv, NewSilverNetworkServer(&objs))

	log.Printf("Silver plugin listening on %s (XDP on %s, cgroup %s)",
		grpcAddr, iface, cgroupPath)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down Silver plugin...")
		rd.Close()
		srv.GracefulStop()
	}()

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("gRPC serve: %v", err)
	}
}
