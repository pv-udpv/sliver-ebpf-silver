// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// xsk_consumer.go — AF_XDP socket consumer that feeds frames into nDPI
//
// Uses raw syscalls for UMEM/ring setup (no CGo dependency on libxdp).
// Receives redirected packets from silver_xsk.bpf.c via XSKMAP.

package ndpi

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "sync/atomic"
    "time"
    "unsafe"

    "golang.org/x/sys/unix"
)

const (
    NumFrames    = 4096
    FrameSize    = 2048
    UmemSize     = NumFrames * FrameSize
    RxRingSize   = 2048
    FillRingSize = 2048
    CompRingSize = 2048
    TxRingSize   = 2048
)

type XSKConsumer struct {
    fd       int
    ifIndex  int
    queueID  int
    umem     []byte
    tracker  *FlowTracker
    running  atomic.Bool
    stats    XSKStats
}

type XSKStats struct {
    FramesReceived atomic.Uint64
    BytesReceived  atomic.Uint64
    FlowsDetected atomic.Uint64
    Errors         atomic.Uint64
}

type XSKConfig struct {
    IfaceName  string
    QueueID    int
    XSKMapFD   int
    FlowTTL    time.Duration
}

func NewXSKConsumer(cfg XSKConfig, tracker *FlowTracker) (*XSKConsumer, error) {
    iface, err := net.InterfaceByName(cfg.IfaceName)
    if err != nil {
        return nil, fmt.Errorf("interface %s: %w", cfg.IfaceName, err)
    }

    fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
    if err != nil {
        return nil, fmt.Errorf("socket(AF_XDP): %w", err)
    }

    umem := make([]byte, UmemSize)
    umemReg := unix.XDPUmemReg{
        Addr: uint64(uintptr(unsafe.Pointer(&umem[0]))),
        Len:  UmemSize, Size: FrameSize, Headroom: 0,
    }
    _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
        uintptr(fd), unix.SOL_XDP, unix.XDP_UMEM_REG,
        uintptr(unsafe.Pointer(&umemReg)),
        unsafe.Sizeof(umemReg), 0)
    if errno != 0 {
        unix.Close(fd)
        return nil, fmt.Errorf("setsockopt XDP_UMEM_REG: %v", errno)
    }

    for _, opt := range []struct{ name int; value uint32 }{
        {unix.XDP_UMEM_FILL_RING, FillRingSize},
        {unix.XDP_UMEM_COMPLETION_RING, CompRingSize},
        {unix.XDP_RX_RING, RxRingSize},
    } {
        v := opt.value
        _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
            uintptr(fd), unix.SOL_XDP, uintptr(opt.name),
            uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v), 0)
        if errno != 0 {
            unix.Close(fd)
            return nil, fmt.Errorf("setsockopt ring %d: %v", opt.name, errno)
        }
    }

    sa := unix.SockaddrXDP{
        Flags: unix.XDP_COPY, Ifindex: uint32(iface.Index),
        QueueID: uint32(cfg.QueueID),
    }
    if err := unix.Bind(fd, &sa); err != nil {
        unix.Close(fd)
        return nil, fmt.Errorf("bind AF_XDP: %w", err)
    }

    if cfg.XSKMapFD > 0 {
        key := uint32(cfg.QueueID)
        val := uint32(fd)
        _, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(2),
            uintptr(unsafe.Pointer(&struct {
                mapFD uint32; key uint64; value uint64; flags uint64
            }{uint32(cfg.XSKMapFD),
              uint64(uintptr(unsafe.Pointer(&key))),
              uint64(uintptr(unsafe.Pointer(&val))), 0})), 32)
        if errno != 0 {
            log.Printf("XSKMAP update (non-fatal): %v", errno)
        }
    }

    return &XSKConsumer{
        fd: fd, ifIndex: iface.Index, queueID: cfg.QueueID,
        umem: umem, tracker: tracker,
    }, nil
}

func (xsk *XSKConsumer) Run() {
    xsk.running.Store(true)
    log.Printf("XSK consumer running on ifindex=%d queue=%d", xsk.ifIndex, xsk.queueID)

    pollFDs := []unix.PollFd{{Fd: int32(xsk.fd), Events: unix.POLLIN}}

    for xsk.running.Load() {
        n, err := unix.Poll(pollFDs, 100)
        if err != nil {
            if err == unix.EINTR { continue }
            xsk.stats.Errors.Add(1)
            continue
        }
        if n == 0 { continue }

        buf := make([]byte, FrameSize)
        nr, _, err := unix.Recvfrom(xsk.fd, buf, unix.MSG_DONTWAIT)
        if err != nil { continue }
        if nr < 34 { continue }

        xsk.stats.FramesReceived.Add(1)
        xsk.stats.BytesReceived.Add(uint64(nr))
        xsk.processFrame(buf[:nr])
    }
}

func (xsk *XSKConsumer) processFrame(frame []byte) {
    if len(frame) < 14 { return }
    etherType := binary.BigEndian.Uint16(frame[12:14])
    if etherType != 0x0800 { return }
    ipPacket := frame[14:]
    if len(ipPacket) < 20 { return }

    proto := ipPacket[9]
    srcIP := binary.BigEndian.Uint32(ipPacket[12:16])
    dstIP := binary.BigEndian.Uint32(ipPacket[16:20])
    ihl := int(ipPacket[0]&0x0f) * 4
    if len(ipPacket) < ihl { return }

    var srcPort, dstPort uint16
    if proto == 6 || proto == 17 {
        if len(ipPacket) < ihl+4 { return }
        srcPort = binary.BigEndian.Uint16(ipPacket[ihl : ihl+2])
        dstPort = binary.BigEndian.Uint16(ipPacket[ihl+2 : ihl+4])
    }

    key := FlowKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Proto: proto}
    tsMs := uint64(time.Now().UnixMilli())

    result, err := xsk.tracker.ProcessPacket(key, ipPacket, tsMs)
    if err != nil { xsk.stats.Errors.Add(1); return }
    if result.Detected { xsk.stats.FlowsDetected.Add(1) }
}

func (xsk *XSKConsumer) Stop()  { xsk.running.Store(false) }
func (xsk *XSKConsumer) Close() { xsk.Stop(); unix.Close(xsk.fd) }

func (xsk *XSKConsumer) GetStats() (received, bytes, detected, errors uint64) {
    return xsk.stats.FramesReceived.Load(), xsk.stats.BytesReceived.Load(),
        xsk.stats.FlowsDetected.Load(), xsk.stats.Errors.Load()
}
