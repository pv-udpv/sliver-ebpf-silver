// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// ndpi_engine.go — CGo wrapper for nDPI L7 protocol detection
//
// Links statically against libndpi.a for self-contained .so deployment.
// Provides FlowTracker with automatic TTL-based cleanup.

package ndpi

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/nDPI/src/include
#cgo LDFLAGS: -L${SRCDIR}/../third_party/nDPI/src/lib/.libs -lndpi -lm -lpthread

#include <stdlib.h>
#include <string.h>
#include <ndpi_main.h>
#include <ndpi_api.h>
#include <ndpi_typedefs.h>

static struct ndpi_detection_module_struct* ndpi_init_wrapper() {
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    struct ndpi_detection_module_struct *mod = ndpi_init_detection_module(NULL);
    if (mod == NULL) return NULL;
    ndpi_set_protocol_detection_bitmask2(mod, &all);
    ndpi_finalize_initialization(mod);
    return mod;
}

static ndpi_protocol ndpi_detect_wrapper(
    struct ndpi_detection_module_struct *ndpi_struct,
    struct ndpi_flow_struct *flow,
    const unsigned char *packet,
    unsigned short packetlen,
    unsigned long long current_tick,
    struct ndpi_id_struct *src,
    struct ndpi_id_struct *dst)
{
    return ndpi_detection_process_packet(
        ndpi_struct, flow, packet, packetlen, current_tick, NULL);
}

static const char* ndpi_proto_name(struct ndpi_detection_module_struct *mod, ndpi_protocol proto) {
    return ndpi_get_proto_name(mod, proto.app_protocol != NDPI_PROTOCOL_UNKNOWN ?
        proto.app_protocol : proto.master_protocol);
}

static struct ndpi_flow_struct* alloc_ndpi_flow() {
    struct ndpi_flow_struct *f = (struct ndpi_flow_struct*)ndpi_calloc(1, SIZEOF_FLOW_STRUCT);
    return f;
}

static void free_ndpi_flow(struct ndpi_flow_struct *f) {
    ndpi_flow_free(f);
}

static struct ndpi_id_struct* alloc_ndpi_id() {
    struct ndpi_id_struct *id = (struct ndpi_id_struct*)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    return id;
}

static void free_ndpi_id(struct ndpi_id_struct *id) {
    ndpi_free(id);
}
*/
import "C"
import (
    "fmt"
    "sync"
    "time"
    "unsafe"
)

type DetectionModule struct {
    mod *C.struct_ndpi_detection_module_struct
    mu  sync.Mutex
}

type FlowKey struct {
    SrcIP   uint32
    DstIP   uint32
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}

func (fk FlowKey) Normalize() FlowKey {
    if fk.SrcIP > fk.DstIP || (fk.SrcIP == fk.DstIP && fk.SrcPort > fk.DstPort) {
        return FlowKey{
            SrcIP: fk.DstIP, DstIP: fk.SrcIP,
            SrcPort: fk.DstPort, DstPort: fk.SrcPort,
            Proto: fk.Proto,
        }
    }
    return fk
}

type TrackedFlow struct {
    flow     *C.struct_ndpi_flow_struct
    src      *C.struct_ndpi_id_struct
    dst      *C.struct_ndpi_id_struct
    proto    C.ndpi_protocol
    detected bool
    lastSeen time.Time
    packets  uint64
}

type FlowTracker struct {
    mod   *DetectionModule
    flows map[FlowKey]*TrackedFlow
    mu    sync.Mutex
    ttl   time.Duration
}

type DetectedProto struct {
    MasterProto string
    AppProto    string
    ProtoID     uint16
    Detected    bool
    Packets     uint64
}

func NewDetectionModule() (*DetectionModule, error) {
    mod := C.ndpi_init_wrapper()
    if mod == nil {
        return nil, fmt.Errorf("ndpi_init_detection_module failed")
    }
    return &DetectionModule{mod: mod}, nil
}

func (dm *DetectionModule) Close() {
    dm.mu.Lock()
    defer dm.mu.Unlock()
    if dm.mod != nil {
        C.ndpi_exit_detection_module(dm.mod)
        dm.mod = nil
    }
}

func NewFlowTracker(mod *DetectionModule, ttl time.Duration) *FlowTracker {
    return &FlowTracker{
        mod:   mod,
        flows: make(map[FlowKey]*TrackedFlow),
        ttl:   ttl,
    }
}

func (ft *FlowTracker) ProcessPacket(key FlowKey, ipPacket []byte, tsMs uint64) (*DetectedProto, error) {
    nk := key.Normalize()
    ft.mu.Lock()
    tf, exists := ft.flows[nk]
    if !exists {
        tf = &TrackedFlow{
            flow: C.alloc_ndpi_flow(),
            src:  C.alloc_ndpi_id(),
            dst:  C.alloc_ndpi_id(),
        }
        if tf.flow == nil || tf.src == nil || tf.dst == nil {
            ft.mu.Unlock()
            return nil, fmt.Errorf("failed to allocate nDPI flow structs")
        }
        ft.flows[nk] = tf
    }
    tf.lastSeen = time.Now()
    tf.packets++
    ft.mu.Unlock()

    if tf.detected {
        name := C.GoString(C.ndpi_proto_name(ft.mod.mod, tf.proto))
        return &DetectedProto{
            AppProto: name, ProtoID: uint16(tf.proto.app_protocol),
            Detected: true, Packets: tf.packets,
        }, nil
    }

    proto := C.ndpi_detect_wrapper(
        ft.mod.mod, tf.flow,
        (*C.uchar)(unsafe.Pointer(&ipPacket[0])),
        C.ushort(len(ipPacket)),
        C.ulonglong(tsMs), tf.src, tf.dst,
    )

    if proto.app_protocol != C.NDPI_PROTOCOL_UNKNOWN ||
        proto.master_protocol != C.NDPI_PROTOCOL_UNKNOWN {
        tf.proto = proto
        tf.detected = true
    }

    name := C.GoString(C.ndpi_proto_name(ft.mod.mod, proto))
    return &DetectedProto{
        AppProto: name, ProtoID: uint16(proto.app_protocol),
        Detected: tf.detected, Packets: tf.packets,
    }, nil
}

func WriteBackProto(name string) uint8 {
    switch name {
    case "HTTP":
        return 1
    case "TLS", "QUIC", "DoH_DoT":
        return 2
    case "DNS":
        return 3
    case "gRPC":
        return 4
    case "SSH":
        return 5
    default:
        return 0
    }
}

func (ft *FlowTracker) Cleanup() int {
    ft.mu.Lock()
    defer ft.mu.Unlock()
    cutoff := time.Now().Add(-ft.ttl)
    removed := 0
    for k, tf := range ft.flows {
        if tf.lastSeen.Before(cutoff) {
            C.free_ndpi_flow(tf.flow)
            C.free_ndpi_id(tf.src)
            C.free_ndpi_id(tf.dst)
            delete(ft.flows, k)
            removed++
        }
    }
    return removed
}

func (ft *FlowTracker) Stats() (total, detected, pending int) {
    ft.mu.Lock()
    defer ft.mu.Unlock()
    for _, tf := range ft.flows {
        total++
        if tf.detected { detected++ } else { pending++ }
    }
    return
}
