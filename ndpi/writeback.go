// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// writeback.go — Write nDPI classification results back into BPF flow_table
//
// After nDPI detects a protocol, this updates the flow_value.l7_proto field
// in the shared BPF flow_table map so that all BPF programs can see the result.

package ndpi

import (
    "encoding/binary"
    "log"
    "time"

    "github.com/cilium/ebpf"
)

type WriteBackConfig struct {
    FlowTableMap *ebpf.Map
    Interval     time.Duration
}

type WriteBackEngine struct {
    cfg     WriteBackConfig
    tracker *FlowTracker
    done    chan struct{}
}

type FlowTableKey struct {
    SrcIP     uint32
    DstIP     uint32
    SrcPort   uint16
    DstPort   uint16
    L4Proto   uint8
    Direction uint8
    Pad       uint16
}

func NewWriteBackEngine(cfg WriteBackConfig, tracker *FlowTracker) *WriteBackEngine {
    return &WriteBackEngine{cfg: cfg, tracker: tracker, done: make(chan struct{})}
}

func (wb *WriteBackEngine) Run() {
    ticker := time.NewTicker(wb.cfg.Interval)
    defer ticker.Stop()
    log.Printf("WriteBack engine started (interval=%v)", wb.cfg.Interval)
    for {
        select {
        case <-wb.done:
            return
        case <-ticker.C:
            wb.writeBack()
        }
    }
}

func (wb *WriteBackEngine) writeBack() {
    wb.tracker.mu.Lock()
    defer wb.tracker.mu.Unlock()
    updated := 0
    for fk, tf := range wb.tracker.flows {
        if !tf.detected { continue }
        l7Val := WriteBackProto("detected")
        if l7Val == 0 { continue }
        for _, dir := range []uint8{1, 2} {
            keyBytes := make([]byte, 16)
            binary.LittleEndian.PutUint32(keyBytes[0:4], fk.SrcIP)
            binary.LittleEndian.PutUint32(keyBytes[4:8], fk.DstIP)
            binary.LittleEndian.PutUint16(keyBytes[8:10], fk.SrcPort)
            binary.LittleEndian.PutUint16(keyBytes[10:12], fk.DstPort)
            keyBytes[12] = fk.Proto
            keyBytes[13] = dir
            var valBuf []byte
            if err := wb.cfg.FlowTableMap.Lookup(keyBytes, &valBuf); err != nil { continue }
            const l7ProtoOffset = 88
            if len(valBuf) > l7ProtoOffset {
                valBuf[l7ProtoOffset] = l7Val
                if err := wb.cfg.FlowTableMap.Update(keyBytes, valBuf, ebpf.UpdateExist); err == nil {
                    updated++
                }
            }
        }
    }
    if updated > 0 { log.Printf("WriteBack: updated %d flow entries", updated) }
}

func (wb *WriteBackEngine) Stop() { close(wb.done) }
func (wb *WriteBackEngine) ForceWriteBack() { wb.writeBack() }

func EncodeFlowKey(fk FlowKey, direction uint8) []byte {
    key := make([]byte, 16)
    binary.LittleEndian.PutUint32(key[0:4], fk.SrcIP)
    binary.LittleEndian.PutUint32(key[4:8], fk.DstIP)
    binary.LittleEndian.PutUint16(key[8:10], fk.SrcPort)
    binary.LittleEndian.PutUint16(key[10:12], fk.DstPort)
    key[12] = fk.Proto
    key[13] = direction
    return key
}
