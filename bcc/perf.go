// Copyright 2016 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bcc

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

// perf_reader_raw_cb as defined in bcc libbpf.h
// typedef void (*perf_reader_raw_cb)(void *cb_cookie, void *raw, int raw_size);
extern void callback_to_go(void*, void*, int);
*/
import "C"

type PerfMap struct {
	table   *Table
	readers []*C.struct_perf_reader
	stop    chan bool
}

type callbackData struct {
	receiverChan chan []byte
}

const BPF_PERF_READER_PAGE_CNT = 8

var byteOrder binary.ByteOrder
var callbackRegister = make(map[uint64]*callbackData)
var callbackIndex uint64
var mu sync.Mutex

// In lack of binary.HostEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}
}

func registerCallback(data *callbackData) uint64 {
	mu.Lock()
	defer mu.Unlock()
	callbackIndex++
	for callbackRegister[callbackIndex] != nil {
		callbackIndex++
	}
	callbackRegister[callbackIndex] = data
	return callbackIndex
}

func unregisterCallback(i uint64) {
	mu.Lock()
	defer mu.Unlock()
	delete(callbackRegister, i)
}

func lookupCallback(i uint64) *callbackData {
	return callbackRegister[i]
}

// Gateway function as required with CGO Go >= 1.6
// "If a C-program wants a function pointer, a gateway function has to
// be written. This is because we can't take the address of a Go
// function and give that to C-code since the cgo tool will generate a
// stub in C that should be called."
//export callback_to_go
func callback_to_go(cbCookie unsafe.Pointer, raw unsafe.Pointer, rawSize C.int) {
	callbackData := lookupCallback(uint64(uintptr(cbCookie)))
	receiverChan := callbackData.receiverChan
	go func() {
		receiverChan <- C.GoBytes(raw, rawSize)
	}()
}

// InitPerfMap initializes a perf map with a receiver channel.
func InitPerfMap(table *Table, receiverChan chan []byte) (*PerfMap, error) {
	fd := table.Config()["fd"].(int)
	keySize := table.Config()["key_size"].(uint64)
	leafSize := table.Config()["leaf_size"].(uint64)

	if keySize != 4 || leafSize != 4 {
		return nil, fmt.Errorf("passed table has wrong size")
	}

	callbackDataIndex := registerCallback(&callbackData{
		receiverChan,
	})

	key := make([]byte, keySize)
	leaf := make([]byte, leafSize)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])

	readers := []*C.struct_perf_reader{}

	cpu := 0
	res := 0
	for res == 0 {
		reader, err := C.bpf_open_perf_buffer((C.perf_reader_raw_cb)(unsafe.Pointer(C.callback_to_go)), nil, unsafe.Pointer(uintptr(callbackDataIndex)), -1, C.int(cpu), BPF_PERF_READER_PAGE_CNT)
		if reader == nil {
			return nil, fmt.Errorf("failed to open perf buffer: %v", err)
		}

		perfFd := C.perf_reader_fd(reader)

		readers = append(readers, (*C.struct_perf_reader)(reader))

		byteOrder.PutUint32(leaf, uint32(perfFd))

		r, err := C.bpf_update_elem(C.int(fd), keyP, leafP, 0)
		if r != 0 {
			return nil, fmt.Errorf("unable to initialize perf map: %v", err)
		}

		res = int(C.bpf_get_next_key(C.int(fd), keyP, keyP))
		cpu++
	}
	return &PerfMap{
		table,
		readers,
		make(chan bool),
	}, nil
}

// Start to poll the perf map reader and send back event data
// over the connected channel.
func (pm *PerfMap) Start() {
	go pm.poll(500)
}

// Stop to poll the perf map readers after a maximum of 500ms
// (the timeout we use for perf_reader_poll). Ideally we would
// have a way to cancel the poll, but perf_reader_poll doesn't
// support that yet.
func (pm *PerfMap) Stop() {
	pm.stop <- true
}

func (pm *PerfMap) poll(timeout int) {
	for {
		select {
		case <-pm.stop:
			return
		default:
			C.perf_reader_poll(C.int(len(pm.readers)), &pm.readers[0], C.int(timeout))
		}
	}
}
