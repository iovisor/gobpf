// +build linux

// Copyright 2016 Cilium Project
// Copyright 2016 Sylvain Afchain
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

package elf

import (
	"fmt"
	"os"
	"sort"
	"syscall"
	"unsafe"
)

/*
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <linux/perf_event.h>
#include <poll.h>

// from https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	void *buf;
	int buf_len;
};

static int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}
*/
import "C"

type PerfMap struct {
	name         string
	program      *Module
	receiverChan chan []byte
	pollStop     chan bool
}

// Matching 'struct perf_event_sample in kernel sources
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

func InitPerfMap(b *Module, mapName string, receiverChan chan []byte) (*PerfMap, error) {
	_, ok := b.maps[mapName]
	if !ok {
		return nil, fmt.Errorf("no map with name %s", mapName)
	}
	// Maps are initialized in b.Load(), nothing to do here
	return &PerfMap{
		name:         mapName,
		program:      b,
		receiverChan: receiverChan,
		pollStop:     make(chan bool),
	}, nil
}

func (pm *PerfMap) PollStart() {
	var incoming BytesWithTimestamp

	m, ok := pm.program.maps[pm.name]
	if !ok {
		// should not happen or only when pm.program is
		// suddenly changed
		panic(fmt.Sprintf("cannot find map %q", pm.name))
	}

	go func() {
		cpuCount := len(m.pmuFDs)
		pageSize := os.Getpagesize()
		pageCount := 8
		state := C.struct_read_state{}

		for {
			select {
			case <-pm.pollStop:
				break
			default:
				perfEventPoll(m.pmuFDs)
			}

			for {
				var harvestCount C.int
				beforeHarvest := nowNanoseconds()
				for cpu := 0; cpu < cpuCount; cpu++ {
					for {
						var sample *PerfEventSample
						var lost *PerfEventLost

						ok := C.perf_event_read(C.int(pageCount), C.int(pageSize),
							unsafe.Pointer(&state), unsafe.Pointer(m.headers[cpu]),
							unsafe.Pointer(&sample), unsafe.Pointer(&lost))

						switch ok {
						case 0:
							break // nothing to read
						case C.PERF_RECORD_SAMPLE:
							size := sample.Size - 4
							b := C.GoBytes(unsafe.Pointer(&sample.data), C.int(size))
							incoming = append(incoming, b)
							harvestCount++
							if *(*uint64)(unsafe.Pointer(&b[0])) > beforeHarvest {
								// see comment below
								break
							} else {
								continue
							}
						case C.PERF_RECORD_LOST:
						default:
							// TODO: handle lost/unknown events?
						}
						break
					}

				}

				sort.Sort(incoming)
				for i := 0; i < len(incoming); i++ {
					if *(*uint64)(unsafe.Pointer(&incoming[0][0])) > beforeHarvest {
						// This record has been sent after the beginning of the harvest. Stop
						// processing here to keep the order. "incoming" is sorted, so the next
						// elements also must not be processed now.
						break
					}
					pm.receiverChan <- incoming[0]
					// remove first element
					incoming = incoming[1:]
				}
				if harvestCount == 0 && len(incoming) == 0 {
					break
				}
			}
		}
	}()
}

func (pm *PerfMap) PollStop() {
	pm.pollStop <- true
}

func perfEventPoll(fds []C.int) error {
	var pfds []C.struct_pollfd

	for i, _ := range fds {
		var pfd C.struct_pollfd

		pfd.fd = fds[i]
		pfd.events = C.POLLIN

		pfds = append(pfds, pfd)
	}
	_, err := C.poll(&pfds[0], C.nfds_t(len(fds)), 500)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

// Assume the timestamp is at the beginning of the user struct
type BytesWithTimestamp [][]byte

func (a BytesWithTimestamp) Len() int      { return len(a) }
func (a BytesWithTimestamp) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BytesWithTimestamp) Less(i, j int) bool {
	return *(*C.uint64_t)(unsafe.Pointer(&a[i][0])) < *(*C.uint64_t)(unsafe.Pointer(&a[j][0]))
}

// Matching 'struct perf_event_header in <linux/perf_event.h>
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// Matching 'struct perf_event_lost in kernel sources
type PerfEventLost struct {
	PerfEventHeader
	Id   uint64
	Lost uint64
}

// nowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
func nowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}
