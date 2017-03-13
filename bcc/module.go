// Copyright 2016 PLUMgrid
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
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

// Module type
type Module struct {
	p       unsafe.Pointer
	funcs   map[string]int
	kprobes map[string]unsafe.Pointer
}

type compileRequest struct {
	code   string
	cflags []string
	rspCh  chan *Module
}

const (
	BPF_PROBE_ENTRY = iota
	BPF_PROBE_RETURN
)

var (
	defaultCflags []string
	compileCh     chan compileRequest
	bpfInitOnce   sync.Once
)

func bpfInit() {
	defaultCflags = []string{
		fmt.Sprintf("-DNUMCPUS=%d", runtime.NumCPU()),
	}
	compileCh = make(chan compileRequest)
	go compile()
}

// NewModule constructor
func newModule(code string, cflags []string) *Module {
	cflagsC := make([]*C.char, len(defaultCflags)+len(cflags))
	defer func() {
		for _, cflag := range cflagsC {
			C.free(unsafe.Pointer(cflag))
		}
	}()
	for i, cflag := range cflags {
		cflagsC[i] = C.CString(cflag)
	}
	for i, cflag := range defaultCflags {
		cflagsC[len(cflags)+i] = C.CString(cflag)
	}
	cs := C.CString(code)
	defer C.free(unsafe.Pointer(cs))
	c := C.bpf_module_create_c_from_string(cs, 2, (**C.char)(&cflagsC[0]), C.int(len(cflagsC)))
	if c == nil {
		return nil
	}
	return &Module{
		p:       c,
		funcs:   make(map[string]int),
		kprobes: make(map[string]unsafe.Pointer),
	}
}

// NewModule asynchronously compiles the code, generates a new BPF
// module and returns it.
func NewModule(code string, cflags []string) *Module {
	bpfInitOnce.Do(bpfInit)
	ch := make(chan *Module)
	compileCh <- compileRequest{code, cflags, ch}
	return <-ch
}

func compile() {
	for {
		req := <-compileCh
		req.rspCh <- newModule(req.code, req.cflags)
	}
}

// Close takes care of closing all kprobes opened by this modules and
// destroys the underlying libbpf module.
func (bpf *Module) Close() {
	C.bpf_module_destroy(bpf.p)
	for k, v := range bpf.kprobes {
		C.perf_reader_free(v)
		desc := fmt.Sprintf("-:kprobes/%s", k)
		descCS := C.CString(desc)
		C.bpf_detach_kprobe(descCS)
		C.free(unsafe.Pointer(descCS))
	}
	for _, fd := range bpf.funcs {
		syscall.Close(fd)
	}
}

// LoadNet loads a program of type BPF_PROG_TYPE_SCHED_ACT.
func (bpf *Module) LoadNet(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_SCHED_ACT)
}

// LoadKprobe loads a program of type BPF_PROG_TYPE_KPROBE.
func (bpf *Module) LoadKprobe(name string) (int, error) {
	return bpf.Load(name, C.BPF_PROG_TYPE_KPROBE)
}

// Load a program.
func (bpf *Module) Load(name string, progType int) (int, error) {
	fd, ok := bpf.funcs[name]
	if ok {
		return fd, nil
	}
	fd, err := bpf.load(name, progType)
	if err != nil {
		return -1, err
	}
	bpf.funcs[name] = fd
	return fd, nil
}

func (bpf *Module) load(name string, progType int) (int, error) {
	nameCS := C.CString(name)
	defer C.free(unsafe.Pointer(nameCS))
	start := (*C.struct_bpf_insn)(C.bpf_function_start(bpf.p, nameCS))
	size := C.int(C.bpf_function_size(bpf.p, nameCS))
	license := C.bpf_module_license(bpf.p)
	version := C.bpf_module_kern_version(bpf.p)
	if start == nil {
		return -1, fmt.Errorf("Module: unable to find %s", name)
	}
	logbuf := make([]byte, 65536)
	logbufP := (*C.char)(unsafe.Pointer(&logbuf[0]))
	fd := C.bpf_prog_load(uint32(progType), start, size, license, version, logbufP, C.uint(len(logbuf)))
	if fd < 0 {
		msg := string(logbuf[:bytes.IndexByte(logbuf, 0)])
		return -1, fmt.Errorf("Error loading bpf program:\n%s", msg)
	}
	return int(fd), nil
}

var kprobeRegexp = regexp.MustCompile("[+.]")

func (bpf *Module) attachProbe(evName string, attachType uint32, fnName string, fd int) error {
	if _, ok := bpf.kprobes[evName]; ok {
		return nil
	}

	evNameCS := C.CString(evName)
	fnNameCS := C.CString(fnName)
	res := C.bpf_attach_kprobe(C.int(fd), attachType, evNameCS, fnNameCS, -1, 0, -1, nil, nil)
	C.free(unsafe.Pointer(evNameCS))
	C.free(unsafe.Pointer(fnNameCS))

	if res == nil {
		return fmt.Errorf("Failed to attach BPF kprobe")
	}
	bpf.kprobes[evName] = res
	return nil
}

// AttachKprobe attaches a kprobe fd to a function.
func (bpf *Module) AttachKprobe(fnName string, fd int) error {
	evName := "p_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_ENTRY, fnName, fd)
}

// AttachKretprobe attaches a kretprobe fd to a function.
func (bpf *Module) AttachKretprobe(fnName string, fd int) error {
	evName := "r_" + kprobeRegexp.ReplaceAllString(fnName, "_")

	return bpf.attachProbe(evName, BPF_PROBE_RETURN, fnName, fd)
}

// TableSize returns the number of tables in the module.
func (bpf *Module) TableSize() uint64 {
	size := C.bpf_num_tables(bpf.p)
	return uint64(size)
}

// TableId returns the id of a table.
func (bpf *Module) TableId(name string) C.size_t {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	return C.bpf_table_id(bpf.p, cs)
}

// TableDesc returns a map with table properties (name, fd, ...).
func (bpf *Module) TableDesc(id uint64) map[string]interface{} {
	i := C.size_t(id)
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(bpf.p, i)),
		"fd":        int(C.bpf_table_fd_id(bpf.p, i)),
		"key_size":  uint64(C.bpf_table_key_size_id(bpf.p, i)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(bpf.p, i)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(bpf.p, i)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(bpf.p, i)),
	}
}

// TableIter returns a receveier channel to iterate over entries.
func (bpf *Module) TableIter() <-chan map[string]interface{} {
	ch := make(chan map[string]interface{})
	go func() {
		size := C.bpf_num_tables(bpf.p)
		for i := C.size_t(0); i < size; i++ {
			ch <- bpf.TableDesc(uint64(i))
		}
		close(ch)
	}()
	return ch
}
