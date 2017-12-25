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
	"fmt"
	"unsafe"

	"github.com/iovisor/gobpf/bcc/bccencoding"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

type Table struct {
	id     C.size_t
	module *Module
}

// New tables returns a refernce to a BPF table.
func NewTable(id C.size_t, module *Module) *Table {
	return &Table{
		id:     id,
		module: module,
	}
}

// ID returns the table id.
func (table *Table) ID() string {
	return C.GoString(C.bpf_table_name(table.module.p, table.id))
}

// Name returns the table name.
func (table *Table) Name() string {
	return C.GoString(C.bpf_table_name(table.module.p, table.id))
}

// Config returns the table properties (name, fd, ...).
func (table *Table) Config() map[string]interface{} {
	mod := table.module.p
	return map[string]interface{}{
		"name":      C.GoString(C.bpf_table_name(mod, table.id)),
		"fd":        int(C.bpf_table_fd_id(mod, table.id)),
		"key_size":  uint64(C.bpf_table_key_size_id(mod, table.id)),
		"leaf_size": uint64(C.bpf_table_leaf_size_id(mod, table.id)),
		"key_desc":  C.GoString(C.bpf_table_key_desc_id(mod, table.id)),
		"leaf_desc": C.GoString(C.bpf_table_leaf_desc_id(mod, table.id)),
	}
}

// Entry represents a table entry.
type Entry struct {
	Key   []byte
	Value []byte
}

// TODO: could potentially store KeyFields and ValueFields in Table to avoid
// reflecting to get the types on all calls after first.
//
// and - for max performance, reflection shouldn't be used at all. the code to
// deserialize into the struct should be generated
func (entry *Entry) UnmarshalValue(dest interface{}) error {
	return bccencoding.Unmarshal(entry.Value, dest)
}

func (entry *Entry) UnmarshalKey(dest interface{}) error {
	return bccencoding.Unmarshal(entry.Key, dest)
}

// Get takes a key and returns the value or nil, and an 'ok' style indicator.
func (table *Table) Get(key []byte) (*Entry, bool) {
	mod := table.module.p
	fd := C.bpf_table_fd_id(mod, table.id)
	leaf_size := C.bpf_table_leaf_size_id(mod, table.id)
	leaf := make([]byte, leaf_size)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])
	r := C.bpf_lookup_elem(fd, keyP, leafP)
	if r != 0 {
		return nil, false
	}
	return &Entry{
		Key:   key,
		Value: leaf,
	}, true
}

// Set a key to a value.
func (table *Table) Set(key, leaf []byte) error {
	if table == nil || table.module.p == nil {
		panic("table is nil")
	}
	fd := C.bpf_table_fd_id(table.module.p, table.id)
	keyP := unsafe.Pointer(&key[0])
	leafP := unsafe.Pointer(&leaf[0])
	r, err := C.bpf_update_elem(fd, keyP, leafP, 0)
	if r != 0 {
		return fmt.Errorf("Table.Set: unable to update element (%s=%s): %v", string(key), string(leaf), err)
	}
	return nil
}

// Delete a key.
func (table *Table) Delete(key []byte) error {
	fd := C.bpf_table_fd_id(table.module.p, table.id)
	keyP := unsafe.Pointer(&key[0])
	r, err := C.bpf_delete_elem(fd, keyP)
	if r != 0 {
		return fmt.Errorf("Table.Delete: unable to delete element (%s): %v", string(key), err)
	}
	return nil
}

// Iter returns a receiver channel to iterate over all table entries.
func (table *Table) Iter() <-chan *Entry {
	mod := table.module.p
	ch := make(chan *Entry, 128)
	go func() {
		defer close(ch)
		fd := C.bpf_table_fd_id(mod, table.id)
		key_size := C.bpf_table_key_size_id(mod, table.id)
		leaf_size := C.bpf_table_leaf_size_id(mod, table.id)
		key := make([]byte, key_size)
		leaf := make([]byte, leaf_size)
		keyP := unsafe.Pointer(&key[0])
		leafP := unsafe.Pointer(&leaf[0])
		alternateKeys := []byte{0xff, 0x55}
		res := C.bpf_lookup_elem(fd, keyP, leafP)
		// make sure the start iterator is an invalid key
		for i := 0; i < len(alternateKeys); i++ {
			if res < 0 {
				break
			}
			for j := range key {
				fmt.Println(len(key), len(alternateKeys))
				key[j] = alternateKeys[i]
			}
		}
		if res == 0 {
			return
		}
		for res = C.bpf_get_next_key(fd, keyP, keyP); res == 0; res = C.bpf_get_next_key(fd, keyP, keyP) {
			r := C.bpf_lookup_elem(fd, keyP, leafP)
			if r != 0 {
				continue
			}
			entry := &Entry{
				Key:   make([]byte, key_size),
				Value: make([]byte, leaf_size),
			}
			copy(entry.Key, key)
			copy(entry.Value, leaf)
			ch <- entry
		}
	}()
	return ch
}

func (table *Table) Clear() error {
	for entry := range table.Iter() {
		if err := table.Delete(entry.Key); err != nil {
			return err
		}
	}
	return nil
}
