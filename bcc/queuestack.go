package bcc

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <linux/bpf.h>
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func IsQueueStack(table *Table) bool {
	ttype := C.bpf_table_type_id(table.module, table.id)
	return ttype == C.BPF_MAP_TYPE_QUEUE || ttype == C.BPF_MAP_TYPE_STACK
}

type QueueStack struct {
	Table
}

func (queue *QueueStack) Push(leaf []byte, flags int) error {
	fd := C.bpf_table_fd_id(queue.Table.module.p, queue.Table.id)

	leafP := unsafe.Pointer(&leaf[0])

	r, err := C.bpf_update_elem(fd, nil, leafP, flags)
	if r != 0 {
		leafStr, errL := queue.Table.LeafBytesToStr(leaf)
		if errL != nil {
			leafStr = fmt.Sprintf("%v", leaf)
		}

		return fmt.Errorf("QueueStack.Push: %v: %v", leafStr, err)
	}
	return nil
}

func (queue *QueueStack) Pop() ([]byte, error) {
	fd := C.bpf_table_fd_id(queue.Table.module.p, queue.Table.id)

	leafSize := C.bpf_table_leaf_size_id(queue.Table.module.p, queue.Table.id)

	leaf := make([]byte, leafSize)
	leafP := unsafe.Pointer(&leaf[0])

	r, err := C.bpf_lookup_and_delete(fd, nil, leafP)
	if r != 0 {
		return nil, fmt.Errorf("QueueStack.Pop: %v", err)
	}
	return leaf, nil
}

func (queue *QueueStack) PopP() (unsafe.Pointer, error) {
	fd := C.bpf_table_fd_id(queue.Table.module.p, queue.Table.id)

	leafSize := C.bpf_table_leaf_size_id(queue.Table.module.p, queue.Table.id)

	leaf := make([]byte, leafSize)
	leafP := unsafe.Pointer(&leaf[0])

	r, err := C.bpf_lookup_and_delete(fd, nil, leafP)
	if r != 0 {
		return nil, fmt.Errorf("QueueStack.PopP: %v", err)
	}
	return leafP, nil
}

func (queue *QueueStack) Peek() ([]byte, error) {
	fd := C.bpf_table_fd_id(queue.Table.module.p, queue.Table.id)

	leafSize := C.bpf_table_leaf_size_id(queue.Table.module.p, queue.Table.id)

	leaf := make([]byte, leafSize)
	leafP := unsafe.Pointer(&leaf[0])

	r, err := C.bpf_lookup_elem(fd, nil, leafP)
	if r != 0 {
		return nil, fmt.Errorf("QueueStack.Peek: %v", err)
	}
	return leaf, nil
}

func (queue *QueueStack) PeekP() (unsafe.Pointer, error) {
	fd := C.bpf_table_fd_id(queue.Table.module.p, queue.Table.id)

	leafSize := C.bpf_table_leaf_size_id(queue.Table.module.p, queue.Table.id)

	leaf := make([]byte, leafSize)
	leafP := unsafe.Pointer(&leaf[0])

	r, err := C.bpf_lookup_elem(fd, nil, leafP)
	if r != 0 {
		return nil, fmt.Errorf("QueueStack.Peek: %v", err)
	}
	return leafP, nil
}
