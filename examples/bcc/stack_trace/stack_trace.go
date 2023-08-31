package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc

#include <linux/perf_event.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

struct key_t {
  uint32_t pid;
  int user_stack_id;
  int kernel_stack_id;
};
*/
import "C"

const source string = `
#include <linux/bpf_perf_event.h>
#include <linux/ptrace.h>

const int TOTAL_ENTRIES = 65536; 

struct key_t {
  uint32_t pid;
  int user_stack_id;
  int kernel_stack_id;
};

BPF_STACK_TRACE(stack_traces, TOTAL_ENTRIES);
BPF_PERF_OUTPUT(histogram);

int do_perf_event(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  pid_t tgid = id >> 32;
  pid_t pid = id;

  struct key_t key = {};
  key.pid = tgid;
  key.kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0);
  key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);
  histogram.perf_submit(ctx, &key, sizeof(key));
  return 0;
}
`

func pow(x int) int {
	power := 1
	for power < x {
		power *= 2
	}
	return power
}

func main() {
	var pid int
	var sleep int
	flag.IntVar(&pid, "pid", -1, "PID")
	flag.IntVar(&sleep, "sleep", 30, "Sleep")
	flag.Parse()

	if pid == -1 {
		log.Printf("-pid is required")
		os.Exit(1)
	}

	m := bpf.NewModule(source, []string{})
	defer m.Close()

	fd, err := m.LoadPerfEvent("do_perf_event")
	if err != nil {
		log.Printf("load perf event failed: %v", err)
		os.Exit(1)
	}

	if err = m.AttachPerfEvent(1, 0, 11, 0, -1, -1, -1, fd); err != nil {
		log.Printf("attach perf event failed: %v", err)
		os.Exit(1)
	}

	log.Printf("attached perf event!")

	if sleep < 0 {
		sleep = 30
	}

	aggregate := func() map[C.struct_key_t]int {
		channel := make(chan []byte)
		histogram := bpf.NewTable(m.TableId("histogram"), m)

		perfMap, err := bpf.InitPerfMap(histogram, channel, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
			os.Exit(1)
		}
		stacks := make(map[C.struct_key_t]int)
		perfMap.Start()
		done := time.After(time.Duration(sleep) * time.Second)
		for {
			select {
			case <-done:
				perfMap.Stop()
				return stacks
			default:
			}
			data := <-channel
			event := (*C.struct_key_t)(unsafe.Pointer(&data[0]))
			stacks[*event]++
		}
	}
	stacks := aggregate()
	log.Printf("preparing to aggregate stack...")

	stackTable := bpf.NewTable(m.TableId("stack_traces"), m)
	all := make(map[string]int)
	for stack, count := range stacks {
		if stack.pid != C.uint32_t(pid) {
			continue
		}
		var symbols []string
		var v int
		if stack.user_stack_id > 0 {
			v += count
			addrs := stackTable.GetStackAddr(int(stack.user_stack_id), true)
			for _, addr := range addrs {
				symbols = append(symbols, stackTable.GetAddrSymbol(addr, pid))
			}
		}

		if stack.kernel_stack_id > 0 {
			v += count
			addrs := stackTable.GetStackAddr(int(stack.user_stack_id), true)
			for _, addr := range addrs {
				symbols = append(symbols, stackTable.GetAddrSymbol(addr, pid))
			}
		}

		if len(symbols) != 0 {
			all[strings.Join(symbols, ";")] += count
		}
	}

	for k, v := range all {
		log.Printf("%s: %v", k, v)
	}
}
