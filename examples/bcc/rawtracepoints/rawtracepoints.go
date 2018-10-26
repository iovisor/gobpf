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

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/ksym"
)

import "C"

const source string = `
#include <linux/timer.h>

BPF_HASH(counts, u64);

RAW_TRACEPOINT_PROBE(timer_start) {
    // TP_PROTO(struct timer_list *timer,
    //        unsigned long expires,
    //        unsigned int flags),
    struct timer_list *timer = (struct timer_list *)ctx->args[0];
    void *function = timer->function;

    counts.increment((u64) function);
    return 0;
}
`

func main() {
	flag.Parse()
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	timerStartRTP, err := m.LoadRawTracepoint("raw_tracepoint__timer_start")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load raw tracepoint: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachRawTracepoint("timer_start", timerStartRTP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach raw tracepoint: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("counts"), m)

	fmt.Println("Tracing timer_start()... hit Ctrl-C to end.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Printf("%10s %s\n", "COUNT", "STRING")
	for it := table.Iter(); it.Next(); {
		k := binary.LittleEndian.Uint64(it.Key())
		kSymStr := fmt.Sprintf("%x", k)
		kSym, err := ksym.Ksym(kSymStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decoding KSym %q", kSymStr)
			continue
		}
		v := binary.LittleEndian.Uint64(it.Leaf())
		fmt.Printf("%10d \"%s\"\n", v, kSym)
	}
}
