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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
typedef char strlenkey_t[80];
BPF_HASH(counts, strlenkey_t);

int count(struct pt_regs *ctx) {
	if (!PT_REGS_PARM1(ctx))
		return 0;

	strlenkey_t key;
	u64 zero = 0, *val;

	bpf_probe_read(&key, sizeof(key), (void *)PT_REGS_PARM1(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}
`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

func decodeHexString(raw string) ([]byte, error) {
	ret := ""
	// split on whitespace, replace 0x66 --> 66, concatenate the results then hex decode
	for _, c := range strings.Split(strings.Replace(raw, "0x", "", -1), " ") {
		if c == "[" || c == "]" {
			continue
		}
		if c == "0" {
			break
		}
		ret = fmt.Sprintf("%s%s", ret, c)
	}
	return hex.DecodeString(ret)
}

func decodeHexInt(raw string) (uint64, error) {
	return strconv.ParseUint(raw, 0, 64)
}

func main() {
	pid := flag.Int("pid", -1, "attach to pid, default is all processes")
	flag.Parse()
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	strlenUprobe, err := m.LoadUprobe("count")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe count: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachUprobe("c", "strlen", strlenUprobe, *pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach uprobe to strlen: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("counts"), m)

	fmt.Println("Tracing strlen()... hit Ctrl-C to end.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Printf("%10s %s\n", "COUNT", "STRING")
	for evt := range table.Iter() {
		k, err := decodeHexString(evt.Key)
		if err != nil {
			continue
		}

		v, err := decodeHexInt(evt.Value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to decode result: %s\n", err)
		}
		fmt.Printf("%10d \"%s\"\n", v, ansiEscape.ReplaceAll(k, []byte{}))
	}
}
