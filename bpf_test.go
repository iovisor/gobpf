// +build integration

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

package bpf

import (
	"testing"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/elf"
)

var simple1 string = `
BPF_TABLE("hash", int, int, table1, 10);
int func1(void *ctx) {
	return 0;
}
`

func TestModuleLoadBCC(t *testing.T) {
	b := bcc.NewModule(simple1, []string{})
	if b == nil {
		t.Fatal("prog is nil")
	}
	defer b.Close()
	_, err := b.LoadKprobe("func1")
	if err != nil {
		t.Fatal(err)
	}
}

func TestModuleLoadELF(t *testing.T) {
	b := elf.NewModule("./tests/dummy.o")
	if b == nil {
		t.Fatal("prog is nil")
	}
	err := b.Load()
	if err != nil {
		t.Fatal(err)
	}
	var maps []*elf.Map
	for m := range b.IterMaps() {
		maps = append(maps, m)
	}
	if len(maps) != 1 {
		t.Fatal("unexpcted number of maps")
	}
	if maps[0].Name != "dummy" {
		t.Fatalf("map %q doesn't match expected name 'dummy'", maps[0].Name)
	}
	var probes []*elf.Kprobe
	for p := range b.IterKprobes() {
		probes = append(probes, p)
	}
	if len(probes) != 1 {
		t.Fatalf("unexpcted number of probes: %d", len(probes))
	}
	if probes[0].Name != "kprobe/dummy" {
		t.Fatalf("probe %q doesn't match expected name 'dummy'", probes[0].Name)
	}
}
