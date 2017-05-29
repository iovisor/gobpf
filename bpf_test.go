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
	"strings"
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

var kernelVersion uint32

var (
	kernelVersion46  uint32
	kernelVersion48  uint32
	kernelVersion410 uint32
)

func init() {
	kernelVersion46, _ = elf.KernelVersionFromReleaseString("4.6.0")
	kernelVersion48, _ = elf.KernelVersionFromReleaseString("4.8.0")
	kernelVersion410, _ = elf.KernelVersionFromReleaseString("4.10.0")
}

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

func containsMap(maps []*elf.Map, name string) bool {
	for _, m := range maps {
		if m.Name == name {
			return true
		}
	}
	return false
}

func containsProbe(probes []*elf.Kprobe, name string) bool {
	for _, k := range probes {
		if k.Name == name {
			return true
		}
	}
	return false
}

func containsCgroupProg(cgroupProgs []*elf.CgroupProgram, name string) bool {
	for _, c := range cgroupProgs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func containsSocketFilter(socketFilters []*elf.SocketFilter, name string) bool {
	for _, c := range socketFilters {
		if c.Name == name {
			return true
		}
	}
	return false
}

func checkMaps(t *testing.T, b *elf.Module) {
	var expectedMaps = []string{
		"dummy_hash",
		"dummy_array",
		"dummy_prog_array",
		"dummy_perf",
	}

	if kernelVersion >= kernelVersion46 {
		kernel46Maps := []string{
			"dummy_percpu_hash",
			"dummy_percpu_array",
			"dummy_stack_trace",
		}
		expectedMaps = append(expectedMaps, kernel46Maps...)
	} else {
		t.Logf("kernel doesn't support percpu maps and stacktrace maps. Skipping...")
	}

	if kernelVersion >= kernelVersion48 {
		kernel48Maps := []string{
			"dummy_cgroup_array",
		}
		expectedMaps = append(expectedMaps, kernel48Maps...)
	} else {
		t.Logf("kernel doesn't support cgroup array maps. Skipping...")
	}

	var maps []*elf.Map
	for m := range b.IterMaps() {
		maps = append(maps, m)
	}
	if len(maps) != len(expectedMaps) {
		t.Fatalf("unexpected number of maps. Got %d, expected %d", len(maps), len(expectedMaps))
	}
	for _, em := range expectedMaps {
		if !containsMap(maps, em) {
			t.Fatalf("map %q not found", em)
		}
	}
}

func checkProbes(t *testing.T, b *elf.Module) {
	var expectedProbes = []string{
		"kprobe/dummy",
		"kretprobe/dummy",
	}

	var probes []*elf.Kprobe
	for p := range b.IterKprobes() {
		probes = append(probes, p)
	}
	if len(probes) != len(expectedProbes) {
		t.Fatalf("unexpected number of probes. Got %d, expected", len(probes), len(expectedProbes))
	}
	for _, ek := range expectedProbes {
		if !containsProbe(probes, ek) {
			t.Fatalf("probe %q not found", ek)
		}
	}
}

func checkCgroupProgs(t *testing.T, b *elf.Module) {
	if kernelVersion < kernelVersion410 {
		t.Logf("kernel doesn't support cgroup-bpf. Skipping...")
		return
	}

	var expectedCgroupProgs = []string{
		"cgroup/skb",
		"cgroup/sock",
	}

	var cgroupProgs []*elf.CgroupProgram
	for p := range b.IterCgroupProgram() {
		cgroupProgs = append(cgroupProgs, p)
	}
	if len(cgroupProgs) != len(expectedCgroupProgs) {
		t.Fatalf("unexpected number of cgroup programs. Got %d, expected %v", len(cgroupProgs), len(expectedCgroupProgs))
	}
	for _, cp := range expectedCgroupProgs {
		if !containsCgroupProg(cgroupProgs, cp) {
			t.Fatalf("cgroup program %q not found", cp)
		}
	}
}

func checkSocketFilters(t *testing.T, b *elf.Module) {
	var expectedSocketFilters = []string{
		"socket/dummy",
	}

	var socketFilters []*elf.SocketFilter
	for sf := range b.IterSocketFilter() {
		socketFilters = append(socketFilters, sf)
	}
	if len(socketFilters) != len(expectedSocketFilters) {
		t.Fatalf("unexpected number of socket filters. Got %d, expected %d", len(socketFilters), len(expectedSocketFilters))
	}
	for _, sf := range expectedSocketFilters {
		if !containsSocketFilter(socketFilters, sf) {
			t.Fatalf("socket filter %q not found", sf)
		}
	}
}

func TestModuleLoadELF(t *testing.T) {
	var err error
	kernelVersion, err = elf.CurrentKernelVersion()
	if err != nil {
		t.Fatalf("error getting current kernel version: %v")
	}

	dummyELF := "./tests/dummy.o"
	if kernelVersion > kernelVersion410 {
		dummyELF = "./tests/dummy-410.o"
	} else if kernelVersion > kernelVersion48 {
		dummyELF = "./tests/dummy-48.o"
	} else if kernelVersion > kernelVersion46 {
		dummyELF = "./tests/dummy-46.o"
	}

	b := elf.NewModule(dummyELF)
	if b == nil {
		t.Fatal("prog is nil")
	}
	if err := b.Load(nil); err != nil {
		if !strings.Contains(err.Error(), "invalid argument") {
			t.Fatal(err)
		}
	}
	defer b.Close()

	checkMaps(t, b)
	checkProbes(t, b)
	checkCgroupProgs(t, b)
	checkSocketFilters(t, b)
}
