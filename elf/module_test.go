// +build linux

package elf

import (
	"testing"
)

func TestUpdateSecName(t *testing.T) {
	module := newModule()
	module.maps = make(map[string]*Map)

	module.maps["map"] = &Map{Name: "map"}
	module.probes["probe"] = &Kprobe{Name: "probe"}
	module.uprobes["uprobe"] = &Uprobe{Name: "uprobe"}
	module.cgroupPrograms["cgroup"] = &CgroupProgram{Name: "cgroup"}
	module.socketFilters["socketFilter"] = &SocketFilter{Name: "socketFilter"}
	module.tracepointPrograms["tracepoint"] = &TracepointProgram{Name: "tracepoint"}
	module.schedPrograms["schedProgram"] = &SchedProgram{Name: "schedProgram"}

	for _, test := range []struct {
		mappingType MappingType
		oldName     string
		newName     string
		expected    func() string
	}{
		{
			mappingType: TypeMap,
			oldName:     "map",
			newName:     "newMap",
			expected:    func() string { return module.maps["map"].Name },
		},
		{
			mappingType: TypeProbe,
			oldName:     "probe",
			newName:     "newProbe",
			expected:    func() string { return module.probes["probe"].Name },
		},
		{
			mappingType: TypeUprobe,
			oldName:     "uprobe",
			newName:     "newUprobe",
			expected:    func() string { return module.uprobes["uprobe"].Name },
		},
		{
			mappingType: TypeCgroupProgram,
			oldName:     "cgroup",
			newName:     "newCgroup",
			expected:    func() string { return module.cgroupPrograms["cgroup"].Name },
		},
		{
			mappingType: TypeSocketFilter,
			oldName:     "socketFilter",
			newName:     "newSocketFilter",
			expected:    func() string { return module.socketFilters["socketFilter"].Name },
		},
		{
			mappingType: TypeTracepointProgram,
			oldName:     "tracepoint",
			newName:     "newTracepoint",
			expected:    func() string { return module.tracepointPrograms["tracepoint"].Name },
		},
		{
			mappingType: TypeSchedProgram,
			oldName:     "schedProgram",
			newName:     "newSchedProgram",
			expected:    func() string { return module.schedPrograms["schedProgram"].Name },
		},
	} {
		err := module.UpdateSecName(test.mappingType, test.oldName, test.newName)
		if err != nil {
			t.Fatalf("error occured while using UpdateMappingName function: %s", err)
		}

		if test.expected() != test.newName {
			t.Fatalf("UpdateMappingName function didn't update correctly, expected: %s, actual value: %s", test.newName, test.expected())
		}
	}
}
