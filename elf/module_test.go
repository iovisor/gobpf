// +build linux

package elf

import (
	"testing"
)

func TestSetKprobeForSection(t *testing.T) {
	module := newModule()
	module.probes["probe"] = &Kprobe{Name: "probe"}

	for _, test := range []struct {
		sectionName string
		kprobeName  string
		actual      func() string
	}{
		{
			sectionName: "probe",
			kprobeName:  "newProbe",
			actual:      func() string { return module.probes["probe"].Name },
		},
	} {
		err := module.SetKprobeForSection(test.sectionName, test.kprobeName)
		if err != nil {
			t.Fatalf("error occured while using SetKprobeForSection function: %s", err)
		}

		if test.actual() != test.kprobeName {
			t.Fatalf("SetKprobeForSection function didn't update correctly, expected: %s, actual value: %s", test.kprobeName, test.actual())
		}
	}
}

func TestEnableKprobesError(t *testing.T) {
	module := newModule()
	module.probes["probe"] = &Kprobe{Name: "probe"}
	module.probes["another_probe"] = &Kprobe{Name: "probe"}
	if err := module.EnableKprobes(1); err == nil {
		t.Fatalf("An error should trigger if two sections are mapping to a same kprobe function")
	}
}
