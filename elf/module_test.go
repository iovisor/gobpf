// +build linux

package elf

import (
	"testing"
)

func TestUpdateKprobeNameForHandler(t *testing.T) {
	module := newModule()
	module.probes["probe"] = &Kprobe{Name: "probe"}

	for _, test := range []struct {
		handlerName string
		kprobeName  string
		actual      func() string
	}{
		{
			handlerName: "probe",
			kprobeName:  "newProbe",
			actual:      func() string { return module.probes["probe"].Name },
		},
	} {
		err := module.UpdateKprobeNameForHandler(test.handlerName, test.kprobeName)
		if err != nil {
			t.Fatalf("error occured while using UpdateKprobeNameForHandler function: %s", err)
		}

		if test.actual() != test.kprobeName {
			t.Fatalf("UpdateKprobeNameForHandler function didn't update correctly, expected: %s, actual value: %s", test.kprobeName, test.actual())
		}
	}
}

func TestEnableKprobesError(t *testing.T) {
	module := newModule()
	module.probes["probe"] = &Kprobe{Name: "probe"}
	module.probes["another_probe"] = &Kprobe{Name: "probe"}
	if err := module.EnableKprobes(1); err == nil {
		t.Fatalf("An error should trigger if two handlers are mapping to a same kprobe function")
	}
}
