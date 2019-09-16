// +build linux

package elf

import (
	"testing"
)

func TestUpdateKprobeSecName(t *testing.T) {
	module := newModule()
	module.probes["probe"] = &Kprobe{Name: "probe"}

	for _, test := range []struct {
		oldName  string
		newName  string
		expected func() string
	}{
		{
			oldName:  "probe",
			newName:  "newProbe",
			expected: func() string { return module.probes["probe"].Name },
		},
	} {
		err := module.UpdateKprobeSecName(test.oldName, test.newName)
		if err != nil {
			t.Fatalf("error occured while using UpdateKprobeSecName function: %s", err)
		}

		if test.expected() != test.newName {
			t.Fatalf("UpdateKprobeSecName function didn't update correctly, expected: %s, actual value: %s", test.newName, test.expected())
		}
	}
}
