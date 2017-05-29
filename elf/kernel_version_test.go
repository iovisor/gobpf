// +build linux

// Copyright 2017 Kinvolk
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

package elf

import (
	"testing"
)

var testData = []struct {
	succeed       bool
	releaseString string
	kernelVersion uint32
}{
	{true, "4.1.2-3", 262402},
	{true, "4.8.14-200.fc24.x86_64", 264206},
	{true, "4.1.2-3foo", 262402},
	{true, "4.1.2foo-1", 262402},
	{true, "4.1.2-rkt-v1", 262402},
	{true, "4.1.2rkt-v1", 262402},
	{true, "4.1.2-3 foo", 262402},
	{false, "foo 4.1.2-3", 0},
	{true, "4.1.2", 262402},
	{false, ".4.1.2", 0},
	{false, "4.1.", 0},
	{false, "4.1", 0},
}

func TestKernelVersionFromReleaseString(t *testing.T) {
	for _, test := range testData {
		version, err := KernelVersionFromReleaseString(test.releaseString)
		if err != nil && test.succeed {
			t.Errorf("expected %q to succeed: %s", test.releaseString, err)
		} else if err == nil && !test.succeed {
			t.Errorf("expected %q to fail", test.releaseString)
		}
		if version != test.kernelVersion {
			t.Errorf("expected kernel version %d, got %d", test.kernelVersion, version)
		}
	}
}
