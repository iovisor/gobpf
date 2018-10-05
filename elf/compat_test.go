// +build linux

// (c) 2018 ShiftLeft GmbH <suchakra@shiftleft.io>
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
    "path/filepath"
	"testing"
)

func TestGetSyscallFnName(t *testing.T) {
    fnName, err := getSyscallFnNameWithFile("open", filepath.Join("testdata", "prefix_symbols.txt"))
	if err != nil && fnName != "__x64_sys_open" {
		t.Errorf("expected __x64_sys_open : %s", err)
	}
	fnName, err = getSyscallFnNameWithFile("open", filepath.Join("testdata", "symbols.txt"))
	if err != nil {
        if fnName != "SyS_open" {
            t.Errorf("expected SyS_open :%s", err)
        }
    }
}
