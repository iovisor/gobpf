package ksym

import (
	"strings"
	"testing"
)

const (
	data = "ffffffff91b2a340 T cgroup_freezing"
	addr = "ffffffff91b2a340"
	sym  = "cgroup_freezing"
)

func TestKsym(t *testing.T) {

	r := strings.NewReader(data)
	fn := kLookup(addr, r, ADDRCOL, SYMCOL)

	if fn != sym {
		t.Error("unexpected result")
	}
}

func TestKaddr(t *testing.T) {

	r := strings.NewReader(data)
	fn := kLookup(sym, r, SYMCOL, ADDRCOL)

	if fn != addr {
		t.Error("unexpected result")
	}
}
