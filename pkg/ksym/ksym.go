package ksym

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	KALLSYMS = "/proc/kallsyms"
	ADDRCOL  = 0
	SYMCOL   = 2
)

type kCache struct {
	sync.RWMutex
	ksym map[string]string
}

var symCache kCache
var addrCache kCache

// Ksym translates a kernel memory address into a kernel function name
// using `/proc/kallsyms`
func Ksym(addr string) (string, error) {
	if symCache.ksym == nil {
		symCache.ksym = make(map[string]string)
	}

	symCache.Lock()
	defer symCache.Unlock()

	if _, ok := symCache.ksym[addr]; !ok {
		fd, err := os.Open(KALLSYMS)
		if err != nil {
			return "", err
		}
		defer fd.Close()

		fn := kLookup(addr, fd, ADDRCOL, SYMCOL)
		if fn == "" {
			return "", errors.New("kernel function not found for " + addr)
		}

		symCache.ksym[addr] = fn
	}

	return symCache.ksym[addr], nil
}

// Kaddr translates a kernel function name into a memory address
// using `/proc/kallsyms`
func Kaddr(addr string) (string, error) {
	if addrCache.ksym == nil {
		addrCache.ksym = make(map[string]string)
	}

	addrCache.Lock()
	defer addrCache.Unlock()

	if _, ok := addrCache.ksym[addr]; !ok {
		fd, err := os.Open(KALLSYMS)
		if err != nil {
			return "", err
		}
		defer fd.Close()

		fn := kLookup(addr, fd, SYMCOL, ADDRCOL)
		if fn == "" {
			return "", errors.New("kernel function not found for " + addr)
		}

		addrCache.ksym[addr] = fn
	}

	return addrCache.ksym[addr], nil
}

// kLookup scans given file for string in keyColumn and returns value in valColumn
func kLookup(addr string, r io.Reader, keyColumn int, valColumn int) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		l := s.Text()
		ar := strings.Split(l, " ")
		if len(ar) != 3 {
			continue
		}

		if ar[keyColumn] == addr {
			return ar[valColumn]
		}
	}

	return ""
}
