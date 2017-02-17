# gobpf

[![Build Status](https://semaphoreci.com/api/v1/alban/gobpf-2/branches/master/badge.svg)](https://semaphoreci.com/alban/gobpf-2) [![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/iovisor/gobpf)

This repository provides go bindings for the [bcc framework](https://github.com/iovisor/bcc)
as well as low-level routines to load and use eBPF programs from .elf
files.

gobpf is in early stage, but usable. Input and contributions are very much welcome.

To get started, first install (either by package or source) libbcc. Then, simply:

```
go install github.com/iovisor/gobpf
sudo -E go test github.com/iovisor/gobpf
```

Example code can be found in the `examples/` directory.

We recommend to vendor gobpf and pin its version as the API probably
undergoes change during development.

## Building ELF object files

To build ELF object files for usage with `github.com/iovisor/gobpf/elf`,
you must use distinct sections (`SEC("...")`). Currently, only
`kprobe/...` and `maps/...` are supported. For an example, see
`tests/dummy.c`.
