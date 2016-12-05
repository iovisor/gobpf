[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/iovisor/gobpf)

This repository provides go bindings for the [bcc framework](https://github.com/iovisor/bcc).

gobpf is in early stage, but usable. Input and contributions are very much welcome.

To get started, first install (either by package or source) libbcc. Then, simply:

```
go install github.com/iovisor/gobpf
sudo -E go test github.com/iovisor/gobpf
```

Example code can be found in the `examples/` directory.

We recommend to vendor gobpf and pin its version as the API probably
undergoes change during development.
