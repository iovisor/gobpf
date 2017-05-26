package bpffs

import (
	"fmt"
	"syscall"
)

const (
	BPFFSPath = "/sys/fs/bpf"
)

// IsMounted checks if the BPF fs is mounted already
func IsMounted() (bool, error) {
	var data syscall.Statfs_t
	if err := syscall.Statfs(BPFFSPath, &data); err != nil {
		return false, fmt.Errorf("cannot statfs %q: %v", BPFFSPath, err)
	}
	// https://github.com/coreutils/coreutils/blob/v8.27/src/stat.c#L275
	return data.Type == 0xCAFE4A11, nil
}

// Mount mounts the BPF fs if not already mounted
func Mount() error {
	mounted, err := IsMounted()
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	if err := syscall.Mount(BPFFSPath, BPFFSPath, "bpf", 0, ""); err != nil {
		return fmt.Errorf("error mounting %q: %v", BPFFSPath, err)
	}
	return nil
}
