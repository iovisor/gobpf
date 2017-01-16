// +build !linux

package elf

import "fmt"

type Module struct{}
type Kprobe struct{}

func NewModule(fileName string) *Module {
	return nil
}

func (b *Module) EnableKprobe(secName string) error {
	return fmt.Errorf("not supported")
}

func (b *Module) IterKprobes() <-chan *Kprobe {
	return nil
}

func (b *Module) EnableKprobes() error {
	return fmt.Errorf("not supported")
}
