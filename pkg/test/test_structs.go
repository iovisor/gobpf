package test

/*
#include "../../tests/dummy_structs.h"
*/
import "C"
import (
	"unsafe"
)

type S1 struct {
	A uint
}
type S2 struct {
	A uint
	B uint
}
type S8 struct {
	A uint
	B uint
	C uint
	D uint
	E uint
	F uint
	G uint
	H uint
}

func ReadS1(data []byte) *S1 {
	if len(data) != int(unsafe.Sizeof(C.struct_S1{})) {
		return nil
	}
	eventC := (*C.struct_S1)(unsafe.Pointer(&data[0]))
	return &S1{
		A: uint((*eventC).a),
	}
}

func ReadS2(data []byte) *S2 {
	if len(data) != int(unsafe.Sizeof(C.struct_S2{})) {
		return nil
	}
	eventC := (*C.struct_S2)(unsafe.Pointer(&data[0]))
	return &S2{
		A: uint((*eventC).a),
		B: uint((*eventC).b),
	}
}

func ReadS8(data []byte) *S8 {
	if len(data) != int(unsafe.Sizeof(C.struct_S8{})) {
		return nil
	}
	eventC := (*C.struct_S8)(unsafe.Pointer(&data[0]))
	return &S8{
		A: uint((*eventC).a),
		B: uint((*eventC).b),
		C: uint((*eventC).c),
		D: uint((*eventC).d),
		E: uint((*eventC).e),
		F: uint((*eventC).f),
		G: uint((*eventC).g),
		H: uint((*eventC).h),
	}
}
