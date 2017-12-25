package bccencoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unsafe"
)

var (
	ByteOrder binary.ByteOrder
)

func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		ByteOrder = binary.LittleEndian
	} else {
		ByteOrder = binary.BigEndian
	}
}

func Unmarshal(data []byte, dest interface{}) error {
	// TODO: This function relies on struct ordering being the same layout
	// in memory as it is in the definition. While this is true today and
	// quite unlikely to change stranger things have happened. Use at your
	// own risk!
	//
	// In the future or if this somehow becomes a problem perhaps `bcc:"0"`
	// type tags could be added to define field ordering definitively.
	ptr := reflect.ValueOf(dest)
	if ptr.Kind() != reflect.Ptr {
		return fmt.Errorf("Wanted pointer to value but got type: %s", ptr.Kind())
	}
	elem := ptr.Elem()

	var (
		// create these here so they are not created all over
		valu32 uint32
		valu64 uint64
	)

	switch elem.Kind() {
	case reflect.Uint32:
		if len(data) != 4 {
			return errors.New("Provided []byte not a uint32 type")
		}
		valu32 = ByteOrder.Uint32(data)
		elem.SetUint(uint64(valu32))
	case reflect.Uint64:
		if len(data) != 8 {
			return errors.New("Provided []byte not a uint64 type")
		}
		valu64 = ByteOrder.Uint64(data)
		elem.SetUint(valu64)
	case reflect.String:
		nullIndex := bytes.IndexByte(data, 0)
		if nullIndex == -1 {
			// No terminator, so it's likely the string is
			// truncated, so use full string
			elem.SetString(string(data))
		} else {
			elem.SetString(string(data[:nullIndex]))
		}
	case reflect.Struct:
		indr := reflect.Indirect(elem)

		byteCursor := 0

		for i := 0; i < indr.NumField(); i++ {
			val := indr.Field(i)

			// TODO: Add additional types if desired. For now these should
			// cover most existing eBPF scripts.
			switch val.Kind() {
			case reflect.Uint32:
				valu32 = ByteOrder.Uint32(data[byteCursor : byteCursor+4])
				//TODO: this feels weird. is it ok?
				val.SetUint(uint64(valu32))
				// set in struct
				byteCursor += 4
			case reflect.Uint64:
				valu64 = ByteOrder.Uint64(data[byteCursor : byteCursor+8])
				val.SetUint(valu64)
				byteCursor += 8
			case reflect.String:
				// advance the cursor until reaching a null-terminated
				// string. store the start so we can use it for a slice
				// index to convert to string at the end.
				start := byteCursor
				for ; data[byteCursor] != 0; byteCursor++ {
				}

				val.SetString(string(data[start:byteCursor]))

				// just go past the null terminator and on to the next
				// field
				byteCursor++
			default:
				return fmt.Errorf("Don't know how to unmarshal type: %s", val.Kind())
			}
		}
	default:
		return fmt.Errorf("Don't know how to unmarshal type: %s", elem.Kind())
	}
	return nil
}
