// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"encoding/binary"
	"unsafe"
)

const intSize = int(unsafe.Sizeof(int(0)))

func Int(n int) Key {
	buf := make([]byte, intSize)
	switch intSize {
	case 4:
		binary.BigEndian.PutUint32(buf, uint32(n))
	case 8:
		binary.BigEndian.PutUint64(buf, uint64(n))
	default:
		panic("unknown int size")
	}

	return buf
}

func Uint64(n uint64) Key {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}

func Uint16(n uint16) Key {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, n)
	return buf
}
