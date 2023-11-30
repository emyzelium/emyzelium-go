package main

/*
#cgo LDFLAGS: -lzmq

#include "zmq.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	keyZ85Len     int = 40
	keyZ85CStrLen     = keyZ85Len + 1
)

func zmqeCurveKeyPair() (string, string, C.int) {
	var secretKeyBuf [keyZ85CStrLen]byte
	var publicKeyBuf [keyZ85CStrLen]byte
	cR := C.zmq_curve_keypair((*C.char)(unsafe.Pointer(&publicKeyBuf[0])), (*C.char)(unsafe.Pointer(&secretKeyBuf[0])))
	return string(publicKeyBuf[:keyZ85Len]), string(secretKeyBuf[:keyZ85Len]), cR
}

func main() {
	publicKey, secretKey, _ := zmqeCurveKeyPair()
	fmt.Printf("Public key: %s\n", publicKey)
	// Make sure no one is behind your back...
	fmt.Printf("Secret key: %s\n", secretKey)
}
