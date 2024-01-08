/*
 * Emyzelium (Go)
 *
 * is another wrapper around ZeroMQ's Publish-Subscribe messaging pattern
 * with mandatory Curve security and optional ZAP authentication filter,
 * over Tor, through Tor SOCKS proxy,
 * for distributed artificial elife, decision making etc. systems where
 * each peer, identified by its public key, onion address, and port,
 * publishes and updates vectors of vectors of bytes of data
 * under unique topics that other peers can subscribe to
 * and receive the respective data.
 *
 * https://github.com/emyzelium/emyzelium-go
 *
 * emyzelium@protonmail.com
 *
 * Copyright (c) 2023-2024 Emyzelium caretakers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Library
 */

package emyzelium

/*
#cgo LDFLAGS: -lzmq

#include "zmq.h"

#include "stdlib.h"
#include "string.h"
*/
import "C"

import (
	"bytes"
	crrand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"
)

const (
	LibVersion string = "0.9.8"
	LibDate    string = "2024.01.08"

	DefPubSubPort uint16 = 0xEDAF // 60847

	DefTorProxyPort uint16 = 9050        // default from /etc/tor/torrc
	DefTorProxyHost string = "127.0.0.1" // default from /etc/tor/torrc

	keyZ85Len     int = 40
	keyZ85CStrLen int = keyZ85Len + 1
	keyBinLen     int = 32

	defIPv6Status int = 1

	curveMechanismId string = "CURVE" // See https://rfc.zeromq.org/spec/27/
	zapDomain        string = "emyz"

	zapSessionIdLen int = 32

	errAlreadyPresent string = "already present"
	errAlreadyAbsent  string = "already absent"
	errAlreadyPaused  string = "already paused"
	errAlreadyResumed string = "already resumed"
	errAbsent         string = "absent"
)

type Etale struct {
	paused bool
	parts  [][]byte
	tOut   int64
	tIn    int64
}

type Ehypha struct {
	subSocket unsafe.Pointer
	etales    map[string]*Etale
}

type Efunguz struct {
	secretKey           string
	publicKey           string
	whitelistPublicKeys map[string]bool
	torProxyPort        uint16
	torProxyHost        string
	ehyphae             map[string]*Ehypha
	context             unsafe.Pointer
	zapSocket           unsafe.Pointer
	zapSessionId        []byte
	pubSocket           unsafe.Pointer
	monSocket           unsafe.Pointer
	inConnNum           uint
}

func timeMuSec() int64 {
	return time.Now().UnixMicro()
}

func cutPadKeyStr(s string) string {
	l := len(s)
	if l >= keyZ85Len {
		return s[:keyZ85Len]
	} else {
		return s + strings.Repeat(" ", keyZ85Len-l)
	}
}

func zmqeBind(socket unsafe.Pointer, endPoint string) C.int {
	endPointBuf := []byte(endPoint)
	endPointBuf = append(endPointBuf, 0)
	return C.zmq_bind(socket, (*C.char)(unsafe.Pointer(&endPointBuf[0])))
}

func zmqeConnect(socket unsafe.Pointer, endPoint string) C.int {
	endPointBuf := []byte(endPoint)
	endPointBuf = append(endPointBuf, 0)
	return C.zmq_connect(socket, (*C.char)(unsafe.Pointer(&endPointBuf[0])))
}

func zmqeSocketMonitorAll(socket unsafe.Pointer, endPoint string) C.int {
	endPointBuf := []byte(endPoint)
	endPointBuf = append(endPointBuf, 0)
	return C.zmq_socket_monitor(socket, (*C.char)(unsafe.Pointer(&endPointBuf[0])), C.ZMQ_EVENT_ALL)
}

func zmqeSetSockOptInt(socket unsafe.Pointer, optionName C.int, optionValue int) C.int {
	cOptionValue := C.int(optionValue)
	return C.zmq_setsockopt(socket, optionName, unsafe.Pointer(&cOptionValue), C.sizeof_int)
}

func zmqeSetSockOptStr(socket unsafe.Pointer, optionName C.int, optionValue string) C.int {
	valueBuf := []byte(optionValue)
	valueBuf = append(valueBuf, 0)
	return C.zmq_setsockopt(socket, optionName, unsafe.Pointer(&valueBuf[0]), C.size_t(len(valueBuf)))
}

func zmqeSetSockOptVec(socket unsafe.Pointer, optionName C.int, optionValue []byte) C.int {
	return C.zmq_setsockopt(socket, optionName, unsafe.Pointer(&optionValue[0]), C.size_t(len(optionValue)))
}

func zmqeGetSockOptEvents(socket unsafe.Pointer) C.int {
	var optionValue C.int
	var optionLen C.size_t = C.sizeof_int
	C.zmq_getsockopt(socket, C.ZMQ_EVENTS, unsafe.Pointer(&optionValue), (*C.size_t)(&optionLen))
	return optionValue
}

func zmqeCurvePublic(secretKey string) (string, C.int) {
	secretKey = cutPadKeyStr(secretKey)
	secretKeyBuf := []byte(secretKey)
	secretKeyBuf = append(secretKeyBuf, 0)
	var publicKeyBuf [keyZ85CStrLen]byte
	cR := C.zmq_curve_public((*C.char)(unsafe.Pointer(&publicKeyBuf[0])), (*C.char)(unsafe.Pointer(&secretKeyBuf[0])))
	if cR != 0 {
		return "", cR
	}
	return string(publicKeyBuf[:keyZ85Len]), cR
}

func zmqeSend(socket unsafe.Pointer, parts [][]byte) {
	var msg C.zmq_msg_t
	for i := 0; i < len(parts); i++ {
		cSize := C.size_t(len(parts[i]))
		C.zmq_msg_init_size(&msg, cSize)
		if cSize > 0 {
			C.memcpy(C.zmq_msg_data(&msg), unsafe.Pointer(&parts[i][0]), cSize)
		}
		var flags C.int = 0
		if (i + 1) < len(parts) {
			flags = C.ZMQ_SNDMORE
		}
		if C.zmq_msg_send(&msg, socket, flags) < 0 {
			C.zmq_msg_close(&msg)
		}
	}
}

func zmqeRecv(socket unsafe.Pointer) [][]byte {
	var parts [][]byte
	var msg C.zmq_msg_t
	var cMore C.int
	for {
		C.zmq_msg_init(&msg)
		C.zmq_msg_recv(&msg, socket, 0)
		cSize := C.zmq_msg_size(&msg)
		part := make([]byte, int(cSize))
		cData := C.zmq_msg_data(&msg)
		if cSize > 0 {
			C.memcpy(unsafe.Pointer(&part[0]), cData, cSize)
		}
		parts = append(parts, part)
		cMore = C.zmq_msg_get(&msg, C.ZMQ_MORE)
		C.zmq_msg_close(&msg)
		if cMore == 0 {
			break
		}
	}
	return parts
}

func (e *Etale) init() {
	e.paused = false
	e.tOut = -1
	e.tIn = -1
}

// Deep copy, ensures immutability of original data
func (e *Etale) Parts() [][]byte {
	var copyParts [][]byte
	for _, part := range e.parts {
		copyPart := make([]byte, len(part))
		copy(copyPart, part)
		copyParts = append(copyParts, copyPart)
	}
	return copyParts
}

func (e *Etale) TOut() int64 {
	return e.tOut
}

func (e *Etale) TIn() int64 {
	return e.tIn
}

func (e *Ehypha) init(context unsafe.Pointer, secretKey string, publicKey string, serverKey string, onion string, port uint16, torProxyPort uint16, torProxyHost string) {
	e.subSocket = C.zmq_socket(context, C.ZMQ_SUB)
	zmqeSetSockOptStr(e.subSocket, C.ZMQ_CURVE_SECRETKEY, secretKey)
	zmqeSetSockOptStr(e.subSocket, C.ZMQ_CURVE_PUBLICKEY, publicKey)
	zmqeSetSockOptStr(e.subSocket, C.ZMQ_CURVE_SERVERKEY, serverKey)
	zmqeSetSockOptStr(e.subSocket, C.ZMQ_SOCKS_PROXY, fmt.Sprintf("%s:%d", torProxyHost, torProxyPort))
	zmqeConnect(e.subSocket, fmt.Sprintf("tcp://%s.onion:%d", onion, port))

	e.etales = make(map[string]*Etale)
}

func (e *Ehypha) AddEtale(title string) (*Etale, error) {
	if et, ok := e.etales[title]; !ok {
		net := new(Etale)
		net.init()
		e.etales[title] = net
		zmqeSetSockOptStr(e.subSocket, C.ZMQ_SUBSCRIBE, title)
		return net, nil
	} else {
		return et, errors.New(errAlreadyPresent)
	}
}

func (e *Ehypha) GetEtale(title string) (*Etale, error) {
	if et, ok := e.etales[title]; ok {
		return et, nil
	} else {
		return nil, errors.New(errAbsent)
	}
}

func (e *Ehypha) DelEtale(title string) error {
	if _, ok := e.etales[title]; ok {
		delete(e.etales, title)
		zmqeSetSockOptStr(e.subSocket, C.ZMQ_UNSUBSCRIBE, title)
		return nil
	} else {
		return errors.New(errAlreadyAbsent)
	}
}

func (e *Ehypha) PauseEtale(title string) error {
	if et, ok := e.etales[title]; ok {
		if !et.paused {
			zmqeSetSockOptStr(e.subSocket, C.ZMQ_UNSUBSCRIBE, title)
			et.paused = true
			return nil
		} else {
			return errors.New(errAlreadyPaused)
		}
	} else {
		return errors.New(errAbsent)
	}
}

func (e *Ehypha) ResumeEtale(title string) error {
	if et, ok := e.etales[title]; ok {
		if et.paused {
			zmqeSetSockOptStr(e.subSocket, C.ZMQ_SUBSCRIBE, title)
			et.paused = false
			return nil
		} else {
			return errors.New(errAlreadyResumed)
		}
	} else {
		return errors.New(errAbsent)
	}
}

func (e *Ehypha) PauseEtales() {
	for title, et := range e.etales {
		if !et.paused {
			zmqeSetSockOptStr(e.subSocket, C.ZMQ_UNSUBSCRIBE, title)
			et.paused = true
		}
	}
}

func (e *Ehypha) ResumeEtales() {
	for title, et := range e.etales {
		if et.paused {
			zmqeSetSockOptStr(e.subSocket, C.ZMQ_SUBSCRIBE, title)
			et.paused = false
		}
	}
}

func (e *Ehypha) update() {
	t := timeMuSec()
	for zmqeGetSockOptEvents(e.subSocket)&C.ZMQ_POLLIN != 0 {
		msgParts := zmqeRecv(e.subSocket)
		// Sanity checks...
		if len(msgParts) >= 2 {
			// 0th is topic, 1st is remote time, rest (optional) is data
			topic := msgParts[0]
			l := len(topic)
			if (l > 0) && (topic[l-1] == 0) {
				title := string(topic[:(l - 1)])
				if et, ok := e.etales[title]; ok {
					if !et.paused {
						if len(msgParts[1]) == 8 { // int64
							et.parts = make([][]byte, 0)
							et.parts = append(et.parts, msgParts[2:]...)
							et.tOut = int64(binary.LittleEndian.Uint64(msgParts[1]))
							et.tIn = t
						}
					}
				}
			}
		}
	}
}

func (e *Ehypha) drop() {
	e.etales = make(map[string]*Etale)
	C.zmq_close(e.subSocket)
	e.subSocket = nil
}

func (e *Efunguz) Init(secretKey string, whitelistPublicKeys map[string]bool, pubPort uint16, torProxyPort uint16, torProxyHost string) {
	e.secretKey = cutPadKeyStr(secretKey)
	e.publicKey, _ = zmqeCurvePublic(e.secretKey)

	e.whitelistPublicKeys = make(map[string]bool)
	for k := range whitelistPublicKeys {
		e.whitelistPublicKeys[cutPadKeyStr(k)] = true
	}

	e.torProxyPort = torProxyPort
	e.torProxyHost = torProxyHost

	e.ehyphae = make(map[string]*Ehypha)

	e.context = C.zmq_ctx_new()

	C.zmq_ctx_set(e.context, C.ZMQ_IPV6, C.int(defIPv6Status))
	C.zmq_ctx_set(e.context, C.ZMQ_BLOCKY, 0)

	// At first, REP socket for ZAP auth...
	e.zapSocket = C.zmq_socket(e.context, C.ZMQ_REP)
	zmqeBind(e.zapSocket, "inproc://zeromq.zap.01")

	e.zapSessionId = make([]byte, zapSessionIdLen)
	crrand.Read(e.zapSessionId) // must be cryptographically random... is it?

	// ..and only then, PUB socket
	e.pubSocket = C.zmq_socket(e.context, C.ZMQ_PUB)
	zmqeSetSockOptInt(e.pubSocket, C.ZMQ_CURVE_SERVER, 1)
	zmqeSetSockOptStr(e.pubSocket, C.ZMQ_CURVE_SECRETKEY, e.secretKey)
	zmqeSetSockOptVec(e.pubSocket, C.ZMQ_ZAP_DOMAIN, []byte(zapDomain)) // to enable auth, must be non-empty due to ZMQ RFC 27
	zmqeSetSockOptVec(e.pubSocket, C.ZMQ_ROUTING_ID, e.zapSessionId)    // to make sure only this pubSocket can pass auth through zapSocket; see update()

	// Before binding, attach monitor
	zmqeSocketMonitorAll(e.pubSocket, "inproc://monitor-pub")
	e.monSocket = C.zmq_socket(e.context, C.ZMQ_PAIR)
	zmqeConnect(e.monSocket, "inproc://monitor-pub")

	zmqeBind(e.pubSocket, fmt.Sprintf("tcp://*:%d", pubPort))

	e.inConnNum = 0
}

func (e *Efunguz) AddWhitelistPublicKeys(publicKeys map[string]bool) {
	for k := range publicKeys {
		e.whitelistPublicKeys[cutPadKeyStr(k)] = true
	}
}

func (e *Efunguz) DelWhitelistPublicKeys(publicKeys map[string]bool) {
	for k := range publicKeys {
		delete(e.whitelistPublicKeys, cutPadKeyStr(k))
	}
}

func (e *Efunguz) ClearWhitelistPublicKeys() {
	e.whitelistPublicKeys = make(map[string]bool)
}

func (e *Efunguz) ReadWhitelistPublicKeys(filePath string) {
	if content, err := os.ReadFile(filePath); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if len(line) >= keyZ85Len {
				e.whitelistPublicKeys[line[:keyZ85Len]] = true
			}
		}
	}
}

func (e *Efunguz) AddEhypha(publicKey string, onion string, port uint16) (*Ehypha, error) {
	cpPublicKey := cutPadKeyStr(publicKey)
	if eh, ok := e.ehyphae[cpPublicKey]; !ok {
		neh := new(Ehypha)
		neh.init(e.context, e.secretKey, e.publicKey, cpPublicKey, onion, port, e.torProxyPort, e.torProxyHost)
		e.ehyphae[cpPublicKey] = neh
		return neh, nil
	} else {
		return eh, errors.New(errAlreadyPresent)
	}
}

func (e *Efunguz) GetEhypha(publicKey string) (*Ehypha, error) {
	cpPublicKey := cutPadKeyStr(publicKey)
	if eh, ok := e.ehyphae[cpPublicKey]; ok {
		return eh, nil
	} else {
		return nil, errors.New(errAbsent)
	}
}

func (e *Efunguz) DelEhypha(publicKey string) error {
	cpPublicKey := cutPadKeyStr(publicKey)
	if eh, ok := e.ehyphae[cpPublicKey]; ok {
		eh.drop()
		delete(e.ehyphae, cpPublicKey)
		return nil
	} else {
		return errors.New(errAlreadyAbsent)
	}
}

func (e *Efunguz) EmitEtale(title string, parts [][]byte) {
	var msgParts [][]byte

	topic := []byte(title)
	topic = append(topic, 0)
	msgParts = append(msgParts, topic)

	tOut := timeMuSec()
	tOutBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(tOutBuf, uint64(tOut))
	msgParts = append(msgParts, tOutBuf)

	msgParts = append(msgParts, parts...)

	zmqeSend(e.pubSocket, msgParts)
}

func (e *Efunguz) Update() {
	for zmqeGetSockOptEvents(e.zapSocket)&C.ZMQ_POLLIN != 0 {
		request := zmqeRecv(e.zapSocket)
		var reply [][]byte

		version := request[0]
		sequence := request[1]
		// domain := request[2]
		// address := request[3]
		identity := request[4]
		mechanism := request[5]
		keyBin := request[6]

		keyBin = keyBin[:min(keyBinLen, len(keyBin))]
		keyBuf := make([]byte, keyZ85CStrLen)
		C.zmq_z85_encode((*C.char)(unsafe.Pointer(&keyBuf[0])), (*C.uchar)(unsafe.Pointer(&keyBin[0])), C.size_t(keyBinLen))
		keyZ85 := string(keyBuf[:keyZ85Len])

		reply = append(reply, version, sequence)

		if bytes.Equal(identity, e.zapSessionId) && bytes.Equal(mechanism, []byte(curveMechanismId)) && ((len(e.whitelistPublicKeys) == 0) || e.whitelistPublicKeys[keyZ85]) {
			// Auth passed
			// Though needless (yet), set user-id to client's public key
			reply = append(reply,
				[]byte("200"), []byte("OK"), []byte(keyZ85), []byte(""))
		} else {
			// Auth failed
			reply = append(reply,
				[]byte("400"), []byte("FAILED"), []byte(""), []byte(""))
		}

		zmqeSend(e.zapSocket, reply)
	}

	for _, eh := range e.ehyphae {
		eh.update()
	}

	for zmqeGetSockOptEvents(e.monSocket)&C.ZMQ_POLLIN != 0 {
		event_msg := zmqeRecv(e.monSocket)
		if len(event_msg) > 0 {
			if len(event_msg[0]) >= 2 {
				event_num := uint(event_msg[0][0]) + (uint(event_msg[0][1]) << 8)
				if event_num&uint(C.ZMQ_EVENT_ACCEPTED) != 0 {
					e.inConnNum++
				}
				if (event_num&uint(C.ZMQ_EVENT_DISCONNECTED) != 0) && (e.inConnNum > 0) {
					e.inConnNum--
				}
			}
		}
	}
}

func (e *Efunguz) InConnectionsNum() uint {
	return e.inConnNum
}

func (e *Efunguz) Drop() {
	for _, eh := range e.ehyphae {
		eh.drop() // to close subSocket of each ehypha before terminating context, to which those sockets belong; freezes otherwise
	}
	e.ehyphae = make(map[string]*Ehypha)

	C.zmq_close(e.monSocket)
	C.zmq_close(e.pubSocket)
	C.zmq_close(e.zapSocket)

	C.zmq_ctx_shutdown(e.context)
	for C.zmq_ctx_term(e.context) == -1 {
		if C.zmq_errno() == C.EINTR {
			continue
		} else {
			break
		}
	}

	e.secretKey = ""
	e.publicKey = ""
	e.whitelistPublicKeys = map[string]bool{}
	e.torProxyPort = 0
	e.torProxyHost = ""
	e.context = nil
	e.zapSocket = nil
	e.zapSessionId = []byte{}
	e.pubSocket = nil
	e.monSocket = nil
	e.inConnNum = 0
}
