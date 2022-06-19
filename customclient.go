// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"encoding/hex"
	"errors"
	//"github.com/dop251/goja"
	"github.com/robertkrimen/otto"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

const (
	// Default TCP timeout is not set
	customMaxLength      = 10240
	customTimeout     = 10 * time.Second
	customIdleTimeout = 60 * time.Second
)

// CustomClientHandler implements Packager and Transporter interface.
type CustomClientHandler struct {
	customPackager
	customTransporter
}

// NewCustomClientHandler allocates a new CustomClientHandler.
func NewCustomClientHandler(address string) *CustomClientHandler {
	h := &CustomClientHandler{}
	h.Address = address
	h.Timeout = tcpTimeout
	h.IdleTimeout = customIdleTimeout
	return h
}

// CustomClient creates TCP client with default handler and given connect string.
func CustomClient(address string) Client {
	handler := NewCustomClientHandler(address)
	return NewClient(handler)
}

// customPackager implements Packager interface.
type customPackager struct {
	VerifyFunc string
	DecodeFunc string
	EncodeFunc string
}

// Encode adds modbus application protocol header:
//  Transaction identifier: 2 bytes
//  Protocol identifier: 2 bytes
//  Length: 2 bytes
//  Unit identifier: 1 byte
//  Function code: 1 byte
//  Data: n bytes
func (mb *customPackager) Encode(pdu *ProtocolDataUnit) (adu []byte, err error) {
	// goja
	//vm := goja.New()
	//_, err = vm.RunString(mb.EncodeFunc)
	//if err!=nil {
	//	panic(err)
	//}
	//var fn func(string) string
	//err = vm.ExportTo(vm.Get("encode"), &fn)
	//if err != nil {
	//	panic(err)
	//}
	//
	//ss := fn(pdu.CustomCode)
	//adu, _ = hex.DecodeString(ss)

	//otto
	vm := otto.New()
	_, err = vm.Run(mb.EncodeFunc)
	if err!=nil {
		panic(err)
	}
	value, err := vm.Call("encode", nil, pdu.CustomCode)
	if err != nil {
		panic(err)
	}
	adu, _ = hex.DecodeString(value.String())

	return
}

// Verify confirms transaction, protocol and unit id.
func (mb *customPackager) Verify(aduRequest []byte, aduResponse []byte) (err error) {
	aduReq := hex.EncodeToString(aduRequest)
	aduRep := hex.EncodeToString(aduResponse)
	//goja
	//vm := goja.New()
	//_, err = vm.RunString(mb.VerifyFunc)
	//if err!=nil {
	//	panic(err)
	//}
	//var fn func(string, string) bool
	//err = vm.ExportTo(vm.Get("verify"), &fn)
	//if err != nil {
	//	panic(err)
	//}
	//
	//ret := fn(aduReq, aduRep)
	//if !ret {
	//	return errors.New("Verify error")
	//}

	//otto
	vm := otto.New()
	_, err = vm.Run(mb.VerifyFunc)
	if err!=nil {
		panic(err)
	}
	value, err := vm.Call("verify", nil, aduReq, aduRep)
	if err != nil {
		panic(err)
	}
	if ret,_ := value.ToBoolean();!ret {
		return errors.New("Verify error")
	}

	return
}

// Decode extracts PDU from TCP frame:
//  Transaction identifier: 2 bytes
//  Protocol identifier: 2 bytes
//  Length: 2 bytes
//  Unit identifier: 1 byte
func (mb *customPackager) Decode(adu []byte) (pdu *ProtocolDataUnit, err error) {
	//goja
	//vm := goja.New()
	//_, err = vm.RunString(mb.DecodeFunc)
	//if err!=nil {
	//	panic(err)
	//}
	//var fn func(string) string
	//err = vm.ExportTo(vm.Get("decode"), &fn)
	//if err != nil {
	//	panic(err)
	//}
	//s := hex.EncodeToString(adu)
	//ss := fn(s)
	//res, _ := hex.DecodeString(ss)
	//pdu = &ProtocolDataUnit{}
	//pdu.Data = res

	//otto
	vm := otto.New()
	_, err = vm.Run(mb.DecodeFunc)
	if err!=nil {
		panic(err)
	}
	aduStr := hex.EncodeToString(adu)
	ss, err := vm.Call("decode", nil, aduStr)
	if err != nil {
		panic(err)
	}
	res, _ := hex.DecodeString(ss.String())
	pdu = &ProtocolDataUnit{}
	pdu.Data = res

	return
}

// customTransporter implements Transporter interface.
type customTransporter struct {
	// Connect string
	Address string
	// Connect & Read timeout
	Timeout time.Duration
	// Idle timeout to close the connection
	IdleTimeout time.Duration
	// Transmission logger
	Logger *log.Logger

	// TCP connection
	mu           sync.Mutex
	Conn         net.Conn
	closeTimer   *time.Timer
	lastActivity time.Time
	HeaderLength uint8
	DataLength   uint8
	CrcLength    uint8
}

// Send sends data to server and ensures response length is greater than header length.
func (mb *customTransporter) Send(aduRequest []byte) (aduResponse []byte, err error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Set timer to close when idle
	mb.lastActivity = time.Now()
	//mb.startCloseTimer()
	// Set write and read timeout
	var timeout time.Time
	if mb.Timeout > 0 {
		timeout = mb.lastActivity.Add(mb.Timeout)
	}
	if err = mb.Conn.SetDeadline(timeout); err != nil {
		return
	}
	// Send data
	mb.logf("modbus: sending % x", aduRequest)
	if _, err = mb.Conn.Write(aduRequest); err != nil {
		return
	}
	// Read header first
	var data [customMaxLength]byte
	readLength := mb.HeaderLength+mb.DataLength+mb.CrcLength
	if _, err = io.ReadFull(mb.Conn, data[:readLength]); err != nil {
		return
	}
	aduResponse = data[:mb.HeaderLength+mb.DataLength+mb.CrcLength]
	mb.logf("modbus: received % x\n", aduResponse)
	return
}

// Connect establishes a new connection to the address in Address.
// Connect and Close are exported so that multiple requests can be done with one session
func (mb *customTransporter) Connect() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	return mb.connect()
}

func (mb *customTransporter) IsConnect() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if mb.Conn == nil {
		return errors.New("Bad Connection")
	}
	return nil
}

func (mb *customTransporter) connect() error {
	if mb.Conn == nil {
		dialer := net.Dialer{Timeout: mb.Timeout}
		conn, err := dialer.Dial("tcp", mb.Address)
		if err != nil {
			return err
		}
		mb.Conn = conn
	}
	return nil
}

func (mb *customTransporter) startCloseTimer() {
	if mb.IdleTimeout <= 0 {
		return
	}
	if mb.closeTimer == nil {
		mb.closeTimer = time.AfterFunc(mb.IdleTimeout, mb.closeIdle)
	} else {
		mb.closeTimer.Reset(mb.IdleTimeout)
	}
}

// Close closes current connection.
func (mb *customTransporter) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	return mb.close()
}

// flush flushes pending data in the connection,
// returns io.EOF if connection is closed.
func (mb *customTransporter) flush(b []byte) (err error) {
	if err = mb.Conn.SetReadDeadline(time.Now()); err != nil {
		return
	}
	// Timeout setting will be reset when reading
	if _, err = mb.Conn.Read(b); err != nil {
		// Ignore timeout error
		if netError, ok := err.(net.Error); ok && netError.Timeout() {
			err = nil
		}
	}
	return
}

func (mb *customTransporter) logf(format string, v ...interface{}) {
	if mb.Logger != nil {
		mb.Logger.Printf(format, v...)
	}
}

// closeLocked closes current connection. Caller must hold the mutex before calling this method.
func (mb *customTransporter) close() (err error) {
	if mb.Conn != nil {
		err = mb.Conn.Close()
		mb.Conn = nil
	}
	return
}

// closeIdle closes the connection if last activity is passed behind IdleTimeout.
func (mb *customTransporter) closeIdle() {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if mb.IdleTimeout <= 0 {
		return
	}
	idle := time.Now().Sub(mb.lastActivity)
	if idle >= mb.IdleTimeout {
		mb.logf("modbus: closing connection due to idle timeout: %v", idle)
		mb.close()
	}
}
