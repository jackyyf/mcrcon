package mcrcon

import (
	"bufio"
	"encoding/binary"
	"net"
	"math/rand"
	"errors"
	"fmt"
	"bytes"
	"os"
)

const (
	Response int32 = 0
	Command int32 = 2
	Login int32 = 3
)

var (
	ErrAuthFailed = errors.New("Invalid password")
	ErrBadProtocol = errors.New("Invalid protocol")
)

type Session struct {
	req_id int32
	passwd string
	server string
	conn net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	authenticated bool
}

type Packet struct {
	req_id int32
	ptype int32
	payload []byte
}

func NewConn(server string, passwd string) (ret *Session, err error) {
	ret = new(Session)
	ret.passwd = passwd
	ret.server = server
	ret.req_id = rand.Int31()
	ret.conn, err = net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	ret.reader = bufio.NewReader(ret.conn)
	ret.writer = bufio.NewWriter(ret.conn)
	if err = ret.login(); err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *Session) sendPacket(pkt *Packet) (err error) {
	length := int32(4 + 4 + 2 + len(pkt.payload))
	err = binary.Write(s.writer, binary.LittleEndian, length)
	if err != nil {
		return
	}
	err = binary.Write(s.writer, binary.LittleEndian, pkt.req_id)
	if err != nil {
		return
	}
	err = binary.Write(s.writer, binary.LittleEndian, pkt.ptype)
	if err != nil {
		return
	}
	_, err = s.writer.Write(pkt.payload)
	if err != nil {
		return
	}
	_, err = s.writer.Write([]byte{0x00, 0x00})
	if err != nil {
		return
	}
	err = s.writer.Flush()
	fmt.Fprintf(os.Stderr, "Packet sent: length=%d, type=%d, req_id=%d\n", length, pkt.ptype, pkt.req_id)
	return
}

func (s *Session) recvPacket() (pkt *Packet, err error) {
	var length int32
	binary.Read(s.reader, binary.LittleEndian, &length)
	if length < 10 || length > 1400 {
		return nil, fmt.Errorf("Invalid length: %d", length)
	}
	payload := make([]byte, length)
	if _, err := s.reader.Read(payload); err != nil {
		return nil, errors.New("Unable to read packet: " + err.Error())
	}
	reader := bytes.NewReader(payload)
	pkt = new(Packet)
	binary.Read(reader, binary.LittleEndian, &pkt.req_id)
	binary.Read(reader, binary.LittleEndian, &pkt.ptype)
	pkt.payload = make([]byte, length - 10)
	if n, err := reader.Read(pkt.payload); n != int(length - 10) {
		if err != nil {
			panic("Reader Error: " + err.Error())
		} else {
			panic("recvPacket error, please check.")
		}
	}
	// Protocol check.
	term := payload[len(payload) - 2:]
	if term[0] != '\x00' || term[1] != '\x00' {
		return nil, errors.New("Invalid packet: not terminated by two NUL bytes.")
	}
	fmt.Fprintf(os.Stderr, "Packet received: length=%d, type=%d, req_id=%d\n", length, pkt.ptype, pkt.req_id)
	return pkt, nil
}

func (s *Session) login() (err error) {
	if s.authenticated {
		panic("Already login.")
	}
	pkt := new(Packet)
	pkt.ptype = Login
	pkt.req_id = s.req_id
	pkt.payload = []byte(s.passwd)
	if err = s.sendPacket(pkt); err != nil {
		return
	}
	if pkt, err = s.recvPacket(); err != nil {
		return
	}
	if pkt.ptype == -1 || pkt.req_id == -1 {
		return ErrAuthFailed
	}
	if pkt.req_id != s.req_id || pkt.ptype != 2 {
		return ErrBadProtocol
	}
	return nil
}

func (s *Session) Command(cmd string) (resp string, err error) {
	pkt := new(Packet)
	pkt.ptype = Command
	pkt.req_id = s.req_id
	pkt.payload = []byte(cmd)
	if err = s.sendPacket(pkt); err != nil {
		return
	}
	if pkt, err = s.recvPacket(); err != nil {
		return
	}
	if pkt.ptype != 0 || pkt.req_id != s.req_id {
		return "", ErrBadProtocol
	}
	return string(pkt.payload), nil
}
