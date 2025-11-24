package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	dnsFlagQR = 1 << 15
	dnsFlagRD = 1 << 8
	dnsFlagRA = 1 << 7

	dnsClassIN = 1
	dnsTypeA   = 1
	dnsTypePTR = 12
)

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
	raw   []byte
}

type dnsQuery struct {
	id       uint16
	flags    uint16
	question dnsQuestion
}

type dnsAnswer struct {
	name  string
	rtype uint16
	class uint16
	ttl   uint32
	rdata []byte
}

func parseDNSQuery(msg []byte) (*dnsQuery, error) {
	if len(msg) < 12 {
		return nil, errors.New("dns message too short")
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount != 1 {
		return nil, fmt.Errorf("unsupported qdcount %d", qdCount)
	}

	offset := 12
	name, next, err := parseDNSName(msg, offset)
	if err != nil {
		return nil, err
	}
	if next+4 > len(msg) {
		return nil, errors.New("dns question truncated")
	}

	raw := make([]byte, next+4-offset)
	copy(raw, msg[offset:next+4])

	q := dnsQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[next : next+2]),
		Class: binary.BigEndian.Uint16(msg[next+2 : next+4]),
		raw:   raw,
	}

	return &dnsQuery{
		id:       binary.BigEndian.Uint16(msg[0:2]),
		flags:    binary.BigEndian.Uint16(msg[2:4]),
		question: q,
	}, nil
}

func buildDNSResponse(query *dnsQuery, answer *dnsAnswer) ([]byte, error) {
	var header [12]byte
	binary.BigEndian.PutUint16(header[0:2], query.id)

	flags := dnsFlagQR | dnsFlagRA
	if query.flags&dnsFlagRD != 0 {
		flags |= dnsFlagRD
	}
	binary.BigEndian.PutUint16(header[2:4], uint16(flags))
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], 1)

	buf := bytes.NewBuffer(header[:])
	buf.Write(query.question.raw)

	rr, err := encodeDNSAnswer(answer)
	if err != nil {
		return nil, err
	}
	buf.Write(rr)
	return buf.Bytes(), nil
}

func encodeDNSAnswer(ans *dnsAnswer) ([]byte, error) {
	nameWire, err := encodeDNSName(ans.name)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(nameWire)

	var fields [10]byte
	binary.BigEndian.PutUint16(fields[0:2], ans.rtype)
	binary.BigEndian.PutUint16(fields[2:4], ans.class)
	binary.BigEndian.PutUint32(fields[4:8], ans.ttl)
	binary.BigEndian.PutUint16(fields[8:10], uint16(len(ans.rdata)))
	buf.Write(fields[:])
	buf.Write(ans.rdata)
	return buf.Bytes(), nil
}

func parseDNSName(msg []byte, offset int) (string, int, error) {
	var labels []string
	visited := 0
	pos := offset
	next := -1

	for {
		if pos >= len(msg) {
			return "", 0, errors.New("dns name out of range")
		}
		length := int(msg[pos])
		if length == 0 {
			if next == -1 {
				next = pos + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", 0, errors.New("dns pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			if ptr >= len(msg) {
				return "", 0, errors.New("dns pointer out of range")
			}
			if next == -1 {
				next = pos + 2
			}
			pos = ptr
			visited++
			if visited > len(msg) {
				return "", 0, errors.New("dns pointer loop")
			}
			continue
		}

		if pos+1+length > len(msg) {
			return "", 0, errors.New("dns label truncated")
		}
		label := string(msg[pos+1 : pos+1+length])
		labels = append(labels, label)
		pos += 1 + length
	}

	if next == -1 {
		next = pos + 1
	}

	name := strings.ToLower(strings.Join(labels, "."))
	if name == "" {
		name = "."
	} else {
		name += "."
	}
	return name, next, nil
}

func encodeDNSName(name string) ([]byte, error) {
	if name == "." {
		return []byte{0}, nil
	}
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	var buf bytes.Buffer
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if len(part) > 63 {
			return nil, fmt.Errorf("dns label %q is too long", part)
		}
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0)
	return buf.Bytes(), nil
}

func (a *App) dnsAnswerFor(q dnsQuestion) (*dnsAnswer, error) {
	if q.Class != dnsClassIN {
		return nil, nil
	}
	switch q.Type {
	case dnsTypeA:
		ip, ok := a.aRecords[q.Name]
		if !ok {
			return nil, nil
		}
		rawIP := ip.As4()
		data := append([]byte(nil), rawIP[:]...)
		return &dnsAnswer{
			name:  q.Name,
			rtype: dnsTypeA,
			class: dnsClassIN,
			ttl:   a.dnsTTL,
			rdata: data,
		}, nil
	case dnsTypePTR:
		target, ok := a.ptrRecords[q.Name]
		if !ok {
			return nil, nil
		}
		nameWire, err := encodeDNSName(target)
		if err != nil {
			return nil, err
		}
		return &dnsAnswer{
			name:  q.Name,
			rtype: dnsTypePTR,
			class: dnsClassIN,
			ttl:   a.dnsTTL,
			rdata: nameWire,
		}, nil
	default:
		return nil, nil
	}
}
