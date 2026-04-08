package dns

import (
	"encoding/binary"
	"testing"
)

// testing header parser
func TestParseHeader(t *testing.T) {
	data := make([]byte, 12)

	binary.BigEndian.PutUint16(data[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(data[2:4], 0x0010) // Flags
	binary.BigEndian.PutUint16(data[4:6], 1)      // QDCount
	binary.BigEndian.PutUint16(data[6:8], 0)      // ANCount
	binary.BigEndian.PutUint16(data[8:10], 0)     // NSCount
	binary.BigEndian.PutUint16(data[10:12], 0)    // ARCount

	header, err := parseHeader(data)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if header.ID != 0x1234 {
		t.Errorf("expected ID 0x1234, got %x", header.ID)
	}

	if header.QDCount != 1 {
		t.Errorf("expected QDCount 1, got %d", header.QDCount)
	}
}

// testing name parsing
func TestParseName(t *testing.T) {
	data := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}

	name, offset, err := parseName(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedLen := len(data)

	if offset != expectedLen {
		t.Errorf("expected offset %d, got %d", expectedLen, offset)
	}

	if string(name) != string(data) {
		t.Errorf("expected %v, got %v", data, name)
	}
}

// testing pointer case
func TestParseName_WithPointer(t *testing.T) {
	data := []byte{
		0xC0, 0x0C, // pointer
	}

	name, offset, err := parseName(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if offset != 2 {
		t.Errorf("expected offset 2, got %d", offset)
	}

	if len(name) != 2 {
		t.Errorf("expected 2 bytes, got %d", len(name))
	}
}

// testing parsing question
func TestParseQuestion(t *testing.T) {
	data := []byte{
		3, 'w', 'w', 'w',
		0,
		0, 1, // QTYPE A
		0, 1, // QCLASS IN
	}

	q, offset, err := parseQuestion(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q.QType != 1 {
		t.Errorf("expected QType 1, got %d", q.QType)
	}

	if q.QClass != 1 {
		t.Errorf("expected QClass 1, got %d", q.QClass)
	}

	if offset != len(data) {
		t.Errorf("expected offset %d, got %d", len(data), offset)
	}
}

// testing parsing resource
func TestParseResource(t *testing.T) {
	data := []byte{
		3, 'w', 'w', 'w',
		0,
		0, 1, // TYPE A
		0, 1, // CLASS IN
		0, 0, 0, 60, // TTL
		0, 4, // RDLENGTH
		1, 2, 3, 4, // RDATA
	}

	res, offset, err := parseResource(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Type != 1 {
		t.Errorf("expected Type 1, got %d", res.Type)
	}

	if res.Class != 1 {
		t.Errorf("expected Class 1, got %d", res.Class)
	}

	if res.TTL != 60 {
		t.Errorf("expected TTL 60, got %d", res.TTL)
	}

	if res.RDLength != 4 {
		t.Errorf("expected RDLength 4, got %d", res.RDLength)
	}

	expectedRData := []byte{1, 2, 3, 4}
	if string(res.RData) != string(expectedRData) {
		t.Errorf("expected RData %v, got %v", expectedRData, res.RData)
	}

	if offset != len(data) {
		t.Errorf("expected offset %d, got %d", len(data), offset)
	}
}

// testing truncated RData
func TestParseResource_TruncatedRData(t *testing.T) {
	data := []byte{
		3, 'w', 'w', 'w',
		0,
		0, 1,
		0, 1,
		0, 0, 0, 60,
		0, 4, // says 4 bytes
		1, 2, // only 2 provided
	}

	_, _, err := parseResource(data, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// full packet test

func TestParse_WithAnswer(t *testing.T) {
	data := make([]byte, 0)

	// Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCount
	binary.BigEndian.PutUint16(header[6:8], 1) // ANCount
	data = append(data, header...)

	// Question
	data = append(data,
		3, 'w', 'w', 'w',
		0,
		0, 1,
		0, 1,
	)

	// Answer
	data = append(data,
		3, 'w', 'w', 'w',
		0,
		0, 1,
		0, 1,
		0, 0, 0, 60,
		0, 4,
		1, 2, 3, 4,
	)

	packet, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(packet.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(packet.Answers))
	}

	if packet.Answers[0].TTL != 60 {
		t.Errorf("expected TTL 60, got %d", packet.Answers[0].TTL)
	}
}
