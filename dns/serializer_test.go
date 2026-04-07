package dns

import (
	"encoding/binary"
	"testing"
)

// testing if header is right
func TestSerialize_HeaderOnly(t *testing.T) {
	packet := Packet{
		Header: Header{
			ID:      0x1234,
			Flags:   0x0100,
			QDCount: 0,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
	}

	result := Serialize(packet)

	expected := []byte{}
	expected = binary.BigEndian.AppendUint16(expected, 0x1234)
	expected = binary.BigEndian.AppendUint16(expected, 0x0100)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)

	if string(result) != string(expected) {
		t.Errorf("got %v, wanted %v", result, expected)
	}

}

// question testing
func TestSerialize_OneQuestion(t *testing.T) {
	packet := Packet{
		Header: Header{
			ID:      1,
			Flags:   0,
			QDCount: 1,
		},
		Questions: []Question{
			{
				QName:  []byte{3, 'w', 'w', 'w', 0}, // "www."
				QType:  1,                           // A
				QClass: 1,                           // IN
			},
		},
	}

	result := Serialize(packet)

	expected := []byte{}
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)

	expected = append(expected, []byte{3, 'w', 'w', 'w', 0}...)
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint16(expected, 1)

	if string(result) != string(expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}

// answer testing
func TestSerialize_Answer(t *testing.T) {
	packet := Packet{
		Header: Header{
			ANCount: 1,
		},
		Answers: []Resource{
			{
				Name:     []byte{0},
				Type:     1,
				Class:    1,
				TTL:      300,
				RDLength: 4,
				RData:    []byte{127, 0, 0, 1},
			},
		},
	}

	result := Serialize(packet)

	expected := []byte{}
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint16(expected, 0)
	expected = binary.BigEndian.AppendUint16(expected, 0)

	expected = append(expected, []byte{0}...)
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint16(expected, 1)
	expected = binary.BigEndian.AppendUint32(expected, 300)
	expected = binary.BigEndian.AppendUint16(expected, 4)
	expected = append(expected, []byte{127, 0, 0, 1}...)

	if string(result) != string(expected) {
		t.Errorf("got %v, want %v", result, expected)
	}
}
