package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func Parse(data []byte) (Packet, error) {
	packet := Packet{}

	// header
	header, err := parseHeader(data)
	if err != nil {
		fmt.Printf("invalid header\n%v", err)
		return Packet{}, err
	}
	packet.Header = header

	offset := 12

	// question
	questionCount := packet.Header.QDCount
	questions := make([]Question, 0, questionCount)
	for i := 0; i < int(questionCount); i++ {
		var question Question
		var err error

		question, offset, err = parseQuestion(data, offset)
		if err != nil {
			fmt.Printf("invalid question\n%v", err)
			continue
		}

		questions = append(questions, question)
	}
	packet.Questions = questions

	// answer
	answerCount := packet.Header.ANCount
	answers := make([]Resource, 0, answerCount)
	for i := 0; i < int(answerCount); i++ {
		var answer Resource
		var err error

		answer, offset, err = parseResource(data, offset)
		if err != nil {
			fmt.Printf("invalid answer\n%v", err)
			continue
		}

		answers = append(answers, answer)
	}
	packet.Answers = answers

	// authority
	authorityCount := packet.Header.NSCount
	authorities := make([]Resource, 0, authorityCount)
	for i := 0; i < int(authorityCount); i++ {
		var authority Resource
		var err error

		authority, offset, err = parseResource(data, offset)
		if err != nil {
			fmt.Printf("invalid authority\n%v", err)
			continue
		}

		authorities = append(authorities, authority)
	}
	packet.Authority = authorities

	// additional
	additionalCount := packet.Header.ARCount
	additionals := make([]Resource, 0, additionalCount)
	for i := 0; i < int(additionalCount); i++ {
		var additional Resource
		var err error

		additional, offset, err = parseResource(data, offset)
		if err != nil {
			fmt.Printf("invalid additional\n%v", err)
			continue
		}

		additionals = append(additionals, additional)
	}
	packet.Additional = additionals

	return packet, nil
}

func parseHeader(data []byte) (Header, error) {
	if len(data) < 12 {
		return Header{}, errors.New("response too short to contain a valid header")
	}

	header := Header{}

	header.ID = binary.BigEndian.Uint16(data[0:2])
	header.Flags = binary.BigEndian.Uint16(data[2:4])
	header.QDCount = binary.BigEndian.Uint16(data[4:6])
	header.ANCount = binary.BigEndian.Uint16(data[6:8])
	header.NSCount = binary.BigEndian.Uint16(data[8:10])
	header.ARCount = binary.BigEndian.Uint16(data[10:12])

	return header, nil
}

func parseQuestion(data []byte, offset int) (Question, int, error) {
	question := Question{}
	var err error

	// QName
	question.QName, offset, err = parseName(data, offset)
	if err != nil {
		fmt.Println(err)
		return Question{}, 0, err
	}

	// if no more bytes left for QType or QClass
	if offset+4 > len(data) {
		return Question{}, 0, fmt.Errorf("not enough data for QType/QClass")
	}

	// QType
	question.QType = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// QClass
	question.QClass = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return question, offset, nil
}

func parseResource(data []byte, offset int) (Resource, int, error) {
	resource := Resource{}
	var err error

	// Name
	resource.Name, offset, err = parseName(data, offset)
	if err != nil {
		fmt.Println(err)
		return Resource{}, 0, err
	}

	// Type
	if offset+2 > len(data) {
		return Resource{}, 0, fmt.Errorf("truncated type")
	}
	resource.Type = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Class
	if offset+2 > len(data) {
		return Resource{}, 0, fmt.Errorf("truncated class")
	}
	resource.Class = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// TTL
	if offset+4 > len(data) {
		return Resource{}, 0, fmt.Errorf("truncated ttl")
	}
	resource.TTL = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// RDLength
	if offset+2 > len(data) {
		return Resource{}, 0, fmt.Errorf("truncated rdlength")
	}
	resource.RDLength = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// RData
	if offset+int(resource.RDLength) > len(data) {
		return Resource{}, 0, fmt.Errorf("truncated rdata")
	}
	resource.RData = data[offset : offset+int(resource.RDLength)]
	offset += int(resource.RDLength)

	return resource, offset, nil
}

func parseName(data []byte, offset int) ([]byte, int, error) {

	var name []byte
	visited := map[int]bool{}

	i := offset
	jumped := false
	var endOffset int

	for {
		//bounds check
		if i >= len(data) {
			return nil, 0, fmt.Errorf("out of bounds")
		}

		// preventing infinite loops
		if visited[i] {
			return nil, 0, fmt.Errorf("compression loop detected")
		}
		visited[i] = true

		length := int(data[i])

		// pointer: 11xxxxxx xxxxxxxx
		if length&0xC0 == 0xC0 {
			if i+1 >= len(data) {
				return nil, 0, fmt.Errorf("truncated pointer")
			}

			ptr := int(binary.BigEndian.Uint16(data[i:i+2]) & 0x3FFF)

			if !jumped {
				endOffset = i + 2
			}

			i = ptr
			jumped = true
			continue
		}

		// null terminator, end of name
		if length == 0 {
			if !jumped {
				endOffset = i + 1
			}
			break
		}

		i++

		// ensuring enough bytes remain
		if i+length > len(data) {
			return nil, 0, fmt.Errorf("invalid label length")
		}

		// appending label length + label
		name = append(name, byte(length))
		name = append(name, data[i:i+length]...)

		i += length
	}

	// return raw slice of the original data
	return name, endOffset, nil
}
