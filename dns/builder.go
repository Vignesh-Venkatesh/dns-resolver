package dns

import (
	"math/rand/v2"
	"strings"
)

type BuildQueryInput struct {
	Random bool   // decide whether to generate random id or not
	ID     uint16 // query ID
	Domain string // domain name
}

func BuildQuery(input BuildQueryInput) Packet {
	query := Packet{}

	// setting query ID
	queryID := input.ID
	if input.Random {
		queryID = uint16(rand.IntN(65536))
	}
	query.Header.ID = queryID

	// flags: standard query
	// 0  0000   0  0  1  0  000 0000
	// QR Opcode AA TC RD RA  Z  RCODE
	query.Header.Flags = 0x0100

	// QDCount
	query.Header.QDCount = 0x0001

	// ANCount
	query.Header.ANCount = 0x0000

	// NSCount
	query.Header.NSCount = 0x0000

	// ARCount
	query.Header.ARCount = 0x0000

	// Question

	// domain name
	domainBytes := []byte{}
	splitString := strings.Split(input.Domain, ".")
	for _, d := range splitString {
		domainBytes = append(domainBytes, byte(len(d)))
		domainBytes = append(domainBytes, []byte(d)...)
	}
	domainBytes = append(domainBytes, 0x00) // null terminator

	question := Question{
		QName:  domainBytes,
		QType:  0x0001, // Type - A
		QClass: 0x0001, // Class - IN
	}

	query.Questions = append(query.Questions, question)

	return query
}
