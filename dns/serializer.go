package dns

import "encoding/binary"

func Serialize(packet Packet) []byte {
	serializedPacket := []byte{}

	// header
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.ID)      // ID
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.Flags)   // Flags
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.QDCount) // QDCount
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.ANCount) // ANCount
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.NSCount) // NSCount
	serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, packet.Header.ARCount) // ARCount

	// question
	for _, q := range packet.Questions {
		serializedPacket = append(serializedPacket, q.QName...)                      // Qname
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, q.QType)  // Qtype
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, q.QClass) // QClass
	}

	// answer
	for _, a := range packet.Answers {
		serializedPacket = append(serializedPacket, a.Name...)                         // Name
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Type)     // Type
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Class)    // Class
		serializedPacket = binary.BigEndian.AppendUint32(serializedPacket, a.TTL)      // TTL
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.RDLength) // RDLength
		serializedPacket = append(serializedPacket, a.RData...)                        // RData
	}

	// authority
	for _, a := range packet.Authority {
		serializedPacket = append(serializedPacket, a.Name...)                         // Name
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Type)     // Type
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Class)    // Class
		serializedPacket = binary.BigEndian.AppendUint32(serializedPacket, a.TTL)      // TTL
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.RDLength) // RDLength
		serializedPacket = append(serializedPacket, a.RData...)                        // RData
	}

	// additional
	for _, a := range packet.Additional {
		serializedPacket = append(serializedPacket, a.Name...)                         // Name
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Type)     // Type
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.Class)    // Class
		serializedPacket = binary.BigEndian.AppendUint32(serializedPacket, a.TTL)      // TTL
		serializedPacket = binary.BigEndian.AppendUint16(serializedPacket, a.RDLength) // RDLength
		serializedPacket = append(serializedPacket, a.RData...)                        // RData
	}

	return serializedPacket
}
