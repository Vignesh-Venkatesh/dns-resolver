// reference - https://datatracker.ietf.org/doc/html/rfc1035#section-4

package dns

type Header struct {
	ID      uint16 // id
	Flags   uint16 // QR, Opcode, AA, TC, RD, RA, Z, RCODE
	QDCount uint16 // specifies number of entries in the question section
	ANCount uint16 // specifies number of resource records in the answer section
	NSCount uint16 // specifies the number of name server resources records in the authority records section
	ARCount uint16 // specifies the number of resource records in the additional records section
}

type Question struct {
	QName  []byte // domain name (in byte format)
	QType  uint16 // specifies the type of the query
	QClass uint16 // specifies the class of the query
}

// answer, authority and additional sections share the same format
type Resource struct {
	Name     []byte // domain name to which this resource record points (in byte format)
	Type     uint16 // specifies the meaning of the data in the RData field
	Class    uint16 // specifies the class of the data in the RData field
	TTL      uint32 // specifies the time interval (in seconds) that the resource record may be cached before it should be discarded
	RDLength uint16 // specifies the length of the RData field
	RData    []byte // describes the resource. varies accoding to the Type and Class
}

// DNS packet
// questions, answers, authority, additional are slices, coz there can be multiple of each
type Packet struct {
	Header     Header
	Questions  []Question
	Answers    []Resource
	Authority  []Resource
	Additional []Resource
}
