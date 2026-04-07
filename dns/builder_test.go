package dns

import "testing"

// testing basic building the query
func TestBuildQuery_Basic(t *testing.T) {
	input := BuildQueryInput{
		Random: false,
		ID:     1234,
		Domain: "vigneshvenkatesh.com",
	}

	packet := BuildQuery(input)

	// ID should match
	if packet.Header.ID != 1234 {
		t.Errorf("expected id 1234, got %d", packet.Header.ID)
	}

	// header checks
	if packet.Header.Flags != 0x0100 {
		t.Errorf("expected Flags 0x0100, got %#x", packet.Header.Flags)
	}
	if packet.Header.QDCount != 1 {
		t.Errorf("expected QDCount 1, got %d", packet.Header.QDCount)
	}
	if packet.Header.ANCount != 0 {
		t.Errorf("expected ANCount 0, got %d", packet.Header.ANCount)
	}
	if packet.Header.NSCount != 0 {
		t.Errorf("expected NSCount 0, got %d", packet.Header.NSCount)
	}
	if packet.Header.ARCount != 0 {
		t.Errorf("expected ARCount 0, got %d", packet.Header.ARCount)
	}

	// checking if it has exactly one question
	if len(packet.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(packet.Questions))
	}

}

// testing if domain encoding is right
func TestBuildQuery_DomainEncoding(t *testing.T) {
	input := BuildQueryInput{
		Random: false,
		ID:     1234,
		Domain: "google.com",
	}

	packet := BuildQuery(input)

	q := packet.Questions[0]

	expected := []byte{
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}

	if string(q.QName) != string(expected) {
		t.Errorf("unexpected QName.\n got: %v\nwant: %v", q.QName, expected)
	}
}

// testing the random id case
func TestBuildQuery_RandomID(t *testing.T) {
	var fixed uint16 = 1234
	different := false
	for range 10 {
		input := BuildQueryInput{Random: true, ID: fixed, Domain: "google.com"}
		packet := BuildQuery(input)
		if packet.Header.ID != fixed {
			different = true
			break
		}
	}
	if !different {
		t.Error("expected random ID to differ from fixed ID across 10 attempts")
	}
}

// testing with single label
func TestBuildQuery_SingleLabel(t *testing.T) {
	input := BuildQueryInput{
		Random: false,
		ID:     1,
		Domain: "localhost",
	}

	packet := BuildQuery(input)
	q := packet.Questions[0]

	expected := []byte{
		9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
		0,
	}

	if string(q.QName) != string(expected) {
		t.Errorf("unexpected QName for single label domain")
	}
}
