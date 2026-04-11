package dns

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

type ResolverInput struct {
	Domain  string
	Verbose bool
}

func verboseLog(enabled bool, format string, args ...any) {
	if enabled {
		fmt.Printf(format+"\n", args...)
	}
}

func verboseSpacer(enabled bool) {
	if enabled {
		fmt.Println()
	}
}

func Resolve(resolverInput ResolverInput) (net.IP, error) {
	domain := resolverInput.Domain
	verbose := resolverInput.Verbose

	rootServers := [13]string{
		"198.41.0.4",     // a.root-servers.net
		"170.247.170.2",  // b.root-servers.net
		"192.33.4.12",    // c.root-servers.net
		"199.7.91.13",    // d.root-servers.net
		"192.203.230.10", // e.root-servers.net
		"192.5.5.241",    // f.root-servers.net
		"192.112.36.4",   // g.root-servers.net
		"198.97.190.53",  // h.root-servers.net
		"192.36.148.17",  // i.root-servers.net
		"192.58.128.30",  // j.root-servers.net
		"193.0.14.129",   // k.root-servers.net
		"199.7.83.42",    // l.root-servers.net
		"202.12.27.33",   // m.root-servers.net
	}

	nameserver := rootServers[rand.IntN(len(rootServers))]

	verboseLog(verbose, "Starting resolution for %s", domain)
	verboseLog(verbose, "Using root server %s", nameserver)

	for {
		// build query for domain
		buildQuery := BuildQueryInput{
			Random: true,
			Domain: domain,
		}

		// building the packet
		packet := BuildQuery(buildQuery)

		// sending it to nameserver over UDP
		verboseSpacer(verbose)
		verboseLog(verbose, "Querying %s for %s", nameserver, domain)

		connection, err := net.Dial("udp", nameserver+":53")
		if err != nil {
			verboseLog(verbose, "Error dialing %s: %v", nameserver, err)
			return nil, err
		}

		// for calculating time per request
		start := time.Now()

		// sending the packet (query)
		_, err = connection.Write(Serialize(packet))
		if err != nil {
			verboseLog(verbose, "Error writing to %s: %v", nameserver, err)
			connection.Close()
			return nil, err
		}

		// reading the response
		response := make([]byte, 512)
		n, err := connection.Read(response)
		if err != nil {
			verboseLog(verbose, "Error reading from %s: %v", nameserver, err)
			connection.Close()
			return nil, err
		}

		duration := time.Since(start)

		verboseLog(verbose, "Received %d bytes from %s (\033[33m%.2fms\033[0m)", n, nameserver, float64(duration.Microseconds())/1000)

		// parsing the response packet
		resp_packet, err := Parse(response[:n])
		if err != nil {
			verboseLog(verbose, "Error parsing response: %v", err)
			connection.Close()
			return nil, err
		}

		verboseLog(verbose, "Answers: %d, Authority: %d, Additional: %d",
			resp_packet.Header.ANCount,
			resp_packet.Header.NSCount,
			resp_packet.Header.ARCount,
		)

		verboseSpacer(verbose)

		// if answers available
		if resp_packet.Header.ANCount > 0 {
			for _, answer := range resp_packet.Answers {
				switch answer.Type {

				// A record
				case 1:
					ip := net.IP(answer.RData)

					verboseSpacer(verbose)
					verboseLog(verbose, "%s -> %s", domain, ip.String())

					connection.Close()
					return ip, nil

				// CNAME
				case 5:
					// parsing the CNAME target from RData
					cnameLabels, _, err := parseName(response[:n], answer.RDataOffset)
					if err != nil {
						connection.Close()
						return nil, err
					}

					cname := LabelsToString(cnameLabels)

					verboseLog(verbose, "CNAME %s -> %s", domain, cname)

					connection.Close()

					// recursively resolving the CNAME target
					return Resolve(ResolverInput{
						Domain:  cname,
						Verbose: verbose,
					})
				}

			}
		}

		// if no answers available
		// looping through Additional
		found := false
		for _, additional := range resp_packet.Additional {
			if additional.Type == 1 {
				nameserver = net.IP(additional.RData).String()

				verboseLog(verbose, "Following referral to %s", nameserver)
				found = true
				break
			}
		}

		if !found {
			// looping through authority
			for _, authority := range resp_packet.Authority {
				// NS record
				if authority.Type == 2 {
					nsName, _, err := parseName(authority.RData, 0)
					if err != nil {
						return nil, fmt.Errorf("could not resolve %s", domain)
					}

					// converting label bytes to domain string
					nsHostname := LabelsToString(nsName)

					// resolving NS hostname to IP
					nsIP, err := Resolve(ResolverInput{
						Domain:  nsHostname,
						Verbose: verbose,
					})
					if err != nil {
						continue // trying next NS record
					}

					nameserver = nsIP.String()
					verboseLog(verbose, "Following referral to %s (%s)", nsHostname, nameserver)

					found = true
					break
				}
			}
		}

		if !found {
			verboseSpacer(verbose)
			verboseLog(verbose, "Failed to resolve %s", domain)

			connection.Close()
			return nil, fmt.Errorf("could not resolve %s", domain)
		}

		connection.Close()
	}

}

// function to convert byte format to string
func LabelsToString(name []byte) string {
	var labels []string
	i := 0

	for i < len(name) {
		length := int(name[i])
		if length == 0 {
			break
		}
		i++

		if i+length > len(name) {
			break
		}

		labels = append(labels, string(name[i:i+length]))
		i += length
	}

	return strings.Join(labels, ".")
}
