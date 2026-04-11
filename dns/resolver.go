package dns

import (
	"fmt"
	"math/rand/v2"
	"net"
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

		verboseLog(verbose, "Received %d bytes from %s (%.2fms)", n, nameserver, float64(duration.Microseconds())/1000)

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
				// A Record
				if answer.Type == 1 {
					ip := net.IP(answer.RData)

					verboseSpacer(verbose)
					verboseLog(verbose, "Resolved %s -> %s", domain, ip.String())

					connection.Close()
					return ip, nil
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
			verboseSpacer(verbose)
			verboseLog(verbose, "Failed to resolve %s", domain)

			connection.Close()
			return nil, fmt.Errorf("could not resolve %s", domain)
		}

		connection.Close()
	}

}
