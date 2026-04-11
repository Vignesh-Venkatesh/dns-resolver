package main

import (
	"flag"
	"fmt"

	"github.com/Vignesh-Venkatesh/dns-resolver/dns"
)

func main() {

	// domain name
	var domainPtr string
	flag.StringVar(&domainPtr, "domain", "", "domain name")
	flag.StringVar(&domainPtr, "d", "", "domain name")

	// verbose flag
	var verbosePtr bool
	flag.BoolVar(&verbosePtr, "verbose", false, "verbose")
	flag.BoolVar(&verbosePtr, "v", false, "verbose")

	// parsing flags
	flag.Parse()

	// fmt.Println("domain:\n", domainPtr)
	// fmt.Println("verbose:", verbosePtr)

	resolverInput := dns.ResolverInput{
		Domain:  domainPtr,
		Verbose: verbosePtr,
	}

	resolve, err := dns.Resolve(resolverInput)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Resolve: %v\n", resolve.String())
}
