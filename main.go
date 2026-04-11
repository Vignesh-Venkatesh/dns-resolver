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

	// dns resolver
	resolverInput := dns.ResolverInput{
		Domain:  domainPtr,
		Verbose: verbosePtr,
	}
	resolve, err := dns.Resolve(resolverInput)

	// output
	if err != nil {
		fmt.Printf("\n\033[31m\033[1mError: %v\n", err)
		return
	}
	fmt.Printf("\n\033[32m\033[1mResolved: %v\n", resolve.String())
}
