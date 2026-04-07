package main

import (
	"flag"
	"fmt"
)

func main() {
	var domainPtr string
	flag.StringVar(&domainPtr, "domain", "", "domain name")
	flag.StringVar(&domainPtr, "d", "", "domain name")

	flag.Parse()
	fmt.Println("domain:", domainPtr)
}
