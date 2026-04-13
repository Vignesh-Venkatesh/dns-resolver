# DNS Resolver
A recursive DNS resolver built from scratch in Go, without using any DNS libraries.

Read the full write up on how this resolver was built on my [blog](https://blog.vigneshvenkatesh.com/blog/dns-resolver-1)

---
## Demo
```bash
> go run main.go -d vigneshvenkatesh.com

Resolved: 104.21.72.45
```

with `-v` (verbose) flag:
```bash
> go run main.go -d vigneshvenkatesh.com -v
Starting resolution for vigneshvenkatesh.com
Using root server 192.58.128.30

Querying 192.58.128.30 for vigneshvenkatesh.com
Received 498 bytes from 192.58.128.30 (547.87ms)
Answers: 0, Authority: 13, Additional: 11

Following referral to 192.5.6.30

Querying 192.5.6.30 for vigneshvenkatesh.com
Received 359 bytes from 192.5.6.30 (306.33ms)
Answers: 0, Authority: 2, Additional: 12

Following referral to 108.162.194.230

Querying 108.162.194.230 for vigneshvenkatesh.com
Received 70 bytes from 108.162.194.230 (11.75ms)
Answers: 2, Authority: 0, Additional: 0


vigneshvenkatesh.com -> 104.21.72.45

Resolved: 104.21.72.45
```

---
## How it works
- The resolver starts at one of the 13 root servers and sends a raw DNS 
query built from scratch using the RFC 1035 wire format.
- It follows the referral chain: root -> TLD -> authoritative, until it gets an 
answer
- It handles DNS message compression pointers, NS records without glue, and CNAME chains

---
## Features
- Recursive resolution from root servers
- DNS message compression pointer resolution
- NS fallback when glue records are missing
- CNAME following
- Verbose mode showing full resolution chain

---
## Usage
```bash
# basic
go run main.go -d google.com

# verbose
go run main.go -d google.com -v

# build
go build -o dns-resolver
./dns-resolver -d google.com -v
```

---
## Project structure
```
.
├── dns
│   ├── builder.go      # builds outgoing query packets
│   ├── message.go      # DNS packet structs
│   ├── parser.go       # parses raw bytes into packets
│   ├── resolver.go     # recursive resolution logic
│   ├── serializer.go   # serializes packets into raw bytes
│   └── *_test.go       # tests for each component
├── go.mod
├── main.go
└── README.md
```
