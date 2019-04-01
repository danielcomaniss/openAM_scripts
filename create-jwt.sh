#!/bin/bash
IP=127.0.0.10
OUTPUT=context.jwt
KEY="IvowvyVKSYGebWVCW0RDzKGqqiglvpMFFMqjysWUKJMkecfD3VUSF3yPF0ETiINkUpRKTqg9XPQJEWT09NnRSRLTiq6tCr2AcnmPDDqcfdLFgjrBFLEDXV4Si2EtNgAkIC7hzH3uSty0ocmhETfvphzV7EaaBhSSVfirHLUuXas="
echo "Creating context JWT with IP: $IP" 
jwtgen -a HS256 -s $KEY -c "IP=$IP" -e 3600 > $OUTPUT
echo "Stored at $OUTPUT"
