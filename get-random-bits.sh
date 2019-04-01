#!/bin/bash
#smoff 03/01/18 generates random from openssl and b64 encodes
#$1 = number of bits

openssl rand $1 | base64
