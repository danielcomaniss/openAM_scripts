#!/bin/bash
#smoff 12/01/18 view keystore contents
keytool -list -v -keystore $1 -storetype jceks
