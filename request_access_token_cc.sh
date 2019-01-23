#!/bin/bash
#Requests an access_token using client credentials flow and self-signed cert authentication for client
#simon.moffatt@forgerock.com 23/01/18

#GLOBALS
CLIENT_ID=App
CLIENT_CERT_FILE=my-cert.pem
CLIENT_KEY_FILE=my-key.pem
SERVER_CERT_FILE=openam.example.com.cert.pem
SCOPES=read
AM_SERVER=https://openam.example.com:8443
###############################################

clear

TOKEN_RESPONSE=$(curl -s --cacert $SERVER_CERT_FILE \
	-X POST -d "client_id=$CLIENT_ID&grant_type=client_credentials&scope=$SCOPES&response_type=token" \
	"$AM_SERVER/openam/oauth2/access_token" \
	 --cert $CLIENT_CERT_FILE --key $CLIENT_KEY_FILE)

echo $TOKEN_RESPONSE | jq
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq '.access_token' | cut -d "\"" -f 2)
echo ""
curl -s --cacert $SERVER_CERT_FILE \
	-X POST -d "client_id=$CLIENT_ID&token_type_hint=access_token&token=$ACCESS_TOKEN" \
	--cert $CLIENT_CERT_FILE --key $CLIENT_KEY_FILE $AM_SERVER/openam/oauth2/introspect | jq
echo ""
