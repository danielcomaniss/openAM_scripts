#!/bin/bash
#simon.moffatt@forgerock.com - Run through1
clear
USERNAME=demo
PASSWORD=changeit
CLIENTID=OIDClient
CLIENTSECRET=Passw0rd
SCOPE=read%20write
echo "Getting OAuth2 access token #1..."

access_token=$(curl -s --request POST \
  --url http://openam.example.com:8080/openam/oauth2/access_token \
  --header 'authorization: Basic T0lEQ0NsaWVudDpQYXNzdzByZA==' \
  --header 'cache-control: no-cache' \
  --header 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=password&username=$USERNAME&password=$PASSWORD&scope=$SCOPE" | jq '.access_token' | cut -d "\"" -f 2)

echo ""
echo $access_token
echo ""
read -p "Press [Enter] to decode access_token and view the signing key id"
echo ""
header=$(echo $access_token | cut -d'.' -f1)
kid=$(echo $header= | base64 -d | jq '.kid')
echo "Kid: $kid"
echo ""
read -p "Press [Enter] to introspect the token and check it's valid"
echo ""
introspect_response=$(curl -s --request POST \
  --url "http://openam.example.com:8080/openam/oauth2/introspect?token=$access_token"	 --header 'authorization: Basic T0lEQ0NsaWVudDpQYXNzdzByZA==' \
  --header 'cache-control: no-cache' \
  --header 'content-type: application/x-www-form-urlencoded')
echo $introspect_response | jq .
echo ""
read -p "Press [Enter] to introspect the token a 2nd time... and check it's still valid"
echo ""
introspect_response=$(curl -s --request POST \
  --url "http://openam.example.com:8080/openam/oauth2/introspect?token=$access_token"	 --header 'authorization: Basic T0lEQ0NsaWVudDpQYXNzdzByZA==' \
  --header 'cache-control: no-cache' \
  --header 'content-type: application/x-www-form-urlencoded')
echo $introspect_response | jq .
echo ""
read -p "Press [Enter] to introspect the token a 3rd time... and check it's still valid"
echo ""
introspect_response=$(curl -s --request POST \
  --url "http://openam.example.com:8080/openam/oauth2/introspect?token=$access_token"	 --header 'authorization: Basic T0lEQ0NsaWVudDpQYXNzdzByZA==' \
  --header 'cache-control: no-cache' \
  --header 'content-type: application/x-www-form-urlencoded')
echo $introspect_response | jq .
echo ""
