#!/bin/bash
#simon.moffatt@forgerock.com - basic stress tester for AM to get monitoring stats
#31/05/18

clear

#####################################################################################
USER="demo"
PASSWORD="changeit"
OPENAM="http://openam.example.com:8080/openam"
CLIENT_ID="OAuth2Client"
CLIENT_SECRET="Passw0rd"
SCOPE="read"
COUNTER=0
if [ "$3" == "" ]; then MAX=100; else MAX=$3; fi
#####################################################################################

#Check arg set
if [ "$1" == "" ] || [ "$1" == "--help" ] || [ "$1" == "-help" ] || [ "$1" == "-h" ] || [ "$1" == "--h" ]; then
	echo "Usage: $0 function arg counter"
	echo "Eg:    $0 authenticate success 55 - will perform 55 successful authentication requests. Number is optional, defaults to 100"
	echo "---------------------------------------------------------------------------------------------------------------------------"
	echo "All available combinations:"
	echo ""
	echo "authenticate success - successful authentication"
	echo "authenticate fail - failed authentication"
	echo "oauth2 issue - OAuth2 token issuance using password grant"
	exit
fi

function authenticate {

	if [ "$1" == "success" ]; then

		export response=$(curl -X POST -s "$OPENAM/json/authenticate" -H 'cache-control: no-cache' -H 'content-type: application/json' -H "x-openam-password: $PASSWORD" -H "x-openam-username: $USER"   -d '{}' | jq '.tokenId' | cut -d "\"" -f 2)
		echo "Token as $response"
		echo "--------------------------------------------------------------------------------------------------------------------"	
	fi

	if [ "$1" == "fail" ]; then

		export response=$(curl -X POST -s "$OPENAM/json/authenticate" \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-H "x-openam-password: scsdsd" \
		-H "x-openam-username: 2342342" \
		-d '{}' \ 
		| jq '.message' | cut -d "\"" -f 2)
		echo "$response"
	fi

}


function oauth2 {

	if [ "$1" == "issue" ]; then

		export response=$(curl -s -X POST -s "$OPENAM/oauth2/access_token" \
		-H 'Cache-Control: no-cache' \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		-d "grant_type=password&username=$USER&password=$PASSWORD&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=$SCOPE")
   		echo $response
		echo "--------------------------------------------------------------------------------------------------------------------"	

	fi

}

while [  $COUNTER -lt $MAX ]; do
         
	echo "Performing attempt # $COUNTER for function $1 $2"
	$1 $2
	let COUNTER=COUNTER+1 
done

