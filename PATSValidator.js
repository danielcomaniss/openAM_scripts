/**
 simon.moffatt@forgerock.com
 Validates a PAT key:value; checks existence and returns associated resource/permissions as response attributes
**/

//Globals
var submittedUsername, submittedPAT, retrievedPATS

logger.message("Scripted Policy PAT Validator started...");

//PATS attribute format is - "pats" : [ {"f83ee64ef9d15a68e5c7a910395ea1611e2fa138b1b9dd7e090941dfed773b2c": {“resource1” : [ “read”, “write”, “execute” ] } }, ... ,]

//Parse the submitted request
function parseRequest() {
 
  //Need to set username as we're using NOT Never Match on the subjects definition, as the user will not have a local AM session. We simply parse the resource value and map the necessary username for searching
  submittedUsername=resourceURI.split("//")[1].split(":")[0];
  submittedPAT=resourceURI.split("//")[1].split(":")[1];
  logger.message("Submitted User: " + submittedUsername);
  logger.message("Submitted PAT: " + submittedPAT);
}

//Pull out the PATS from the user's profile
function getPATS() {
  
    //Search for the user submitted.  Can't use identity object here as the user doesn't have a session so just need to do a REST call on AM to find the submitted user
    
  	//Authenticate the policyeval user. Make sure this user has privileges to read other users. Realm admin etc.
  	var request = new org.forgerock.http.protocol.Request();  	
    request.method = 'POST';
    request.setUri("http://openam.example.com:8080/openam/json/authenticate");
    request.getHeaders().add('Content-Type', 'application/json');
    request.getHeaders().add('X-OpenAM-Username', 'policyeval');
    request.getHeaders().add('X-OpenAM-Password', 'Passw0rd');
    var response = httpClient.send(request).get();
    //logger.message("AM Authentication Response: " + JSON.parse(response.getEntity()).tokenId);
  	//Capture the token Id so we can re-use during a user search
    iPlanetDirectoryProValue=JSON.parse(response.getEntity()).tokenId
    

	//Create a new HTTP request to do the search 
    var request = new org.forgerock.http.protocol.Request();
  	//Do a call on ../users endpoint.  Change the field to be whatever attribute is used to store the PAT's
    request.setUri("http://openam.example.com:8080/openam/json/users/" + submittedUsername + "?_fields=iplanet-am-user-alias-list");
  	request.setMethod("GET");
    request.getHeaders().add('iPlanetDirectoryPro', iPlanetDirectoryProValue);
    var response = httpClient.send(request).get();
    //Strip out the attribute from the response
    retrievedPATS = JSON.parse(response.getEntity())["iplanet-am-user-alias-list"];
    logger.message("Retrieved PATS: " + retrievedPATS);

}


//Compare the submit PAT against
function verifyPAT() {
  
	//Iterate over the retrievedPATS array looking for a match
  	for (i = 0; i < retrievedPATS.length; i++){
       
        logger.message("Comparing " + submittedPAT + " to " + retrievedPATS[i]);
        
        //Check if the submitted PAT exists
    	if (submittedPAT in JSON.parse(retrievedPATS[i])) {
        
             logger.message("PAT found, permissions are: " + JSON.stringify(JSON.parse(retrievedPATS[i])[submittedPAT]));
        	 //Send the permissions associated with the PAT back as a response attribute
          	 responseAttributes.put("Assigned Permissions", [JSON.stringify(JSON.parse(retrievedPATS[i])[submittedPAT])]);
             //Give access
             authorized=true;  
             
        }
     
    }   
    
}

//Run through
parseRequest();
getPATS();
verifyPAT();
