//simon.moffatt@forgerock.com - 11/04/18
//Script for Responsive Context Check - checking previously used IP and user-agent against those being seen at resource access time. Authorization is responsive based on changes intra-session

//Logger utility
function logMessage(message) {
    logger.message("Responsive Context Check scripted authorization: " + message);
}

logMessage("Started");

//Globals -------------------------------------------------------------------------------------------------------------------------------------------
var profileUA, profileIP, currentIP, currentUA, attributeWhereUAStored, attributeWhereIPStored, checkUA, checkIP;
var IPCorrect, UACorrect = false;

//Edit where the IP and user-agent have been stored
attributeWhereUAStored="mail";
attributeWhereIPStored="telephoneNumber";
  
//Decide what to check
checkUA=true;
checkIP=true;
//---------------------------------------------------------------------------------------------------------------------------------------------------

logMessage("Checking User-Agent? " + checkUA);
logMessage("Checking IP address? " + checkIP);

  
//Retrieve User-Agent from profile
function retrieveUAFromProfile() {

  	var profileUASet = identity.getAttribute(attributeWhereUAStored);
    if (profileUASet == null || profileUASet.isEmpty()) {
        
      	logMessage("User agent not found on profile");
        return false;
    }
  
    profileUA = profileUASet.iterator().next();
    logMessage("User agent found on profile as " + profileUA);
   

}

//Retrieve IP address from profile
function retrieveIPFromProfile() {

  	var profileIPSet = identity.getAttribute(attributeWhereIPStored);
    if (profileIPSet == null || profileIPSet.isEmpty()) {
        
      	logMessage("IP address not found on profile");
        return false;
    }
  
    profileIP = profileIPSet.iterator().next();
    logMessage("IP address found on profile as " + profileIP);
   

}

//Retrieve IP address from request
function retrieveIPFromRequest() {

  	var currentIPSet = environment.get("IP");
    if (currentIPSet == null || currentIPSet.isEmpty()) {
        logMessage("No IP specified in the evaluation request environment parameters.");
        return false;
    }
    currentIP = currentIPSet.iterator().next();
    logMessage("IP found with this resource request: " + currentIP);
   

}

//Retrieve User-Agent address from request
function retrieveUAFromRequest() {

  	var currentUASet = environment.get("User-Agent");
    if (currentUASet == null || currentUASet.isEmpty()) {
        logMessage("No User-Agent specified in the evaluation request environment parameters.");
        return false;
    }
    currentUA = currentUASet.iterator().next();
    logMessage("User-Agent found with this resource request: " + currentUA);
   

}

//Generic compare function
function comparator(profile,current){
 
  if(profile == current) {
    
   return true;
   
  }
  
  return false;
  
}


//Runtime---------------------------------------------------------------------------------------------------------------------
//If we're checking the inbound and profile IP address, retrieve both, compare and set a decision variable
if (checkIP){
  
	retrieveIPFromProfile();
	retrieveIPFromRequest();
	IPCorrect=comparator(profileIP, currentIP);
  	logMessage("Profile IP same as current IP: " + IPCorrect);
	  	
}

//If we're checking the inbound and profile User-Agent, retrieve both, compare and set a decision variable
if (checkUA){
	
	retrieveUAFromProfile();	
	retrieveUAFromRequest();
  	UACorrect=comparator(profileUA, currentUA);
  	logMessage("Profile User-Agent same as current User-Agent: " + UACorrect);
  	
}

//Overall authorization decision based on active decision variables


if (checkIP) {
  
 	authorized = IPCorrect; 
    if (!authorized) {advice.put("IP",["Mismatch"])};
  	 
}

if (checkUA) {
  
  	authorized = UACorrect; 
  	if (!authorized) {advice.put("User-Agent",["Mismatch"])};
}

if (checkIP && checkUA) {
 
  	authorized = (UACorrect && IPCorrect);
  	
}

logMessage("Authorized: " + authorized);
