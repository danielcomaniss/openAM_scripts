//simon.moffatt@forgerock.com - 11/01/18 - internally validates an Oauth2 access_token presented as an env value

logger.message("Scripted OAuth2 policy validator: started");

//Globals
var subittedAccessToken;

//Connection Information
var AMSERVER="http://openam.example.com:8080";
var OAuth2AuthorizationHeader="T0lEQ0NsaWVudDpQYXNzdzByZA=="; //base64(OAuth2ClientId:OAuth2ClientSecret)

//Policy Evaluation Variables
var performAuthLevelCheck=true;
var acceptableAuthLevel=5;
var performScopeCheck=true;
var acceptableScopes=["mail","profile"];

//Verify Auth Level found within access_token against acceptable level configured in globals
function checkAuthLevel(authLevel){
  
  logger.message("Scripted OAuth2 policy validator: checking auth level");
  logger.message("Scripted OAuth2 policy validator: acceptable auth level = " + acceptableAuthLevel);
  logger.message("Scripted OAuth2 policy validator: retrieved auth level = " + authLevel);
  
  if (authLevel < acceptableAuthLevel) {
       
    advice.put("acceptable_auth_level_not_met",[acceptableAuthLevel.toString()]);
    authorized=false;
    
  }
 
}

//Verify that the scopes assigned to the presented access_token fall inside the acceptable scope list
function checkScopes(scope){
 
  retrievedScopes=scope.split(" ");
  logger.message("Scripted OAuth2 policy validator: checking scopes");
  logger.message("Scripted OAuth2 policy validator: acceptable scopes = " + acceptableScopes);
  logger.message("Scripted OAuth2 policy validator: retrieved scopes = " + retrievedScopes);
  logger.message("Scripted OAuth2 policy validator: acceptable scopes length = " + acceptableScopes.length);
  logger.message("Scripted OAuth2 policy validator: retrieved scopes length = " + retrievedScopes.length);
    
  //Check if acceptable array is bigger than submitted short cut out
  if(acceptableScopes.length > retrievedScopes.length) {
  
    logger.message("Scripted OAuth2 policy validator: retrieved scopes contains too few entries");
    advice.put("acceptable_scopes_not_met",["submitted scopes too few"]);
    authorized=false;
    return;
    
  }

  //Loop over acceptable scopes and see if they exist in retrieved scopes
  for(var i=0; i < acceptableScopes.length; i++){
    
  	logger.message("Scripted OAuth2 policy validator: validating acceptable scope entry " + acceptableScopes[i]);
   
    //If the acceptable scope entry isn't found
 	if(retrievedScopes.indexOf(acceptableScopes[i]) == -1) {
       
       	logger.message("Scripted OAuth2 policy validator: didn't find acceptable scope entry " + acceptableScopes[i] + " in retrievedScopes :-(");       
    	advice.put("acceptable_scopes_not_met",["submitted scopes missing required entry"]); 
      	authorized=false;
       	{ break; }
       
     }
  }
  
}

//Verifies material found within the access_token
function validate(response){
	 
	//Dissect the introspection response from AM
    var tokenActive = JSON.parse(response.getEntity()).active;
    var sub = JSON.parse(response.getEntity()).sub;
    var scope = JSON.parse(response.getEntity()).scope;
    var exp = JSON.parse(response.getEntity()).exp;		
    var authLevel = JSON.parse(response.getEntity()).auth_level;
    
   	logger.message("Scripted OAuth2 policy validator: AM introspect is token active? " + tokenActive);
   	logger.message("Scripted OAuth2 policy validator: subject associated with introspected access_token " + sub);
    logger.message("Scripted OAuth2 policy validator: scopes associated with introspected access_token " + scope);
    logger.message("Scripted OAuth2 policy validator: auth_level associated with introspected access_token " + authLevel);
      
    if(tokenActive){

      //Stuff that gets sent back to calling request
      responseAttributes.put("sub",[sub]);
      responseAttributes.put("scope",[scope]);
      responseAttributes.put("auth_level",[authLevel.toString()]);
      ttl=exp; //Set time to live of policy decision to be the exp length of the access_token
      username=sub;
      authorized=true;

      //Checks auth level against pre-determined level set in globals
      if(performAuthLevelCheck){

          checkAuthLevel(authLevel)

      }
      
      //Checks scopes 
      if(performScopeCheck){
        
       	checkScopes(scope);
        
      }
   	}
}

//Calls ../introspect endpoint on AM
function introspect(AT){

    var request = new org.forgerock.http.protocol.Request();  	
  	request.method = 'POST';
    request.setUri(AMSERVER + "/openam/oauth2/introspect?token=" + encodeURIComponent(AT));
    request.getHeaders().add('Content-Type', 'application/x-www-form-urlencoded');
	request.getHeaders().add('cache-control', 'no-cache');
  	request.getHeaders().add('authorization', 'Basic ' + OAuth2AuthorizationHeader);
    var response = httpClient.send(request).get();
  	
  	//Send the introspection response to validator function to dissect
  	if(response){
      
      		validate(response);

    }
}


//Retrieve access_token

submittedAccessToken=environment.get("access_token");

if(submittedAccessToken){
  	
    AT = submittedAccessToken.iterator().next();
    logger.message("Scripted OAuth2 policy validator: access_token found as " + AT);
 	introspect(AT);
  
} else {
    
  logger.message("Scripted OAuth2 policy validator: access_token not found");
  authorized=false;

}
