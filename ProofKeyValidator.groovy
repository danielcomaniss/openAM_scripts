/*
* simon.moffatt@forgerock.com 28/02/19
* Verifies an externally presented nonce against a SHA256 hashed representation stored on the user's profile during authentication
* Similar in concept to https://tools.ietf.org/html/rfc7636 - PKCE for OAuth2
* Login to a tree that captures base64(sha256(nonce)) where nonce is a secret used only once per authentication request
* During a PDP request, the nonce is sent in as an env attribute.  This script performs a hash compare of the presented nonce against what was stored during authentication, providing simple proof of possession.
* Assumption that requests are made over TLS and the the application that stores the token is insecure
*/

//Imports
import org.forgerock.util.encode.Base64url
import org.forgerock.openam.shared.security.crypto.Fingerprints

//Globals
def PROOFKEY_ATTRIBUTE= "givenName"; //Profile attribute where the hashed proof key was stored during login

//Generic Logging
def logMessage(message){
 	 
	logger.message("Scripted policy condition Proof Key validator: " + message)

}

//Retrieve the proofKey from the submitted environmental payload
def submittedProofKeySet = environment.get("proofKey")

//proofKey not found...
if (submittedProofKeySet == null || submittedProofKeySet.isEmpty()) {
        
        logMessage("proofKey attribute missing from env payload")
        advice.put("Message",["proofKey missing from environment payload"])
  		authorized=false
  
} else {
        
        //Strip out the submitted proofKey
        def submittedProofKey = submittedProofKeySet.iterator().next()
        logMessage("proofKey submitted as " + submittedProofKey)
        
  		//Retrieve the key stored on the user's profile (removing any trailing == in case they were stored)
  		def storedProofKey = identity.getAttribute(PROOFKEY_ATTRIBUTE).iterator().next() //.replace("=","")
  		logMessage("stored proofKey retrieved as " + storedProofKey)
  		
  		//Take submitted proofKey create SHA256 hash
  		def submittedProofKeyHashed = Fingerprints.generate(submittedProofKey)
  		
  		//Take the hash and Base64URL encode
   		//def submittedProofKeyHashedAndEncoded=Base64url.encode(submittedProofKeyHashed)                                                	
  		logMessage("submitted proofKey hashed " + submittedProofKeyHashed)
  
  		//Compare submitted proofKey with the hashed version stored on profile
  		if (storedProofKey == submittedProofKeyHashed) {
        	
          	logMessage("proofKeys identical :-) authorized = true")
          	ttl=1000*60	//time to live set to 1 minute in milliseconds
          	authorized=true
          
        
        } else {
         
           	logMessage("proofKeys not the same :-( authorized = false")
            advice.put("Message",["proofKey invalid"]) 
 			authorized=false
        };

}
