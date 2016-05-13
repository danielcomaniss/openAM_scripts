/*
* simon.moffatt@forgerock.com 11/05/16
* Verifies an externally presented JWT using HMAC shared secret
* Uses the Forgerock json-web-token libs
*/


logger.message("Scripted policy condition ExternalJWTVerifier: Called ************************************")

//Imports
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.handlers.HmacSigningHandler
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jws.handlers.SigningHandler
import org.forgerock.json.jose.utils.Utils
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.JwsHeader
import org.forgerock.util.encode.Base64url
import org.forgerock.json.jose.jws.SignedJwt

//Globals
def HMAC_SECRET= "password"; //Shared secret that is used to sign the JWT

/* As the user we're evaluating wont have an OpenAM session, we need to receive their 3rd party JWT.  This needs presenting within the environment
* map. This just checks the environment map is not empty and contains the JWT attribute...
*/


jwtSet = environment.get("jwt")

if (jwtSet.isEmpty()) {
        
  		logger.warning("Scripted policy condition ExternalJWTVerifier: Environment JWT attribute missing, Authorization = false")
  		advice.put("Message",["Environment:{jwt:[JWT token]} missing"])      
  		authorized=false
  
} else {
  
  		//Verify the signature of the submitted JWT

  		//Strip out the he submitted JWT
  		def submittedJwt = jwtSet.iterator().next()
		def submittedHeaderEncoded = submittedJwt.tokenize('.')[0] //Split into header
  		def submittedClaimsEncoded = submittedJwt.tokenize('.')[1] //Split into claims
  		def submittedSignatureEncoded = submittedJwt.tokenize('.')[2] //split into signature
  
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted header - " + submittedHeaderEncoded)
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted claims - " + submittedClaimsEncoded)
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted signature - " + submittedSignatureEncoded)
		
  		//Deconstruct in order to verify
  		String submittedHeaderDecoded = Utils.base64urlDecode(submittedHeaderEncoded);
        String submittedClaimsDecoded = Utils.base64urlDecode(submittedClaimsEncoded);
        byte[] submittedSignatureDecoded = Base64url.decode(submittedSignatureEncoded);
  
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted header decoded - " + submittedHeaderDecoded)
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted claims decoded - " + submittedClaimsDecoded)
  		logger.message("Scripted policy condition ExternalJWTVerifier: submitted signature decoded - " + submittedSignatureDecoded)

        JwsHeader jwsHeader = new JwsHeader(Utils.parseJson(submittedHeaderDecoded));
        JwtClaimsSet claimsSet = new JwtClaimsSet(Utils.parseJson(submittedClaimsDecoded));
  		
  		
  		//Convert shared secret String to byte[] array
		byte[] HMAC_SECRET_AS_BYTES = HMAC_SECRET.getBytes("UTF-8")
  
  		def payload = submittedHeaderEncoded + "." + submittedClaimsEncoded
  		byte[] payloadAsBytes = payload.getBytes("UTF-8")
  		    
  		//Pull in the ForgeRock classes used for verification
  		SignedJwt reconstructedJwt = new SignedJwt(jwsHeader, claimsSet, payloadAsBytes, submittedSignatureDecoded)
		SigningHandler signingHandler = new HmacSigningHandler(HMAC_SECRET_AS_BYTES)
  		validSignature = reconstructedJwt.verify(signingHandler)
              		
        logger.message("Scripted policy condition ExternalJWTVerifier: validJWTSignature - " + validSignature)
  
  		if (validSignature == true){
 
  			logger.message("Scripted policy condition ExternalJWTVerifier: JWT signature valid")
    	    authorized=true
          
        } else {
          
  			logger.message("Scripted policy condition ExternalJWTVerifier: JWT signature invalid")
    	    advice.put("Message",["JWT signature invalid"])    
            authorized=false

        }

}
