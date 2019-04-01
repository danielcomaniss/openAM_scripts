/*
* simon.moffatt@forgerock.com 11/05/16 - verifies an externally presented JWT using HMAC shared secret
* andrew.potter@forgerock.com 25/07/16 - added RS256 verification
* simon.moffatt@forgerock.com 27/03/19 - altered to be focused on validating generic JWT within the env payload and extracting claims and comparing to profile attributes
*/

//Imports
import org.forgerock.json.jose.jws.JwsAlgorithm
import org.forgerock.json.jose.jws.handlers.HmacSigningHandler
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.json.jose.jws.handlers.SigningHandler
import org.forgerock.json.jose.utils.Utils
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.json.jose.jws.JwsHeader
import org.forgerock.util.encode.Base64url
//RSA additional imports
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwk.JWKSet
import org.forgerock.json.jose.jwk.JWK
import org.forgerock.json.jose.jwk.RsaJWK
import sun.security.rsa.RSAPublicKeyImpl
import org.forgerock.util.SignatureUtil
import org.forgerock.json.jose.jws.handlers.RSASigningHandler

def authorized=false

//Generic logging function
def logMessage(String message){
  
 	 logger.message("Scripted policy condition ContextJWTVerifier: " + message)
}

logMessage("started")

//Verifies the claims within the JWT against those stored against the user's profile
def verifyContext(claimsSet){
 
  	//Attributes used on the profile to store the context that was captured during login
    def IP_ATTRIBUTE="givenName"
	
  	//Compare IP at login versus IP in the presented context object          
    def IPAtLogin=identity.getAttribute(IP_ATTRIBUTE).iterator().next()
    def IPNow=claimsSet.getClaim("IP").toString()
         
  	//Get issued at
  	def iat = claimsSet.getIssuedAtTime()
  	logMessage("JWT iat as " + iat)
  
  	//Get expiration
  	def exp = claimsSet.getExpirationTime()
  	logMessage("JWT exp as " + exp)
  
  	//Get current date
  	def timeNow = new Date()
  	logMessage("Time now " + timeNow)
  
  	//IAP freshness limit
  	def iatLimit=new Date(System.currentTimeMillis() - 60 * 1000);
	logMessage("iat Limit " + iatLimit)
  
  
	//Check if JWT expired
  	if(exp < timeNow){
    
  		logMessage("JWT exp expired")
        advice.put("Message",["Context object invalid"])
      	
    } else {
      
        //Check JWT freshness
       	if(iat < iatLimit) {
    
  		logMessage("JWT issued too long ago")
        advice.put("Message",["Context object invalid"])
      	
        } else {
        	
          	logMessage("IP at login found as " + IPAtLogin)
            logMessage("IP now found as " + IPNow)
          
          	//Check IP claim
            if(IPAtLogin == IPNow){
      
              	logMessage("IP validation passed")
              	authorized=true
            
            } else {

               logMessage("IP validation failed")
               advice.put("Message",["Context object invalid"])  

           }
        }
    }  
}



//Verify the JWT - present, signature, iap/exp
def verifyJWT(){
  
  	//def HMAC_SECRET= "Passw0rd"; //Shared secret that is used to sign the JWT
    def JWK_URI = "http://as.uma.com:8080/openam/oauth2/ScopeAz/connect/jwk_uri"; //jwk_uri for OIDC provider

  	//Where the Key material is stored against the user's profile
  	def KEY_ATTRIBUTE="mail" 

  	//The attribute that will contain the signed JWT that contains the user context
	jwtSet = environment.get("context")

	if (jwtSet.isEmpty()) {

      logMessage("environment payload is missing attribute called context")
      advice.put("Message",["Environment:{jwt:[JWT token]} missing"])
      authorized=false
	
	} else {

  
  		//Verify the signature of the submitted JWT
        def validSignature = false
        //Strip out the submitted JWT
        def submittedJwt = jwtSet.iterator().next()
        def submittedHeaderEncoded = submittedJwt.tokenize('.')[0] //Split into header
        def submittedClaimsEncoded = submittedJwt.tokenize('.')[1] //Split into claims
        def submittedSignatureEncoded = submittedJwt.tokenize('.')[2] //split into signature

        logMessage("submitted header - " + submittedHeaderEncoded)
        logMessage("submitted claims - " + submittedClaimsEncoded)
        logMessage("submitted signature - " + submittedSignatureEncoded)

        //Deconstruct in order to verify
        String submittedHeaderDecoded = Utils.base64urlDecode(submittedHeaderEncoded);
        String submittedClaimsDecoded = Utils.base64urlDecode(submittedClaimsEncoded);
        byte[] submittedSignatureDecoded = Base64url.decode(submittedSignatureEncoded);
        
        logMessage("submitted header decoded - " + submittedHeaderDecoded)
        logMessage("submitted claims decoded - " + submittedClaimsDecoded)
        logMessage("submitted signature decoded - " + submittedSignatureDecoded)

        //convert the submitted header and claims into relevant objects for use later
        JwsHeader jwsHeader = new JwsHeader(Utils.parseJson(submittedHeaderDecoded));
        JwtClaimsSet claimsSet = new JwtClaimsSet(Utils.parseJson(submittedClaimsDecoded));
  
        // we'll also need the payload in bytes
        def payload = submittedHeaderEncoded + "." + submittedClaimsEncoded
        byte[] payloadAsBytes = payload.getBytes("UTF-8")
    
        //Create a signing manager object
        SigningManager signingManager = new SigningManager()
        def signingHandler
  
        logMessage("header.alg: " + jwsHeader.getParameter("alg"))

        if (jwsHeader.getParameter("alg").toString() == "HS256") {

          	//Retrieve the key stored on the user profile
          	def HMAC_SECRET=identity.getAttribute(KEY_ATTRIBUTE).iterator().next()
          
          	//Convert shared secret String to byte[] array
            byte[] HMAC_SECRET_AS_BYTES = HMAC_SECRET.getBytes("UTF-8")
          
          	//get the HMAC signing handler
            signingHandler = signingManager.newHmacSigningHandler(HMAC_SECRET_AS_BYTES)

        } else if (jwsHeader.getParameter("alg").toString() == "RS256") {
          //RS256 public key
          // get jwkset from JWK_URI 
          //   result 'entity' should be similar to:
          //   {"keys":[{"kty":"RSA","kid":"uamVGmFKfz1ZTibV56uylOgL9Q0=","use":"sig","alg":"RS256","n":"ALZCFA5MoaXNl9-j9NBpUQFfhX58ao3JyHCfCk1HHOMk5BZv8puqw5eiYv5Een6HXhdP4BzWs67JpUKB6A39R5V2qwdH6NPfa4_QRUJ9mshoyTzHQuEAvBFeFAifDtb4jWPBPWvupDH9Ko3X3-RXImQPQfH640L-eInEa6YEzBl1QsCz-QS3U3BoIQuLrpvOJbDk5XUp8yFFCE8CYX8o-XS7vetYR8D67FQQcZYkOg6vbxzrRm405ix_UfxSrnnBeOZNIWaNYfwcZoUeXvBl3HKfAgMhjBzfwtLGhcAuTOo6Ge1B2NDDrWMcdPV5v5e-vlnW9fOW4oqmcGUtn8zpN_M","e":"AQAB"}]}
          def resp = httpClient.get(JWK_URI,null)
          if (resp.getStatusCode() == 200) {
            logMessage("body:" + resp.getEntity())
            //Build a JWKSet from the jwk_uri response
            JWKSet jwkset = JWKSet.parse(resp.getEntity())
            logMessage("jwk[0]: " + jwkset.getJWKsAsList()[0].toString())
            //get the first JWK from the set and create as an RsaJWK
            RsaJWK rsajwk = RsaJWK.parse(jwkset.getJWKsAsList()[0].toString())
            logMessage("rsajwk:" + rsajwk.toString())
            //create the RSASigningHandler to verify the signature
            signingHandler = signingManager.newRsaSigningHandler(rsajwk.toRSAPublicKey())

          }

        }
                 
        //Reconstruct the JWT in order to verify with the signing handler
        SignedJwt reconstructedJwt = new SignedJwt(jwsHeader, claimsSet, payloadAsBytes, submittedSignatureDecoded)
        validSignature = reconstructedJwt.verify(signingHandler)
        logMessage("signature valid - " + validSignature)
  
        if (validSignature == true){
        	          
          	verifyContext(claimsSet)
        	
          
        } else {
          
            advice.put("Message",["Context object invalid"])    
            authorized=false
        }
	}
  
}

verifyJWT()
