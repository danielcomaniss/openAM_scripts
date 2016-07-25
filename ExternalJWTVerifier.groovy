/*
* simon.moffatt@forgerock.com 11/05/16
* Verifies an externally presented JWT using HMAC shared secret
* andrew.potter@forgerock.com 25/07/16 - added RS256 verification
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
//RSA additional imports
import org.forgerock.json.jose.jws.SignedJwt
import org.forgerock.json.jose.jwk.JWKSet
import org.forgerock.json.jose.jwk.JWK
import org.forgerock.json.jose.jwk.RsaJWK
import sun.security.rsa.RSAPublicKeyImpl
import org.forgerock.util.SignatureUtil
import org.forgerock.json.jose.jws.handlers.RSASigningHandler

//Globals
def HMAC_SECRET= "password"; //Shared secret that is used to sign the JWT
def JWK_URI = "http://as.uma.com:8080/openam/oauth2/ScopeAz/connect/jwk_uri"; //jwk_uri for OIDC provider

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
	def validSignature = false
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
        
        logger.message("header.alg:" + jwsHeader.getParameter("alg"))
        
        def payload = submittedHeaderEncoded + "." + submittedClaimsEncoded
        byte[] payloadAsBytes = payload.getBytes("UTF-8")
  
        if (jwsHeader.getParameter("alg").toString() == "HS256") {
  	    //HMAC shared key	
            //Convert shared secret String to byte[] array
            byte[] HMAC_SECRET_AS_BYTES = HMAC_SECRET.getBytes("UTF-8")
            
            //Pull in the ForgeRock classes used for verification
            SignedJwt reconstructedJwt = new SignedJwt(jwsHeader, claimsSet, payloadAsBytes, submittedSignatureDecoded)
            SigningHandler signingHandler = new HmacSigningHandler(HMAC_SECRET_AS_BYTES)
            validSignature = reconstructedJwt.verify(signingHandler)
            logger.message("Scripted policy condition ExternalJWTVerifier: validJWTSignature - " + validSignature)
            
        } else if (jwsHeader.getParameter("alg").toString() == "RS256") {
          //RS256 public key
          // get jwkset from JWK_URI 
          //   result 'entity' should be similar to:
          //   {"keys":[{"kty":"RSA","kid":"uamVGmFKfz1ZTibV56uylOgL9Q0=","use":"sig","alg":"RS256","n":"ALZCFA5MoaXNl9-j9NBpUQFfhX58ao3JyHCfCk1HHOMk5BZv8puqw5eiYv5Een6HXhdP4BzWs67JpUKB6A39R5V2qwdH6NPfa4_QRUJ9mshoyTzHQuEAvBFeFAifDtb4jWPBPWvupDH9Ko3X3-RXImQPQfH640L-eInEa6YEzBl1QsCz-QS3U3BoIQuLrpvOJbDk5XUp8yFFCE8CYX8o-XS7vetYR8D67FQQcZYkOg6vbxzrRm405ix_UfxSrnnBeOZNIWaNYfwcZoUeXvBl3HKfAgMhjBzfwtLGhcAuTOo6Ge1B2NDDrWMcdPV5v5e-vlnW9fOW4oqmcGUtn8zpN_M","e":"AQAB"}]}
          def resp = httpClient.get(JWK_URI,null)
          if (resp.getStatusCode() == 200) {
            logger.message("body:" + resp.getEntity())
            //Build a JWKSet from the jwk_uri response
            JWKSet jwkset = JWKSet.parse(resp.getEntity())
            logger.message("jwk[0]: " + jwkset.getJWKsAsList()[0].toString())
            //get the first JWK from the set and create as an RsaJWK
            RsaJWK rsajwk = RsaJWK.parse(jwkset.getJWKsAsList()[0].toString())
            logger.message("rsajwk:" + rsajwk.toString())
            //create the RSASigningHandler to verify the signature
            SignatureUtil sigutil = new SignatureUtil()
            SigningHandler rsaSigningHandler = new RSASigningHandler(rsajwk.toRSAPublicKey(),sigutil)
            validSignature = rsaSigningHandler.verify(JwsAlgorithm.RS256, payloadAsBytes, submittedSignatureDecoded)
            logger.message("RSA Sig is valid?: " + validSignature)
            
          }
        }
        
        if (validSignature == true){
        	logger.message("Scripted policy condition ExternalJWTVerifier: JWT signature valid")
        	authorized=true
          
        } else {
            logger.message("Scripted policy condition ExternalJWTVerifier: JWT signature invalid")
    	    advice.put("Message",["JWT signature invalid"])    
            authorized=false
        }
}
