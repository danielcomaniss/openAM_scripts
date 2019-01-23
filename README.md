<b>ForgeRock OpenAM/Access Management Scripted authentication and authorization artifacts</b>
<br/>
<br/>
<b>authenticationPasswordUpdate.js</b>
<br/>
Captures the submitted password from the sharedState object and stores against the users DJ profile - useful when migrating users from
existing stores and then using the Dynamic Profile creation option in OpenAM
<br/>
<br/>
<b>ExternalJWTVerifier.groovy</b>
<br/>
Scripted policy condition used to check the HMAC signature on an externally generated JWT
<br/>
<br/>
<b>PATSValidator.js</b>
<br/>
Scripted policy condition used to check the submitted Personal Access Tokens
<br/>
<br/>
<b>OAuth2Validator.js</b>
<br/>
Scripted policy condition, that allows PDP decisions to be made against an AM issued OAuth2 access_token
<br/>
<br/>
<b>ResponsiveContextCheck.js</b>
<br/>
Scripted policy condition, that compares previously stored context to the current access request.
<br/>
<br/>
<b>stress-test-am.sh</b>
<br/>
Basic bash script to perform configurable number of authentication, failed authentication, OAuth2 grants etc to generate monitoring stats for Grafana et al.
<br/>
<br/>
<b>create-and-add-self-signed-cert-to-am-keystore</b>
<br/>
Basic script to create a 2048 bit RSA private key for demo signing.  Adds into the AM default keystore.jceks
<br/>
<br/>
<b>get-oauth2-access-token.sh</b>
<br/>
Basic script for testing OAuth2 key rotation
<br/>
<br/>
<b>create_ec_key_and_cert</b>
<br/>
Creates EC private key and associated certificate
<br/>
<br/>
<b>request_access_token_cc</b>
<br/>
Requests access token using client creds flow, authenticating client via MTLS
<br/>
Use as-is, no warranty.

