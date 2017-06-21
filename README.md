<b>OpenAM Scripted authentication and authorization artifacts</b>
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
<<br/>
<br/>
<b>PATSValidator.js</b>
<br/>
Scripted policy condition used to check the submitted Personal Access Tokens
<br/>
Use as-is, no warranty.

