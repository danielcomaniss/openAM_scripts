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
Use as-is, no warranty.

