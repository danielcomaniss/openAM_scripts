//Captures the submitted user password from sharedState and stores against the user store in OpenDJ.
//Used for MySQL database migrations

logger.message("Scripted Password Update Module: starting...");
logger.message("Scripted Password Update Module: updating password for " + username);

//Capture submitted password from shared state
submittedPassword = sharedState.get("javax.security.auth.login.password");
//Update the user record with the password
idRepository.setAttribute(username, "userpassword", [submittedPassword]);

//Default as we're not testing authentication in this module
authState = SUCCESS;
