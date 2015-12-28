 // Don't commit this file to your public repos. This config is for first-run
 exports.creds = {
     mongoose_auth_local: 'mongodb://localhost/tasklist', // Your mongo auth uri goes here
     clientID: 'cff56d8f-f602-4afd-94e4-c95b76f1c81e',
     audience: 'https://kidventus.net/tasks',
    // you cannot have users from multiple tenants sign in to your server unless you use the common endpoint
 	// example: https://login.microsoftonline.com/common/.well-known/openid-configuration
     identityMetadata: 'https://login.microsoftonline.com/cff56d8f-f602-4afd-94e4-c95b76f1c81e/.well-known/openid-configuration', 
     validateIssuer: true, // if you have validation on, you cannot have users from multiple tenants sign in to uyour server
     passReqToCallback: false

 };


