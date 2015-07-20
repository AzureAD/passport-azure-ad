 // Don't commit this file to your public repos. This config is for first-run
 exports.creds = {
     mongoose_auth_local: 'mongodb://localhost/tasklist', // Your mongo auth uri goes here
     issuer: 'https://sts.windows.net/cff56d8f-f602-4afd-94e4-c95b76f1c81e/',
     audience: 'http://kidventus.com/TodoListService',
     identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration' // For using Microsoft you should never need to change this.
 };


