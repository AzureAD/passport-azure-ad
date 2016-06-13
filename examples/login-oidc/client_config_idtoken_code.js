  // Don't commit this file to your public repos. This config is for first-run
  //

  exports.creds = {
    // This is your app's 'REPLY URL' in AAD
    returnURL: 'http://localhost:3000/auth/openid/return',

    // replace <your_tenant_name_or_id> with your tenant name or your tenant id,
    // tenant name is something like: *.onmicrosoft.com
    // tenant id is something like: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, to find your tenant id, go to your
    // tenant homepage in AAD, and your tenant id will be part of the url:
    // https://manage.windowsazure.com/microsoft.onmicrosoft.com#Workspaces/ActiveDirectoryExtension/Directory/'Your_tenant_id_is_here'/directoryQuickStart 
    identityMetadata: 'https://login.microsoftonline.com/<your_tenant_name_or_id>/.well-known/openid-configuration',
       
    // This is your app's 'CLIENT ID' in AAD
    clientID: 'your_client_id_in_AAD',
    
    // This is your app's 'key' in AAD. Required, if in the responseType, you are doing 'id_token code' or 'code',
    // and optional for 'id_token'
    clientSecret: 'your_app_key_in_AAD', 
    
    // for AAD should be set to true
    skipUserProfile: true,
    
    // id_token for login flow, and code for accessing resources
    responseType: 'id_token code',
    
    // we should have token passed back to us in a POST
    responseMode: 'form_post',
    
    // additional scopes you may wish to pass
    // scope: ['email', 'profile'], 
    // if you have validation on, you cannot have users from multiple tenants sign in
    validateIssuer: true,
    
    // if you want to use the req object in your verify function for the passport strategy, set passReqToCallback true.
    // for example, if your verify function is like "function(req, profile, done)", passReqToCallback should be set true.
    passReqToCallback: false,
    
    // valid are 'info', 'warn', 'error'. Error always goes to stderr in Unix.
    loggingLevel: 'info',
  };
