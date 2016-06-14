  // Don't commit this file to your public repos. This config is for first-run
  //

  exports.creds = {
    // This is your app's 'REPLY URL' in AAD
    returnURL: 'http://localhost:3000/auth/openid/return',

    // replace <your_tenant_name> with your tenant name,
    // which is something like: "*.onmicrosoft.com"
    identityMetadata: 'https://login.microsoftonline.com/<your_tenant_name>/.well-known/openid-configuration',
    
    // This is your app's 'CLIENT ID' in AAD
    clientID: '2abf3a52-7d86-460b-a1ef-77dc43de8aad',
    
    // This is your app's 'key' in AAD. Required if you are doing 'id_token code' or 'code',
    // and optional for 'id_token'
    clientSecret: 'myAppSecret=', 
    
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
    
    passReqToCallback: false,

    // valid are 'info', 'warn', 'error'. Error always goes to stderr in Unix.
    loggingLevel: 'info',
  };
