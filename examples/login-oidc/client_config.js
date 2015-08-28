  // Don't commit this file to your public repos. This config is for first-run
  //
 exports.creds = {
 	returnURL: 'http://localhost:3000/auth/openid/return',
 	identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration', // For using Microsoft you should never need to change this.
 	realm: 'http://localhost:3000',
 	clientID: '6450da98-4793-4dbd-9945-56a26737e229',
 	clientSecret: 'vPSgl3vyVR8w8Ge/A8hYbhIm8eZEcAmC4JCIB5jeoI8=',
 	skipUserProfile: true, // for OpenID only flows this should be set to true
 	responseType: 'id_token code', // for login only flows
 	responseMode: 'form_post', // As per the OAuth 2.0 standard.
 	//scope: ['email', 'profile'] // additional scopes you may wish to pass
 };