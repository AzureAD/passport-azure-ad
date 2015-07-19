  // Don't commit this file to your public repos. This config is for first-run
  //
 exports.creds = {
 	returnURL: 'http://localhost:3000/auth/openid/return',
 	identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration', // For using Microsoft you should never need to change this.
 	realm: 'http://localhost:3000',
 	clientID: 'c9655d1d-f356-46a7-afe1-431c0d6eeb37',
 	clientSecret: 'jRXwIofdH7Hju2V1E1ab5v5uLVf68mhVgEeIRaBMXf0='
 };