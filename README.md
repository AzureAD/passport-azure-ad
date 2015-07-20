# Windows Azure Active Directory Passport.js Plug-In
=============

passport-azure-ad is a collection of [Passport](http://passportjs.org/) Strategies to help you integrate with Azure Active Ditectory. It includes OpenID Connect, WS-Federation, and SAML-P authentication and authorization. These providers lets you integrate your Node app with Windows Azure AD so you can use its many features, including web single sign-on (WebSSO).


The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library as well as Kiyofumi Kondoh's [passport-openid-google](https://github.com/kkkon/passport-google-openidconnect).

passport-azure-ad has been tested to work with both [Windows Azure Active Directory](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

For a detailed walkthrough of using Passport.js to add web single sign-on to a Node app, see: [Windows Azure AD Walkthrough for Node.js](https://github.com/MSOpenTech/AzureAD-Node-Sample/wiki).


## Installation

    $ npm install passport-azure-ad

## Usage

### Configure strategy

This sample uses the OAuth2Bearer Strategy:

```javascript

// We pass these options in to the ODICBearerStrategy.

var options = {
    // The URL of the metadata document for your app. We will put the keys for token validation from the URL found in the jwks_uri tag of the in the metadata.
    identityMetadata: config.creds.identityMetadata,
    issuer: config.creds.issuer,
    audience: config.creds.audience

};

var bearerStrategy = new BearerStrategy(options,
    function(token, done) {
        log.info('verifying the user');
        log.info(token, 'was the token retreived');
        findById(token.sub, function(err, user) {
            if (err) {
                return done(err);
            }
            if (!user) {
                // "Auto-registration"
                log.info('User was added automatically as they were new. Their sub is: ', token.sub);
                users.push(token);
                owner = token.sub;
                return done(null, token);
            }
            owner = token.sub;
            return done(null, user, token);
        });
    }
);
```
This sample uses the OIDCStrategy:

```javascript
// Use the OIDCStrategy within Passport.
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier), and invoke a callback
//   with a user object.
passport.use(new OIDCStrategy({
    callbackURL: config.creds.returnURL,
    realm: config.creds.realm,
    clientID: config.creds.clientID,
    clientSecret: config.creds.clientSecret,
    oidcIssuer: config.creds.issuer,
    identityMetadata: config.creds.identityMetadata
  },
  function(iss, sub, profile, accessToken, refreshToken, done) {
    log.info('We received profile of: ', profile);
    log.info('Example: Email address we received was: ', profile._json.upn);
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByEmail(profile._json.upn, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      });
    });
  }
));
```
### Provide the authentication callback for OIDCStrategy

To complete the sample, provide a route that corresponds to the path configuration parameter that is sent to the strategy:

```javascript

app.get('/login', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('Login was called in the Sample');
    res.redirect('/');
});

// POST /auth/openid
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in OpenID authentication will involve redirecting
//   the user to their OpenID provider.  After authenticating, the OpenID
//   provider will redirect the user back to this application at
//   /auth/openid/return


app.post('/auth/openid', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('Authenitcation was called in the Sample');
    res.redirect('/');
  });

// GET /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.

app.get('/auth/openid/return', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    log.info('We received a return from AzureAD.');
    res.redirect('/');
    
  });
```

## License
Copyright (c) Microsoft Corp.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
