[![Stories in Ready](https://badge.waffle.io/AzureAD/passport-azure-ad.png?label=ready&title=Ready)](https://waffle.io/AzureAD/passport-azure-ad)
# Microsoft Azure Active Directory Passport.js Plug-In
=============

passport-azure-ad is a collection of [Passport](http://passportjs.org/) Strategies to help you integrate with Azure Active Ditectory. It includes OpenID Connect, WS-Federation, and SAML-P authentication and authorization. These providers let you integrate your Node app with Microsoft Azure AD so you can use its many features, including web single sign-on (WebSSO), Endpoint Protection with OAuth, and JWT token issuance and validation.

passport-azure-ad has been tested to work with both [Windows Azure Active Directory](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).


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
passport.use(new OIDCStrategy({
    callbackURL: config.creds.returnURL,
    realm: config.creds.realm,
    clientID: config.creds.clientID,
    clientSecret: config.creds.clientSecret,
    oidcIssuer: config.creds.issuer,
    identityMetadata: config.creds.identityMetadata,
    responseType: config.creds.responseType,
    responseMode: config.creds.responseMode,
    skipUserProfile: config.creds.skipUserProfile
    scope: config.creds.scope
  },
  function(iss, sub, profile, claims, accessToken, refreshToken, params, done) {
    log.info('We received claims of: ', claims);
    log.info('Example: Email address we received was: ', claims.preferred_username || claims.upn);
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByEmail(claims.preferred_username, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(claims);
          return done(null, claims);
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

// POST /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.post('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function(req, res) {
    
    res.redirect('/');
  });

  app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

```

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

Azure Identity samples for this plug-in is here: [https://github.com/AzureADSamples/WebApp-OpenIdConnect-nodejs](https://github.com/AzureADSamples/WebApp-OpenIdConnect-nodejs)


## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one. We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the Apache 2.0 license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

More details [about contribution](https://github.com/AzureAD/passport-azure-ad/blob/master/contributing.md) 

## Versions
Please check the releases for updates.

## Acknowledgements

The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library as well as Kiyofumi Kondoh's [passport-openid-google](https://github.com/kkkon/passport-google-openidconnect).

## License
Copyright (c) Microsoft Corp.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
