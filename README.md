# Windows Azure Active Directory Passport.js Plug-In
=============

passport-azure-ad is a collection of [Passport](http://passportjs.org/) Strategies to help you integrate with Azure Active Ditectory. It includes OpenID Connect, WS-Federation, and SAML-P authentication and authorization. These providers lets you integrate your Node app with Windows Azure AD so you can use its many features, including web single sign-on (WebSSO).


The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library.

passport-azure-ad has been tested to work with both [Windows Azure Active Directory](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

For a detailed walkthrough of using Passport.js to add web single sign-on to a Node app, see: [Windows Azure AD Walkthrough for Node.js](https://github.com/MSOpenTech/AzureAD-Node-Sample/wiki).


## Installation

    $ npm install passport-azure-ad

## Usage

### Configure strategy

This sample uses the OpenID Connect protocol:

```javascript
	var options = {
	identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration'
				};

var oidcStrategy = new OIDCBearerStrategy(options,
          function(token, done) {
             findById(token.sub, function (err, user) {
               if (err) { return done(err); }
                 if (!user) {
          // "Auto-registration"
          log.info('User was added automatically as they were new. Their sub is: ', token.sub)
          users.push(token);
          return done(null, token);
        }
               return done(null, user, token);
             });
          });

        passport.use(oidcStrategy);


	var users = [];

  var findById = function (id, fn) {
    for (var i = 0, len = users.length; i < len; i++) {
      var user = users[i];
      if (user.id === id) {
        return fn(null, user);
      }
    }
    return fn(null, null);
  };
```

### Provide the authentication callback

To complete the sample, provide a route that corresponds to the path configuration parameter that is sent to the strategy:

```javascript
	// what to do when Azure Active Directory sends us back a token

	app.post('/login/callback',
	passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
	function(req, res) {
	res.redirect('/');
	});
```

## License
Copyright (c) Microsoft Corp.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
