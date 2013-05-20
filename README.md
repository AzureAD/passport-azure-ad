# Windows Azure Active Directory Passport.js Plug-In
=============

[Passport](http://passportjs.org/) is authentication middleware for Node.js. Passport can be used in any Express-based web application. A comprehensive and large set of strategies support authentication using a username and password, Facebook, Twitter, and more. In order to enable you to quickly integrate Windows Azure Active Directory in to your website quickly, we have developed a strategy for Windows Azure Active Directory.

The passport-azure-ad module is a WS-Federation / SAML-P authentication provider for Passport. This provider lets you integrate your Node app with Windows Azure AD so you can use its many features, including web single sign-on (WebSSO). 


The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library.

passport-azure-ad has been tested to work with both [Windows Azure Active Directory](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

For a detailed walkthrough of using Passport.js to add web single sign-on to a Node app, see: [Windows Azure AD Walkthrough for Node.js](https://github.com/MSOpenTech/AzureAD-Node-Sample/wiki).

## Installation

    $ npm install passport-azure-ad

## Usage

### Configure strategy

This sample uses a WS-Federation protocol:

```javascript
	var config = {
	realm: 'http://localhost:3000',
	identityProviderUrl: 'https://login.windows.net/ad0ffc54-96b9-4757-bbb0-fcc293e2f4aa/wsfed',
	identityMetadata: 'https://login.windows.net/ad0ffc54-96b9-4757-bbb0-fcc293e2f4aa/federationmetadata/2007-06/federationmetadata.xml'
				};

	var wsfedStrategy = new wsfedsaml2(config,
    	function(profile, done) {
    	if (!profile.email) {
    	return done(new Error("No email found"), null);
    	}
    	// asynchronous verification, for effect...
    	process.nextTick(function () {
    	findByEmail(profile.email, function(err, user) {
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
	});


	passport.use(wsfedStrategy);

	var users = [];

	function findByEmail(email, fn) {
	for (var i = 0, len = users.length; i < len; i++) {
	var user = users[i];
	if (user.email === email) {
	return fn(null, user);
	}
	}
	return fn(null, null);
	}
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
Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
