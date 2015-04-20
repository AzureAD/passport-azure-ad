# Windows Azure Active Directory Passport.js Plug-In

[Passport](http://passportjs.org/) is authentication middleware for Node.js. Passport can be used in any Express-based web application. A comprehensive and large set of strategies support authentication using a username and password, Facebook, Twitter, and more. In order to enable you to quickly integrate Windows Azure Active Directory in to your website quickly, we have developed a strategy for Windows Azure Active Directory.

The passport-azure-ad module is a WS-Federation / SAML-P authentication provider for Passport. This provider lets you integrate your Node app with Windows Azure AD so you can use its many features, including web single sign-on (WebSSO). 


The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library.

passport-azure-ad has been tested to work with both [Windows Azure Active Directory](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

For a detailed walkthrough of using Passport.js to add web single sign-on to a Node app, see: [Windows Azure AD Walkthrough for Node.js](https://github.com/MSOpenTech/AzureAD-Node-Sample/wiki).

## Installation

```
$ npm install passport-azure-ad
```

## Usage

This sample uses a WS-Federation protocol with express:

```javascript
var express = require('express');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var wsfedsaml2 = require('passport-azure-ad').WsfedStrategy;

// create app
var app = express();

// add peer dependencies middleware
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));

// add passport middleware
app.use(passport.initialize());
app.use(passport.session());

var config = {
	realm: 'http://localhost:3000/',
	identityProviderUrl: 'https://login.windows.net/ad0ffc54-96b9-4757-bbb0-fcc293e2f4aa/wsfed',
	identityMetadata: 'https://login.windows.net/ad0ffc54-96b9-4757-bbb0-fcc293e2f4aa/federationmetadata/2007-06/federationmetadata.xml'
	logoutUrl:'http://localhost:3000/'
};

var wsfedStrategy = new wsfedsaml2(config, function(profile, done) {
    if (!profile.email) {
        done(new Error("No email found"));
        return;
    }
    // validate the user here
    done(null, profile);
});

passport.use(wsfedStrategy);

// implement your user session strategy here
// http://passportjs.org/guide/configure/
passport.serializeUser(function(user,cb){
	// TODO: save the user to a persistence layer (in-memory, redis cache, etc)
	// cb([err], [userId])
});

passport.deserializeUser(function(userId,cb){
	// TODO: load a user from the persistence layer
	// cb([err], [user])
});

// send the user to WAAD to authenticate	
app.get('/login', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }), function(req, res) {
    res.redirect('/');
});

// callback from WAAD with a token
app.post('/login/callback', passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }), function(req, res) {
    res.redirect('/');
});

app.listen(process.env.PORT || 3000)
```

## License
Copyright (c) Microsoft Open Technologies, Inc.  All rights reserved. Licensed under the Apache License, Version 2.0 (the "License"); 
