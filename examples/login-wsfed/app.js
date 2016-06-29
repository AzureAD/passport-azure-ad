/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
* Permission is hereby granted, free of charge, to any person obtaining a copy of this 
* software and associated documentation files (the "Software"), to deal in the Software 
* without restriction, including without limitation the rights to use, copy, modify, 
* merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
* permit persons to whom the Software is furnished to do so, subject to the following 
* conditions:
*
* The above copyright notice and this permission notice shall be 
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS 
* OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT 
* OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

'use strict';

/**
 * Module dependencies.
 */
var express = require('express');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var bodyParser = require('body-parser');
var http = require('http');
var path = require('path');
var passport = require('passport');
var wsfedsaml2 = require('../../lib/index').WsfedStrategy;
var engine = require('ejs-locals');

var app = express();

var config = {
   // Enter the App ID URI of your application. To find this value in the Windows Azure Management Portal,
  // click Active Directory, click Integrated Apps, click your app, and click Configure.
  // The App ID URI is at the bottom of the page in the Single Sign-On section.
  realm: 'http://localhost:3000',

  // Enter the endpoint to which your app sends sign-on and sign-out requests when using WS-Federation protocol.
  // To find this value in the Windows Azure Management Portal, click Active Directory, click Integrated Apps,
  // and in the black menu bar at the bottom of the page, click View endpoints.
  // Then, copy the value of the WS-Federation Sign-On Endpoint.
  // Note: This field is ignored if you specify an identityMetadata url
  identityProviderUrl: 'https://login.windows.net/GraphDir1.OnMicrosoft.com/wsfed',

  // This is the URL that Active Directory will redirect to with the token after the login process.
  // Ensure this is an HTTPS endpoint and is included in the Reply URL list in Active Directory -> Application -> Configuration -> Reply URL
   wreply: 'https://localhost:3000/login/callback',

  // Enter the logout url of your application. The user will be redirected to this endpoint after
  // the auth token has been revoked by the WSFed endpoint.
  logoutUrl: 'http://localhost:3000/',

  // Enter the URL of the federation metadata document for your app or the cert of the X.509 certificate found
  // in the X509Certificate tag of the RoleDescriptor with xsi:type="fed:SecurityTokenServiceType" in the federation metadata.
  // If you enter both fields, the metadata takes precedence
  identityMetadata: 'https://login.windows.net/GraphDir1.OnMicrosoft.com/federationmetadata/2007-06/federationmetadata.xml'
};

// array to hold logged in users
var users = [];

// use ejs-locals for all ejs templates:
app.engine('ejs', engine);

app.configure(function(){
  app.set('port', process.env.PORT || 3000);
  app.set('views',__dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(express.methodOverride());
  app.use(cookieParser());
  app.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
  app.use(bodyParser.urlencoded({ extended : true }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(path.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});

var findByEmail = function (email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
var ensureAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
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
  }
);

passport.use(wsfedStrategy);

http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
});



app.get('/', function(req, res){
  if(req.user) {
    res.render('index', { user: req.user });
  } else {
    res.render('index', { user: req.user });
  }
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user:req.user });
});

app.get('/login',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/logout', function(req, res){

// clear the passport session cookies
  req.logout();

// We need to redirect the user to the WSFED logout endpoint so the
// auth token will be revoked
  wsfedStrategy.logout({}, function(err, url) {
    if(err) {
      res.redirect('/');
    } else {
      res.redirect(url);
    }
  });
});

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function(user, done) {
  done(null, user.email);
});

passport.deserializeUser(function(id, done) {
  findByEmail(id, function (err, user) {
    done(err, user);
  });
});



