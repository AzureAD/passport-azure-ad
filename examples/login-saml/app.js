/* global __dirname */
/* global process */
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
var passport = require('passport');
var http = require('http');
var SamlStrategy = require('../../lib/index').SamlStrategy;
var fs = require('fs');
var engine = require('ejs-locals');
var PATH = require('path');

var app = express();

var config = {
  // required options
  identityMetadata: 'https://login.windows.net/GraphDir1.OnMicrosoft.com/federationmetadata/2007-06/federationmetadata.xml',
  loginCallback: 'http://localhost:3000/login/callback/',
  issuer: 'http://localhost:3000',  // this is the URI you entered for APP ID URI when configuring SSO for you app on Azure AAD

  // optional, but required to support SAML logout
  appUrl: 'http://localhost:3000',
  logoutCallback: 'http://localhost:3000/logout/callback/',
  privateCert: fs.readFileSync('./private.pem', 'utf-8'),
  publicCert: fs.readFileSync('./public.pem', 'utf-8'),

  // optional parameters for Service Provider Federation metadata file
  contactFirstName: 'First',
  contactLastName: 'Last',
  contactEmail: 'admin@example.com',
  organizationName: 'Examples, Inc',
  organizationDisplayName: 'Examples, Inc',
  organizationUrl: 'http://localhost:3000'
};

// array to hold logged in users
var users = [];

var findByEmail = function(email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

// Keep a reference to the saml Strategy as we will need it in /logout
var samlStrategy = new SamlStrategy(config, function(profile, done) {
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

passport.use(samlStrategy);

// use ejs-locals for all ejs templates:
app.engine('ejs', engine);

// configure Express
app.configure(function() {
  app.set('port', process.env.PORT || 3000);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.favicon());
  app.use(express.logger('dev'));
  app.use(cookieParser());
  app.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
  app.use(bodyParser.urlencoded({ extended : true }));
  app.use(express.methodOverride());
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(PATH.join(__dirname, 'public')));
});

app.configure('development', function(){
  app.use(express.errorHandler());
});

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


app.get('/', function(req, res){
  if(req.user) {
    res.render('index', { user: req.user});
  } else {
    res.render('index', { user: req.user });
  }
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/logout/callback', function(req, res){
  console.log("logout post from:" + req.ip);
  res.redirect('/');
});

app.get('/logout', function(req, res){

// TODO: There is currently a bug with the AAD samlStrategy endpoint that will not redirect to our app. So it is disabled for now
  req.logout();
  res.redirect('/');

/*
// We need to redirect the user to the SAML logout endpoint
  // use the saml Strategy to setup the parameters for the logout url
  samlStrategy.logout(req, function(err, url) {
    // clear the session cookies
    if(err) {
      res.redirect('/');
    } else {
      //res.redirect(url);
      res.redirect('/');
    }
  });
  req.logout();
 */
});


// Save the Service Federation Metadata XML file to the app directory.
// File is saved as federationmetadata.xml
//
// In order to run your app on localhost, you will need to upload this file to
// a server. You will then have to update the Federation Metadata URL in the SSO
// settings portion of the Active Directory Integrated App configuration page
// on the Azure management Portal. If you make any changes to the above SAML configs,
// you will need to upload this file again to your server.
app.get('/identity', function(req, res){
  // We need to redirect the user to the samlStrategy logout endpoint
  // use the saml Strategy to setup the parameters for the logout url
  samlStrategy.identity(function(err, data) {
    // clear the session cookies
    if(err) {
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/html");
      res.end(err.message);
    } else {
      res.writeHead(200, {'Content-Type': 'application/xml'});
      res.end(data);
      var path = PATH.join(__dirname, 'federationmetadata.xml');
      fs.writeFileSync(path,data);
    }
  });
});

http.createServer(app).listen(app.get('port'), function(){
  console.log("Express server listening on port " + app.get('port'));
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
