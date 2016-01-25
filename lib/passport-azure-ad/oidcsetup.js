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

var configuration = require('./oidcconfig').configuration,
Log = require('./logging').getLogger;

var log = new Log("AzureAD: OIDC Setup");

exports = module.exports = function(identifier, done) {
  log.info('OpenID Discovery...');
  log.info('  identifer: ' + identifier);
  
  exports.discovery(identifier, function(err, issuer) {
    if (err) { return done(err); }
    
    exports.configuration(issuer, function(err, config) {
      if (err) { return done(err); }
      
      log.info('CONFIG:');
      log.info(config);
      
      if (config.clientID) {
        // If the configuration contains a client ID, setup is complete and
        // authentication can proceed.  Having a client ID means the relying
        // party has been registered with the provider, either via a manual
        // process or dynamically during a previous authentication attempt.
        
        log.info('Client ID has been provided. We will be using: ', config.clientID);

        return done(null, config);
      } else {
        // There's no client ID available, meaning the relying party is not
        // registered with the provider.  Attempt to dynamically register with
        // the provider and proceed if that is successful.
        log.info('Client ID has not been provided. Azure does not currently support dynamic registration. Failing');

          return done(err);
      }
    });
  });
};


var discoverers = [];
var configurers = [];
var registerers = [];

exports.discovery = function(identifier, done) {
  if (typeof identifier === 'function') {
    return discoverers.push(identifier);
  }

  var stack = discoverers;
  (function pass(i, err, issuer) {
    //  `err` is ignored so that fallback discovery mechanisms will be
    //       attempted.
    if (err) {
      log.info('discovery attempt failed...');
      log.info(err);
    }
    // issuer was obtained, done
    if (issuer) { return done(null, issuer); }
    
    var layer = stack[i];
    if (!layer) {
      log.warn('Failed to discover OpenID Connect provider for endpoint: ', issuer);
      return done(new Error('Failed to discover OpenID Connect provider'));
    }
    
    try {
      layer(identifier, function(e, is) { pass(i + 1, e, is); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
};

exports.configuration = function(issuer, done) {
  if (typeof issuer === 'function') {
    return configurers.push(issuer);
  }
  
  var stack = configurers;
  (function pass(i, err, config) {
    // error or config was obtained, done
    if (err || config) { return done(err, config); }
    
    var layer = stack[i];
    if (!layer) {
      // Locally-implemented methods of loading configuration did not obtain a
      // result.  Proceed to protocol-defined mechanisms in an attempt to
      // discover the provider's configuration.
      log.warn('Could not load configuration locally. Trying remote loading');
      return configuration(issuer, done);
    }
    
    try {
      layer(issuer, function(e, c) { pass(i + 1, e, c); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
};

exports.registration = function(provider, done) {
  if (typeof provider === 'function') {
    return registerers.push(provider);
  }
  
  var stack = registerers;
  (function pass(i, err, config) {
    // error or config was obtained, done
    if (err || config) { return done(err, config); }
    
    var layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to register with OpenID Connect provider'));
    }
    
    try {
      layer(provider, function(e, c) { pass(i + 1, e, c); } );
    } catch (ex) {
      return done(ex);
    }
  })(0);
};
