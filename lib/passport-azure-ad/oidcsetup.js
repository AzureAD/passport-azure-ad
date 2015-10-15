/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  Apache License 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @flow
 */

var configuration = require('./oidcconfig').configuration
, bunyan = require('bunyan');

var log = bunyan.createLogger({
    name: 'Microsoft OIDC Passport Strategy: Setup'
});

exports = module.exports = function(identifier, done) {
  log.info('OpenID Discovery...');
  log.info('  identifer: ' + identifier);
  
  exports.discovery(identifier, function(err, issuer) {
    if (err) { return done(err); }
    
    exports.configuration(issuer, function(err, config) {
      if (err) { return done(err); };
      
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
}


var discoverers = [];
var configurers = [];
var registerers = [];

exports.discovery = function(identifier, done) {
  if (typeof identifier === 'function') {
    return discoverers.push(identifier);
  }

  var stack = discoverers;
  (function pass(i, err, issuer) {
    // NOTE: `err` is ignored so that fallback discovery mechanisms will be
    //       attempted.
    if (err) {
      log.info('discovery attempt failed...');
      log.info(err);
    }
    // issuer was obtained, done
    if (issuer) { return done(null, issuer); }
    
    var layer = stack[i];
    if (!layer) {
      log.warn('Failed to discover OpenID Connect provider for endpont: ', issuer);
      return done(new Error('Failed to discover OpenID Connect provider'));
    }
    
    try {
      layer(identifier, function(e, is) { pass(i + 1, e, is); } )
    } catch (ex) {
      return done(ex);
    }
  })(0);
}

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
      layer(issuer, function(e, c) { pass(i + 1, e, c); } )
    } catch (ex) {
      return done(ex);
    }
  })(0);
}

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
      layer(provider, function(e, c) { pass(i + 1, e, c); } )
    } catch (ex) {
      return done(ex);
    }
  })(0);
}
