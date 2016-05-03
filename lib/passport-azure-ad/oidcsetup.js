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

const protocolDefinedConfiguration = require('./oidcconfig').configuration;
const Log = require('./logging').getLogger;

const log = new Log('AzureAD: OIDC Setup');
const discoverers = [];
const configurers = [];
const registerers = [];

function discovery(identifier, done) {
  if (typeof identifier === 'function') {
    return discoverers.push(identifier);
  }

  const stack = discoverers;
  (function pass(i, err, issuer) {
    //  `err` is ignored so that fallback discovery mechanisms will be
    //       attempted.
    if (err) {
      log.info('discovery attempt failed...');
      log.info(err);
    }
    // issuer was obtained, done
    if (issuer) {
      return done(null, issuer);
    }

    const layer = stack[i];
    if (!layer) {
      log.warn('Failed to discover OpenID Connect provider for endpoint: ', issuer);
      return done(new Error('Failed to discover OpenID Connect provider'));
    }

    try {
      layer(identifier, (layerError, layerIssuer) => { pass(i + 1, layerError, layerIssuer); });
    } catch (ex) {
      return done(ex);
    }
    return false;
  }(0));
  return false;
}

function configuration(issuer, done) {
  if (typeof issuer === 'function') {
    return configurers.push(issuer);
  }

  const stack = configurers;
  (function pass(i, err, config) {
    // error or config was obtained, done
    if (err || config) {
      return done(err, config);
    }

    const layer = stack[i];
    if (!layer) {
      // Locally-implemented methods of loading configuration did not obtain a
      // result.  Proceed to protocol-defined mechanisms in an attempt to
      // discover the provider's configuration.
      log.warn('Could not load configuration locally. Trying remote loading');
      return protocolDefinedConfiguration(issuer, done);
    }

    try {
      layer(issuer, (layerError, layerConfiguration) => {
        pass(i + 1, layerError, layerConfiguration);
      });
    } catch (ex) {
      return done(ex);
    }
    return false;
  }(0));
  return false;
}

function registration(provider, done) {
  if (typeof provider === 'function') {
    return registerers.push(provider);
  }

  const stack = registerers;
  (function pass(i, err, config) {
    // error or config was obtained, done
    if (err || config) {
      return done(err, config);
    }

    const layer = stack[i];
    if (!layer) {
      return done(new Error('Failed to register with OpenID Connect provider'));
    }

    try {
      layer(provider, (layerError, layerConfiguration) => {
        pass(i + 1, layerError, layerConfiguration);
      });
    } catch (ex) {
      return done(ex);
    }
    return false;
  }(0));
  return false;
}

function oidcSetup(identifier, done) {
  log.info('OpenID Discovery...');
  log.info(`identifer: ${identifier}`);

  discovery(identifier, (discoveryError, issuer) => {
    if (discoveryError) {
      return done(discoveryError);
    }

    return configuration(issuer, (configurationError, config) => {
      if (configurationError) {
        return done(configurationError);
      }

      log.info('CONFIG:');
      log.info(config);

      if (!config.clientID) {
        // There's no client ID available, meaning the relying party is not
        // registered with the provider.  Attempt to dynamically register with
        // the provider and proceed if that is successful.
        log.info('Client ID has not been provided. Azure does not currently support dynamic registration. Failing');

        return done(new Error('clientId has not been provided'));
      }
      // If the configuration contains a client ID, setup is complete and
      // authentication can proceed.  Having a client ID means the relying
      // party has been registered with the provider, either via a manual
      // process or dynamically during a previous authentication attempt.

      log.info('Client ID has been provided. We will be using: ', config.clientID);

      return done(null, config);
    });
  });
}

oidcSetup.discovery = discovery;
oidcSetup.configuration = configuration;
oidcSetup.registration = registration;

module.exports = oidcSetup;
