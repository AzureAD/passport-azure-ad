/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
'use strict';

const BearerStrategy = require('passport-http-bearer').Strategy;
const util = require('util');
const jwt = require('jsonwebtoken');
const Metadata = require('./metadata').Metadata;
const Log = require('./logging').getLogger;
const jws = require('jws');

/**
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the verified and decoded bearer token provided as a credential.
 * The verify callback is responsible for finding the user who posesses the
 * token, and invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `realm`    authentication realm, defaults to 'Users'
 *   - `scope`    list of scope values indicating the required scope of the
 *                access token for accessing the requested resource
 *   - `audience` if you want to check JWT audience (aud), provide a value here
 *   - `issuer`   if you want to check JWT issuer (iss), provide a value here
 *
 * Examples:
 *
 *     passport.use(new OIDCBearerStrategy(
 *       secretOrPublicKey
 *       function(token, done) {
 *         User.findById(token.sub, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, token);
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 * For further details on JSON Web Token, refert to [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
 *
 * @param {object} options - The Options.
 * @param {Function} verify - The verify callback.
 * @constructor
 */

function Strategy(options, verifyFn) {
  const self = this;
  const log = new Log('AzureAD: Bearer Strategy');
  const verify = (typeof options === 'function') ? options : verifyFn;
  const opts = (typeof options === 'function') ? {} : options;

  // Passport requires a verify function
  if (typeof verify !== 'function') {
    throw new TypeError('BearerStrategy requires a verify callback.');
  }

  // if logging level specified, switch to it.
  if (opts.loggingLevel) { log.levels('console', opts.loggingLevel); }

  if (opts.policyName) {
    log.info('B2C: We have been instructed that this is a B2C tenant. We will configure as required.');

    if (!options.tenantName) {
      throw new TypeError('BearerStrategy requires you pass the tenant name if using a B2C tenant.');
    } else {
      // We are replacing the common endpoint with the concrete metadata of a B2C tenant.
      opts.identityMetadata = opts.identityMetadata
        .replace('common', opts.tenantName)
        .concat(`?p=${opts.policyName}`);
    }
  }

  // warn about validating the issuer
  if (!opts.validateIssuer) {
    log.warn(`We are not validating the issuer.
      This is fine if you are expecting multiple organizations to connect to your app.
      Otherwise you should validate the issuer.`);
  }

  // if you want to check JWT audience (aud), provide a value here
  if (opts.audience) {
    log.info('Audience provided to Strategy was: ', opts.audience);
  }

  if (opts.identityMetadata) {
    log.info('Metadata url provided to Strategy was: ', opts.identityMetadata);
    this.metadata = new Metadata(opts.identityMetadata, 'oidc', opts);
  }

  if (!opts.certificate && !opts.identityMetadata) {
    log.warn('No options was presented to Strategy as required.');
    throw new TypeError(`OIDCBearerStrategy requires either a PEM encoded public key
      or a metadata location that contains cert data for RSA and ECDSA callback.`);
  }

  // Token validation settings. Hopefully most of these will be pulled from the metadata and this is not needed
  // @TODO: this won't work - fetch is async, throwing in an async callback is not recommended because that exception can not be located.
  // Also, this fetch would load parameters required by `BearerStrategy`. It is recommended to write own `authenticate` method for this Strategy
  self.metadata.fetch((fetchMetadataError) => {
    if (fetchMetadataError) {
      throw new Error(`Unable to fetch metadata: ${fetchMetadataError}`);
    }

    if (opts.validateIssuer) {
      opts.issuer = self.metadata.oidc.issuer;
    }
    opts.algorithms = self.metadata.oidc.algorithms;
  });

  function jwtVerify(req, token, done) {
    const decoded = jws.decode(token);
    let PEMkey = null;

    if (decoded == null) {
      done(null, false, 'Invalid JWT token.');
    }

    log.info('token decoded:  ', decoded);

    // We have two different types of token signatures we have to validate here. One provides x5t and the other a kid.
    // We need to call the right one.

    if (decoded.header.x5t) {
      PEMkey = this.metadata.generateOidcPEM(decoded.header.x5t);
    } else if (decoded.header.kid) {
      PEMkey = this.metadata.generateOidcPEM(decoded.header.kid);
    } else {
      throw new TypeError('We did not receive a token we know how to validate');
    }

    jwt.verify(token, PEMkey, options, (err, verifiedToken) => {
      if (err) {
        if (err instanceof jwt.TokenExpiredError) {
          log.warn('Access token expired');
          return done(null, false, 'The access token expired');
        }
        if (err instanceof jwt.JsonWebTokenError) {
          log.warn('An error was received validating the token', err.message);
          return done(null, false, util.format('Invalid token (%s)', err.message));
        }
        return done(err, false);
      }
      log.info(verifiedToken, 'was token going out of verification');
      if (opts.passReqToCallback) {
        log.info('We did pass Req back to Callback');
        return verify(req, verifiedToken, done);
      }
      log.info('We did not pass Req back to Callback');
      return verify(verifiedToken, done);
    });
  }

  // force passReqToCallback to be `true` for our decoding verify wrapper
  /* eslint-disable no-underscore-dangle */
  BearerStrategy.call(this, util._extend({}, opts, { passReqToCallback: true }), jwtVerify);
  /* eslint-enable no-underscore-dangle */

  this.name = 'oauth-bearer'; // Me, a name I call myself.
}

util.inherits(Strategy, BearerStrategy);

module.exports = Strategy;
