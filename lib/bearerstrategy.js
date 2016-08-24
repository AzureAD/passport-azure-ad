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

/* eslint no-underscore-dangle: 0 */

const async = require('async');
const cacheManager = require('cache-manager');
const jws = require('jws');
const passport = require('passport');
const util = require('util');

const aadutils = require('./aadutils');
const jwt = require('./jsonWebToken');
const Metadata = require('./metadata').Metadata;
const Log = require('./logging').getLogger;

const log = new Log('AzureAD: Bearer Strategy');
const memoryCache = cacheManager.caching({ store: 'memory', max: 3600, ttl: 1800 /* seconds */ });
const ttl = 1800; // 30 minutes cache

/**
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 * or
 *     function(req, token, done) { ... }
 *
 * The latter enables you to use the request object. In order to use this
 * signature, the passReqToCallback value in options (see the Options instructions
 * below) must be set true, so the strategy knows you want to pass the request
 * to the `verify` callback function.
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
 *
 * Options:
 *
 *   - `realm`    authentication realm, defaults to 'Users'
 *   - `scope`    list of scope values indicating the required scope of the
 *                access token for accessing the requested resource
 *   - `audience` if you want to check JWT audience (aud), provide a value here
 *   - `issuer`   if you want to check JWT issuer (iss), provide a value here
 *   - `loggingLevel`
 *                'info', 'warn' or 'error'. Error always goes to stderr in Unix
 *   - `validateIssuer`
 *                'true' or 'false'. Strategy cannot handle uses from multiple 
 *                tenants if set to 'true'
 *   - `passReqToCallback`
 *                'true' or 'false'. Must set to 'true' if you want to pass the
 *                'req' object to your verify callback
 *   - `clientID` your client id in AAD
 *   - `identityMetadata`
 *                If you have users from multiple tenants (in the case of B2C), use
 *                'https://login.microsoftonline.com/common/.well-known/openid-configuration'
 *                Otherwise, replace 'common' with your tenant name (something 
 *                like *.onmicrosoft.com) or your tenant id
 *   - `policyName`
 *                Policy name (B2C only)
 *   - `tenantName`
 *                Tenant name (B2C only, specify the tenant from multiple tenants)
 *
 *
 * Examples:
 *
 *     passport.use(new BearerStrategy(
 *       options,
 *       function(token, done) {
 *         User.findById(token.sub, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, token);
 *         });
 *       }
 *     ));
 *
 * The name of this strategy is 'oauth-bearer', so use this name as the first 
 * parameter of the authenticate function. Moreover, we don't need session 
 * support for request containing bearer tokens, so the session option can be
 * set to false.
 * 
 *     app.get('/protected_resource', 
 *       passport.authenticate('oauth-bearer', {session: false}), 
 *       function(req, res) { 
 *         ... 
 *       });
 *
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens]
 * (http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 * For further details on JSON Web Token, refert to [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
 *
 * @param {object} options - The Options.
 * @param {Function} verify - The verify callback.
 * @constructor
 */
function Strategy(options, verifyFn) {
  passport.Strategy.call(this);
  this.name = 'oauth-bearer'; // Me, a name I call myself.

  this._verify = (typeof options === 'function') ? options : verifyFn;
  this._options = (typeof options === 'function') ? {} : options;

  // (1) check the existence of the verify function, and set passReqToCallback
  if (typeof this._verify !== 'function') {
    throw new TypeError('BearerStrategy requires a verify callback.');
  }
  if (this._options.passReqToCallback === undefined || this._options.passReqToCallback === null) {
    log.warn(`passReqToCallback is not set, settting it to true by default`);
    this._passReqToCallback = true;
  } else {
    this._passReqToCallback = this._options.passReqToCallback;
  }

  // (2) modify some fields of this._options
  if (!this._options.realm)
    this._options.realm = 'Users';
  if (!Array.isArray(this._options.scope))
    this._options.scope = [this._options.scope];

  // (3) log some info of this._options

  options = this._options;

  if (options.clientID === undefined || options.clientID === null || options.clientID === '')
    throw new Error('options.clientID cannot be null or empty.');

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  // check if we are using the common endpoint
  options._isCommonEndpoint = (options.identityMetadata && options.identityMetadata.indexOf('/common/') != -1);

  // the default value of validateIssuer is true 
  if (options.validateIssuer === undefined || options.validateIssuer === null) 
    options.validateIssuer = true;

  // issuer validation for common endpoint is not supported
  if (options._isCommonEndpoint && options.validateIssuer) {
    throw new Error(`Configuration error. Please either replace 'common' in identity metadata url with your tenant guid (something like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), or set 'validateIssuer' false. Issuer validation is not supported for common endpoint.`);
  }

  // give a warning if user is not validating issuer for non-common endpoint
  if (!options._isCommonEndpoint && !options.validateIssuer) {
    log.warn(`Production environments should always validate the issuer.`);
  }

  // if you want to check JWT audience (aud), provide a value here
  if (options.audience) {
    log.info('Audience provided to Strategy was: ', options.audience);
  } else {
    options.audience = options.clientID;
  }
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.jwtVerify = function jwtVerifyFunc(req, token, done) {
  const self = this;

  const decoded = jws.decode(token);
  let PEMkey = null;

  if (decoded == null) {
    return done(null, false, 'Invalid JWT token.');
  }

  log.info('token decoded:  ', decoded);

  // use the provided PEMkey or generate one using the metadata. WEhen we
  // generate the PEMkey, there are two different types of token signatures
  // we have to validate here. One provides x5t and the other a kid. We 
  // need to call the right one.
  if (self._options.certificate) {
    PEMkey = self._options.certificate;
  } else if (decoded.header.x5t) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.x5t);
  } else if (decoded.header.kid) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.kid);
  } else {
    return done(null, false, 'We did not reveive a token we know how to validate');
  }

  jwt.verify(token, PEMkey, self._options, (err, verifiedToken) => {
    if (err) {
      if (err.message)
        return self.fail(err.message);
      else
        return self.fail('cannot verify id token');
    }
    log.info('VerifiedToken: ', verifiedToken);
    if (self._passReqToCallback) {
      log.info('We did pass Req back to Callback');
      return self._verify(req, verifiedToken, done);
    }
    log.info('We did not pass Req back to Callback');
    return self._verify(verifiedToken, done);
  });
}

/*
 * We let the metadata loading happen in `authenticate` function, and use waterfall
 * to make sure the authentication code runs after the metadata loading is finished.
 */
Strategy.prototype.authenticate = function authenticateStrategy(req) {
  const self = this;

  /* Some introduction to async.waterfall (from the following link):
   * http://stackoverflow.com/questions/28908180/what-is-a-simple-implementation-of-async-waterfall
   *
   *   Runs the tasks array of functions in series, each passing their results 
   * to the next in the array. However, if any of the tasks pass an error to 
   * their own callback, the next function is not executed, and the main callback
   * is immediately called with the error.
   *
   * Example:
   *
   * async.waterfall([
   *   function(callback) {
   *     callback(null, 'one', 'two');
   *   },
   *   function(arg1, arg2, callback) {
   *     // arg1 now equals 'one' and arg2 now equals 'two'
   *     callback(null, 'three');
   *   },
   *   function(arg1, callback) {
   *     // arg1 now equals 'three'
   *     callback(null, 'done');
   *   }
   * ], function (err, result) {
   *      // result now equals 'done'    
   * }); 
   */
  async.waterfall([

    // compute metadata url
    (next) => {
      if (!self._options.certificate && !self._options.identityMetadata) {
        var message = 'options.certificate and options.identityMetadata are both null. ' +
            'It is not possible to validate a JWT token, BearerStrategy requires either ' +
            'a PEM encoded public key or a metadata location that contains cert data ' +
            ' for RSA and ECDSA callback';
        log.warn(message);
        return next(new TypeError(message));
      }

      // (1) no metadata but have a certificate, pass `null` to the next function, 
      // which will skip the metadata loading
      if (!self._options.identityMetadata)
        return next(null, null);

      // (2) there is only metadata, we calulate the metadataURL and pass it to the
      // next function for metadata loading

      // default key for metadata cache
      var cacheKey = 'ordinary';

      var metadataURL = self._options.identityMetadata;

      if (self._options.policyName) {
        log.info('B2C: using policy %s', self._options.policyName);
        
        if (!self._options.tenantName) {
          return next(new TypeError('B2C: BearerStrategy requires you to pass the tenant name if using a B2C tenant.'));
        }

        // We are replacing the common endpoint with the concrete metadata of a B2C tenant.
        metadataURL = metadataURL
            .replace('common', self._options.tenantName)
            .concat(`?p=${self._options.policyName}`)
            .concat(`&${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
            .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);

        // use the policy name as the metadata cache key
        cacheKey = 'policy: ' + policyName;
      } else {
        metadataURL = metadataURL.concat(`?${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
        .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);
      }

      log.info('Metadata url provided to Strategy was: ', metadataURL);
      self.metadata = new Metadata(metadataURL, 'oidc', self._options);

      return next(null, cacheKey);
    },

    // fetch metadata from server or cache (if there is)
    (cacheKey, next) => {

      // if cacheKey is null, then we skip metadata loading
      if (!cacheKey)
        return next(null, null);

      // usage of memoryCache.wrap(key, work, opt, cb):
      // (1) anytime there is an error, it calls cb(err, null)
      // (2) if result is found using the key, then it will call cb(null, result)
      // (3) if result is not found, it will call work. work is like:
      //    work(cacheCallback) {
      //      generate result;
      //      cacheCallback(err, result);
      //    }
      //    `cacheCallback` is provided by memoryCache, which is like:
      //    cacheCallback(err, result) {
      //      if no err, save result into memory cache;
      //      cb(err, result);  
      //    }
      //
      // So the following function will return `next(err, self.metadata)`
      return memoryCache.wrap(cacheKey, (cacheCallback) => {
        self.metadata.fetch((fetchMetadataError) => {
          if (fetchMetadataError) {
            return cacheCallback(new Error(`Unable to fetch metadata: ${fetchMetadataError}`));
          }
          return cacheCallback(null, self.metadata);
        }); 
      }, { ttl }, next);
    },

    // configure using metadata
    (metadata, next) => {
      if (metadata) {
          self.metadata = metadata;
          if (self._options.validateIssuer) {
            self._options.issuer = self.metadata.oidc.issuer;
          }
          self._options.algorithms = self.metadata.oidc.algorithms;
      }

      return next();
    },

    // extract the access token from the request, after getting the token, it 
    // will call `jwtVerify` to verify the token. If token is verified, `jwtVerify`
    // will provide the token payload to self._verify function. self._verify is
    // provided by the developer, it's up to the developer to decide if the token
    // payload is considered authenticated. If authenticated, self._verify will
    // provide `user` object (developer's decision of its content) to `verified` 
    // function here, and the `verified` function does the final work of stuffing
    // the `user` obejct into req.user, so the following middleware can use it.
    // This is basically how bearerStrategy works.
    (next) => {
      var token;

      // token could be in header, query or body

      if (req.headers && req.headers.authorization) {
        var auth_components = req.headers.authorization.split(' ');
        if (auth_components.length == 2) {
          if (/^Bearer$/.test(auth_components[0]))
            token = auth_components[1];
        } else {
          return self.fail(400);
        }
      }

      if (req.query && req.query.access_token) {
        if (token)
          return self.fail(400);
        token = req.query.access_token;
      }

      if (req.body && req.body.access_token) {
        if (token)
          return self.fail(400);
        token = req.body.access_token;
      }

      if (!token)
        return self.fail('token is not found'); 

      function verified(err, user, info) {
        if (err)
          return self.error(err);

        if (!user) {
          var err_message = 'error: invalid_token';
          if (info && typeof info == 'string')
            err_message += ', error description: ' + info;
          else if (info)
            err_message += ', error description: ' + JSON.stringify(info);
          return self.fail(err_message);
        }

        return self.success(user, info);
      }

      return self.jwtVerify(req, token, verified);
    }],

    (waterfallError) => { // This function gets called after the three tasks have called their 'task callbacks'
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
    }
  );
};

module.exports = Strategy;
