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
const CONSTANTS = require('./constants');
const jwt = require('./jsonWebToken');
const Metadata = require('./metadata').Metadata;
const Log = require('./logging').getLogger;
const UrlValidator = require('valid-url');

const log = new Log('AzureAD: Bearer Strategy');
const memoryCache = cacheManager.caching({ store: 'memory', max: 3600, ttl: 1800 /* seconds */ });
const ttl = 1800; // 30 minutes cache

const B2C_PREFIX = 'b2c_1_';

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
 *   - `identityMetadata`   (1) Required
 *                          (2) must be a https url string
 *                          (3) Description:
 *                          the metadata endpoint provided by the Microsoft Identity Portal that provides 
 *                          the keys and other important info at runtime. Examples:
 *                          <1> v1 tenant-specific endpoint
 *                          - https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/.well-known/openid-configuration
 *                          - https://login.microsoftonline.com/your_tenant_guid/.well-known/openid-configuration
 *                          <2> v1 common endpoint
 *                          - https://login.microsoftonline.com/common/.well-known/openid-configuration
 *                          <3> v2 tenant-specific endpoint
 *                          - https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/v2.0/.well-known/openid-configuration
 *                          - https://login.microsoftonline.com/your_tenant_guid/v2.0/.well-known/openid-configuration
 *                          <4> v2 common endpoint
 *                          - https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
 *                         
 *                          Note: you cannot use common endpoint for B2C
 *
 *   - `clientID`           (1) Required
 *                          (2) must be a string
 *                          (3) Description:
 *                          The Client ID of your app in AAD
 *
 *   - `validateIssuer`     (1) Required to set to false if you don't want to validate issuer, default value is true
 *                          (2) Description:
 *                          For common endpoint, you should either set `validateIssuer` to false, or provide the `issuer`, since
 *                          we cannot grab the `issuer` value from metadata.
 *                          For non-common endpoint, we use the `issuer` from metadata, and `validateIssuer` should be always true
 *
 *   - `issuer`             (1) Required if you are using common endpoint and set `validateIssuer` to true, or if you want to specify the allowed issuers
 *                          (2) must be a string or an array of strings
 *                          (3) Description:
 *                          For common endpoint, we use the `issuer` provided.
 *                          For non-common endpoint, if the `issuer` is not provided, we use the issuer provided by metadata
 *
 *   - `passReqToCallback`  (1) Required to set true if you want to use the `function(req, token, done)` signature for the verify function, default is false
 *                          (2) Description:
 *                          Set `passReqToCallback` to true use the `function(req, token, done)` signature for the verify function
 *                          Set `passReqToCallback` to false use the `function(token, done)` signature for the verify function 
 *
 *   - `isB2C`              (1) Required to set to true for using B2C, default value is false
 *                          
 *   - `policyName`         (1) Required for using B2C
 *                          (2) Description:
 *                          policy name. Should be a string starting with 'B2C_1_' (case insensitive)
 *
 *
 *   - `allowMultiAudiencesInToken`
 *                          (1) Required if you allow access_token whose `aud` claim contains multiple values
 *                          (2) Description:
 *                          The default value is false 
 *
 *   - `scope`              (1) Optional
 *                          (2) Array of accepted scopes.
 *                          (3) Description:  
 *                          If `scope` is provided, we will validate if access token contains any of the scopes listed in `scope`. 
 *
 *   - `loggingLevel`       (1) Optional
 *                          (2) must be 'info', 'warn', 'error'
 *                          (3) Description:  
 *                          logging level 
 *
 *   - `audience`           (1) Optional
 *                          (2) must be a string or an array of strings
 *                          (3) Description:
 *                          We invalidate the `aud` claim in access_token against `audience`. The default value is `clientID` 
 *
 *   - `clockSkew`          (1) Optional
 *                          (2) must be a positive integer
 *                          (3) Description:
 *                          the clock skew (in seconds) allowed in token validation, default value is CLOCK_SKEW
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

  if (!options)
    throw new Error('In BearerStrategy constructor: options is required');
  if (!verifyFn || typeof verifyFn !== 'function')
    throw new Error('In BearerStrategy constructor: verifyFn is required and it must be a function');

  this._verify = verifyFn;
  this._options = options;

  //---------------------------------------------------------------------------
  // Set up the default values
  //---------------------------------------------------------------------------

  // clock skew. Must be a postive integer
  if (options.clockSkew && (typeof options.clockSkew !== 'number' || options.clockSkew <= 0 || options.clockSkew % 1 !== 0))
    throw new Error('clockSkew must be a positive integer');
  if (!options.clockSkew)
    options.clockSkew = CONSTANTS.CLOCK_SKEW;

  // default value of passReqToCallback is false
  if (options.passReqToCallback !== true)
    options.passReqToCallback = false;

  // default value of validateIssuer is true 
  if (options.validateIssuer !== false) 
    options.validateIssuer = true;

  // default value of allowMultiAudiencesInToken is false
  if (options.allowMultiAudiencesInToken !== true)
    options.allowMultiAudiencesInToken = false;

  // if options.audience is a string or an array of string, then we use it;
  // otherwise we use the clientID
  if (options.audience && typeof options.audience === 'string')
    options.audience = [options.audience];
  else if (!options.audience || !Array.isArray(options.audience) || options.length === 0)
    options.audience = [options.clientID, 'spn:' + options.clientID];

  // default value of isB2C is false
  if (options.isB2C !== true)
    options.isB2C = false;

  // turn issuer into an array
  if (options.issuer === '')
    options.issuer = null;
  if (options.issuer && Array.isArray(options.issuer) && options.issuer.length === 0)
    options.issuer = null; 
  if (options.issuer && !Array.isArray(options.issuer))
    options.issuer = [options.issuer];

  //---------------------------------------------------------------------------
  // validate the things in options
  //---------------------------------------------------------------------------

  // clientID should not be empty
  if (!options.clientID || options.clientID === '')
    throw new Error('In BearerStrategy constructor: clientID cannot be empty');

  // identityMetadata must be https url
  if (!options.identityMetadata || !UrlValidator.isHttpsUri(options.identityMetadata))
    throw new Error('In BearerStrategy constructor: identityMetadata must be provided and must be a https url');

  // if scope is provided, it must be an array
  if (options.scope && (!Array.isArray(options.scope) || options.scope.length === 0))
    throw new Error('In BearerStrategy constructor: scope must be a non-empty array');

  //---------------------------------------------------------------------------
  // treatment of common endpoint and issuer
  //---------------------------------------------------------------------------

  // check if we are using the common endpoint
  options._isCommonEndpoint = (options.identityMetadata.indexOf('/common/') != -1);

  // issuer validation for common endpoint is not supported
  if (options._isCommonEndpoint && options.validateIssuer && !options.issuer)
    throw new Error(`In BearerStrategy constructor: you are using common endpoint, please either set 'validateIssuer' to false, or provide 'issuer' value in options`);

  // give a warning if user is not validating issuer
  if (!options.validateIssuer)
    log.warn(`Production environments should always validate the issuer.`);

  //---------------------------------------------------------------------------
  // B2C. 
  // (1) policy must be provided and must have the valid prefix
  // (2) common endpoint is not supported
  //---------------------------------------------------------------------------

  // for B2C, 
  if (options.isB2C) {
    if (!options.policyName || !options.policyName.toLowerCase().startsWith(B2C_PREFIX))
      throw new Error('In BearerStrategy constructor: invalid policy for B2C');
    if (options._isCommonEndpoint)
      throw new Error(`In BearerStrategy constructor: common endpoint is not supported for B2C, please replace 'common' with your tenant name or tenant guid in 'identityMetadata'`);
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  log.info(`In BearerStrategy constructor: created strategy with options ${JSON.stringify(options)}`);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.jwtVerify = function jwtVerifyFunc(req, token, metadata, optionsToValidate, done) {
  const self = this;

  const decoded = jws.decode(token);
  let PEMkey = null;

  if (decoded == null) {
    return done(null, false, 'In Strategy.prototype.jwtVerify: Invalid JWT token.');
  }

  log.info('In Strategy.prototype.jwtVerify: token decoded:  ', decoded);

  // When we generate the PEMkey, there are two different types of token signatures
  // we have to validate here. One provides x5t and the other a kid. We need to call 
  // the right one.
  try {
    if (decoded.header.x5t) {
      PEMkey = metadata.generateOidcPEM(decoded.header.x5t);
    } else if (decoded.header.kid) {
      PEMkey = metadata.generateOidcPEM(decoded.header.kid);
    } else {
      return self.failWithLog('In Strategy.prototype.jwtVerify: We did not receive a token we know how to validate');
    }
  } catch (error) {
      return self.failWithLog('In Strategy.prototype.jwtVerify: We did not receive a token we know how to validate');
  }

  log.info('PEMkey generated: ' + PEMkey);

  jwt.verify(token, PEMkey, optionsToValidate, (err, verifiedToken) => {
    if (err) {
      if (err.message)
        return self.failWithLog(err.message);
      else
        return self.failWithLog('In Strategy.prototype.jwtVerify: cannot verify token');
    }

    // scope validation
    if (optionsToValidate.scope) {
      if (!verifiedToken.scp)
        return self.failWithLog('In Strategy.prototype.jwtVerify: scope is not found in token');

      // split scope by blanks and remove empty elements in the array
      var scopesInToken = verifiedToken.scp.split(/[ ]+/).filter(Boolean);
      var hasValidScopeInToken = false;
      for (var i = 0; i < scopesInToken.length; i++) {
        if (optionsToValidate.scope.indexOf(scopesInToken[i]) !== -1) {
          hasValidScopeInToken = true;
          break;
        }
      }
      
      if (!hasValidScopeInToken)
        return self.failWithLog(`In Strategy.prototype.jwtVerify: none of the scopes '${verifiedToken.scp}' in token is accepted`);
    }

    log.info('In Strategy.prototype.jwtVerify: VerifiedToken: ', verifiedToken);
    
    if (self._options.passReqToCallback) {
      log.info('In Strategy.prototype.jwtVerify: We did pass Req back to Callback');
      return self._verify(req, verifiedToken, done);
    } else {
      log.info('In Strategy.prototype.jwtVerify: We did not pass Req back to Callback');
      return self._verify(verifiedToken, done);
    }
  });
};

/*
 * We let the metadata loading happen in `authenticate` function, and use waterfall
 * to make sure the authentication code runs after the metadata loading is finished.
 */
Strategy.prototype.authenticate = function authenticateStrategy(req) {
  const self = this;
  var params = {};
  var optionsToValidate = {};

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

    // compute metadataUrl
    (next) => {
      params.metadataURL = self._options.identityMetadata
            .concat(`?${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
            .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`); ;

      if (self._options.isB2C)
        params.metadataURL = params.metadataURL.concat(`&p=${self._options.policyName}`)

      params.cacheKey = params.metadataURL;

      log.info(`In Strategy.prototype.authenticate: ${JSON.stringify(params)}`);

      return next(null, params);
    },
    
    // load metatadata
    (params, next) => {
      return self.loadMetadata(params, next);
    },

    // configure using metadata
    (metadata, next) => {
      params.metadata = metadata;
      log.info(`In Strategy.prototype.authenticate: received metadata: ${JSON.stringify(metadata)}`);

      // set up issuer
      if (self._options.validateIssuer && !self._options.issuer)
        optionsToValidate.issuer = metadata.oidc.issuer;
      else
        optionsToValidate.issuer = self._options.issuer;

      // set up algorithm
      optionsToValidate.algorithms = metadata.oidc.algorithms;

      // set up audience, validateIssuer, allowMultiAudiencesInToken
      optionsToValidate.audience = self._options.audience;
      optionsToValidate.validateIssuer = self._options.validateIssuer;
      optionsToValidate.allowMultiAudiencesInToken = self._options.allowMultiAudiencesInToken;
      optionsToValidate.ignoreExpiration = self._options.ignoreExpiration;

      // clock skew
      optionsToValidate.clockSkew = self._options.clockSkew;

      // set up scope
      if (self._options.scope)
        optionsToValidate.scope = self._options.scope;

      log.info(`In Strategy.prototype.authenticate: we will validate the following options: ${optionsToValidate}`);

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

      // token could be in header or body. query is not supported.

      if (req.query && req.query.access_token)
        return self.failWithLog('In Strategy.prototype.authenticate: access_token should be passed in request header or body. query is unsupported');

      if (req.headers && req.headers.authorization) {
        var auth_components = req.headers.authorization.split(' ');
        if (auth_components.length == 2 &&auth_components[0].toLowerCase() === 'bearer') {
            token = auth_components[1];
            if (token !== '')
              log.info('In Strategy.prototype.authenticate: received access_token from request header: ${token}');
            else
              self.failWithLog('In Strategy.prototype.authenticate: missing access_token in the header');
        }
      }

      if (req.body && req.body.access_token) {
        if (token)
          return self.failWithLog('In Strategy.prototype.authenticate: access_token cannot be passed in both request header and body');
        token = req.body.access_token;
        if (token)
          log.info(`In Strategy.prototype.authenticate: received access_token from request body: ${token}`);
      }

      if (!token)
        return self.failWithLog('token is not found'); 

      function verified(err, user, info) {
        if (err)
          return self.error(err);

        if (!user) {
          var err_message = 'error: invalid_token';
          if (info && typeof info == 'string')
            err_message += ', error description: ' + info;
          else if (info)
            err_message += ', error description: ' + JSON.stringify(info);
          return self.failWithLog(err_message);
        }

        return self.success(user, info);
      }

      return self.jwtVerify(req, token, params.metadata, optionsToValidate, verified);
    }],

    (waterfallError) => { // This function gets called after the three tasks have called their 'task callbacks'
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
    }
  );
};

Strategy.prototype.loadMetadata = function(params, next) {
  const self = this;
  var metadata = new Metadata(params.metadataURL, 'oidc', self._options);

  // fetch metadata
  return memoryCache.wrap(params.cacheKey, (cacheCallback) => {
    metadata.fetch((fetchMetadataError) => {
      if (fetchMetadataError) {
        return self.failWithLog('In loadMetadata: Unable to fetch metadata');
      }
      return cacheCallback(null, metadata);
    }); 
  }, { ttl }, next);
};

/**
 * fail and log the given message
 *
 * @params {String} message
 */
Strategy.prototype.failWithLog = function(message) {
  log.info(`authentication failed due to: ${message}`);
  return this.fail(message);
};

module.exports = Strategy;
