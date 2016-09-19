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

// third party packages
const async = require('async');
const base64url = require('base64url');
const cacheManager = require('cache-manager');
const _ = require('lodash');
const jws = require('jws');
const objectTransform = require('oniyi-object-transform');
const passport = require('passport');
const querystring = require('querystring');
const url = require('url');
const util = require('util');

// packages from this library
const aadutils = require('./aadutils');
const jwt = require('./jsonWebToken');

// For the following packages we get a constructor and we will use 'new' to create an instance
const InternalOAuthError = require('./errors/internaloautherror');
const InternalOpenIDError = require('./errors/internalopeniderror');
const Log = require('./logging').getLogger;
const Metadata = require('./metadata').Metadata;
const OAuth2 = require('oauth').OAuth2;
const SessionContentHandler = require('./sessionContentHandler').SessionContentHandler;
const UrlValidator = require('valid-url');
const Validator = require('./validator').Validator;

// global variable definitions
const log = new Log('AzureAD: OIDC Passport Strategy');

const memoryCache = cacheManager.caching({ store: 'memory', max: 3600, ttl: 1800 /* seconds */ });
const ttl = 1800; // 30 minutes cache
// Note: callback is optional in set() and del().

function makeProfileObject(src, raw) {
  return {
    // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
    // 'sub' key was named 'user_id'.  Many providers still use the old
    // key, so fallback to that.
    id: src.sub || src.oid || src.user_id,
    displayName: src.name,
    name: {
      familyName: src.family_name,
      givenName: src.given_name,
      middleName: src.middle_name,
    },
    email: src.upn || src.preferred_username || src.oid,
    _raw: raw,
    _json: src,
  };
}

function onProfileLoaded(strategy, args) {
  function verified(err, user, info) {
    if (err) {
      return strategy.error(err);
    }
    if (!user) {
      return strategy.fail(info);
    }
    return strategy.success(user, info);
  }

  const verifyArityArgsMap = {
    8: 'iss sub profile jwtClaims access_token refresh_token params',
    7: 'iss sub profile access_token refresh_token params',
    6: 'iss sub profile access_token refresh_token',
    4: 'iss sub profile',
    3: 'iss sub',
  };

  const arity = (strategy._passReqToCallback) ? strategy._verify.length - 1 : strategy._verify.length;
  let verifyArgs = [args.profile, verified];

  if (verifyArityArgsMap[arity]) {
    verifyArgs = verifyArityArgsMap[arity]
      .split(' ')
      .map((argName) => {
        return args[argName];
      })
      .concat([verified]);
  }

  if (strategy._passReqToCallback) {
    verifyArgs.unshift(args.req);
  }

  return strategy._verify.apply(strategy, verifyArgs);
}

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
 *   - `scope`              list of scope values indicating the required scope of the
 *                          access token for accessing the requested resource. Ex: ['email', 'profile']. 
 *                          We send 'openid' by default and will reject you if you send it a second time.
 *   - `audience`           we check JWT audience (aud), provide a value here
 *   - `clientID`           the application ID of your app in Microsoft Identity platform
 *   - `identityMetadata`   the metadata endpoint provided by the Microsoft Identity Portal that provides 
 *                          the keys and other important info at runtime. We roll keys frequently, so don't
 *                          override this to supply your own.
 *   - `responseType`       for login only flows use id_token. For accessing resources use `id_token code`
 *   - `responseMode`       For login only flows we should have token passed back to us in a POST
 *   - `validateIssuer`     if you have validation on, you cannot have users from multiple tenants sign in
 *   - `passReqToCallback`  if you want the Req to go back to the calling function for other processing use this.
 *   - `sessionContentMaxAmount`     
 *                          the max amount of state/nonce/policy/timeStamp tuples you want to save in session, default is 10
 *   - `sessionContentMaxAge`        
 *                          the lifetime of state/nonce/policy/timeStamp tuples in session, default is 3600s = 60 minutes
 * Examples:
 *
 * passport.use(new OIDCStrategy({
 *   callbackURL: config.creds.returnURL,
 *   scope: config.creds.scopes,
 *   clientID: config.creds.clientID,
 *   identityMetadata: config.creds.identityMetadata,
 *   responseType: config.creds.responseType,
 *   responseMode: config.creds.responseMode,
 *   validateIssuer: config.creds.validateIssuer,
 *   passReqToCallback: config.creds.passReqToCallback,
 *   loggingLevel: config.creds.loggingLevel,
 *   sessionContentMaxAmount: config.creds.sessionContentMaxAmount,
 *   sessionContentMaxAge: config.creds.sessionContentMaxAge,
 * },
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
function Strategy(options, verify) {
  passport.Strategy.call(this);

  /*
   *  Caution when you want to change these values in the member functions of
   *  Strategy, don't use `this`, since `this` points to a subclass of `Strategy`.
   *  To get `Strategy`, use Object.getPrototypeOf(this).
   *  
   *  More comments at the beginning of `Strategy.prototype.authenticate`. 
   */
  this._options = options;
  this.name = 'azuread-openidconnect';
  this._verify = verify;
  this._passReqToCallback = !!options.passReqToCallback;

  this._sessionContentHandler = new SessionContentHandler(options.sessionContentMaxAmount || 10, options.sessionContentMaxAge || 3600);

  /* When a user is authenticated for the first time, passport adds a new field
   * to req.session called 'passport', and puts a 'user' property inside (or your
   * choice of field name and property name if you change passport._key and 
   * passport._userProperty values). req.session['passport']['user'] is usually 
   * user_id (or something similar) of the authenticated user to reduce the size
   * of session. When the user logs out, req.session['passport']['user'] will be
   * destroyed. Any request between login (when authenticated for the first time)
   * and logout will have the 'user_id' in req.session['passport']['user'], so
   * passport can fetch it, find the user object in database and put the user
   * object into a new field: req.user. Then the subsequent middlewares and the 
   * app can use the user object. This is how passport keeps user authenticated. 
   *
   * For state validation, we also take advantage of req.session. we create a new
   * field: req.session[sessionKey], where the sessionKey is our choice (in fact, 
   * this._key, see below). When we send a request with state, we put state into
   * req.session[sessionKey].state; when we expect a request with state in query
   * or body, we compare the state in query/body with the one stored in 
   * req.session[sessionKey].state, and then destroy req.session[sessionKey].state.
   * User can provide a state by using `authenticate(Strategy, {state: 'xxx'})`, or
   * one will be generated automatically. This is essentially how passport-oauth2
   * library does the state validation, and we use the same way in our library. 
   *
   * request structure will look like the following. In real request some fields
   * might not be there depending on the purpose of the request.
   *
   *    request ---|--- sessionID
   *               |--- session --- |--- ...
   *               |                |--- 'passport' ---| --- 'user': 'user_id etc'
   *               |                |---  sessionKey---| --- state: 'xxx'            
   *               |--- ...
   *               |--- 'user':  full user info
   */
  this._key = options.sessionKey || ('OIDC: ' + options.callbackURL);

  if (!options.identityMetadata) {
    // default value should be https://login.microsoftonline.com/common/.well-known/openid-configuration
    log.error('OIDCStrategy requires a metadata location that contains cert data for RSA and ECDSA callback.');
    throw new TypeError(`OIDCStrategy requires a metadata location that contains cert data for RSA and ECDSA callback.`);
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  // check if we are using the common endpoint
  options._isCommonEndpoint = (options.identityMetadata && options.identityMetadata.indexOf('/common/') != -1);

  // default: validate Issuer
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

  // validate other necessary option items provided, we validate them here and only once
  var itemsToValidate = objectTransform({
    source: options,
    pick: ['clientID', 'callbackURL', 'responseType', 'responseMode', 'identityMetadata']
  });

  var validatorConfiguration = {
    clientID: Validator.isNonEmpty,
    callbackURL: Validator.isURL,
    responseType: Validator.isTypeLegal,
    responseMode: Validator.isModeLegal,
    identityMetadata: Validator.isHttpsURL
  };
  // validator will throw exception if a required option is missing
  var validator = new Validator(validatorConfiguration);
  validator.validate(itemsToValidate);

  // we allow 'http' for the callbackURL, but don't recommend using 'http'
  if (UrlValidator.isHttpUri(options.callbackURL))
    log.warn(`Using http for callbackURL is not recommended, please consider using https`);

  // check if Azure v2.0 is being used, v2.0 doesn't have a userinfo endpoint
  if (options.identityMetadata.indexOf('/v2.0/') != -1)
    this._options._isV2 = true;
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function authenticateStrategy(req, options) {
  /* 
   * We should be careful using 'this'. Avoid the usage like `this.xxx = ...`
   * unless you know what you are doing.
   *
   * In the passport source code 
   * (https://github.com/jaredhanson/passport/blob/master/lib/middleware/authenticate.js)
   * when it attempts to call the `oidcstrategy.authenticate` function, passport
   * creates an instance inherting oidcstrategy and then calls `instance.authenticate`.  
   * Therefore, when we come here, `this` is the instance, its prototype is the
   * actual oidcstrategy, i.e. the `Strategy`. This means:
   * (1) `this._options = `, `this._verify = `, etc only adds new fields to the
   *      instance, it doesn't change the values in oidcstrategy, i.e. `Strategy`. 
   * (2) `this._options`, `this._verify`, etc returns the field in the instance,
   *     and if there is none, returns the field in oidcstrategy, i.e. `strategy`.
   * (3) each time we call `authenticate`, we will get a brand new instance
   * 
   * If you want to change the values in `Strategy`, use 
   *      const oidcstrategy = Object.getPrototypeOf(self);
   * to get the strategy first.
   *
   * Note: Simply do `const self = Object.getPrototypeOf(this)` and use `self`
   * won't work, since the `this` instance has a couple of functions like
   * success/fail/error... which `authenticate` will call. The following is the
   * structure of `this`:
   *
   *   this
   *   | --  success:  function(user, info)
   *   | --  fail:     function(challenge, status)
   *   | --  redirect: function(url, status)
   *   | --  pass:     function()
   *   | --  __proto__:  Strategy
   *                 | --  _verify
   *                 | --  _options
   *                 | --  ...
   *                 | --  __proto__:
   *                              | --  authenticate:  function(req, options)
   *                              | --  ...
   */ 
  const self = this;

  // Allow for some overrides that may come in to the authenticate strategy.
  //
  //       It's important all options are in self._options before we continue, as we'll be validating these and
  //       loading them through a validator. We should only use the data in configurator() for actual param passing
  //       otherwise we could have injection issues.
  //

  if (options.resourceURL) { self._options.resourceURL = options.resourceURL; }
  if (options.resourceType) { self._options.responseType = options.responseType; }
  if (options.responseMode) { self._options.responseMode = options.responseMode; }

  async.waterfall(
    [
      /* 
       * Step 1. compute metadata url 
       */
      (next) => {
        // B2C interception
        let metadataUrl = self._options.identityMetadata;

        // use 'ordinary' as the default cachekey, in the case of B2C, we will
        // change the value to policy later
        let cachekey = 'ordinary';

        // We listen for the p paramter in any response and set it. If it has been set already and in memory (profile) we skip this as it's not necessary to set again.
        // @TODO when forceB2C is set but no req.query.p is present, the policy variable would be 'undefined'
        if (req.query.p || options.forceB2C) {
          log.info('B2C: Found a policy inside of the login request. This is a B2C tenant!');

          if (!self._options.tenantName) {
            log.error(`For B2C you must specify a tenant name, none was presented to Strategy as required.
              (example: tenantName:contoso.onmicrosoft.com)`);
            return next(new TypeError(`OIDCStrategy requires you specify a tenant name to
              Strategy if using a B2C tenant. (example: tenantName:contoso.onmicrosoft.com')`));
          }

          // @TODO: could be undefined
          const policy = req.query.p;

          metadataUrl = self._options.identityMetadata
            .replace('common', self._options.tenantName)
            .concat(`?p=${policy}`)
            .concat(`&${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
            .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);

          cachekey = 'policy: ' + policy; // this policy will become cache key.

          log.info('B2C: New Metadata url provided to Strategy was: ', metadataUrl);
        }
        else
        {
          metadataUrl = metadataUrl.concat(`?${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
          .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);
        }

        self.metadata = new Metadata(metadataUrl, 'oidc', self._options);

        return next(null, metadataUrl, cachekey);
      },

      /* 
       * Step 2. load options from metadata url
       */
      (metadataUrl, cachekey, next) => {
        return self.setOptions(self._options, metadataUrl, cachekey, next);
      },

      /* 
       * Step 3. the following are the scenarios for the coming request
       * (1) error response
       * (1) implicit flow (response_type = 'id_token')
       *     This case we get a 'id_token'
       * (2) hybrid flow (response_type = 'id_token code')
       *     This case we get both 'id_token' and 'code'
       * (3) authorization code flow (response_type = 'code')
       *     This case we get a 'code', we will use it to get 'access_token' and 'id_token'
       * (5) for any other request, we will ask for authorization and initialize the authorization process 
       */
      (next) => {
        var err, err_description, id_token, code, state;
        err = err_description = id_token = code = state = null;

        // we shouldn't get any access_token or refresh_token from the request
        if ((req.query && (req.query.access_token || req.query.refresh_token)) ||
          (req.body && (req.body.access_token || req.body.refresh_token)))
          return self.fail('neither access token nor refresh token is expected in the incoming request');

        // the source (query or body) to get err, id_token, code etc
        var source = null;

        if (req.query && (req.query.error || req.query.id_token || req.query.code))
          source = req.query;
        else if (req.body && (req.body.error || req.body.id_token || req.body.code))
          source = req.body;

        if (source) {
          err = source.error;
          err_description = source.error_description;
          id_token = source.id_token;
          code = source.code;
          state = source.state;
        }

        if (!err && !id_token && !code) {
          // ask for authorization, initialize the authorization process
          return self._flowInitializationHandler(req, next);
        }

        // find the {state: x, nonce: x, policy: x, timeStamp: x} tuple by state from the session
        if (!state)
          return self.fail('state is missing in the request');
        var tuple = self._sessionContentHandler.findAndDeleteTupleByState(req, self._key, state);
        if (!tuple)
          return self.fail('state provided in the request is not recognized');

        if (err) {
          // handle error response
          return self._errorResponseHandler(err, err_description);
        } else if (id_token && code) {
          // handle hybrid flow
          return self._hybridFlowHandler(id_token, code, tuple, req, next);
        } else if (id_token) {
          // handle implicit flow
          return self._implicitFlowHandler(id_token, tuple, req, next);
        } else {
          // handle authorization code flow
          return self._authCodeFlowHandler(code, tuple, req, next);
        }
      }
    ],

    (waterfallError) => {
      // this code gets called after the three steps above are done
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
    });
};

/**
 * Pick the parameters required for oauth flow
 *
 * @param {options} parameters from metadata and user config file
 */
Strategy.prototype.configOauth = function configOauth(options) {
  this._options._configForOauth = objectTransform({
    source: options,
    pick: [
      'algorithms',
      'authorizationURL',
      'callbackURL',
      'clientID',
      'clientSecret',
      'identifierField',
      'oidcIssuer',
      'passReqToCallback',
      'resourceURL',
      'responseMode',
      'responseType',
      'revocationURL',
      'scope',
      'scopeSeparator',
      'tokenInfoURL',
      'tokenURL',
      'userInfoURL',
    ],
  });
}

/**
 * Load options from metadata to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object} options
 */
Strategy.prototype.setOptions = function setOptions(options, metadataUrl, cachekey, done) {
  const self = this;

  // Loading metadata from endpoint.
  async.waterfall([
    // fetch the metadata
    function loadMetadata(next) {
      log.info('Parsing Metadata: ', metadataUrl);

      memoryCache.wrap(cachekey, (cacheCallback) => {
        self.metadata.fetch((fetchMetadataError) => {
          if (fetchMetadataError) {
            return cacheCallback(new Error(`Unable to fetch metadata: ${fetchMetadataError}`));
          }
          return cacheCallback(null, self.metadata);
        });
      }, { ttl }, next);
    },
    // merge fetched metadata with options
    function loadOptions(metadata, next) {
      self.metadata = metadata;

      // fetched metadata always takes precedence over configured options

      // use default values where no option is present
      const opts = {
        identifierField: 'openid_identifier', // What's the recommended field name for OpenID Connect?
        scopeSeparator: ' ',
        tokenInfoURL: null,
      };

      const pickedFromOptions = objectTransform({
        source: options,
        pick: [
          'callbackURL',
          'clientID',
          'clientSecret',
          'identifierField',
          'passReqToCallback',
          'resourceURL',
          'responseMode',
          'responseType',
          'scope',
          'scopeSeparator',
        ],
      });

      // pick values from fetched metadata
      const pickedFromMetadata = objectTransform({
        source: metadata.oidc,
        map: {
          auth_endpoint: 'authorizationURL',
          end_session_endpoint: 'revocationURL',
          issuer: 'oidcIssuer',
          token_endpoint: 'tokenURL',
          tokeninfo_endpoint: 'tokenInfoURL',
          userinfo_endpoint: 'userInfoURL',
        },
        pick: [
          'algorithms'
        ]
      });

      _.assign(opts, pickedFromOptions, pickedFromMetadata);

      // Now that we have our options for configuration, let's check them for issues.
      const validatorConfig = {
        authorizationURL: Validator.isHttpsURL,
        tokenURL: Validator.isHttpsURL,
        algorithms: Validator.isNonEmpty
      };

      // validator will throw exception if a required option is missing
      const checker = new Validator(validatorConfig);
      checker.validate(opts);

      // set the oidcIssuer
      self._options.oidcIssuer = opts.oidcIssuer;
      self._options.algorithms = opts.algorithms;

      next(null, opts);
    },
    // push merged options to self._configurers for later use
    function setConfiguration(opts, next) {
      log.info('Setting parameters for oauth', opts);

      self.configOauth(opts);

      next();
    },
  ], done);
};

/**
 * validate id_token, and pass the validated claims and the payload to callback
 * if code (resp. access_token) is provided, we will validate the c_hash (resp at_hash) as well
 *
 * @param {String} id_token
 * @param {String} code (if you want to validate c_hash)
 * @param {String} access_token (if you want to validate at_hash)
 * @param {String} nonce
 * @param {Object} req
 * @param {Function} callback
 */
Strategy.prototype._validateResponse = function validateResponse(id_token, code, access_token, nonce, req, callback) {
  const self = this;

  // decode id_token
  const decoded = jws.decode(id_token);
  if (decoded == null)
    return self. fail(null, false, 'Invalid JWT token');

  log.info('token decoded: ', decoded);

  // get Pem Key
  var PEMkey = null;
  if (decoded.header.kid) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.kid);
  } else if (decoded.header.x5t) {
    PEMkey = self.metadata.generateOidcPEM(decoded.header.x5t);
  } else {
    return self.fail('We did not receive a token we know how to validate');
  }

  var options = self._options;

  // if user didn't set audience use clientID by default
  if (!options.audience)
    options.audience = options.clientID;
  // since we are asking token for ourselves, we don't allow multiple audiences in id_token
  options.allowMultiAudiencesInToken = false;

  // if the user wants to validate issuer, we must have it
  if (options.validateIssuer) {
    options.issuer = options.oidcIssuer;
    if (!options.issuer)
      return self.fail("options.validateIssuer is true, but options.oidcIssuer is null.");
  }

  // verify id_token signature and claims
  return jwt.verify(id_token, PEMkey, options, (err, jwtClaims) => {
    if (err) {
      if (err.message)
        return self.fail(err.message);
      else
        return self.fail("cannot verify id token");
    }

    log.info("Claims received: ", jwtClaims);

    // jwt checks the 'nbf', 'exp', 'aud', 'iss' claims
    // there are a few other things we will check below

    // check the nonce in claims
    if (!jwtClaims.nonce || jwtClaims.nonce !== nonce)
      return self.fail('invalid nonce');

    // check c_hash
    if (jwtClaims.c_hash) {
      // checkHashValueRS256 checks if code is null, so we don't bother here
      if (!aadutils.checkHashValueRS256(code, jwtClaims.c_hash)) 
        return self.fail("invalid c_hash");
    }

    // check at_hash
    if (jwtClaims.at_hash) {
      // checkHashValueRS256 checks if access_token is null, so we don't bother here
      if (!aadutils.checkHashValueRS256(access_token, jwtClaims.at_hash))
        return self.fail("invalid at_hash");
    }

    // return jwt claims and jwt claims string
    var idTokenSegments = id_token.split('.');
    var jwtClaimsStr = base64url.decode(idTokenSegments[1]);
    return callback(jwtClaimsStr, jwtClaims);
  });
};

/**
 * handle error response
 *
 * @params {String} err 
 * @params {String} err_description
 */
Strategy.prototype._errorResponseHandler = function errorResponseHandler(err, err_description) {
  const self = this;

  log.info('Error received in the response was: ', err);
  if (err_description)
    log.info('Error description received in the response was: ', err_description);

  // Unfortunately, we cannot return the 'error description' to the user, since 
  // it goes to http header by default and it usually contains characters that
  // http header doesn't like, which causes the program to crash. 
  return self.fail(err);
};

/**
 * handle the response where we only get 'id_token' in the response
 *
 * @params {Object} id_token
 * @params {Object} tuple  -- state/nonce/policy/timeStamp tuple 
 * @params {Object} req
 * @params {Function} next
 */
Strategy.prototype._implicitFlowHandler = function implicitFlowHandler(id_token, tuple, req, next) {
  /* we will do the following things in order
   * (1) validate id_token
   * (2) use the claims in the id_token for user's profile
   */

  const self = this;

  log.info('entering Strategy.prototype._implicitFlowHandler, received id_token: ' + id_token);

  // validate the id_token
  return self._validateResponse(id_token, null, null, tuple.nonce, req, (jwtClaimsStr, jwtClaims) => {
    const sub = jwtClaims.sub;
    const iss = jwtClaims.iss;
    
    // we are not doing auth code so we set the tokens to null
    const access_token = null;
    const refresh_token = null;
    const params = null;

    log.info('we are in implicit flow, use the content in id_token as the profile');

    return onProfileLoaded(self, {
      req,
      sub,
      iss,
      profile: makeProfileObject(jwtClaims, jwtClaimsStr),
      jwtClaims,
      access_token,
      refresh_token,
      params,
    });
  });
};

/**
 * handle the response where we get 'id_token' and 'code' in the response
 *
 * @params {Object} id_token 
 * @params {Object} code
 * @params {Object} tuple  -- state/nonce/policy/timeStamp tuple
 * @params {Object} req
 * @params {Function} next
 */
Strategy.prototype._hybridFlowHandler = function hybridFlowHandler(id_token, code, tuple, req, next) {
  /* we will do the following things in order
   * (1) validate the id_token and the code
   * (2) if there is no userinfo token needed (or ignored if using AAD v2 ), we use 
   *     the claims in id_token for user's profile
   * (3) if userinfo token is needed, we will use the 'code' and the authorization code flow
   */
  const self = this;

  log.info('entering Strategy.prototype._hybridFlowHandler, received code: ' + code + ', received id_token: ' + id_token);

  // validate the id_token and the code
  return self._validateResponse(id_token, code, null, tuple.nonce, req, (jwtClaimsStr, jwtClaims) => {
    // c_hash is required for 'code id_token' flow. If we have c_hash, then _validateResponse already
    // validates it; otherwise, _validateResponse ignores the c_hash check, and we check here
    if (!jwtClaims.c_hash)
      return self.fail("we are in hybrid flow using code id_token, but c_hash is not found in id_token");

    const sub = jwtClaims.sub;
    const iss = jwtClaims.iss;

    // now we use the authorization code flow
    return self._authCodeFlowHandler(code, tuple, req, next, iss, sub);
  });
};

/**
 * handle the response where we only get 'code' in the response
 *
 * @params {Object} code
 * @params {Object} tuple  -- state/nonce/policy/timeStamp tuple
 * @params {Object} req
 * @params {Function} next
 * // the following are required if you used 'code id_token' flow then call this function to 
 * // redeem the code for another id_token from the token endpoint. iss and sub are those 
 * // in the id_token from authorization endpoint, and they should match those in the id_token
 * // from the token endpoint 
 * @params {String} iss
 * @params {String} sub
 */
Strategy.prototype._authCodeFlowHandler = function authCodeFlowHandler(code, tuple, req, next, iss, sub) {
  /* we will do the following things in order:
   * (1) use code to get id_token and access_token
   * (2) validate the id_token and the access_token received
   * (3) if user asks for userinfo and we are using AAD v1, then we use access_token to get
   *     userinfo, then make sure the userinfo has the same 'sub' as that in the 'id_token'
   */
  const self = this;

  log.info('entering Strategy.prototype._authCodeFlowHandler, received code: ' + code);

  var issFromPrevIdToken = iss;
  var subFromPrevIdToken = sub;

  let libraryVersion = aadutils.getLibraryVersion();
  let libraryVersionParameterName = aadutils.getLibraryVersionParameterName();
  let libraryProduct = aadutils.getLibraryProduct();
  let libraryProductParameterName = aadutils.getLibraryProductParameterName();

  const config = self._options._configForOauth;

  const oauth2 = new OAuth2(
    config.clientID, // consumerKey
    config.clientSecret, // consumer secret
    '', // baseURL (empty string because we use absolute urls for authorize and token paths)
    config.authorizationURL, // authorizePath
    config.tokenURL, // accessTokenPath
    {libraryProductParameterName : libraryProduct,
     libraryVersionParameterName : libraryVersion} // customHeaders
  );

  let callbackURL = config.callbackURL;
  // options.callbackURL is merged into config object while `setOptions` call
  if (!callbackURL) {
    return next(new Error('no callbackURL found'));
  }

  const parsedCallbackURL = url.parse(callbackURL);
  if (!parsedCallbackURL.protocol) {
    // The callback URL is relative, resolve a fully qualified URL from the
    // URL of the originating request.
    callbackURL = url.resolve(aadutils.originalURL(req), callbackURL);
  }

  return oauth2.getOAuthAccessToken(code, {
    grant_type: 'authorization_code',
    redirect_uri: callbackURL,
  }, (getOAuthAccessTokenError, access_token, refresh_token, params) => {
    if (getOAuthAccessTokenError) {
    return next(new InternalOAuthError('failed to obtain access token', getOAuthAccessTokenError));
    }

    var id_token = params.id_token;

    // id_token should be present
    if (!id_token)
      return self.fail('id_token is not received');

    // token_type must be 'Bearer'
    if (params.token_type !== 'Bearer') {
      log.info('token_type received is: ', params.token_type);
      return self.fail(`token_type received is not 'Bearer'`);
    }

    log.info('received id_token: ', id_token);

    return self._validateResponse(id_token, null, access_token, tuple.nonce, req, (jwtClaimsStr, jwtClaims) => {
      // for 'code id_token' flow, check iss/sub in the id_token from the authorization endpoint
      // with those in the id_token from token endpoint
      if (issFromPrevIdToken && issFromPrevIdToken !== jwtClaims.iss)
        return self.fail('After redeeming the code, iss in id_token from authorize_endpoint does not match iss in id_token from token_endpoint');
      if (subFromPrevIdToken && subFromPrevIdToken !== jwtClaims.sub)
        return self.fail('After redeeming the code, iss in id_token from authorize_endpoint does not match iss in id_token from token_endpoint');

      const sub = jwtClaims.sub;
      const iss = jwtClaims.iss;
      
      // load the userinfo if this is not v2
      if (!self._options._isV2) {
        // make sure we get an access_token
        if (!access_token)
          return self.fail("we want to access userinfo endpoint, but access_token is not received");

        let parsedUrl;
        try {
          parsedUrl = url.parse(config.userInfoURL, true);
        } catch (urlParseException) {
          return next(
            new InternalOpenIDError(
              `Failed to parse config property 'userInfoURL' with value ${config.userInfoURL}`,
              urlParseException
            )
          );
        }

        parsedUrl.query.schema = 'openid';
        delete parsedUrl.search; // delete operations are slow; should we rather just overwrite it with {}
        const userInfoURL = url.format(parsedUrl);

        // ask oauth2 to use authorization header to bearer access token
        oauth2.useAuthorizationHeaderforGET(true);
        return oauth2.get(userInfoURL, access_token, (getUserInfoError, body) => {
          if (getUserInfoError) {
            return next(new InternalOAuthError('failed to fetch user profile', getUserInfoError));
          }

          log.info('Profile loaded from MS identity', body);

          var userinfoReceived = null;
          // use try / catch around JSON.parse --> could fail unexpectedly
          try {
            userinfoReceived = JSON.parse(body);
          } catch (ex) {
            return next(ex);
          }

          // make sure the 'sub' in userinfo is the same as the one in 'id_token'
          if (userinfoReceived.sub !== jwtClaims.sub) {
            log.error('sub in userinfo is ' + userinfoReceived.sub + ', but does not match sub in id_token, which is ' + id_token.sub);
            return self.fail('sub received in userinfo and id_token do not match');
          }

          return onProfileLoaded(self, {
            req,
            sub,
            iss,
            profile: makeProfileObject(userinfoReceived, body),
            jwtClaims,
            access_token,
            refresh_token,
            params,
          });
        });
      } else {
        // v2 doesn't have userinfo endpoint, so we use the content in id_token as the profile
        log.info('v2 has no userinfo endpoint, using the content in id_token as the profile');

        return onProfileLoaded(self, {
          req,
          sub,
          iss,
          profile: makeProfileObject(jwtClaims, jwtClaimsStr),
          jwtClaims,
          access_token,
          refresh_token,
          params,
        });
      }
    });
  });
};

/**
 * prepare the initial authorization request
 *
 * @params {Object} req
 * @params {Function} next
 */
Strategy.prototype._flowInitializationHandler = function flowInitializationHandler(req, next) {
  // The request being authenticated is initiating OpenID Connect
  // authentication. Prior to redirecting to the provider, configuration will
  // be loaded. The configuration is typically either pre-configured or
  // discovered dynamically. When using dynamic discovery, a user supplies
  // their identifer as input.

  const self = this;

  log.info(`entering Strategy.prototype._flowInitializationHandler`);

  let identifier;
  if (req.body && req.body[this._identifierField]) {
    identifier = req.body[this._identifierField];
  } else if (req.query && req.query[this._identifierField]) {
    identifier = req.query[this._identifierField];
  }

  var options = self._options;
  var config = options._configForOauth;

  let callbackURL = options.callbackURL || config.callbackURL;
  if (callbackURL) {
    const parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(aadutils.originalURL(req), callbackURL);
    }
  }

  log.info('Going in with our config loaded as: ', config);

  const params = {};
  if (self.authorizationParams) {
    _.assign(params, self.authorizationParams(options));
  }
  _.assign(params, {
      redirect_uri: callbackURL,
    }, objectTransform({
      source: config,
      map: {
        responseMode: 'response_mode',
        responseType: 'response_type',
        clientID: 'client_id',
        resourceURL: 'resource',
      },
  }));

  log.info('We are sending the response_type: ', params.response_type);
  log.info('We are sending the response_mode: ', params.response_mode);

  let scope = config.scope;
  if (Array.isArray(scope)) {
    scope = scope.join(config.scopeSeparator);
  }
  if (scope) {
    params.scope = ['openid', scope].join(config.scopeSeparator);
  } else {
    params.scope = 'openid';
  }

  // @TODO: Policy parameter should be included.
  // if (policy) { params['p'] = policy; }; 

  // add state/nonce/policy/timeStamp tuple to session
  let state = params.state = aadutils.uid(32);
  let nonce = params.nonce = aadutils.uid(32);

  self._sessionContentHandler.add(req, self._key, {state: state, nonce: nonce, policy: req.query.p, timeStamp: Date.now()});

  params[aadutils.getLibraryProductParameterName()] = aadutils.getLibraryProduct();
  params[aadutils.getLibraryVersionParameterName()] = aadutils.getLibraryVersion();
  let location;

  // Implement support for standard OpenID Connect params (display, prompt, etc.)
  if (req.query.p) {
    location = `${config.authorizationURL}&${querystring.stringify(params)}`;
  } else {
    location = `${config.authorizationURL}?${querystring.stringify(params)}`;
  }

  return self.redirect(location);
};

module.exports = Strategy;
