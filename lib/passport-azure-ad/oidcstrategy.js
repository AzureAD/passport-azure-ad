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

/**
 * Module dependencies.
 */
var passport = require('passport'),
   url = require('url'),
   querystring = require('querystring'),
   util = require('util'),
   utils = require('./aadutils'),
   OAuth2 = require('oauth').OAuth2,
   setup = require('./oidcsetup'),
   Validator = require('./validator').Validator,
   Log = require('./logging').getLogger,
   InternalOAuthError = require('./errors/internaloautherror'),
   Metadata = require('./metadata').Metadata,
   async = require('async'),
   base64url = require('base64url'),
   jws = require('jws'),
   jwt = require('jsonwebtoken'),
   nonceHandler = require('./nonceHandler'),
   stateHandler = require('./stateHandler'),
   UrlValidator = require('valid-url');

var cacheManager = require('cache-manager');
var log = new Log("AzureAD: OIDC Passport Strategy");
var memoryCache = cacheManager.caching({ store: 'memory', max: 3600, ttl: 1800/*seconds*/ });
var ttl = 1800; // 30 minutes cache

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
        if (err) { return strategy.error(err); }
        if (!user) { return strategy.fail(info); }
        strategy.success(user, info);
    }

    var verifyArityArgsMap = {
        8: 'iss sub profile jwtClaims access_token refresh_token params',
        7: 'iss sub profile access_token refresh_token params',
        6: 'iss sub profile access_token refresh_token',
        4: 'iss sub profile',
        3: 'iss sub'
    };

    var arity = (strategy._passReqToCallback) ? strategy._verify.length - 1 : strategy._verify.length;
    var verifyArgs = [args.profile, verified];

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

// Note: callback is optional in set() and del().

/**
 * `Strategy` constructor.
 *
 * The OpenID Connect authentication strategy authenticates requests using
 * OpenID Connect, which is an identity layer on top of the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    passport.Strategy.call(this);
    this._options = options;
    this.name = 'azuread-openidconnect';
    this._verify = verify;
    this._configurers = [];
    this._cacheKey = 'ordinary';
    this._skipUserProfile = '';
    this._passReqToCallback = !!options.passReqToCallback;
    this._key = options.sessionKey || ('OIDC: ' + options.callbackURL);

    if (!options.identityMetadata) {
        log.error("No options was presented to Strategy as required.");
        throw new TypeError('OIDCStrategy requires either a PEM encoded public key or a metadata location that contains cert data for RSA and ECDSA callback.');
    }

    // if logging level specified, switch to it.
    if (options.loggingLevel) { log.levels("console", options.loggingLevel); }

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
        log.warn(`We are not checking the audience because audience is not provided in the config file. \
      Checking audience is a mitigation against forwarding attacks, providing the audience in the \
      config file is strongly recommended.`);
    }

    // validating the properties in config
    var config = {
        clientID: Validator.isNonEmpty,
        responseType: Validator.isTypeLegal,
        responseMode: Validator.isModeLegal,
        callbackURL: Validator.isURL,
        identityMetadata: Validator.isURL
    };

    // validator will throw exception if a required option is missing
    var checker = new Validator(config);
    checker.validate(options);

    // we allow 'http' for the callbackURL, but don't recommend using 'http'
    if (UrlValidator.isHttpUri(options.callbackURL))
        log.warn(`Using http for callbackURL is not recommended, please consider using https`);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
    var self = this;

    // Allow for some overrides that may come in to the authenticate strategy.
    // 
    //        It's important all options are in self._options before we continue, as we'll be validating these and
    //       loading them through a validator. We should only use the data in configurator() for actual param passing
    //       otherwise we could have injection issues.
    //       
    if (options.resourceURL) { self._options.resourceURL = options.resourceURL; }
    if (options.resourceType) { self._options.responseType = options.responseType; }
    if (options.responseMode) { self._options.responseMode = options.responseMode; }

    async.waterfall([
        /* 
        * Step 1. compute metadata url 
        */
      function (next) {

          // B2C interception
          var metadata = null;

          // We listen for the p paramter in any response and set it. If it has been set already and in memory (profile) we skip this as it's not necessary to set again.
          if (req.query.p || options.forceB2C) {

              log.info("B2C: Found a policy inside of the login request. This is a B2C tenant!");
              log.info("");

              if (!self._options.tenantName) {
                  log.error("For B2C you must specify a tenant name, none was presented to Strategy as required. (example: tenantName:contoso.onmicrosoft.com");
                  throw new TypeError('OIDCStrategy requires you specify a tenant name to Strategy if using a B2C tenant. (example: tenantName:contoso.onmicrosoft.com');
              }

              var policy = req.query.p;

              metadata = self._options.identityMetadata.replace("common", self._options.tenantName);
              metadata = metadata.concat('?p=' + policy);
              metadata = metadata.concat('&' + utils.getLibraryProductParameterName() + "=" + utils.getLibraryProduct());
              metadata = metadata.concat('&' + utils.getLibraryVersionParameterName() + "=" + utils.getLibraryVersion());
              self._cacheKey = policy; // this policy will become cache key.

              log.info('B2C: New Metadata url provided to Strategy was: ', metadata);
          } else {
              metadata = self._options.identityMetadata;
              metadata = metadata.concat('?' + utils.getLibraryProductParameterName() + "=" + utils.getLibraryProduct());
              metadata = metadata.concat('&' + utils.getLibraryVersionParameterName() + "=" + utils.getLibraryVersion());
          }
          next(null, metadata);
      },

    /* 
    * Step 2. load options from metadata url
    */
    function (metadata, next) {
        // Once loaded, we now set options.
        self.setOptions(self._options, metadata, function (err) {
            if (err) { return self.error(err); }
            return next(null);
        });
    },

    /* 
    * Step 3. the following are the scenarios for the coming request
    * (1) error response
    * (2) authorization code flow (response_type = 'code')
    *     This case we get a 'code', we will use it to get 'access_token' and 'id_token'
    * (3) implicit flow (response_type = 'id_token')
    *     This case we get a 'id_token'
    * (5) for any other request, we will ask for authorization and initialize the authorization process 
    */
    function (next) {
        var err, err_description, id_token, code;
        err = err_description = id_token = code = null;

        if ((req.query && (req.query.access_token || req.query.refresh_token)) ||
            (req.body && (req.body.access_token || req.body.refresh_token))) 
        {
          // we do not support "token" flows yet: 'code token', 'id_token token', 'code id_token token'
          return self.fail("neither access token nor refresh token is expected in the incoming request");
        }

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
        }

        if (!err && !id_token && !code) {
            // ask for authorization, initialize the authorization process
            return self._flowInitializationHandler(req, next);
        }

        // check state
        var stateCheckResult = stateHandler.verifyState(req, self._key);
        if (!stateCheckResult.valid) {
            return self.fail(stateCheckResult.errorMessage);
        }

        if (err) {
            // handle error response
            return self._errorResponseHandler(err, err_description);
        } else if (id_token && code) {
            // handle hybrid flow
            return self._hybridFlowHandler(id_token, code, req, next);
        } else if (id_token) {
            // handle implicit flow
            return self._implicitFlowHandler(id_token, req, next);
        } else {
            // handle authorization code flow
            return self._authCodeFlowHandler(code, req, next);
        }

    }], function (err) { //This function gets called after the steps above are completed
        if (err) {
            return err;
        }
    });
};

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
Strategy.prototype.setOptions = function (options, metadata, done) {
    var self = this;

    // Loading metadata from endpoint.
    async.waterfall([

       // fetch the metadata
       function loadMetadata(next) {

           log.info("Parsing Metadata");
           log.info("Metadata we have is: ", metadata);

           memoryCache.wrap(self._cacheKey, function (cacheCallback) {
               metadata = new Metadata(metadata, "oidc", options);
               metadata.fetch(function (err) {
                   if (err) {
                       return cacheCallback(new Error("Unable to fetch metadata: " + err));
                   } else {
                       return cacheCallback(null, metadata);
                   }
               });
           }, { ttl: ttl }, next);
       },

   function loadOptions(metadata, next) {
       self.metadata = metadata;
       log.info("Setting options");

       self._skipUserProfile = options.skipUserProfile || false;
       // What's the recommended field name for OpenID Connect?
       options.identifierField = options.identifierField || 'openid_identifier';
       options.scope = options.scope;
       options.scopeSeparator = options.scopeSeparator || ' ';

       // https://login.microsoftonline.com/common/.well-known/openid-configuration
       // We will always use the values returned from the metadata endpoint. If they conflict with the configuration below the
       // values from the metadata endpoint will be used instead.
       options.algorithms = metadata.oidc.algorithms;
       options.authorizationURL = metadata.oidc.auth_endpoint;
       options.tokenURL = metadata.oidc.token_endpoint;
       options.userInfoURL = metadata.oidc.userinfo_endpoint;
       options.revocationURL = metadata.oidc.end_session_endpoint;
       options.tokenInfoURL = metadata.oidc.tokeninfo_endpoint || null;
       options.oidcIssuer = metadata.oidc.issuer;

       // validating the urls received from metadata endpoint
       var config = {
           algorithms: Validator.isNonEmpty,
           authorizationURL: Validator.isURL,
           tokenURL: Validator.isURL
       };

       // validator will throw exception if a required option is missing or invalid
       var checker = new Validator(config);
       checker.validate(options);

       next(null, options);
   },

     function setConfiguration(options, next) {

         // This OpenID Connect strategy is configured to work with a specific
         // provider.  Override the discovery process with pre-configured endpoints.
         log.info("Setting a configuration for later");
         self.configure(function (identifier, done) {
             return done(null, {
                 algorithms: options.algorithms,
                 authorizationURL: options.authorizationURL,
                 tokenURL: options.tokenURL,
                 userInfoURL: options.userInfoURL,
                 clientID: options.clientID,
                 clientSecret: options.clientSecret,
                 callbackURL: options.callbackURL,
                 revocationURL: options.revocationURL,
                 tokenInfoURL: options.tokenInfoURL,
                 oidcIssuer: options.oidcIssuer,
                 responseMode: options.responseMode,
                 responseType: options.responseType,
                 passReqToCallback: options.passReqToCallback,
                 scope: options.scope,
                 scopeSeparator: options.scopeSeparator,
                 identifierField: options.identifierField,
                 resourceURL: options.resourceURL

             });
         });

         next(null, options);
     },
    ], function (err) {
        done(err, options);
    });
};

/**
 * Register a function used to configure the strategy.
 *
 * OpenID Connect is an identity layer on top of OAuth 2.0.  OAuth 2.0 requires
 * knowledge of certain endpoints (authorization, token, etc.) as well as a
 * client identifier (and corresponding secret) registered at the authorization
 * server.
 *
 * Configuration functions are responsible for loading this information.  This
 * is typically done via one of two popular mechanisms:
 *
 *   - The configuration is known ahead of time, and pre-configured via options
 *     to the strategy.
 *   - The configuration is dynamically loaded, using optional discovery and
 *     registration specifications.  (Note: Providers are not required to
 *     implement support for dynamic discovery and registration.  As such, there
 *     is no guarantee that this will result in successfully initiating OpenID
 *     Connect authentication.)
 *
 * @param {Function} fn
 * @api public
 */
Strategy.prototype.configure = function (identifier, done) {
    if (typeof identifier === 'function') {
        return this._configurers.push(identifier);
    }

    // private implementation that traverses the chain of configurers, attempting
    // to load configuration
    var stack = this._configurers;
    (function pass(i, err, config) {
        // an error or configuration was obtained, done
        if (err || config) { return done(err, config); }

        var layer = stack[i];
        if (!layer) {
            // Strategy-specific functions did not result in obtaining configuration
            // details.  Proceed to protocol-defined mechanisms in an attempt
            // to discover the provider's configuration.
            return setup(identifier, done);
        }

        try {
            layer(identifier, function (e, c) { pass(i + 1, e, c); });
        } catch (ex) {
            return done(ex);
        }
    })(0);
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function (issuer, subject, done) {
    if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 2) {
        // async
        this._skipUserProfile(issuer, subject, function (err, skip) {
            if (err) { return done(err); }
            if (!skip) { return done(null, true); }
            return done(null, false);
        });
    } else {
        var skip = (typeof this._skipUserProfile === 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
        if (!skip) { return done(null, true); }
        return done(null, false);
    }
};

/**
 * validate id_token, and pass the validated claims and the payload to callback
 * if code (access_token) is provided, we will validate the c_hash (at_hash) as well
 *
 * @param {String} id_token
 * @param {String} code (if you want to validate c_hash)
 * @param {String} access_token (if you want to validate at_hash)
 * @param {Object} req
 * @param {Function} callback
 */
Strategy.prototype._validateResponse = function validateResponse(idToken, code, access_token, req, callback) {
    const self = this;

    // decode id_token
    var decoded = jws.decode(idToken);
    if (decoded == null)
        return self.fail(null, false, 'Invalid JWT token');
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

    // since the id_token is for itself, so the 'aud' is the clientID by default
    if (!options.audience)
      options.audience = options.clientID;

    // if the user wants to validate issuer, we must have it
    if (options.validateIssuer) {
        options.issuer = options.oidcIssuer;
        if (!options.issuer)
            return self.fail("validateIssuer is set true but issuer is missing");
    }

    // verify id_token signature and claims
    return jwt.verify(idToken, PEMkey, options, (err, jwtClaims) => {
        if (err) {
          if (err.message)
            return self.fail(err.message);
          else
            return self.fail("jwt.verify returned an error, but error message was not set");
        }

        log.info("Claims received: ", jwtClaims);

        // jwt checks the 'nbf', 'exp', 'aud', 'iss' claims
        // there are a few other things we will check below

        // we don't allow multiple audiences in id_token
        if (Array.isArray(jwtClaims.aud) && jwtClaims.aud.length > 1)
            return self.fail('we do not allow multiple audiences in id_token');

        // check the nonce in claims
        var nonceCheckResult = nonceHandler.verifyNonce(req, self._key, jwtClaims.nonce);
        if (!nonceCheckResult.valid)
            return self.fail(nonceCheckResult.errorMessage);

        // check c_hash
        if (jwtClaims.c_hash) {
            // checkHashValueRS256 checks if code is null, so we don't bother here
            if (!utils.checkHashValueRS256(code, jwtClaims.c_hash))
                return self.fail("invalid c_hash");
        }

        // check at_hash
        if (jwtClaims.at_hash) {
            // checkHashValueRS256 checks if access_token is null, so we don't bother here
            if (!utils.checkHashValueRS256(access_token, jwtClaims.at_hash))
                return self.fail("invalid at_hash");
        }

        // return jwt claims and jwt claims string
        var idTokenSegments = idToken.split('.', 3);
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
    var self = this;

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
 * @params {Object} req
 * @params {Function} next
 */
Strategy.prototype._implicitFlowHandler = function implicitFlowHandler(id_token, req, next) {
    /* we will do the following things in order
     * (1) validate id_token
     * (2) use the claims in the id_token for user's profile
     */

    var self = this;

    log.info('entering Strategy.prototype._implicitFlowHandler, received id_token: ' + id_token);

    // validate the id_token
    return self._validateResponse(id_token, null, null, req, (jwtClaimsStr, jwtClaims) => {
        const sub = jwtClaims.sub;
        const iss = jwtClaims.iss;

        return self._shouldLoadUserProfile(iss, sub, (err, load) => {
            if (err) {
                return next(err);
            }

            if (load) {
                // we do not have a userinfo endpoint for id token at the moment
                log.warn('We do not have a userinfo endpoint for id_token, we will use the claims in id_token for the profile.');
            }

            // we are not doing auth code so we set the tokens to null
            var access_token = null,
                refresh_token = null,
                params = null;

            // lets do an id_token fallback. We use id_token over userInfo endpoint for now
            // log.info('PROFILE FALLBACK: Since we did not use the UserInfo endpoint, falling back to id_token for profile.');
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
    });
};

/**
 * handle the response where we get 'id_token' and 'code' in the response
 *
 * @params {Object} id_token 
 * @params {Object} code
 * @params {Object} req
 * @params {Function} next
 */
Strategy.prototype._hybridFlowHandler = function hybridFlowHandler(id_token, code, req, next) {
    /* we will do the following things in order
     * (1) validate the id_token and the code
     * (2) if there is no userinfo token needed, we use 
     *     the claims in id_token for user's profile
     * (3) if userinfo token is needed, we will use the 'code' and the authorization code flow
     */
    var self = this;

    log.info('entering Strategy.prototype._hybridFlowHandler, received code: ' + code + ', received id_token: ' + id_token);

    // nonce is deleted after id_token is valiated. If we use the authorization code
    // flow, we will get a second id_token, so we want to save the nonce and use it
    // for the second id_token validation later. 
    var nonce = req.session[self._key].nonce;

    // save nonce, since if we use the authorization code flow later, we have to check 
    // nonce again.

    // validate the id_token and the code
    return self._validateResponse(id_token, code, null, req, (jwtClaimsStr, jwtClaims) => {
        // c_hash is required for 'code id_token' flow. If we have c_hash, then _validateResponse already
        // validates it; otherwise, _validateResponse ignores the c_hash check, and we check here
        if (!jwtClaims.c_hash)
            return self.fail("we are in hybrid flow using code id_token, but c_hash is not found in id_token");

        var sub = jwtClaims.sub;
        var iss = jwtClaims.iss;

        return self._shouldLoadUserProfile(iss, sub, (err, load) => {
            if (err) {
                return next(err);
            }

            // since we will get a second id_token, we put nonce back into req.session
            nonceHandler.addNonceToSession(req, self._key, nonce);

            // now we use the authorization code flow
            return self._authCodeFlowHandler(code, req, next, iss, sub);
        });
    });
};

/**
 * handle the response where we only get 'code' in the response
 *
 * @params {Object} code
 * @params {Object} req
 * @params {Function} next
 * // the following are required if you used 'code id_token' flow then call this function to 
 * // redeem the code for another id_token from the token endpoint. iss and sub are those 
 * // in the id_token from authorization endpoint, and they should match those in the id_token
 * // from the token endpoint 
 * @params {String} iss
 * @params {String} sub
 */
Strategy.prototype._authCodeFlowHandler = function authCodeFlowHandler(code, req, next, iss, sub) {
    /* we will do the following things in order:
     * (1) use code to get id_token and access_token
     * (2) validate the id_token and the access_token received
     * (3) if user asks for userinfo and we are using AAD v1, then we use access_token to get
     *     userinfo, then make sure the userinfo has the same 'sub' as that in the 'id_token'
     */
    var self = this;

    log.info('entering Strategy.prototype._authCodeFlowHandler, received code: ' + code);

    var issFromPrevIdToken = iss;
    var subFromPrevIdToken = sub;

    // use `null` as identifier since we are in the callback phase of OAuth 2.0 Dance already
    // identifier only has impact on the `authorize` endpoint
    return self.configure(null, (err, config) => {
        if (err) {
            return next(err);
        }

        var libraryVersion = utils.getLibraryVersion();
        var libraryVersionParameterName = utils.getLibraryVersionParameterName();
        var libraryProduct = utils.getLibraryProduct();
        var libraryProductParameterName = utils.getLibraryProductParameterName();

        var oauth2 = new OAuth2(
          config.clientID, // consumerKey
          config.clientSecret, // consumer secret
          '', // baseURL (empty string because we use absolute urls for authorize and token paths)
          config.authorizationURL, // authorizePath
          config.tokenURL, // accessTokenPath
          {                 // custom headers
              libraryProductParameterName: libraryProduct,
              libraryVersionParameterName: libraryVersion
          }
        );

        var callbackURL = config.callbackURL;
        // options.callbackURL is merged into config object while `setOptions` call
        if (!callbackURL) {
            return next(new Error('no callbackURL found'));
        }

        var parsedCallbackURL = url.parse(callbackURL);
        if (!parsedCallbackURL.protocol) {
            // The callback URL is relative, resolve a fully qualified URL from the
            // URL of the originating request.
            callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }

        log.info("sending request to AAD token endpoint to redeem authorization code");
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
            log.info('Access Token: ' + access_token);
            log.info('');
            log.info('Refresh Token: ' + refresh_token);
            log.info('');
            log.info(params);
            log.info('----');

            return self._validateResponse(id_token, null, access_token, req, (jwtClaimsStr, jwtClaims) => {
                // for 'code id_token' flow, check iss/sub in the id_token from the authorization endpoint
                // with those in the id_token from token endpoint
                if (issFromPrevIdToken && issFromPrevIdToken !== jwtClaims.iss)
                    return self.fail('After redeeming the code, iss in id_token from authorize_endpoint does not match iss in id_token from token_endpoint');
                if (subFromPrevIdToken && subFromPrevIdToken !== jwtClaims.sub)
                    return self.fail('After redeeming the code, iss in id_token from authorize_endpoint does not match iss in id_token from token_endpoint');

                var sub = jwtClaims.sub;
                var iss = jwtClaims.iss;

                log.info('Claims received: ', jwtClaims);

                return self._shouldLoadUserProfile(iss, sub, (shouldLoadUserProfileError, load) => {
                    if (shouldLoadUserProfileError) {
                        return next(shouldLoadUserProfileError);
                    }

                    if (load) {
                        // make sure we get an access_token
                        if (!access_token)
                            return self.fail("we want to access userinfo endpoint, but access_token is not received");

                        var parsedUrl;
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
                        var userInfoURL = url.format(parsedUrl);

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
                    }

                    // lets do an id_token fallback. We use id_token over userInfo endpoint for now
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
            });
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

    var self = this;

    log.info(`entering Strategy.prototype._flowInitializationHandler`);

    var identifier;
    if (req.body && req.body[this._identifierField]) {
        identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
        identifier = req.query[this._identifierField];
    }

    return self.configure(identifier, (configureError, config) => {
        if (configureError) {
            return next(configureError);
        }

        var options = self._options;

        var callbackURL = options.callbackURL || config.callbackURL;
        if (callbackURL) {
            const parsed = url.parse(callbackURL);
            if (!parsed.protocol) {
                // The callback URL is relative, resolve a fully qualified URL from the
                // URL of the originating request.
                callbackURL = url.resolve(utils.originalURL(req), callbackURL);
            }
        }

        log.info('Going in with our config loaded as: ', config);

        var params = {};
        if (self.authorizationParams) { params = self.authorizationParams(options); }
        params['response_type'] = config.responseType;
        log.info('We are sending the response_type: ', params['response_type']);
        params['client_id'] = config.clientID;
        params['redirect_uri'] = callbackURL;
        params['response_mode'] = config.responseMode;
        log.info('We are sending the response_mode: ', params['response_mode']);
        var scope = config.scope;
        if (Array.isArray(scope)) { scope = scope.join(config.scopeSeparator); }
        if (scope) {
            params.scope = 'openid' + config.scopeSeparator + scope;
        } else {
            params.scope = 'openid';
        }
        if (config.resourceURL) {
            params['resource'] = config.resourceURL;
        }

        // @TODO: Policy parameter should be included.
        // if (policy) { params['p'] = policy; }; 

        // add state to params and session, use a randomly generated one
        var state = params.state = utils.uid(24);
        log.info('Adding state to the request: ', state);
        stateHandler.addStateToSession(req, self._key, state);

        // add nonce, use a randomly generated one
        var nonce = params.nonce = utils.uid(16);
        log.info('Adding nonce to the request: ', nonce);
        nonceHandler.addNonceToSession(req, self._key, nonce);

        params[utils.getLibraryProductParameterName()] = utils.getLibraryProduct();
        params[utils.getLibraryVersionParameterName()] = utils.getLibraryVersion();

        var location;
        // Implement support for standard OpenID Connect params (display, prompt, etc.)
        if (req.query.p) {
            location = `${config.authorizationURL}&${querystring.stringify(params)}`;
        } else {
            location = `${config.authorizationURL}?${querystring.stringify(params)}`;
        }

        return self.redirect(location);
    });
}
/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
