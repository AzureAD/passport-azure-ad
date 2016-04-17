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
   querystring= require('querystring'),
   util = require('util'),
   utils = require('./aadutils'),
   OAuth2 = require('oauth').OAuth2,
   setup = require('./oidcsetup'),
   Validator = require('./validator').Validator,
   Log = require('./logging').getLogger,
   InternalOAuthError = require('./errors/internaloautherror'),
   Metadata = require('./metadata').Metadata,
   async = require('async');

var cacheManager = require('cache-manager');

var log = new Log("AzureAD: OIDC Passport Strategy");

var memoryCache = cacheManager.caching({store: 'memory', max: 3600, ttl: 1800/*seconds*/});
var ttl = 1800; // 30 minutes cache


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

    if (!options.identityMetadata) {
        log.error("No options was presented to Strategy as required.");
        throw new TypeError('OIDCStrategy requires either a PEM encoded public key or a metadata location that contains cert data for RSA and ECDSA callback.');
    }

    // if logging level specified, switch to it.
    if (options.loggingLevel) { log.levels("console", options.loggingLevel); }


    // warn about validating the issuer
    if (!options.validateIssuer) {
      log.warn("We are not validating the issuer. This is fine if you are expecting multiple organizations to connect to your app. Otherwise you should validate the issuer.");
  }
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
Strategy.prototype.authenticate = function(req, options) {
  var self = this;

  // Allow for some overrides that may come in to the authenticate strategy.
  // 
  //        It's important all options are in self._options before we continue, as we'll be validating these and
  //       loading them through a validator. We should only use the data in configurator() for actual param passing
  //       otherwise we could have injection issues.
  //       
  // 
  if (options.resourceURL) { self._options.resourceURL = options.resourceURL;  }
  if (options.resourceType) { self._options.responseType = options.responseType; }
  if (options.responseMode) { self._options.responseMode = options.responseMode; }

async.waterfall([ 

  function(next) {

      // B2C interception
      // 
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
        self._cacheKey = policy; // this policy will become cache key.

        log.info('B2C: New Metadata url provided to Strategy was: ', metadata);
        

    } else {
      metadata = self._options.identityMetadata;
    }

    next(null, metadata);

},


function(metadata, next) {
// Once loaded, we now set options.
// 

self.setOptions(self._options, metadata, function(err) {
  if (err) { return self.error(err); } 

  return next(null);
});


},

function(next) {

  if (req.query && req.query.error) {

    log.info("OPENID CONNECT ERROR: We are in the OpenID Connect Response with error. Assumed because no auth code was in the query.");
        log.info("");
        log.info('Error received was: ', req.query.error);


    //       Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }


  else if (req.query && req.query.code || req.method === 'POST' && req.body['code']) {

      log.info('Query received was: ', req.query);
      var code;

    if (req.query) { code = req.query.code; }
    if (req.body['code']) { code = req.body['code']; }

    log.info("OAUTH2: Got access code: ", code);

    self.configure(null, function(err, config) {
      if (err) { return self.error(err); }

      var oauth2 = new OAuth2(config.clientID,  config.clientSecret,
                              '', config.authorizationURL, config.tokenURL);

      var callbackURL = options.callbackURL || config.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }

      oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL }, function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        log.info('TOKEN RECEIVED');
        log.info('Access Token: ' + accessToken);
        log.info('');
        log.info('Refresh Token: ' + refreshToken);
        log.info('');
        log.info(params);
        log.info('----');

        var idToken = params['id_token'];
        if (!idToken) { return self.error(new Error('ID Token not present in token response')); }

        var idTokenSegments = idToken.split('.'),
        jwtClaimsStr,
        jwtClaims;

        try {
          jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
          jwtClaims = JSON.parse(jwtClaimsStr);
        } catch (ex) {
          return self.error(ex);
        }

        log.info('Claims received: ', jwtClaims);

        var iss = jwtClaims.iss;
        var sub = jwtClaims.sub;
        // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
        // "sub" claim was named "user_id".  Many providers still issue the
        // claim under the old field, so fallback to that.
        if (!sub) {
          sub = jwtClaims.user_id;
        }

        //       Ensure claims are validated per:
        //       http://openid.net/specs/openid-connect-basic-1_0.html#id_token


        self._shouldLoadUserProfile(iss, sub, function(err, load) {
          if (err) { return self.error(err); }

          if (load) {
            var parsed = url.parse(config.userInfoURL, true);
            parsed.query['schema'] = 'openid';
            delete parsed.search;
            var userInfoURL = url.format(parsed);

            oauth2.get(userInfoURL, refreshToken, function (err, body) {
              if (err) { return self.error(new InternalOAuthError('failed to fetch user profile', err)); }

              log.info('PROFILE LOADED FROM MS IDENTITY');
              log.info(body);
              log.info('-------');

              var profile = {};

              try {
                var json = JSON.parse(body);

                profile.id = json.sub;
                // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
                // "sub" key was named "user_id".  Many providers still use the old
                // key, so fallback to that.
                if (!profile.id) {
                  profile.id = json.user_id;
                }

                profile.displayName = json.name;
                profile.name = { familyName: json.family_name,
                                 givenName: json.given_name,
                                 middleName: json.middle_name };

                profile._raw = body;
                profile._json = json;

                onProfileLoaded(profile);
              } catch(ex) {
                return self.error(ex);
              }
            });
          } else {

            // lets do an id_token fallback. We use id_token over userInfo endpoint for now
            //
            if (idToken) {

              log.info('PROFILE LOADED FROM MS IDENTITY');
              log.info('-------');
              log.info("PROFILE FALLBACK: Since we didn't use the UserInfo endpoint, falling back to id_token for profile.");

              var profile = {};

              try {

                profile.id = jwtClaims.sub || jwtClaims.oid;
                // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
                // "sub" key was named "user_id".  Many providers still use the old
                // key, so fallback to that.
                if (!profile.id) {
                  profile.id = jwtClaims.user_id;
                }

                profile.displayName = jwtClaims.name;
                profile.name = { familyName: jwtClaims.family_name,
                                 givenName: jwtClaims.given_name,
                                 middleName: jwtClaims.middle_name };

                profile.email = jwtClaims.upn || jwtClaims.preferred_username || jwtClaims.oid;

                profile._raw = jwtClaimsStr;
                profile._json =  jwtClaims;

                onProfileLoaded(profile);
              } catch(ex) {
                return self.error(ex);
              }

            } else {
            onProfileLoaded();
          }
          }

          function onProfileLoaded(profile) {
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              self.success(user, info);
            }

            var arity;

            if (self._passReqToCallback) {
              arity = self._verify.length;
              if (arity === 9) {
                self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity === 8) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity === 7) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity === 5) {
                self._verify(req, iss, sub, profile, verified);
              } else if (arity === 4) { 
                self._verify(req, iss, sub, verified);
              }
              else { // default - just pass back a profile
                self._verify(req, profile, verified);
              }
            } else {
              arity = self._verify.length;
              if (arity === 8) {
                self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity === 7) {
                self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity === 6) {
                self._verify(iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity === 4) {
                self._verify(iss, sub, profile, verified);
              } else if (arity === 3) { 
                self._verify(iss, sub, verified);
              }
              else { // default - just pass back a profile
                self._verify(profile, verified);
              }
            }
          }

        });
      });
    });
  } else if (req.body && req.method === 'POST') {

        log.info("OPENID CONNECT: We are in the OpenID Connect Only Response. Assumed because no auth code was in the query and we are POST.");
        log.info("");
        log.info('Body received was: ', req.body);

        var profile = {};

        //We are not doing auth code so we set the tokens to null
        //

        var accessToken = null;
        var refreshToken = null;
        var params = null;

        // We have a response, get the user identity out of it
        //
        var idToken = req.body['id_token'];
        if (!idToken) { return self.error(new Error('ID Token not present in response')); }

        var idTokenSegments = idToken.split('.'),
        jwtClaimsStr,
        jwtClaims;

        try {
          jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
          jwtClaims = JSON.parse(jwtClaimsStr);
        } catch (ex) {
          return self.error(ex);
        }

        log.info('Claimes received: ', jwtClaims);

        var iss = jwtClaims.iss;
        var sub = jwtClaims.sub;
        // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
        // "sub" claim was named "user_id".  Many providers still issue the
        // claim under the old field, so fallback to that.
        if (!sub) {
          sub = jwtClaims.user_id;
        }

        self._shouldLoadUserProfile(iss, sub, function(err, load) {
          if (err) { return self.error(err); }

          if (load) {

            // we do not have a userinfo endpoint for id token at the moment
            //
            

             } else {

        // lets do an id_token fallback. We use id_token over userInfo endpoint for now
            //
            if (idToken) {

              log.info('PROFILE LOADED FROM MS IDENTITY');
              log.info('-------');
              log.info("PROFILE FALLBACK: Since we didn't use the UserInfo endpoint, falling back to id_token for profile.");


              try {

                profile.id = jwtClaims.sub || jwtClaims.oid;
                // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
                // "sub" key was named "user_id".  Many providers still use the old
                // key, so fallback to that.
                if (!profile.id) {
                  profile.id = jwtClaims.user_id;
                }

                profile.displayName = jwtClaims.name;
                profile.name = { familyName: jwtClaims.family_name,
                                 givenName: jwtClaims.given_name,
                                 middleName: jwtClaims.middle_name };

                profile.email = jwtClaims.upn || jwtClaims.preferred_username || jwtClaims.oid;

                profile._raw = jwtClaimsStr;
                profile._json =  jwtClaims;

                onProfileLoaded(profile);
              } catch(ex) {
                return self.error(ex);
              }

            } else {
            onProfileLoaded();
          } 
        }

          function onProfileLoaded(profile) {
            function verified(err, user, info) {
              if (err) { return self.error(err); }
              if (!user) { return self.fail(info); }
              self.success(user, info);
            }

            var arity;

            if (self._passReqToCallback) {
              arity = self._verify.length;
              if (arity === 9) {
                self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity === 8) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity === 7) {
                self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity === 5) {
                self._verify(req, iss, sub, profile, verified);
              } else if (arity === 4) { 
                self._verify(req, iss, sub, verified);
              }
              else { // default - just pass back a profile
                self._verify(req, profile, verified);
              }
            } else {
              arity = self._verify.length;
              if (arity === 8) {
                self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
              } else if (arity === 7) {
                self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
              } else if (arity === 6) {
                self._verify(iss, sub, profile, accessToken, refreshToken, verified);
              } else if (arity === 4) {
                self._verify(iss, sub, profile, verified);
              } else if (arity === 3) { 
                self._verify(iss, sub, verified);
              }
              else { // default - just pass back a profile
                self._verify(profile, verified);
              }
            }
          }
        });

    } else {
    // The request being authenticated is initiating OpenID Connect
    // authentication.  Prior to redirecting to the provider, configuration will
    // be loaded.  The configuration is typically either pre-configured or
    // discovered dynamically.  When using dynamic discovery, a user supplies
    // their identifer as input.

    log.info("OPENID CONNECT: We are in the OpenID Connect Inital Flow. Assumed because no auth code was in the query and we are not POST.");
    log.info("");
    log.info('Body received was: ', req.body);

    var identifier;
    if (req.body && req.body[this._identifierField]) {
      identifier = req.body[this._identifierField];
    } else if (req.query && req.query[this._identifierField]) {
      identifier = req.query[this._identifierField];
    }



    self.configure(identifier, function(err, config) {
      if (err) { return self.error(err); }

      var callbackURL = options.callbackURL || config.callbackURL;
      if (callbackURL) {
        var parsed = url.parse(callbackURL);
        if (!parsed.protocol) {
          // The callback URL is relative, resolve a fully qualified URL from the
          // URL of the originating request.
          callbackURL = url.resolve(utils.originalURL(req), callbackURL);
        }
      }

log.info("Going in with our config loaded as: ", config);

      var params = {};
      if (self.authorizationParams) { params = self.authorizationParams(options); }
      params['response_type'] = config.responseType;
      log.info('We are sending the response_type: ', params['response_type']);
      params['client_id'] = config.clientID;
      params['redirect_uri'] = callbackURL;
      params['response_mode'] = config.responseMode;
      log.info('We are sending the response_mode: ', params['response_mode']);
      params['nonce'] = utils.uid(16);
      var scope = config.scope;
      if (Array.isArray(scope)) { scope = scope.join(self._scopeSeparator); }
      if (scope) {
        params.scope = 'openid' + config.scopeSeparator + scope;
      } else {
        params.scope = 'openid';
      }
      if (config.resourceURL) {
      params['resource'] = config.resourceURL; 
      }



      //if (policy) { params['p'] = policy; }; // Policy parameter should be included.


      // Add support for automatically generating a random state for verification.
      
      var state;

      if (!options.state) { state = utils.uid(16); }
      else { state = options.state; }

      params.state = state; 

      var location;

      // Implement support for standard OpenID Connect params (display, prompt, etc.)

      if (req.query.p) { 

        location = config.authorizationURL + '&' + querystring.stringify(params);

      }else {

        location = config.authorizationURL + '?' + querystring.stringify(params);
      }

      

      self.redirect(location);
    });
  } 

  next(null);

}  ], function(err) { //This function gets called after the two tasks have called their "task callbacks"
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
 Strategy.prototype.setOptions = function(options, metadata, done) {
var self = this;

// Loading metadata from endpoint.
// 
// 
 async.waterfall([
          
            // fetch the metadata
    function loadMetadata(next) {

    log.info("Parsing Metadata");
    log.info("Metadata we have is: ", metadata);
    


    memoryCache.wrap(self._cacheKey, function (cacheCallback) {
    metadata = new Metadata(metadata, "oidc", options);
    metadata.fetch(function(err) {
        if (err) {
            return cacheCallback(new Error("Unable to fetch metadata: " + err));
        } else {
              return cacheCallback(null, metadata); }
        }); }, {ttl: ttl}, next);
    

  },
function loadOptions(metadata, next) {


log.info("Setting options");

  self._skipUserProfile = options.skipUserProfile || false;
    // What's the recommended field name for OpenID Connect?
  options.identifierField = options.identifierField || 'openid_identifier';
  options.scope = options.scope;
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.passReqToCallback = options.passReqToCallback;
  options.responseType = options.responseType;
  options.responseMode = options.responseMode;
  options.resourceURL = options.resourceURL;



  // https://login.microsoftonline.com/common/.well-known/openid-configuration
  // We will always use the values returned from the metadata endpoint. If they conflict with the configuration below the
  // values from the metadata endpoint will be used instead.
  //
  options.authorizationURL = metadata.oidc.auth_endpoint;
  options.tokenURL = metadata.oidc.token_endpoint;
  options.userInfoURL = metadata.oidc.userinfo_endpoint;
  options.revocationURL = metadata.oidc.end_session_endpoint;
  options.tokenInfoURL = metadata.oidc.tokeninfo_endpoint || null;
  options.oidcIssuer = metadata.oidc.issuer;
  options.clientID = options.clientID;
  options.clientSecret = options.clientSecret;
  options.callbackURL = options.callbackURL;


  // Now that we have our options for configuration, let's check them for issues.

        var config = {
        clientID: Validator.isNonEmpty,
        callbackURL: Validator.isNonEmpty,
        responseType: Validator.isTypeLegal,
        responseMode: Validator.isModeLegal,
        authorizationURL: Validator.isURL,
        tokenURL: Validator.isURL
       // callbackURL: Validator.isURL  // We allow http for now :-/
    };

    // validator will throw exception if a required option is missing
    var checker = new Validator(config);
    checker.validate(options);

  next(null, options); 
},

  function setConfiguration(options, next) {

    // This OpenID Connect strategy is configured to work with a specific
    // provider.  Override the discovery process with pre-configured endpoints.
    // 
    // 
    log.info("Setting a configuration for later");
    self.configure(function(identifier, done) {
      return done(null, {
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
], function(err) {
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
Strategy.prototype.configure = function(identifier, done) {
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
      layer(identifier, function(e, c) { pass(i + 1, e, c); } );
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
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(issuer, subject, function(err, skip) {
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
 * Expose `Strategy`.
 */
module.exports = Strategy;
