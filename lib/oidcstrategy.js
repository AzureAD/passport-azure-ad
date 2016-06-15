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

const url = require('url');
const querystring = require('querystring');
const util = require('util');

const async = require('async');
const _ = require('lodash');
const passport = require('passport');
const OAuth2 = require('oauth').OAuth2;
const cacheManager = require('cache-manager');
const objectTransform = require('oniyi-object-transform');

const utils = require('./aadutils');
const setup = require('./oidcsetup');
const Validator = require('./validator').Validator;
const Log = require('./logging').getLogger;
const InternalOAuthError = require('./errors/internaloautherror');
const InternalOpenIDError = require('./errors/internalopeniderror');
const Metadata = require('./metadata').Metadata;

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
    8: 'iss sub profile jwtClaims accessToken refreshToken params',
    7: 'iss sub profile accessToken refreshToken params',
    6: 'iss sub profile accessToken refreshToken',
    5: 'iss sub profile',
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
 *   - `realm`              authentication realm, defaults to 'Users'
 *   - `scope`              list of scope values indicating the required scope of the
 *                          access token for accessing the requested resource. Ex: ['email', 'profile']. 
 *                          We send 'openid' by default and will reject you if you send it a second time.
 *   - `audience` 	        we check JWT audience (aud), provide a value here
 *   - `oidcIssuer`         we check JWT issuer (iss) if you have validateIssuer turned to "true", 
 *                          provide a value here.
 *   - `clientID`           the application ID of your app in Microsoft Identity platform
 *   - `identityMetadata`   the metadata endpoint provided by the Microsoft Identity Portal that provides 
 *                          the keys and other important info at runtime. We roll keys frequently, so don't
 *                          override this to supply your own.
 *   - `skipUserProfile`    Microsoft Identity platform doesn't support a userinfo endpoint yet, so we should 
 *                          skip loading a profile from it.
 *   - `responseType`       for login only flows use id_token. For accessing resources use `id_token code`
 *   - `responseMode`       For login only flows we should have token passed back to us in a POST
 *   - `validateIssuer`     if you have validation on, you cannot have users from multiple tenants sign in
 *   - `passReqToCallback`  if you want the Req to go back to the calling function for other processing use this.
 *
 * Examples:
 *
 *    passport.use(new OIDCStrategy({
 *   callbackURL: config.creds.returnURL,
 *   realm: config.creds.realm,
 *   scope: config.creds.scopes,
 *   clientID: config.creds.clientID,
 *   oidcIssuer: config.creds.issuer,
 *   identityMetadata: config.creds.identityMetadata,
 *   skipUserProfile: config.creds.skipUserProfile,
 *   responseType: config.creds.responseType,
 *   responseMode: config.creds.responseMode,
 *   validateIssuer: config.creds.validateIssuer,
 *   passReqToCallback: config.creds.passReqToCallback,
 *   loggingLevel: config.creds.loggingLevel
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
  this._options = options;
  this.name = 'azuread-openidconnect';
  this._verify = verify;
  this._configurers = [];
  this._cacheKey = 'ordinary';
  this._skipUserProfile = !!options.skipUserProfile;
  this._passReqToCallback = !!options.passReqToCallback;

  if (!options.identityMetadata) {
    // default value should be https://login.microsoftonline.com/common/.well-known/openid-configuration
    log.error('No options was presented to Strategy as required.');
    throw new TypeError(`OIDCStrategy requires either a PEM encoded public key
      or a metadata location that contains cert data for RSA and ECDSA callback.`);
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  // warn about validating the issuer
  if (!options.validateIssuer) {
    log.warn(`We are not validating the issuer.
      This is fine if you are expecting multiple organizations to connect to your app.
      Otherwise you should validate the issuer.`);
  }
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
      // compute metadata url
      (next) => {
        // B2C interception
        let metadata = self._options.identityMetadata;

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

          // @TODO: assumes that self._options.identityMetadata is of type string.
          //        according to Strategy constructor, it could also be a PEM encodede public key
          metadata = self._options.identityMetadata
            .replace('common', self._options.tenantName)
            .concat(`?p=${policy}`);

          self._cacheKey = policy; // this policy will become cache key.

          log.info('B2C: New Metadata url provided to Strategy was: ', metadata);
        }

        return next(null, metadata);
      },
      // load options from metadata url
      (metadata, next) => {
        self.setOptions(self._options, metadata, next);
      },
      // handle error response
      (next) => {
        if (!(req.query && req.query.code)) {
          return next();
        }
        // @TODO: need more specific error handling
        //        response might include error_code, error_details and more

        // Error information pertaining to OAuth 2.0 flows is encoded in the
        // query parameters, and should be propagated to the application.

        log.info(`OPENID CONNECT ERROR: We are in the OpenID Connect Response with error.
          Assumed because no auth code was in the query.`);
        log.info('Error received was: ', req.query.error);

        // pass error to `next` and handle error occurance centrally in `async.waterfall`'s callback
        return next(req.query.error);
      },
      // handle authorize code response (incoming redirect after user consent was given)
      (next) => {
        if (!(
            (req.method === 'GET' && req.query && req.query.code) ||
            (req.method === 'POST' && req.body && req.body.code))) {
          return next();
        }
        const code = (req.query && req.query.code) ? req.query.code : req.body.code;

        if (!code) {
          return next(new Error('Failed to extract `code` from request object'));
        }

        log.info('OAUTH2: Got access code: ', code);

        // use `null` as identifier since we are in the callback phase of OAuth 2.0 Dance already
        // identifier only has impact on the `authorize` endpoint
        return self.configure(null, (err, config) => {
          if (err) {
            return next(err);
          }

          const oauth2 = new OAuth2(
            config.clientID, // consumerKey
            config.clientSecret, // consumer secret
            '', // baseURL (empty string because we use absolute urls for authorize and token paths)
            config.authorizationURL, // authorizePath
            config.tokenURL, // accessTokenPath
            {} // customHeaders
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
            callbackURL = url.resolve(utils.originalURL(req), callbackURL);
          }

          return oauth2.getOAuthAccessToken(code, {
            grant_type: 'authorization_code',
            redirect_uri: callbackURL,
          }, (getOAuthAccessTokenError, accessToken, refreshToken, params) => {
            if (getOAuthAccessTokenError) {
              return next(new InternalOAuthError('failed to obtain access token', getOAuthAccessTokenError));
            }

            log.info('TOKENS RECEIVED: %j', {
              accessToken,
              refreshToken,
              params,
            });

            const idToken = params.id_token;
            if (!idToken) {
              return next(new Error('ID Token not present in token response'));
            }

            const idTokenSegments = idToken.split('.');
            let jwtClaimsStr;
            let jwtClaims;

            try {
              jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
              jwtClaims = JSON.parse(jwtClaimsStr);
            } catch (ex) {
              return next(ex);
            }

            log.info('Claims received: ', jwtClaims);

            // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
            // 'sub' claim was named 'user_id'.  Many providers still issue the
            // claim under the old field, so fallback to that.
            const sub = jwtClaims.sub || jwtClaims.user_id;
            const iss = jwtClaims.iss;

            // Ensure claims are validated per:
            // http://openid.net/specs/openid-connect-basic-1_0.html#id_token

            return self._shouldLoadUserProfile(iss, sub, (shouldLoadUserProfileError, load) => {
              if (shouldLoadUserProfileError) {
                return next(shouldLoadUserProfileError);
              }

              if (load) {
                // version 2.0 of Azure AD endpoints does not provide a userinfo_endpoint information
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

                return oauth2.get(userInfoURL, refreshToken, (getUserInfoError, body) => {
                  if (getUserInfoError) {
                    return next(new InternalOAuthError('failed to fetch user profile', getUserInfoError));
                  }

                  log.info('PROFILE LOADED FROM MS IDENTITY', body);

                  // use try / catch around JSON.parse --> could fail unexpectedly
                  try {
                    return onProfileLoaded(self, {
                      req,
                      sub,
                      iss,
                      profile: makeProfileObject(JSON.parse(body), body),
                      jwtClaims,
                      accessToken,
                      refreshToken,
                      params,
                    });
                  } catch (ex) {
                    return next(ex);
                  }
                });
              }

              // lets do an id_token fallback. We use id_token over userInfo endpoint for now
              return onProfileLoaded(self, {
                req,
                sub,
                iss,
                profile: (idToken) ? makeProfileObject(jwtClaims, jwtClaimsStr) : undefined,
                jwtClaims,
                accessToken,
                refreshToken,
                params,
              });
            });
          });
        });
      },
      //
      (next) => {
        if (!(req.body && req.method === 'POST')) {
          return next();
        }

        log.info(`OPENID CONNECT: We are in the OpenID Connect Only Response.
          Assumed because no auth code was in the query and we are POST.`);
        log.info('Body received was: ', req.body);

        // We are not doing auth code so we set the tokens to null
        const accessToken = null;
        const refreshToken = null;
        const params = null;

        // We have a response, get the user identity out of it
        const idToken = req.body.id_token;
        if (!idToken) {
          return next(new Error('ID Token not present in response'));
        }

        const idTokenSegments = idToken.split('.');
        let jwtClaimsStr;
        let jwtClaims;

        try {
          jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
          jwtClaims = JSON.parse(jwtClaimsStr);
        } catch (ex) {
          return next(ex);
        }

        log.info('Claimes received: ', jwtClaims);

        // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
        // 'sub' claim was named 'user_id'.  Many providers still issue the
        // claim under the old field, so fallback to that.
        const sub = jwtClaims.sub || jwtClaims.user_id;
        const iss = jwtClaims.iss;

        return self._shouldLoadUserProfile(iss, sub, (err, load) => {
          if (err) {
            return next(err);
          }

          if (load) {
            // we do not have a userinfo endpoint for id token at the moment
            // @TODO: need error handling accordingly
          }

          // lets do an id_token fallback. We use id_token over userInfo endpoint for now
          // log.info('PROFILE FALLBACK: Since we did not use the UserInfo endpoint, falling back to id_token for profile.');

          return onProfileLoaded(self, {
            req,
            sub,
            iss,
            profile: (idToken) ? makeProfileObject(jwtClaims, jwtClaimsStr) : undefined,
            jwtClaims,
            accessToken,
            refreshToken,
            params,
          });
        });
      },
      // initialize OAuth 2.0 Authorize Flow
      (next) => {
        // The request being authenticated is initiating OpenID Connect
        // authentication. Prior to redirecting to the provider, configuration will
        // be loaded. The configuration is typically either pre-configured or
        // discovered dynamically. When using dynamic discovery, a user supplies
        // their identifer as input.

        log.info(`OPENID CONNECT: We are in the OpenID Connect Inital Flow.
          Assumed because no auth code was in the query and we are not POST.`);
        log.info('Body received was: ', req.body);

        let identifier;
        if (req.body && req.body[this._identifierField]) {
          identifier = req.body[this._identifierField];
        } else if (req.query && req.query[this._identifierField]) {
          identifier = req.query[this._identifierField];
        }

        return self.configure(identifier, (configureError, config) => {
          if (configureError) {
            return next(configureError);
          }

          let callbackURL = options.callbackURL || config.callbackURL;
          if (callbackURL) {
            const parsed = url.parse(callbackURL);
            if (!parsed.protocol) {
              // The callback URL is relative, resolve a fully qualified URL from the
              // URL of the originating request.
              callbackURL = url.resolve(utils.originalURL(req), callbackURL);
            }
          }

          log.info('Going in with our config loaded as: ', config);

          const params = {};
          if (self.authorizationParams) {
            _.assign(params, self.authorizationParams(options));
          }
          _.assign(params, {
            redirect_uri: callbackURL,
            nonce: utils.uid(16),
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

          // if (policy) { params['p'] = policy; }; // Policy parameter should be included.

          // Add support for automatically generating a random state for verification.

          let state;

          if (!options.state) { state = utils.uid(16); } else { state = options.state; }

          params.state = state;

          let location;

          // Implement support for standard OpenID Connect params (display, prompt, etc.)

          if (req.query.p) {
            location = `${config.authorizationURL}&${querystring.stringify(params)}`;
          } else {
            location = `${config.authorizationURL}?${querystring.stringify(params)}`;
          }

          return self.redirect(location);
        });
      },
    ],
    (waterfallError) => { // This function gets called after the three tasks have called their 'task callbacks'
      if (waterfallError) {
        return self.error(waterfallError);
      }
      return true;
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
Strategy.prototype.setOptions = function setOptions(options, metadataUrl, done) {
  const self = this;

  // Loading metadata from endpoint.
  async.waterfall([
    // fetch the metadata
    function loadMetadata(next) {
      log.info('Parsing Metadata: ', metadataUrl);

      memoryCache.wrap(self._cacheKey, (cacheCallback) => {
        const metadata = new Metadata(metadataUrl, 'oidc', options);
        metadata.fetch((fetchMetadataError) => {
          if (fetchMetadataError) {
            return cacheCallback(new Error(`Unable to fetch metadata: ${fetchMetadataError}`));
          }
          return cacheCallback(null, metadata);
        });
      }, { ttl }, next);
    },
    // merge fetched metadata with options
    function loadOptions(metadata, next) {
      // fetched metadata always takes precendence over configured options

      self._skipUserProfile = !!options.skipUserProfile;

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
      });

      _.assign(opts, pickedFromOptions, pickedFromMetadata);

      // Now that we have our options for configuration, let's check them for issues.
      const validatorConfig = {
        clientID: Validator.isNonEmpty,
        callbackURL: Validator.isNonEmpty,
        responseType: Validator.isTypeLegal,
        responseMode: Validator.isModeLegal,
        authorizationURL: Validator.isURL,
        tokenURL: Validator.isURL,
        // callbackURL: Validator.isURL  // We allow http for now :-/
      };

      // validator will throw exception if a required option is missing
      const checker = new Validator(validatorConfig);
      checker.validate(opts);

      next(null, opts);
    },
    // push merged options to self._configurers for later use
    function setConfiguration(opts, next) {
      log.info('Setting configuration for later', opts);

      self.configure((identifier, configureDone) => {
        return configureDone(null, objectTransform({
          source: opts,
          pick: [
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
        }));
      });
      next();
    },
  ], done);
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
Strategy.prototype.configure = function configureStrategy(identifier, done) {
  if (typeof identifier === 'function') {
    return this._configurers.push(identifier);
  }

  // private implementation that traverses the chain of configurers, attempting
  // to load configuration
  const stack = this._configurers;
  (function pass(i, err, config) {
    // an error or configuration was obtained, done
    if (err || config) {
      return done(err, config);
    }

    const layer = stack[i];
    if (!layer) {
      // Strategy-specific functions did not result in obtaining configuration
      // details.  Proceed to protocol-defined mechanisms in an attempt
      // to discover the provider's configuration.
      return setup(identifier, done);
    }

    try {
      layer(identifier, (layerError, layerConfig) => { pass(i + 1, layerError, layerConfig); });
    } catch (ex) {
      return done(ex);
    }
    return false;
  }(0));
  return false;
};

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function shouldLoadUserProfile(issuer, subject, done) {
  // check if _skipUserProfile is an async function (expexts more than 2 arguments)
  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 2) {
    return this._skipUserProfile(issuer, subject, (err, skip) => {
      return done(err, !skip);
    });
  }
  const skip = (typeof this._skipUserProfile === 'function') ?
    this._skipUserProfile(issuer, subject) :
    this._skipUserProfile;
  return done(null, !skip);
};

module.exports = Strategy;
