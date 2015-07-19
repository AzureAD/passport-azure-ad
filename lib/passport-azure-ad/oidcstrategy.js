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

/*jslint node: true */
"use strict";

var passport = require('passport');
var url = require('url');
var querystring = require('querystring');
var util = require('util');
var utils = require('./aadutils');
var OAuth2 = require('oauth').OAuth2;
var setup = require('./oidcsetup');
var Metadata = require('./metadata').Metadata;
var InternalOAuthError = require('./errors/internaloautherror');

// Logging

var bunyan = require('bunyan');
var log = bunyan.createLogger({
    name: 'Microsoft OpenID Connect: Passport Strategy: OIDC Strategy'
});

var PEMkey = null;
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

 // if you want to check JWT issuer that is not in the token (not recommended), provide a value here

    if (options.identityMetadata) {

        log.info('Metadata url provided to Strategy was: ', options.identityMetadata);
        this.metadata = new Metadata(options.identityMetadata, "oidc");
    }

    if (!options.certificate && !options.identityMetadata) {
        log.warn("No options was presented to Strategy as required.");
        throw new TypeError('BearerStrategy requires either a PEM encoded public key or a metadata location that contains cert data for RSA and ECDSA callback.');
    }

    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    // Passport requires a verify function

    if (!verify) {
        throw new TypeError('OIDCStrategy requires a verify callback. Do not cheat!');
    }

    // Token validation settings. Hopefully most of these will be pulled from the metadata and this is not needed


    this.metadata.fetch(function(err) {
        if (err) {
            throw new Error("Unable to fetch metadata: " + err);
        }

    });

  // TODO: What's the recommended field name for OpenID Connect?
  this._identifierField = options.identifierField || 'openid_identifier';
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

    this.configurers = [];

    options.authorizationURL = this.metadata.oidc.auth_endpoint;
    options.tokenURL = this.metadata.oidc.token_endpoint;
    options.userInfoURL = this.metadata.oidc.userinfo_endpoint;
    options.revocationURL = this.metadata.oidc.end_session_endpoint;
    options.tokenInfoURL = null; //TODO: Do we have this? I think not.
    options.oidcIssuer = this.metadata.oidc.issuer;

    if (options.authorizationURL && options.tokenURL) {
        // This OpenID Connect strategy is configured correctly to work with AzureAD

        this.configure(function(identifier, done) {
            return done(null, {
                authorizationURL: options.authorizationURL,
                tokenURL: options.tokenURL,
                userInfoURL: options.userInfoURL,
                clientID: options.clientID,
                clientSecret: options.clientSecret,
                callbackURL: options.callbackURL,
                revocationURL: options.revocationURL,
                tokenInfoURL: options.tokenInfoURL,
                oidcIssuer: options.oidcIssuer
            });
        });
    }

    passport.Strategy.call(this);

    this.name = 'azuread-openidconnect'; // me, a name I call myself
}

/**
 * Authenticate request by delegating to an OpenID Connect provider.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
        // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
        //       query parameters, and should be propagated to the application.
        return this.fail();
    }


    if (req.query && req.query.code) {
        var code = req.query.code;

        this.configure(null, function(err, config) {
            if (err) {
                return self.error(err);
            }

            var oauth2 = new OAuth2(config.clientID, config.clientSecret,
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

            oauth2.getOAuthAccessToken(code, {
                grant_type: 'authorization_code',
                redirect_uri: callbackURL
            }, function(err, accessToken, refreshToken, params) {
                if (err) {
                    return self.error(new InternalOAuthError('failed to obtain access token', err));
                }

                if (log_verbose) {
                    log.info('Tokens were received! They are: ');
                    log.info('AT: ' + accessToken);
                    log.info('RT: ' + refreshToken);
                    log.info(params);
                    log.info('----');
                }

                var idToken = params['id_token'];
                if (!idToken) {
                    return self.error(new Error('ID Token not present in token response'));
                }

                var idTokenSegments = idToken.split('.'),
                    jwtClaimsStr, jwtClaims;

                try {
                    jwtClaimsStr = new Buffer(idTokenSegments[1], 'base64').toString();
                    jwtClaims = JSON.parse(jwtClaimsStr);
                } catch (ex) {
                    return self.error(ex);
                }

                if (log_verbose) {
                    console.log(jwtClaims);
                }

                var iss = jwtClaims.iss;
                var sub = jwtClaims.sub;
                // Prior to OpenID Connect Basic Client Profile 1.0 - draft 22, the
                // "sub" claim was named "user_id".  Many providers still issue the
                // claim under the old field, so fallback to that.
                if (!sub) {
                    sub = jwtClaims.user_id;
                }

                // ID Token Validation
                //   http://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2.1

                {
                    // 1. iss(issuer)
                    if (config.oidcIssuer != jwtClaims.iss) {
                        return self.error(new InternalOAuthError('validate error. issuer not match: ' + jwtClaims.iss, err));
                    }

                    // 2. aud(audience)
                    if (config.clientID != jwtClaims.aud) {
                        return self.error(new InternalOAuthError('validate error. audience not match: ' + jwtClaims.aud, err));
                    }

                    // 5. exp
                    var epoch = Math.round(new Date() / 1000);
                    if (log_verbose) {
                        console.log('exp  =' + jwtClaims.exp);
                        console.log('epoch=' + epoch);
                    }
                    if (jwtClaims.exp <= epoch) {
                        return self.error(new InternalOAuthError('validate error. expired: ' + jwtClaims.exp, err));
                    }
                }

                self._shouldLoadUserProfile(iss, sub, function(err, load) {
                    if (err) {
                        return self.error(err);
                    };

                    if (load) {
                        var parsed = url.parse(config.userInfoURL, true);
                        parsed.query['schema'] = 'openid';
                        delete parsed.search;
                        var userInfoURL = url.format(parsed);

                        // NOTE: We are calling node-oauth's internal `_request` function (as
                        //       opposed to `get`) in order to send the access token in the
                        //       `Authorization` header rather than as a query parameter.
                        //
                        //       Additionally, the master branch of node-oauth (as of
                        //       2013-02-16) will include the access token in *both* headers
                        //       and query parameters, which is a violation of the spec.
                        //       Setting the fifth argument of `_request` to `null` works
                        //       around this issue.  I've noted this in comments here:
                        //       https://github.com/ciaranj/node-oauth/issues/117

                        //oauth2.get(userInfoURL, accessToken, function (err, body, res) {
                        oauth2._request("GET", userInfoURL, {
                            'Authorization': "Bearer " + accessToken,
                            'Accept': "application/json"
                        }, null, null, function(err, body, res) {
                            if (err) {
                                return self.error(new InternalOAuthError('failed to fetch user profile', err));
                            }


                            log.info('PROFILE');
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
                                profile.name = {
                                    familyName: json.family_name,
                                    givenName: json.given_name,
                                    middleName: json.middle_name
                                };

                                profile._raw = body;
                                profile._json = json;

                                onProfileLoaded(profile);
                            } catch (ex) {
                                return self.error(ex);
                            }
                        });
                    } else {
                        var profile = {};
                        profile.id = sub;
                        onProfileLoaded(profile);
                    }

                    function onProfileLoaded(profile) {
                        function verified(err, user, info) {
                            if (err) {
                                return self.error(err);
                            }
                            if (!user) {
                                return self.fail(info);
                            }
                            self.success(user, info);
                        }

                        if (self._passReqToCallback) {
                            var arity = self._verify.length;
                            if (arity == 9) {
                                self._verify(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
                            } else if (arity == 8) {
                                self._verify(req, iss, sub, profile, accessToken, refreshToken, params, verified);
                            } else if (arity == 7) {
                                self._verify(req, iss, sub, profile, accessToken, refreshToken, verified);
                            } else if (arity == 5) {
                                self._verify(req, iss, sub, profile, verified);
                            } else { // arity == 4
                                self._verify(req, iss, sub, verified);
                            }
                        } else {
                            var arity = self._verify.length;
                            if (arity == 8) {
                                self._verify(iss, sub, profile, jwtClaims, accessToken, refreshToken, params, verified);
                            } else if (arity == 7) {
                                self._verify(iss, sub, profile, accessToken, refreshToken, params, verified);
                            } else if (arity == 6) {
                                self._verify(iss, sub, profile, accessToken, refreshToken, verified);
                            } else if (arity == 4) {
                                self._verify(iss, sub, profile, verified);
                            } else { // arity == 3
                                self._verify(iss, sub, verified);
                            }
                        }
                    }

                });
            });
        });
    } else {
        // The request being authenticated is initiating OpenID Connect
        // authentication.  Prior to redirecting to the provider, configuration will
        // be loaded.  The configuration is typically either pre-configured or
        // discovered dynamically.  When using dynamic discovery, a user supplies
        // their identifer as input.

        var identifier;
        if (req.body && req.body[this._identifierField]) {
            identifier = req.body[this._identifierField];
        } else if (req.query && req.query[this._identifierField]) {
            identifier = req.query[this._identifierField];
        }

        this.configure(identifier, function(err, config) {
            if (err) {
                return self.error(err);
            }

            var callbackURL = options.callbackURL || config.callbackURL;
            if (callbackURL) {
                var parsed = url.parse(callbackURL);
                if (!parsed.protocol) {
                    // The callback URL is relative, resolve a fully qualified URL from the
                    // URL of the originating request.
                    callbackURL = url.resolve(utils.originalURL(req), callbackURL);
                }
            }

            var params = self.authorizationParams(options);
            params['response_type'] = 'code';
            params['client_id'] = config.clientID;
            params['redirect_uri'] = callbackURL;
            var scope = options.scope || self._scope;
            if (Array.isArray(scope)) {
                scope = scope.join(self._scopeSeparator);
            }
            if (scope) {
                params.scope = 'openid' + self._scopeSeparator + scope;
            } else {
                params.scope = 'openid';
            }

            var location = config.authorizationURL + '?' + querystring.stringify(params);
            self.redirect(location);
        });
    }
}

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
        if (err || config) {
            return done(err, config);
        }

        var layer = stack[i];
        if (!layer) {
            // Strategy-specific functions did not result in obtaining configuration
            // details.  Proceed to protocol-defined mechanisms in an attempt
            // to discover the provider's configuration.
            return setup(identifier, done);
        }

        try {
            layer(identifier, function(e, c) {
                pass(i + 1, e, c);
            })
        } catch (ex) {
            return done(ex);
        }
    })(0);
}


/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OpenID Connect providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OpenID Connect specification, OpenID Connect-based
 * authentication strategies can overrride this function in order to populate
 * these parameters as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    if (options.state) {
        params['state'] = options.state;
    }
    if (options.prompt) {
        params['prompt'] = options.prompt;
    }
    if (options.display) {
        params['display'] = options.display;
    }
    if (options.login_hint) {
        params['login_hint'] = options.login_hint;
    }
    if (options.accessType) {
        params['access_type'] = options.accessType;
    }
    if (options.openidRealm) {
        params['openid.realm'] = options.openidRealm;
    }
    if (options.hd) {
        params['hd'] = options.hd;
    }
    return params;
}

/**
 * Check if should load user profile, contingent upon options.
 *
 * @param {String} issuer
 * @param {String} subject
 * @param {Function} done
 * @api private
 */
Strategy.prototype._shouldLoadUserProfile = function(issuer, subject, done) {
    if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
        // async
        this._skipUserProfile(issuer, subject, function(err, skip) {
            if (err) {
                return done(err);
            }
            if (!skip) {
                return done(null, true);
            }
            return done(null, false);
        });
    } else {
        var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile(issuer, subject) : this._skipUserProfile;
        if (!skip) {
            return done(null, true);
        }
        return done(null, false);
    }
}

Strategy.prototype.revoke = function(options, done) {
    var self = this;

    this.configure(null, function(err, config) {
        if (err) {
            return done(err);
        }

        var oauth2 = new OAuth2(config.clientID, config.clientSecret,
            '', config.authorizationURL, config.tokenURL);

        var revocationURL = options.revocationURL || config.revocationURL;
        if (revocationURL) {
            var parsed = url.parse(revocationURL);
            if (!parsed.protocol) {
                // The callback URL is relative, resolve a fully qualified URL from the
                // URL of the originating request.
                revocationURL = url.resolve(utils.originalURL(req), revocationURL);
            }
        }

        var param = '?token=' + options.accessToken;

        log.info('revoke param=');
        log.info(param);

        oauth2._request("GET", revocationURL + param, {
            'Authorization': "Bearer " + options.accessToken,
            'Accept': "application/json"
        }, null, null, function(err, body, res) {

            log.info('REVOKE');
            log.info(body);
            log.info(res);

            if (err) {
                return done(new InternalOAuthError('failed to revoke access token', err));
            }
            done(null);
        });
    });
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
