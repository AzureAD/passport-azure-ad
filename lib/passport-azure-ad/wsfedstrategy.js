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
'use strict';


var passport = require('passport');
var util = require('util');
var saml = require('./wsfedsaml');
var wsfed = require('./wsfederation');
var Metadata = require('./metadata').Metadata;
var bunyan = require('bunyan');

var log = bunyan.createLogger({
    name: 'Microsoft WSFederation: Passport Strategy'
});
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
 *   - `realm`    authentication realm, defaults to "Users"
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


function Strategy(options, verify) {
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    if (!verify) {
        throw new Error('Windows Azure Access Control Service authentication strategy requires a verify function');
    }

    this.name = 'wsfed-saml2';

    passport.Strategy.call(this);

    if (!options.realm) {
        throw new Error('options.realm is required.');
    }

    if (!options.logoutUrl) {
        throw new Error('options.logoutUrl is required.');
    }

    this.realm = options.realm;
    this.certs = [];

    // Create the metadata object if the user has specified a federation metadata url
    if (options.identityMetadata) {
        this.metadata = new Metadata(options.identityMetadata, 'wsfed');
        this.identityProviderUrl = null;
    } else {
        if (!options.cert) {
            throw new Error('options.cert is required. You must set a X509Certificate certificate from the federationmetadata.xml file for your app');
        }
        if (!options.identityProviderUrl) {
            throw new Error('option.identityProviderUrl is required You must set the identityProviderUrl for your app');
        }

        this.metadata = null;
        this.identityProviderUrl = options.identityProviderUrl;
        this.certs.push(options.cert);
    }

    options.metadata = this.metadata;

    this._verify = verify;
    this._saml = new saml.SAML(options);
    this._wsfed = new wsfed(options);
    this._passReqToCallback = !!options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
    var self = this,
        wsfed;

    if (this.metadata && !this.metadata.wsfed) {
        this.metadata.fetch(function(err) {
            if (err) {
                return self.error(err);
            } else {
                wsfed = self.metadata.wsfed;
                self._saml.certs = wsfed.certs;
                self._wsfed.identityProviderUrl = wsfed.loginEndpoint;
                self._doAuthenticate(req);
            }
        });
    } else {
        self._doAuthenticate(req);
    }
};

Strategy.prototype.logout = function(options, callback) {
    this._wsfed.logout(options, callback);
};

Strategy.prototype._doAuthenticate = function(req) {
    var self = this;

    if (req.body && req.method === 'POST') {
        // We have a response, get the user identity out of it
        var token = this._wsfed.extractToken(req);
        self._saml.validateResponse(token, function(err, profile) {
            if (err) {
                return self.error(err);
            }

            var verified = function(err, user, info) {
                if (err) {
                    return self.error(err);
                }

                if (!user) {
                    return self.fail(info);
                }

                self.success(user, info);
            };

            if (self._passReqToCallback) {
                self._verify(req, profile, verified);
            } else {
                self._verify(profile, verified);
            }
        });
    } else {
        // Initiate new ws-fed authentication request
        this._wsfed.getRequestSecurityTokenUrl({}, function(err, url) {
            if (err) {
                return self.error(err);
            } else {
                return self.redirect(url);
            }
        });
    }
};


module.exports = Strategy;
