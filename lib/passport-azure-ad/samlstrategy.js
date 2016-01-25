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

/*jslint node: true */
"use strict";

var passport = require('passport');
var util = require('util');
var saml = require('./saml');

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
        throw new Error('SAML authentication strategy requires a verify function');
    }

    this.name = 'saml';

    passport.Strategy.call(this);

    this._verify = verify;
    this._saml = new saml.SAML(options);
    this._passReqToCallback = !!options.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {
    var self = this;
    if (req.body && req.body.SAMLResponse) {
        // We have a response, get the user identity out of it
        var response = req.body.SAMLResponse;

        this._saml.validateResponse(response, function(err, profile, loggedOut) {
            if (err) {
                return self.error(err);
            }

            if (loggedOut) {
                if (self._saml.options.logoutRedirect) {
                    self.redirect(self._saml.options.logoutRedirect);
                    return;
                } else {
                    self.redirect("/");
                }

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
        // Initiate new SAML authentication request

        this._saml.getAuthorizeUrl(req, function(err, url) {
            if (err) {
                return self.fail();
            }

            self.redirect(url);
        });
    }

};

Strategy.prototype.logout = function(req, callback) {
    this._saml.getLogoutUrl(req, callback);
};

Strategy.prototype.identity = function(callback) {
    this._saml.identity(callback);
};

module.exports = Strategy;
