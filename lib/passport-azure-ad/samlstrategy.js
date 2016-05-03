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

'use strict';

/* eslint no-underscore-dangle: 0 */

const util = require('util');
const passport = require('passport');
const saml = require('./saml');

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

function Strategy(options, verifyFn) {
  const verify = (typeof options === 'function') ? options : verifyFn;
  const opts = (typeof options === 'function') ? {} : options;

  // Passport requires a verify function
  if (typeof verify !== 'function') {
    throw new TypeError('SAMLStrategy requires a verify callback.');
  }

  passport.Strategy.call(this);
  this.name = 'saml';

  this._verify = verify;
  this._saml = new saml.SAML(opts);
  this._passReqToCallback = !!opts.passReqToCallback;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function authenticate(req) {
  const self = this;
  if (req.body && req.body.SAMLResponse) {
    // We have a response, get the user identity out of it
    const response = req.body.SAMLResponse;

    self._saml.validateResponse(response, (validateResponseError, profile, loggedOut) => {
      if (validateResponseError) {
        return self.error(validateResponseError);
      }

      if (loggedOut) {
        if (self._saml.options.logoutRedirect) {
          return self.redirect(self._saml.options.logoutRedirect);
        }
        return self.redirect('/');
      }

      function verified(verifyError, user, info) {
        if (verifyError) {
          return self.error(verifyError);
        }

        if (!user) {
          return self.fail(info);
        }

        return self.success(user, info);
      }

      if (self._passReqToCallback) {
        return self._verify(req, profile, verified);
      }
      return self._verify(profile, verified);
    });
  } else {
    // Initiate new SAML authentication request
    self._saml.getAuthorizeUrl(req, (err, url) => {
      if (err) {
        return self.fail();
      }

      return self.redirect(url);
    });
  }
};

Strategy.prototype.logout = function logout(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

Strategy.prototype.identity = function identity(callback) {
  this._saml.identity(callback);
};

module.exports = Strategy;
