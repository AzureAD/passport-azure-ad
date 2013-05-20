/*
 Copyright (c) Microsoft Open Technologies, Inc.
 All Rights Reserved
 Apache License 2.0

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

"use strict";

var passport = require('passport');
var util = require('util');
var saml = require('./saml');

function Strategy (options, verify) {
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
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req) {
  var self = this;
  if (req.body && req.body.SAMLResponse) {
    // We have a response, get the user identity out of it
    var response = req.body.SAMLResponse;

    this._saml.validateResponse(response, function (err, profile, loggedOut) {
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

      var verified = function (err, user, info) {
        if (err) {
          return self.error(err);
        }

        if (!user) {
          return self.fail(info);
        }

        self.success(user, info);
      };

      self._verify(profile, verified);
    });
  } else {
    // Initiate new SAML authentication request

    this._saml.getAuthorizeUrl(req, function (err, url) {
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
