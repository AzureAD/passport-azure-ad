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

'use strict';


var passport = require('passport');
var util = require('util');
var saml = require('./wsfedsaml');
var wsfed = require('./wsfederation');
var Metadata = require('./metadata').Metadata;


function Strategy (options, verify) {
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
  if(options.identityMetadata) {
    this.metadata = new Metadata(options.identityMetadata);
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
  this._wsfed =  new wsfed(options);
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req) {
  var self = this,
    wsfed;

  if(this.metadata && !this.metadata.wsfed) {
    this.metadata.fetch(function(err) {
      if(err) {
        return this.error(err);
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

Strategy.prototype._doAuthenticate = function (req) {
  var self = this;

  if (req.body && req.method === 'POST') {
    // We have a response, get the user identity out of it
    var token = this._wsfed.extractToken(req);
    self._saml.validateResponse(token, function (err, profile) {
      if (err) {
        return self.error(err);
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
    // Initiate new ws-fed authentication request
    this._wsfed.getRequestSecurityTokenUrl({}, function(err, url) {
      if(err) {
        return self.error(err);
      } else {
        return self.redirect(url);
      }
    });
  }
};


module.exports = Strategy;