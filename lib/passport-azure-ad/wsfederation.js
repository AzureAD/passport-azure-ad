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

var xmldom = require('xmldom');
var xtend = require('xtend');
var qs = require('querystring');

var WsFederation = module.exports = function WsFederation (options) {
  this.realm = options.realm;

  if(options.homeRealm) {
    this.homerealm = options.homerealm;
  } else {
    this.homerealm = '';
  }
  this.identityProviderUrl = options.identityProviderUrl;
  this.wreply = options.wreply;
  this.logoutUrl = options.logoutUrl;
};


WsFederation.prototype.getRequestSecurityTokenUrl = function (options, callback) {

  var query = xtend(options || {}, {
    wtrealm: this.realm,
    wa:      'wsignin1.0'
  });

  if (this.homerealm) {
    query.whr = this.homerealm;
  } else {
    query.whr = '';

  }

  if (this.wreply) {
    query.wreply = this.wreply;
  }

    callback(null,this.identityProviderUrl + '?' + qs.encode(query));
};

WsFederation.prototype.logout = function (options, callback) {

  var query = xtend(options || {}, {
    wtrealm: this.realm,
    wa:      'wsignout1.0'
  });

  if (this.homerealm) {
    query.whr = this.homerealm;
  } else {
    query.whr = '';
  }

  query.wreply = this.logoutUrl;

  callback(null,this.identityProviderUrl + '?' + qs.encode(query));
};


WsFederation.prototype.extractToken = function(req) {

  var doc = new xmldom.DOMParser().parseFromString(req.body['wresult']);
  var token = doc.getElementsByTagNameNS('http://schemas.xmlsoap.org/ws/2005/02/trust', 'RequestedSecurityToken')[0].firstChild;
  var tokenString = new xmldom.XMLSerializer().serializeToString(token);

  return tokenString;
};

Object.defineProperty(WsFederation, 'realm', {
  get: function () {
    return this.realm;
  }
});

Object.defineProperty(WsFederation, 'homeRealm', {
  get: function () {
    return this.homeRealm;
  }
});

Object.defineProperty(WsFederation, 'identityProviderUrl', {
  get: function () {
    return this.identityProviderUrl;
  },
  set: function (url) {
    this.identityProviderUrl = url;
  }
});

