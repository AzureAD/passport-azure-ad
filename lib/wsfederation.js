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

const xmldom = require('xmldom');
const xtend = require('xtend');
const qs = require('querystring');

function WsFederation(options) {
  this.realm = options.realm;

  if (options.homeRealm) {
    this.homerealm = options.homeRealm;
  } else {
    this.homerealm = '';
  }
  this.identityProviderUrl = options.identityProviderUrl;
  this.wreply = options.wreply;
  this.logoutUrl = options.logoutUrl;
}

WsFederation.prototype.getRequestSecurityTokenUrl = function getRequestSecurityTokenUrl(options, callback) {
  const query = xtend(options || {}, {
    wtrealm: this.realm,
    wa: 'wsignin1.0',
  });

  if (this.homerealm) {
    query.whr = this.homerealm;
  } else {
    query.whr = '';
  }

  if (this.wreply) {
    query.wreply = this.wreply;
  }

  callback(null, `${this.identityProviderUrl}?${qs.encode(query)}`);
};

WsFederation.prototype.logout = function logout(options, callback) {
  const query = xtend(options || {}, {
    wtrealm: this.realm,
    wa: 'wsignout1.0',
  });

  if (this.homerealm) {
    query.whr = this.homerealm;
  } else {
    query.whr = '';
  }

  query.wreply = this.logoutUrl;

  callback(null, `${this.identityProviderUrl}?${qs.encode(query)}`);
};

WsFederation.prototype.extractToken = function extractToken(req) {
  const wresult = (req.params && req.params.wresult) ? req.params.wresult : req.body.wresult;
  const doc = new xmldom.DOMParser().parseFromString(wresult);
  const token = doc.getElementsByTagNameNS(
    'http://schemas.xmlsoap.org/ws/2005/02/trust',
    'RequestedSecurityToken')[0].firstChild;
  const tokenString = new xmldom.XMLSerializer().serializeToString(token);

  return tokenString;
};

Object.defineProperty(WsFederation, 'realm', {
  get: function getRealm() {
    return this.realm;
  },
});

Object.defineProperty(WsFederation, 'homeRealm', {
  get: function getHomeRealm() {
    return this.homeRealm;
  },
});

Object.defineProperty(WsFederation, 'identityProviderUrl', {
  get: function getIdentityProviderUlr() {
    return this.identityProviderUrl;
  },
  set: function setIdentityProviderUlr(url) {
    this.identityProviderUrl = url;
  },
});

module.exports = WsFederation;
