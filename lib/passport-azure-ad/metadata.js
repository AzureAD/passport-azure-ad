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

const xml2js = require('xml2js');
const request = require('request');
const async = require('async');
const objectTransform = require('oniyi-object-transform');
const aadutils = require('./aadutils');

const Log = require('./logging').getLogger;

const log = new Log('AzureAD: Metadata Parser');

function Metadata(url, authtype, options) {
  if (!url) {
    throw new Error('Metadata: url is a required argument');
  }
  if (!authtype) {
    throw new Error('OIDCBearerStrategy requires an authentication type specified to metadata parser. Valid types are `saml`, `wsfed`, or `odic`');
  }

  // if logging level specified, switch to it.
  if (options.loggingLevel) { log.levels('console', options.loggingLevel); }

  this.url = url;
  this.metadata = null;
  this.authtype = authtype;
}

Object.defineProperty(Metadata, 'url', {
  get: function getUrl() {
    return this.url;
  },
});

Object.defineProperty(Metadata, 'saml', {
  get: function getSaml() {
    return this.saml;
  },
});

Object.defineProperty(Metadata, 'wsfed', {
  get: function getWsfed() {
    return this.wsfed;
  },
});

Object.defineProperty(Metadata, 'oidc', {
  get: function getOidc() {
    return this.oidc;
  },
});

Object.defineProperty(Metadata, 'metadata', {
  get: function getMetadata() {
    return this.metadata;
  },
});

Metadata.prototype.updateSamlMetadata = function updateSamlMetadata(doc, next) {
  try {
    this.saml = {};

    const entity = aadutils.getElement(doc, 'EntityDescriptor');
    const idp = aadutils.getElement(entity, 'IDPSSODescriptor');
    const signOn = aadutils.getElement(idp[0], 'SingleSignOnService');
    const signOff = aadutils.getElement(idp[0], 'SingleLogoutService');
    const keyDescriptor = aadutils.getElement(idp[0], 'KeyDescriptor');
    this.saml.loginEndpoint = signOn[0].$.Location;
    this.saml.logoutEndpoint = signOff[0].$.Location;

    // copy the x509 certs from the metadata
    this.saml.certs = [];
    for (let j = 0; j < keyDescriptor.length; j++) {
      this.saml.certs.push(keyDescriptor[j].KeyInfo[0].X509Data[0].X509Certificate[0]);
    }
    next(null);
  } catch (e) {
    next(new Error(`Invalid SAMLP Federation Metadata ${e.message}`));
  }
};

Metadata.prototype.updateWsfedMetadata = function updateWsfedMetadata(doc, next) {
  try {
    this.wsfed = {};
    const entity = aadutils.getElement(doc, 'EntityDescriptor');
    const roles = aadutils.getElement(entity, 'RoleDescriptor');
    for (let i = 0; i < roles.length; i++) {
      const role = roles[i];
      if (role['fed:SecurityTokenServiceEndpoint']) {
        const endpoint = role['fed:SecurityTokenServiceEndpoint'];
        const endPointReference = aadutils.getFirstElement(endpoint[0], 'EndpointReference');
        this.wsfed.loginEndpoint = aadutils.getFirstElement(endPointReference, 'Address');

        const keyDescriptor = aadutils.getElement(role, 'KeyDescriptor');
        // copy the x509 certs from the metadata
        this.wsfed.certs = [];
        for (let j = 0; j < keyDescriptor.length; j++) {
          this.wsfed.certs.push(keyDescriptor[j].KeyInfo[0].X509Data[0].X509Certificate[0]);
        }
        break;
      }
    }
  } catch (e) {
    next(new Error(`Invalid WSFED Federation Metadata ${e.message}`));
  }
  return next(null);
};

Metadata.prototype.updateOidcMetadata = function updateOidcMetadata(doc, next) {
  log.info('Request to update the Open ID Connect Metadata');

  const self = this;

  self.oidc = objectTransform({
    source: doc,
    map: {
      id_token_signing_alg_values_supported: 'algorithms',
      authorization_endpoint: 'auth_endpoint',
    },
    whitelist: [
      'issuer',
      'auth_endpoint',
      'algorithms',
      'token_endpoint',
      'userinfo_endpoint',
      'end_session_endpoint',
    ],
  });
  const jwksUri = doc.jwks_uri;

  log.info('Algorithm retrieved was: ', self.oidc.algorithms);
  log.info('Issuer we are using is: ', self.oidc.issuer);
  log.info('Key Endpoint we will use is: ', jwksUri);
  log.info('Authentication endpoint we will use is: ', self.oidc.auth_endpoint);
  log.info('Token endpoint we will use is: ', self.oidc.token_endpoint);
  log.info('User info endpoint we will use is: ', self.oidc.userinfo_endpoint);
  log.info('The logout endpoint we will use is: ', self.oidc.end_session_endpoint);

  // fetch the signing keys
  request.get(jwksUri, { json: true }, (err, response, body) => {
    if (err) {
      return next(err);
    }
    if (response.statusCode !== 200) {
      return next(new Error(`Error: ${response.statusCode} Cannot get AAD Signing Keys`));
    }
    self.oidc.keys = body.keys;
    return next();
  });
};

Metadata.prototype.generateOidcPEM = function generateOidcPEM(kid) {
  const keys = this && this.oidc && Array.isArray(this.oidc.keys) ? this.oidc.keys : null;
  let pubKey = null;

  if (!(kid && keys)) {
    return null;
  }

  keys.some((key) => {
    log.info('working on key:', key);

    // are we working on the right key?
    if (!key.kid === kid) {
      return false;
    }

    // check for `modulus` to be present
    if (!key.n) {
      log.warn('modulus is empty; corrupt key', key);
      return false;
    }

    // check for `exponent` to be present
    if (!key.e) {
      log.warn('exponent is empty; corrupt key', key);
      return false;
    }

    // generate PEM from `modulus` and `exponent`
    const modulus = new Buffer(key.n, 'base64');
    const exponent = new Buffer(key.e, 'base64');

    pubKey = aadutils.rsaPublicKeyPem(modulus, exponent);
    return pubKey;
  });

  return pubKey;
};

Metadata.prototype.fetch = function fetch(callback) {
  const self = this;

  async.waterfall([
    // fetch the Federation metadata for the AAD tenant
    (next) => {
      request.get(self.url, (err, response, body) => {
        if (err) {
          return next(err);
        }
        if (response.statusCode !== 200) {
          log.error('Cannot get AAD Federation metadata from endpoint you specified', self.url);
          return next(new Error(`Error: ${response.statusCode} Cannot get AAD Federation metadata from ${self.url}`));
        }
        return next(null, body);
      });
    },
    // parse retrieved metadata (could be xml or json)
    (body, next) => {
      // use xml parser for saml or wsfed authTypes
      if (self.authtype === 'saml' || self.authtype === 'wsfed') {
        // parse the AAD Federation metadata xml
        const parser = new xml2js.Parser({
          explicitRoot: true,
        });

        // Note: xml responses from Azure AAD have a leading \ufeff which breaks xml2js parser!
        return parser.parseString(body.replace('\ufeff', ''), (err, data) => {
          self.metatdata = data;
          next(err);
        });
      }

      // use json parser for oidc authType
      if (self.authtype === 'oidc') {
        log.info('Parsing JSON retreived from the endpoint');
        self.metadata = JSON.parse(body);
        return next(null);
      }

      // no supported authType found
      log.error('No Authentication type specified to metadata parser. Valid types are saml, wsfed, or odic');
      return next(new Error('No Authentication type specified to metadata parser. Valid types are saml, wsfed, or odic'));
    },
    // call update method for parsed metadata and authType
    (next) => {
      if (self.authtype === 'saml') {
        return self.updateSamlMetadata(self.metatdata, next);
      }
      if (self.authtype === 'wsfed') {
        return self.updateWsfedMetadata(self.metatdata, next);
      }
      if (self.authtype === 'oidc') {
        return self.updateOidcMetadata(self.metadata, next);
      }
      return next(new Error(`unsupported authType '${self.authtype}'`));
    },
  ], (waterfallError) => {
    // return err or success (err === null) to callback
    callback(waterfallError);
  });
};

exports.Metadata = Metadata;
