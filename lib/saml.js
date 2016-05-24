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

const zlib = require('zlib');
const crypto = require('crypto');
const querystring = require('querystring');
const async = require('async');
const xml2js = require('xml2js');
const xmlCrypto = require('xml-crypto');
const xmldom = require('xmldom');
const objectTransform = require('oniyi-object-transform');
const Validator = require('./validator').Validator;
const templates = require('./templates/templates');
const pem = require('./pem');
const aadutils = require('./aadutils');
const samlutils = require('./samlutils');
const Metadata = require('./metadata').Metadata;

const SamlUrn = {
  success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
};

function SAML(options) {
  // required options for SAML
  const config = {
    identityMetadata: Validator.isNonEmpty,
    loginCallback: Validator.isNonEmpty,
    issuer: Validator.isNonEmpty,
  };

  // enforce that user has provided both public and private certs if at least one cert is present
  // or logoutCallback is present
  if (options.privateCert || options.publicCert || options.logoutCallback) {
    config.logoutCallback = Validator.isNonEmpty;
    config.privateCert = Validator.isNonEmpty;
    config.publicCert = Validator.isNonEmpty;
  }

  // validator will throw exception if a required option is missing
  const checker = new Validator(config);
  checker.validate(options);
  this.options = this.initialize(options);
  this.metadata = new Metadata(options.identityMetadata, 'saml', options);
  this.federationMetadata = null;
}

SAML.prototype.initialize = function initialize(options) {
  // @TODO: there should be a better way to define optional defaults, do they really have to be empty strings?
  const opts = aadutils.merge({
    protocol: 'https://',
    x509PublicCert: '',
    // setup optional service federation metadata parameters
    organizationName: '',
    organizationDisplayName: '',
    organizationUrl: '',
    contactFirstName: '',
    contactLastName: '',
    contactEmail: '',
  }, options || {});

  if (opts.publicCert) {
    opts.x509PublicCert = pem.getCertificate(opts.publicCert);
  }

  return opts;
};

SAML.prototype.identity = function identity(callback) {
  // params for the metadata template
  const params = objectTransform({
    source: this.options,
    map: {
      issuer: 'APP_ID_URI',
      appUrl: 'APP_URL',
      loginCallback: 'LOGIN_CALLBACK',
      logoutCallback: 'LOGOUT_CALLBACK',
      x509PublicCert: 'CERT',
      organizationName: 'ORGANIZATON_NAME',
      organizationDisplayName: 'ORGANIZATON_DISPLAY_NAME',
      organizationUrl: 'ORGANIZATON_URL',
      contactFirstName: 'GIVEN_NAME',
      contactLastName: 'SURNAME',
      contactEmail: 'EMAIL',
    },
  });

  const self = this;
  if (this.federationMetadata === null) {
    templates.compile('federationmetadata.template.xml', params, (compileError, data) => {
      if (compileError === null) {
        self.federationMetadata = data;
      }
      callback(compileError, data);
    });
  } else {
    callback(null, this.federationMetadata);
  }
};

SAML.prototype.signRequest = function signRequest(xml) {
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function generateAuthorizeRequest() {
  const id = `id${samlutils.generateUniqueID()}`;
  const instant = samlutils.generateInstant();

  // build callback based on host we are running on?
  // loginCallback = this.options.protocol + req.headers.host + this.options.path;

  const request = `<samlp:AuthnRequest
                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="${id}"
                    Version="2.0"
                    IssueInstant="${instant}"
                    IsPassive="false"
                    AssertionConsumerServiceURL="${this.options.loginCallback}"
                  >
                    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
                      ${this.options.issuer}
                    </Issuer>
                  </samlp:AuthnRequest>`;
  return request;
};

SAML.prototype.generateLogoutRequest = function generateLogoutRequest(req) {
  const id = `_${samlutils.generateUniqueID()}`;
  const instant = samlutils.generateInstant();
  const request = `<samlp:LogoutRequest
                    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID=""${id}
                    Version="2.0"
                    IssueInstant="${instant}"
                   >
                    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">${this.options.issuer}</Issuer>
                    <NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">${req.user.nameID}</NameID>
                  </samlp:LogoutRequest>`;
  return request;
};

SAML.prototype.requestToUrl = function requestToUrl(request, operation, callback) {
  const self = this;
  async.waterfall([
    (next) => {
      if (!self.metadata.saml0) {
        self.metadata.fetch(next);
      } else {
        next(null);
      }
    },
    (next) => {
      zlib.deflateRaw(request, (deflateError, buffer) => {
        if (deflateError) {
          return callback(deflateError);
        }

        const base64 = buffer.toString('base64');
        let target = `${self.metadata.saml.loginEndpoint}?`;
        const samlRequest = {
          SAMLRequest: base64,
        };
        if (operation === 'logout') {
          target = `${self.metadata.saml.logoutEndpoint}?`;
          if (self.options.privateCert) {
            samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
            samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
          }
        }

        target += querystring.stringify(samlRequest);

        return next(null, target);
      });
    },
  ], (waterfallError, target) => {
    return callback(waterfallError, target);
  });
};

SAML.prototype.getAuthorizeUrl = function getAuthorizeUrl(req, callback) {
  const request = this.generateAuthorizeRequest();
  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function getLogoutUrl(req, callback) {
  const request = this.generateLogoutRequest(req);
  this.requestToUrl(request, 'logout', callback);
};

SAML.prototype.validateSignature = function validSignature(xml, cert) {
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const xpathExpression = '//*[local-name(.)="Signature" and namespace-uri(.)="http: //www.w3.org/2000/09/xmldsig#"]';
  const signature = xmlCrypto.xpath(doc, xpathExpression)[0];
  const sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: () => {
      return '<X509Data></X509Data>';
    },
    getKey: () => {
      // should I use the key in keyInfo or in cert?
      return pem.certToPEM(cert);
    },
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.checkSamlStatus = function checkSamlStatus(response, next) {
  try {
    const status = aadutils.getElement(response, 'Status');
    const statusCode = aadutils.getElement(status[0], 'StatusCode');
    const result = aadutils.getElement(statusCode[0].$, 'Value');
    if (result !== SamlUrn.success) {
      return next(new Error(`SAML response error: ${JSON.stringify(status)}`));
    }
    return next();
  } catch (e) {
    return next(new Error(`Invalid SAML response: ${e.message}`));
  }
};

SAML.prototype.validateResponse = function validateResponse(samlResponse, callback) {
  const self = this;
  let xml = null;
  let version = '';
  let response = null;

  // asynchronously process the samlResponse to create the user profile
  async.waterfall([
    // parse the samlResponse into a JavaScript object
    (next) => {
      xml = new Buffer(samlResponse, 'base64').toString('utf8');
      const parser = new xml2js.Parser({
        explicitRoot: true,
      });
      parser.parseString(xml, (err, doc) => {
        response = aadutils.getElement(doc, 'Response');
        next();
      });
    },
    (next) => {
      // check for an error in the samlResponse
      self.checkSamlStatus(response, next);
    },
    (next) => {
      // check version of SAML response
      if (response.$.MajorVersion === '1') {
        version = '1.1';
      } else if (response.$.Version === '2.0') {
        version = '2.0';
      }

      if (version === '') {
        next(new Error('SAML Assertion version not supported'), null);
      } else {
        next(null);
      }
    },
    (next) => {
      // check for token expiration
      const assertion = response.Assertion[0];
      if (!samlutils.validateExpiration(assertion, version)) {
        next(new Error('Token has expired.'), null);
      } else {
        next(null);
      }
    },
    (next) => {
      // check for valid audience
      const assertion = response.Assertion[0];
      if (!samlutils.validateAudience(assertion, self.options.issuer, version)) {
        next(new Error('Token has expired.'), null);
      } else {
        next(null);
      }
    },
    (next) => {
      // check to see if we have loaded the x509 certs from the AAD metadata url
      if (!self.metadata.saml || !self.metadata.saml.certs || self.metadata.saml.certs.length === 0) {
        self.metadata.fetch(next);
      } else {
        next(null);
      }
    },
    (next) => {
      // validate the Signature
      self.checkSignature(xml, next);
    },
    (next) => {
      self.getProfile(response, next);
    },
  ], (waterfallError, profile) => {
    // return the err and profile to the caller
    callback(waterfallError, profile, false);
  });
};

SAML.prototype.checkSignature = function checkSignature(xml, next) {
  // validate the Signature
  const self = this;

  if (!(self.metadata && self.metadata.saml && Array.isArray(self.metadata.saml.certs))) {
    return next(new Error('no SAML certs available in metadata'));
  }

  const validSignature = self.metadata.saml.certs.some((cert) => {
    return !!self.validateSignature(xml, cert);
  });

  if (!validSignature) {
    return next(new Error('Invalid signature'));
  }
  return next();
};

SAML.prototype.getProfile = function getProfile(response, callback) {
  const assertion = aadutils.getElement(response, 'Assertion');
  if (!assertion) {
    return callback(new Error('getProfile: Missing SAML assertion'));
  }

  try {
    const profile = samlutils.getProfile(assertion);
    return callback(null, profile);
  } catch (e) {
    return callback(new Error(`getProfile error: ${e.message}`));
  }
};

exports.SAML = SAML;
