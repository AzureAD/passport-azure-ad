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

var zlib = require('zlib');
var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var querystring = require('querystring');
var Validator = require('./validator').Validator;
var templates = require('./templates/templates');
var async = require('async');
var pem = require('./pem');
var aadutils = require('./aadutils');
var samlutils = require('./samlutils');
var Metadata = require('./metadata').Metadata;

var SamlUrn = {
  success: 'urn:oasis:names:tc:SAML:2.0:status:Success'
};

var SAML = function (options) {
  // required options for SAML
  var config = {
    identityMetadata: Validator.isNonEmpty,
    loginCallback: Validator.isNonEmpty,
    issuer: Validator.isNonEmpty
  };

  // enforce that user has provided both public and private certs if at least one cert is present
  // or logoutCallback is present
  if(options.privateCert || options.publicCert || options.logoutCallback) {
    config.logoutCallback = Validator.isNonEmpty;
    config.privateCert = Validator.isNonEmpty;
    config.publicCert = Validator.isNonEmpty;
  }

  // validator will throw exception if a required option is missing
  var checker = new Validator(config);
  checker.validate(options);
  this.options = this.initialize(options);
  this.metadata = new Metadata(options.identityMetadata);
  this.federationMetadata = null;
};

SAML.prototype.initialize = function (options) {
  if (!options) {
    options = {};
  }

  if (!options.protocol) {
    options.protocol = 'https://';
  }

  if(options.publicCert) {
    options.x509PublicCert = pem.getCertificate(options.publicCert);
  } else {
    options.x509PublicCert = '';
  }

  // setup optional service federation metadata parameters
  options.organizationName = options.organizationName ? options.organizationName : '';
  options.organizationDisplayName = options.organizationDisplayName ? options.organizationDisplayName : '';
  options.organizationUrl = options.organizationUrl ? options.organizationUrl : '';
  options.contactFirstName = options.contactFirstName ? options.contactFirstName : '';
  options.contactLastName = options.contactLastName ? options.contactLastName : '';
  options.contactEmail = options.contactEmail ? options.contactEmail : '';
  return options;
};

SAML.prototype.identity = function (callback) {
  // params for the metadata template
  var params = {
    APP_ID_URI: this.options.issuer,
    APP_URL:  this.options.appUrl,
    LOGIN_CALLBACK: this.options.loginCallback,
    LOGOUT_CALLBACK: this.options.logoutCallback,
    CERT: this.options.x509PublicCert,
    ORGANIZATON_NAME: this.options.organizationName,
    ORGANIZATON_DISPLAY_NAME: this.options.organizationDisplayName,
    ORGANIZATON_URL: this.options.organizationUrl,
    GIVEN_NAME: this.options.contactFirstName,
    SURNAME: this.options.contactLastName,
    EMAIL: this.options.contactEmail
  };

  var self = this;
  if(this.federationMetadata === null) {
    templates.compile('federationmetadata.template.xml', params, function(err, data) {
      if(err === null) {
        self.federationMetadata = data;
      }
      callback(err, data);
    });
  }
};

SAML.prototype.signRequest = function (xml) {
  var signer = crypto.createSign('RSA-SHA1');
  signer.update(xml);
  return signer.sign(this.options.privateCert, 'base64');
};

SAML.prototype.generateAuthorizeRequest = function () {
  var id = "id" + samlutils.generateUniqueID(),
    instant = samlutils.generateInstant();

  // TODO: build callback based on host we are running on?
  // loginCallback = this.options.protocol + req.headers.host + this.options.path;

  var request = '<samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata"';
  request += ' ID="' + id + '"';
  request += ' Version="2.0"';
  request += ' IssueInstant="' + instant + '"';
  request += ' IsPassive="false"';
  request += ' AssertionConsumerServiceURL="' + this.options.loginCallback  + '"';
  request += ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">';
  request += ' <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">' + this.options.issuer + '</Issuer>';
  request += '</samlp:AuthnRequest>';
  return request;
};

SAML.prototype.generateLogoutRequest = function (req) {
  var id = "_" + samlutils.generateUniqueID();
  var instant = samlutils.generateInstant();
  var request = '<samlp:LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata"';
  request += ' ID="' + id + '"';
  request += ' Version="2.0"';
  request += ' IssueInstant="' + instant + '"';
  request += ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">';
  request += ' <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">' + this.options.issuer + '</Issuer>';
  request += ' <NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">' +  req.user.nameID + '</NameID>';
  request += '</samlp:LogoutRequest>';
  return request;
};

SAML.prototype.requestToUrl = function (request, operation, callback) {
  var self = this;
  async.waterfall([
    function(next){
      if(!self.metadata.saml0) {
        self.metadata.fetch(next);
      } else {
        next(null);
      }
    },
    function(next){
      zlib.deflateRaw(request, function(err, buffer) {
        if (err) {
          return callback(err);
        }

        var base64 = buffer.toString('base64');
        var target = self.metadata.saml.loginEndpoint + '?';
        var samlRequest = {
          SAMLRequest: base64
        };
        if (operation === 'logout') {
          target = self.metadata.saml.logoutEndpoint + '?';
          if (self.options.privateCert) {
            samlRequest.SigAlg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
            samlRequest.Signature = self.signRequest(querystring.stringify(samlRequest));
          }
        }

        target += querystring.stringify(samlRequest);

        return next(null, target);
      });
    }
  ], function (err, target) {
    return callback(err, target);
  });
};

SAML.prototype.getAuthorizeUrl = function (req, callback) {
  var request = this.generateAuthorizeRequest();
  this.requestToUrl(request, 'authorize', callback);
};

SAML.prototype.getLogoutUrl = function(req, callback) {
  var request = this.generateLogoutRequest(req);
  this.requestToUrl(request, 'logout', callback);
};

SAML.prototype.validateSignature = function (xml, cert) {
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath(doc, "//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml();
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data></X509Data>";
    },
    getKey: function () {
      //TODO: should I use the key in keyInfo or in cert?
      return pem.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  return sig.checkSignature(xml);
};

SAML.prototype.checkSamlStatus = function(response, next) {
  try {
    var status = aadutils.getElement(response, 'Status');
    var statusCode = aadutils.getElement(status[0], 'StatusCode');
    var result = aadutils.getElement(statusCode[0].$, 'Value');
    if(result === SamlUrn.success) {
      next(null);
    } else {
      next(new Error('SAML response error:' + JSON.stringify(status)),null);
    }
  } catch (e) {
    next(new Error('Invalid SAML response:' + e.message),null);
  }
};

SAML.prototype.validateResponse = function (samlResponse, callback) {
  var self = this,
    xml = null,
    version = '',
    response = null;

  // asynchronously process the samlResponse to create the user profile
  async.waterfall([
    // parse the samlResponse into a JavaScript object
    function(next){
      xml = new Buffer(samlResponse, 'base64').toString('ascii');
      var parser = new xml2js.Parser({explicitRoot:true});
      parser.parseString(xml, function (err, doc) {
        response = aadutils.getElement(doc, 'Response');
        next(null);
      });
    },
    function(next){
      // check for an error in the samlResponse
      self.checkSamlStatus(response, next);
    },
    function(next) {
      // check version of SAML response
      if (response['$'].MajorVersion === '1') {
        version = '1.1';
      } else if (response['$'].Version === '2.0') {
        version = '2.0';
      }

      if(version === '') {
        next(new Error('SAML Assertion version not supported'), null);
      } else {
        next(null);
      }
    },
    function(next) {
      // check for token expiration
      var assertion = response.Assertion[0];
      if (!samlutils.validateExpiration(assertion, version)) {
        next(new Error('Token has expired.'), null);
      } else {
        next(null);
      }
    },
    function(next) {
      // check for valid audience
      var assertion = response.Assertion[0];
      if (!samlutils.validateAudience(assertion, self.options.issuer, version)) {
        next(new Error('Token has expired.'), null);
      } else {
        next(null);
      }
    },
    function(next){
      // check to see if we have loaded the x509 certs from the AAD metadata url
      if(!self.metadata.saml || self.metadata.saml.certs.length === 0) {
        self.metadata.fetch(next);
      } else {
        next(null);
      }
    },
    function(next){
      // validate the Signature
      self.checkSignature(xml, next);
    },
    function(next) {
      self.getProfile(response, next);
    }
  ], function (err, profile) {
    // return the err and profile to the caller
    callback(err, profile, false);
  });
};

SAML.prototype.checkSignature = function(xml, next) {
  // validate the Signature
  var self = this;
  var validSignature = false;

  // Verify signature
  for (var i=0;i<this.certs.length;i++) {
    if (self.validateSignature(xml, self.metadata.saml.certs[i])) {
      validSignature = true;
      break;
    }
  }

  if (!validSignature) 
    next(new Error('Invalid signature'));
  else 
    next(null);

};

SAML.prototype.getProfile = function (response, callback) {
  var assertion,
    profile = {};

  assertion = aadutils.getElement(response, 'Assertion');
  if (!assertion) {
    return callback(new Error('getProfile: Missing SAML assertion'));
  }

  try {
    profile = samlutils.getProfile(assertion);
    return callback(null, profile);
  } catch(e) {
    callback(new Error("getProfile error:" + e.message));
  }
};

exports.SAML = SAML;
