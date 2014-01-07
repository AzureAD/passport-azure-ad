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

 credits to: https://github.com/bergie/passport-saml
 */


'use strict';

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var pem = require('./pem');
var aadutils = require('./aadutils');
var samlutils = require('./samlutils');

var SAML = function (options) {
  this.options = options;

  if(options.metadata) {
    this.certs = options.metadata.certs;
  } else {
    if (!options.cert) {
      throw new Error('You must set a X509Certificate certificate from the federationmetadata.xml file for your app');
    } else {
      this.certs = [];
      this.certs.push(options.cert);
    }
  }
};

Object.defineProperty(SAML, 'certs', {
  get: function () {
    return this.certs;
  },
  set: function (certs) {
    this.certs = [];
    if(Array.isArray(certs)) {
      this.certs = certs;
    } else {
      this.certs = [];
      this.certs.push(certs);
    }
  }
});

SAML.prototype.validateSignature = function (xml, cert, thumbprint) {
  var self = this;
  var doc = new xmldom.DOMParser().parseFromString(xml);
  var signature = xmlCrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
  var sig = new xmlCrypto.SignedXml(null, { idAttribute: 'AssertionID' });
  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<X509Data></X509Data>";
    },
    getKey: function (keyInfo) {
      if (thumbprint)  {
        var embeddedSignature = keyInfo[0].getElementsByTagName("X509Certificate");
        if (embeddedSignature.length > 0) {
          var base64cer = embeddedSignature[0].firstChild.toString();
          var shasum = crypto.createHash('sha1');
          var der = new Buffer(base64cer, 'base64').toString('binary');
          shasum.update(der);
          self.calculatedThumbprint = shasum.digest('hex');
    
          return pem.certToPEM(base64cer);
        }
      }
      return pem.certToPEM(cert);
    }
  };
  sig.loadSignature(signature.toString());
  var valid = sig.checkSignature(xml);

  if (cert) {
    return valid;
  }

  if (thumbprint) {
    return valid && this.calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
  }
};

SAML.prototype.validateResponse = function (samlAssertionString, callback) {
  var self = this;
  var validSignature = false;
  
  // Verify signature
  for (var i=0;i<this.certs.length;i++) {
    if (self.validateSignature(samlAssertionString, this.certs[i], self.options.thumbprint)) {
      validSignature = true;
      break;
    }
  }

  if (!validSignature) 
    return callback(new Error('Invalid signature'), null);

  var parser = new xml2js.Parser({explicitRoot:true, explicitArray:false});
  parser.parseString(samlAssertionString, function (err, doc) {

    var samlAssertion = aadutils.getElement(doc, 'Assertion');
    var version = '';
    if (samlAssertion['$'].MajorVersion === '1') {
      version = '1.1';
    }
    else if (samlAssertion['$'].Version === '2.0') {
      version = '2.0';
    }
    else {
      return callback(new Error('SAML Assertion version not supported'), null);
    }

    if (!samlutils.validateExpiration(samlAssertion, version)) {
      return callback(new Error('Token has expired.'), null);
    }

    if (!samlutils.validateAudience(samlAssertion, self.options.realm, version)) {
      return callback(new Error('Audience is invalid. Expected: ' + self.options.realm), null);
    }

    try {
      var profile = samlutils.getProfile(samlAssertion);
      return callback(null, profile);
    } catch(e) {
      return callback(new Error("getProfile error:" + e.message));
    }
  });
};

exports.SAML = SAML;
