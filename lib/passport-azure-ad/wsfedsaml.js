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
'use strict';

var xml2js = require('xml2js');
var xmlCrypto = require('xml-crypto');
var crypto = require('crypto');
var xmldom = require('xmldom');
var pem = require('./pem');
var aadutils = require('./aadutils');
var samlutils = require('./samlutils');

var SAML = function(options) {
    this.options = options;

    if (options.metadata) {
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
    get: function() {
        return this.certs;
    },
    set: function(certs) {
        this.certs = [];
        if (Array.isArray(certs)) {
            this.certs = certs;
        } else {
            this.certs = [];
            this.certs.push(certs);
        }
    }
});

SAML.prototype.validateSignature = function(xml, cert, thumbprint) {
    var self = this;
    var doc = new xmldom.DOMParser().parseFromString(xml);
    var signature = xmlCrypto.xpath(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0];
    var sig = new xmlCrypto.SignedXml(null, {
        idAttribute: 'AssertionID'
    });
    sig.keyInfoProvider = {
        getKeyInfo: function() {
            return "<X509Data></X509Data>";
        },
        getKey: function(keyInfo) {
            if (thumbprint) {
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

  if (!validSignature) {
    return callback(new Error('Invalid signature'), null);
  }

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
      if (!profile.issuer)
        return callback(new Error(`Issuer is was not found in token.`));

      if (!self.options.metadata.metatdata.EntityDescriptor['$'].entityID)
        return callback(new Error(`Issuer was not found in metadata obtained from: ${self.options.identityMetadata}`));

      if (!(self.options.metadata.metatdata.EntityDescriptor['$'].entityID === profile.issuer))
        return callback(new Error(`Issuer is invalid. Expected: ${self.options.metadata.metatdata.EntityDescriptor['$'].entityID}, Received in token: ${profile.issuer}`));

      return callback(null, profile);
    } catch(e) {
      return callback(new Error("getProfile error:" + e.message));
    }
  });
};

exports.SAML = SAML;
