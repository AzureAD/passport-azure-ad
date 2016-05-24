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

const crypto = require('crypto');
const xml2js = require('xml2js');
const xmlCrypto = require('xml-crypto');
const xmldom = require('xmldom');
const pem = require('./pem');
const aadutils = require('./aadutils');
const samlutils = require('./samlutils');

function SAML(options) {
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
}

Object.defineProperty(SAML, 'certs', {
  get: function getCerts() {
    return this.certs;
  },
  set: function setCerts(certs) {
    this.certs = [];
    if (Array.isArray(certs)) {
      this.certs = certs;
    } else {
      this.certs = [];
      this.certs.push(certs);
    }
  },
});

SAML.prototype.validateSignature = function validateSignature(xml, cert, thumbprint) {
  const self = this;
  const doc = new xmldom.DOMParser().parseFromString(xml);
  const xpathExpression = '/*/*[local-name(.)="Signature" and namespace-uri(.)="http://www.w3.org/2000/09/xmldsig#""]';
  const signature = xmlCrypto.xpath(doc, xpathExpression)[0];
  const sig = new xmlCrypto.SignedXml(null, {
    idAttribute: 'AssertionID',
  });
  sig.keyInfoProvider = {
    getKeyInfo: () => {
      return '<X509Data></X509Data>';
    },
    getKey: (keyInfo) => {
      if (thumbprint) {
        const embeddedSignature = keyInfo[0].getElementsByTagName('X509Certificate');
        if (embeddedSignature.length > 0) {
          const base64cer = embeddedSignature[0].firstChild.toString();
          const shasum = crypto.createHash('sha1');
          const der = new Buffer(base64cer, 'base64').toString('binary');
          shasum.update(der);
          self.calculatedThumbprint = shasum.digest('hex');

          return pem.certToPEM(base64cer);
        }
      }
      return pem.certToPEM(cert);
    },
  };

  sig.loadSignature(signature.toString());
  const valid = sig.checkSignature(xml);

  if (cert) {
    return valid;
  }

  if (thumbprint) {
    return valid && this.calculatedThumbprint.toUpperCase() === thumbprint.toUpperCase();
  }

  return false;
};

SAML.prototype.validateResponse = function validateResponse(samlAssertionString, callback) {
  const self = this;

  // Verify signature
  const validSignature = this.certs.some((cert) => {
    return !!self.validateSignature(samlAssertionString, cert, self.options.thumbprint);
  });

  if (!validSignature) {
    return callback(new Error('Invalid signature'), null);
  }

  const parser = new xml2js.Parser({ explicitRoot: true, explicitArray: false });
  return parser.parseString(samlAssertionString, (parseError, doc) => {
    if (parseError) {
      return callback(parseError);
    }

    const samlAssertion = aadutils.getElement(doc, 'Assertion');
    let version = '';
    if (samlAssertion.$.MajorVersion === '1') {
      version = '1.1';
    } else if (samlAssertion.$.Version === '2.0') {
      version = '2.0';
    } else {
      return callback(new Error('SAML Assertion version not supported'), null);
    }

    if (!samlutils.validateExpiration(samlAssertion, version)) {
      return callback(new Error('Token has expired.'), null);
    }

    if (!samlutils.validateAudience(samlAssertion, self.options.realm, version)) {
      return callback(new Error(`Audience is invalid. Expected: ${self.options.realm}`));
    }

    try {
      const profile = samlutils.getProfile(samlAssertion);
      return callback(null, profile);
    } catch (e) {
      return callback(new Error(`getProfile error: ${e.message}`));
    }
  });
};

exports.SAML = SAML;
