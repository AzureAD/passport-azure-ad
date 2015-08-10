/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  Apache License 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*jslint node: true */
'use strict';

var crypto = require('crypto');


var bunyan = require('bunyan');
var log = bunyan.createLogger({
    name: 'Microsoft OpenID Connect: Passport Strategy: Metadata Parser'
});


exports.getElement = function(parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:' + elementName]) {
    return parentElement['samlp:'+elementName];
  } else if (parentElement['wsa:' + elementName]) {
    return parentElement['wsa:' + elementName];
  }
  return parentElement[elementName];
};


exports.getFirstElement = function(parentElement, elementName) {
  var element = null;

  if (parentElement['saml:' + elementName]) {
    element = parentElement['saml:' + elementName];
  } else if (parentElement['samlp:' + elementName]) {
  } else if (parentElement['wsa:' + elementName]) {
    element =  parentElement['wsa:' + elementName];
  } else {
    element = parentElement[elementName];
  }
  return Array.isArray(element) ? element[0] : element;
};

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
exports.originalURL = function(req) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https')
               ? 'https'
               : 'http'
    , host = headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
};

/**
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

exports.merge = function(a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * CREDIT: Connect -- utils.uid
 *         https://github.com/senchalabs/connect/blob/2.7.2/lib/utils.js
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */

exports.uid = function(len) {
  return crypto.randomBytes(Math.ceil(len * 3 / 4))
    .toString('base64')
    .slice(0, len);
};

//http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js
exports.rsaPublicKeyPem = function(modulus_b64, exponent_b64) {

    var modulus = new Buffer(modulus_b64, 'base64');
    var exponent = new Buffer(exponent_b64, 'base64');

    var modulus_hex = modulus.toString('hex');
    var exponent_hex = exponent.toString('hex');

    modulus_hex = prepadSigned(modulus_hex);
    exponent_hex = prepadSigned(exponent_hex);

    var modlen = modulus_hex.length/2;
    var explen = exponent_hex.length/2;

    var encoded_modlen = encodeLengthHex(modlen);
    var encoded_explen = encodeLengthHex(explen);
    var encoded_pubkey = '30' +
        encodeLengthHex(
            modlen +
            explen +
            encoded_modlen.length/2 +
            encoded_explen.length/2 + 2
        ) +
        '02' + encoded_modlen + modulus_hex +
        '02' + encoded_explen + exponent_hex;

    var der_b64 = new Buffer(encoded_pubkey, 'hex').toString('base64');

    var pem = '-----BEGIN RSA PUBLIC KEY-----\n'
        + der_b64.match(/.{1,64}/g).join('\n')
        + '\n-----END RSA PUBLIC KEY-----\n';

    return pem;
};

function prepadSigned(hexStr) {
    var msb = hexStr[0];
    if (msb < '0' || msb > '7') {
        return '00'+hexStr;
    } else {
        return hexStr;
    }
}

function toHex(number) {
    var nstr = number.toString(16);
    if (nstr.length%2)  { return '0'+nstr; }
    return nstr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n) {
    if (n<=127) { return toHex(n); }
    else {
        var n_hex = toHex(n);
        var length_of_length_byte = 128 + n_hex.length/2; // 0x80+numbytes
        return toHex(length_of_length_byte)+n_hex;
    }
}
