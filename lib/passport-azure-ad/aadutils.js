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

var crypto = require('crypto'),
    base64url = require('base64url');


exports.getLibraryVersion = () => { return "1.4.6" };
exports.getLibraryProduct = () => { return 'passport-azure-ad' };
exports.getLibraryVersionParameterName = () => { return "x-client-Ver" };
exports.getLibraryProductParameterName = () => { return 'x-client-SKU' };

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
  var headers = req.headers,
  protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https') ? 'https' : 'http',
               host = headers.host,
               path = req.url || '';
  return protocol + '://' + host + path;
};

/**
 * Merge object b with object a.
 *
 *     var a = { name: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { name: 'bar', bar: 'baz' }
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

    var pem = '-----BEGIN RSA PUBLIC KEY-----\n' + 
    der_b64.match(/.{1,64}/g).join('\n') + 
    '\n-----END RSA PUBLIC KEY-----\n';

    return pem;
};

/*jshint latedef: nofunc */
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

// used for c_hash and at_hash validation
// case (1): content = access_token, hashProvided = at_hash
// case (2): content = code, hashProvided = c_hash
exports.checkHashValueRS256 = (content, hashProvided) => {
    if (!content)
        return false;

    // step 1. hash the content
    var digest = crypto.createHash('sha256').update(content, 'ascii').digest();

    // step2. take the first half of the digest, and save it in a buffer
    var buffer = new Buffer(digest.length / 2);
    for (var i = 0; i < buffer.length; i++)
        buffer[i] = digest[i];

    // step 3. base64url encode the buffer to get the hash
    var hashComputed = base64url(buffer);

    return (hashProvided === hashComputed);
};
