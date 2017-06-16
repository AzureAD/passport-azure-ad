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

const base64url = require('base64url');
const crypto = require('crypto');
const util = require('util');

exports.getLibraryProduct = () => { return 'passport-azure-ad' };
exports.getLibraryVersionParameterName = () => { return "x-client-Ver" };
exports.getLibraryProductParameterName = () => { return 'x-client-SKU' };
exports.getLibraryVersion = () => { 
  require('pkginfo')(module, 'version');
  return module.exports.version;
};

exports.getElement = (parentElement, elementName) => {
  if (parentElement[`saml:${elementName}`]) {
    return parentElement[`saml:${elementName}`];
  } else if (parentElement[`samlp:${elementName}`]) {
    return parentElement[`samlp:${elementName}`];
  } else if (parentElement[`wsa:${elementName}`]) {
    return parentElement[`wsa:${elementName}`];
  }
  return parentElement[elementName];
};

exports.getFirstElement = (parentElement, elementName) => {
  const element = exports.getElement(parentElement, elementName);
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
exports.originalURL = (req) => {
  const headers = req.headers;
  const protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https') ? 'https' : 'http';
  const host = headers.host;
  const path = req.url || '';
  return `${protocol}://${host}${path}`;
};

/**
 * Merge object b with object a.
 *
 *     var a = { something: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { something: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

exports.merge = (a, b) => {
  return util._extend(a, b); // eslint-disable-line no-underscore-dangle
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

exports.uid = (len) => {
  var bytes = crypto.randomBytes(Math.ceil(len * 3 / 4));
  return base64url.encode(bytes).slice(0,len);
};

function prepadSigned(hexStr) {
  const msb = hexStr[0];
  if (msb < '0' || msb > '7') {
    return `00${hexStr}`;
  }
  return hexStr;
}

function toHex(number) {
  const nstr = number.toString(16);
  if (nstr.length % 2) {
    return `0${nstr}`;
  }
  return nstr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n) {
  if (n <= 127) {
    return toHex(n);
  }
  const nHex = toHex(n);
  const lengthOfLengthByte = 128 + nHex.length / 2; // 0x80+numbytes
  return toHex(lengthOfLengthByte) + nHex;
}

// http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js
exports.rsaPublicKeyPem = (modulusB64, exponentB64) => {
  const modulus = new Buffer(modulusB64, 'base64');
  const exponent = new Buffer(exponentB64, 'base64');

  const modulusHex = prepadSigned(modulus.toString('hex'));
  const exponentHex = prepadSigned(exponent.toString('hex'));

  const modlen = modulusHex.length / 2;
  const explen = exponentHex.length / 2;

  const encodedModlen = encodeLengthHex(modlen);
  const encodedExplen = encodeLengthHex(explen);
  const encodedPubkey = `30${encodeLengthHex(
          modlen +
          explen +
          encodedModlen.length / 2 +
          encodedExplen.length / 2 + 2
        )}02${encodedModlen}${modulusHex}02${encodedExplen}${exponentHex}`;

  const derB64 = new Buffer(encodedPubkey, 'hex').toString('base64');

  const pem = `-----BEGIN RSA PUBLIC KEY-----\n${derB64.match(/.{1,64}/g).join('\n')}\n-----END RSA PUBLIC KEY-----\n`;

  return pem;
};

// used for c_hash and at_hash validation
// case (1): content = access_token, hashProvided = at_hash
// case (2): content = code, hashProvided = c_hash
exports.checkHashValueRS256 = (content, hashProvided) => {
  if (!content)
    return false;
  
  // step 1. hash the content
  var digest = crypto.createHash('sha256').update(content, 'ascii').digest();

  // step2. take the first half of the digest, and save it in a buffer
  var buffer = new Buffer(digest.length/2);
  for (var i = 0; i < buffer.length; i++)
    buffer[i] = digest[i];

  // step 3. base64url encode the buffer to get the hash
  var hashComputed = base64url(buffer);

  return (hashProvided === hashComputed);
};

// This function is used for handling the tuples containing nonce/state/policy/timeStamp in session
// remove the additional tuples from array starting from the oldest ones
// remove expired tuples in array
exports.processArray = function(array, maxAmount, maxAge) {
  // remove the additional tuples, start from the oldest ones
  if (array.length > maxAmount)
    array.splice(0, array.length - maxAmount);

  // count the number of those already expired
  var count = 0;
  for (var i = 0; i < array.length; i++) {
    var tuple = array[i];
    if (tuple.timeStamp + maxAge * 1000 <= Date.now())
      count++;
    else
      break;
  }

  // remove the expired ones
  if (count > 0)
    array.splice(0, count);
};

// This function is used to find the tuple matching the given state, remove the tuple
// from the array and return the tuple
// @array        - array of {state: x, nonce: x, policy: x, timeStamp: x} tuples
// @state        - the tuple which matches the given state
exports.findAndDeleteTupleByState = (array, state) => {
  if (!array)
    return null;

  for (var i = 0; i < array.length; i++) {
    var tuple = array[i];
    if (tuple['state'] === state) {
      // remove the tuple from the array
      array.splice(i, 1);
      return tuple;
    }
  }

  return null;
};

// copy the fields from source to dest
exports.copyObjectFields = (source, dest, fields) => {
  if (!source || !dest || !fields || !Array.isArray(fields))
    return;

  for (var i = 0; i < fields.length; i++)
    dest[fields[i]] = source[fields[i]];
};

exports.getErrorMessage = (err) => {
  if (typeof err === 'string')
    return err;
  if (err instanceof Error)
    return err.message;

  // if not string or Error, we try to stringify it
  var str;
  try {
    str = JSON.stringify(err);
  } catch (ex) {
    return err;
  }
  return str;
};

