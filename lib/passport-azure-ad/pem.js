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

/*
How to create SAML Logout signing keys on linux/mac

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -sha1 -keyout private.pem -out public.pem
*/


var BEGIN_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----';
var END_PRIVATE_KEY = '-----END PRIVATE KEY-----';

var BEGIN_CERT = '-----BEGIN CERTIFICATE-----';
var END_CERT = '-----END CERTIFICATE-----';

var getCertData = function(pem, begin, end) {

  var data = pem.replace(/[\r\n]/g, "");
  // Extract the base64 encoded cert out of pem file
  var beginCert = data.indexOf(begin) + begin.length;
  if (data[beginCert] === '\n') {
    beginCert = beginCert + 1;
  } else if (data[beginCert] === '\r' && pem[beginCert + 1] === '\n') {
    beginCert = beginCert + 2;
  }

  var endCert = '\n' + data.indexOf(end);
  if (endCert === -1) {
    endCert = '\r\n' + data.indexOf(end);
  }

  return data.substring(beginCert, endCert);
};


exports.getCertificate = function(pem) {
  return getCertData(pem, BEGIN_CERT, END_CERT);
};

exports.getPrivateKey = function(pem) {
  return getCertData(pem, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
};

exports.certToPEM = function(cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};
