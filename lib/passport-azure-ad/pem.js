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

/*
How to create SAML Logout signing keys on linux/mac

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -sha1 -keyout private.pem -out public.pem
*/


var BEGIN_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----';
var END_PRIVATE_KEY = '-----END PRIVATE KEY-----';

var BEGIN_CERT = '-----BEGIN CERTIFICATE-----';
var END_CERT   = '-----END CERTIFICATE-----';

var getCertData = function (pem, begin, end) {

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


exports.getCertificate = function (pem) {
  return getCertData(pem, BEGIN_CERT, END_CERT );
};

exports.getPrivateKey = function (pem) {
  return getCertData(pem, BEGIN_PRIVATE_KEY, END_PRIVATE_KEY );
};

exports.certToPEM = function (cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  cert = cert + "\n-----END CERTIFICATE-----\n";
  return cert;
};
