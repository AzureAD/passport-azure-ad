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

const request = require('request');
const objectTransform = require('oniyi-object-transform');

function configuration(issuerUrl, cb) {
  const options = {
    method: 'GET',
    baseUrl: /\/$/.test(issuerUrl) ? issuerUrl : `${issuerUrl}/`,
    uri: '.well-known/openid-configuration',
  };

  request.get(options, (requestErr, response, body) => {
    if (requestErr) {
      return cb(requestErr);
    }

    if (response.statusCode !== 200) {
      return cb(new Error(`OpenID provider configuration request failed: ${response.statusCode}`));
    }

    const issuerConfig = objectTransform({
      source: body,
      map: {
        authorization_endpoint: 'authorizationURL',
        token_endpoint: 'tokenURL',
        userinfo_endpoint: 'userInfoURL',
        registration_endpoint: 'registrationURL',
      },
      whitelist: [
        'issuer',
        'authorizationURL',
        'tokenURL',
        'userInfoURL',
        'registrationURL',
      ],
    });

    issuerConfig._raw = body; // eslint-disable-line no-underscore-dangle
    return cb(null, issuerConfig);
  });
}

exports = module.exports = configuration;
exports.configuration = configuration;
