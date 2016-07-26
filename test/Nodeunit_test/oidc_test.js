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

/* eslint-disable no-new */

'use strict';

const OidcStrategy = require('../../lib/index').OIDCStrategy;

/*
 ======== A Handy Little Nodeunit Reference ========
 https://github.com/caolan/nodeunit

 Test methods:
 test.expect(numAssertions)
 test.done()
 Test assertions:
 test.ok(value, [message])
 test.equal(actual, expected, [message])
 test.notEqual(actual, expected, [message])
 test.deepEqual(actual, expected, [message])
 test.notDeepEqual(actual, expected, [message])
 test.strictEqual(actual, expected, [message])
 test.notStrictEqual(actual, expected, [message])
 test.throws(block, [error], [message])
 test.doesNotThrow(block, [error], [message])
 test.ifError(value)
 */

function noop() {}

exports.oidc = {
  'no args': (test) => {
    test.expect(1);
    // tests here
    test.throws(() => { new OidcStrategy(); },
      TypeError,
      'Should fail with no arguments)'
    );

    test.done();
  },
  'no verify function': (test) => {
    test.expect(1);
    // tests here
    test.throws(() => { new OidcStrategy({}, null); },
      TypeError,
      'Should fail with no verify function (2nd argument)'
    );

    test.done();
  },

  'no options': (test) => {
    test.expect(1);
    // tests here

    test.throws(
      () => {
        new OidcStrategy({}, noop);
      },
      TypeError,
      'Should fail with no OIDC config options'
    );

    test.done();
  },
  'with invalid option clientID': (test) => {
    test.expect(1);
    // tests here

    const oidcConfig = {
      // required options
      identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
      clientID: '',  // invalid
      callbackURL: 'http://www.example.com',
      responseType: 'id_token',
      responseMode: 'form_post'
    };
    test.throws(
      () => {
        const s = new OidcStrategy(oidcConfig, noop);
      },
      TypeError,
      'Should fail with wrong response config options'
    );

    test.done();
  },
  'with invalid option callbackURL': (test) => {
    test.expect(1);
    // tests here

    const oidcConfig = {
      // required options
      identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
      clientID: '123',
      callbackURL: '',  // invalid
      responseType: 'id_tokennn',
      responseMode: 'form_post'
    };
    test.throws(
      () => {
        const s = new OidcStrategy(oidcConfig, noop);
      },
      TypeError,
      'Should fail with wrong response config options'
    );

    test.done();
  },
  'with invalid option responseType': (test) => {
    test.expect(1);
    // tests here

    const oidcConfig = {
      // required options
      identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
      clientID: '123',
      callbackURL: 'http://www.example.com',
      responseType: 'id_tokennn', // invalid
      responseMode: 'form_post'
    };
    test.throws(
      () => {
        const s = new OidcStrategy(oidcConfig, noop);
      },
      TypeError,
      'Should fail with wrong response config options'
    );

    test.done();
  },
  'with invalid option responseMode': (test) => {
    test.expect(1);
    // tests here

    const oidcConfig = {
      // required options
      identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
      clientID: '123',
      callbackURL: 'http://www.example.com',
      responseType: 'id_token',
      responseMode: 'fragment' // invalid
    };
    test.throws(
      () => {
        const s = new OidcStrategy(oidcConfig, noop);
      },
      Error,
      'Should fail with wrong response config options'
    );

    test.done();
  },
  'with valid options': (test) => {
    test.expect(1);
    // tests here

    const oidcConfig = {
      // required options
      identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
      clientID: '123',
      callbackURL: 'http://www.example.com',
      responseType: 'id_token',
      responseMode: 'form_post'
    };

    test.doesNotThrow(
      () => {
        new OidcStrategy(oidcConfig, noop);
      },
      Error,
      'Should not fail with proper OIDC config options'
    );

    test.done();
  },
};
