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

var SamlStrategy = require('../lib/passport-azure-ad/index').SamlStrategy;

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


exports['saml'] = {

  'no args': function(test) {
    test.expect(1);
    // tests here

    test.throws(
      function() {
        new SamlStrategy();
      },
      Error,
      'Should fail with no arguments)'
    );

    test.done();
  },
  'no verify function': function(test) {
    test.expect(1);
    // tests here

    test.throws(
      function() {
        new SamlStrategy({}, null);
      },
      Error,
      'Should fail with no verify function (2nd argument)'
    );

    test.done();
  },

  'no options': function(test) {
    test.expect(1);
    // tests here

    test.throws(
      function() {
        new SamlStrategy({}, function(){});
      },
      Error,
      'Should fail with no SAML config options'
    );

    test.done();
  },
  'with options': function(test) {
    test.expect(1);
    // tests here

    var samlConfig = {
      // required options
      identityMetadata: 'https://login.windows.net/xxxxxxxxx/federationmetadata.xml',
      loginCallback: 'http://localhost:3000/login/callback/',
      issuer: 'http://localhost:3000'  // this is the URI you entered for APP ID URI when configuring SSO for you app on Azure AAD
    };

    test.doesNotThrow(
      function() {
        new SamlStrategy(samlConfig, function(){});
      },
      Error,
      'Should not fail with proper SAML config options'
    );

    test.done();
  }

};
