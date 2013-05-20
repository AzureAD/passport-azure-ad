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

var WsfedStrategy = require('../lib/passport-azure-ad/index').WsfedStrategy;

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


exports['wsfed'] = {

  'no args': function(test) {
    test.expect(1);

    test.throws(
      function() {
        new WsfedStrategy();
      },
      Error,
      'Should fail with no arguments)'
    );

    test.done();
  },
  'no verify function': function(test) {
    test.expect(1);

    test.throws(
      function() {
        new WsfedStrategy({}, null);
      },
      Error,
      'Should fail with no verify function (2nd argument)'
    );

    test.done();
  },

  'no options': function(test) {
    test.expect(1);

    test.throws(
      function() {
        new WsfedStrategy({}, function(){});
      },
      Error,
      'Should fail with no WSFED config options'
    );

    test.done();
  },
  'with options': function(test) {
    test.expect(1);

    var config = {
      realm: 'http://localhost:3000',
      identityProviderUrl: 'https://login.windows.net/xxxxxxx/wsfed',
      logoutUrl: 'http://localhost:3000/',
      identityMetadata: 'https://login.windows.net/xxxxxxx/federationmetadata/2007-06/federationmetadata.xml',
      cert: 'xxxxxx'
    };

    test.doesNotThrow(
      function() {
        new WsfedStrategy(config, function(){});
      },
      Error,
      'Should not fail with correct WSFED config options'
    );

    test.done();
  },
  'with missing option realm': function(test) {
    test.expect(1);

    var config = {
      identityProviderUrl: 'https://login.windows.net/xxxxxxx/wsfed', // replace the end of this URL with the WS-Fed endpoint from the Azure Portal
      logoutUrl: 'http://localhost:3000/',
      identityMetadata: 'https://login.windows.net/xxxxxxx/federationmetadata/2007-06/federationmetadata.xml', // replace with the Federation Metadata URL from the Azure Portal
      cert: 'xxxxxx'
    };

    test.throws(
      function() {
        new WsfedStrategy(config, function(){});
      },
      Error,
      'Should fail with missing realm config options'
    );

    test.done();
  },
  'with missing option logoutUrl': function(test) {
    test.expect(1);

    var config = {
      realm: 'http://localhost:3000',
      identityProviderUrl: 'https://login.windows.net/xxxxxxx/wsfed', // replace the end of this URL with the WS-Fed endpoint from the Azure Portal
      identityMetadata: 'https://login.windows.net/xxxxxxx/federationmetadata/2007-06/federationmetadata.xml', // replace with the Federation Metadata URL from the Azure Portal
      cert: 'xxxxxx'
    };

    test.throws(
      function() {
        new WsfedStrategy(config, function(){});
      },
      Error,
      'Should fail with missing realm config options'
    );

    test.done();
  },
  'with valid missing option identityMetadata': function(test) {
    test.expect(1);

    var config = {
      realm: 'http://localhost:3000', // replace with your APP URI from registration
      logoutUrl: 'http://localhost:3000/',
      identityProviderUrl: 'https://login.windows.net/xxxxxxx/wsfed', // replace the end of this URL with the WS-Fed endpoint from the Azure Portal
      cert: 'xxxxxx'
    };

    test.doesNotThrow(
      function() {
        new WsfedStrategy(config, function(){});
      },
      Error,
      'Should not fail with missing identityMetadata config option (other options are valid)'
    );

    test.done();
  },
  'with missing options identityMetadata and cert': function(test) {
    test.expect(1);

    var config = {
      realm: 'http://localhost:3000', // replace with your APP URI from registration
      logoutUrl: 'http://localhost:3000/',
      identityProviderUrl: 'https://login.windows.net/xxxxxxx/wsfed' // replace the end of this URL with the WS-Fed endpoint from the Azure Portal
    };

    test.throws(
      function() {
        new WsfedStrategy(config, function(){});
      },
      Error,
      'Should fail with missing identityMetadata and cert options'
    );

    test.done();
  }

};
