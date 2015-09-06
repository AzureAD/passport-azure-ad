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

var OidcStrategy = require('../lib/passport-azure-ad/index').OIDCStrategy;

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


exports['oidc'] = {

    'no args': function(test) {
        test.expect(1);
        // tests here

        test.throws(
            function() {
                new OIDCStrategy();
            },
            Error,
            'Should fail with no arguments)'
        );

        test.done();
    },

    'no tenantName': function(test) {
        test.expect(1);
        // tests here
        // 
        var oidcConfig = {
            // required options
            identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration',
            tenantName: '',
            forceB2C: true
        };

        test.throws(
            function() {
                new OIDCStrategy(oidcConfig, function() {});
            },
            Error,
            'Should fail with no tenantName: specified in B2C tenant options'
        );

        test.done();
    },

    'with options': function(test) {
        test.expect(1);
        // tests here

        var oidcConfig = {
            // required options
            identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration',
            tenantName: 'hypercubeb2c.onmicrosoft.com',
            forceB2C: true
        };

        test.doesNotThrow(
            function() {
                new OidcStrategy(oidcConfig, function() {});
            },
            Error,
            'Should not fail with proper OIDC config options'
        );

        test.done();
    }


};
