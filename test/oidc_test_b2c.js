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

var OIDCStrategy = require('../lib/passport-azure-ad/index').OIDCStrategy;

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


    'no tenantName': function(test) {
        test.expect(1);
        // tests here
        // 
        var oidcConfig = {
            identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration',
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
                new OIDCStrategy(oidcConfig, function() {});
            },
            Error,
            'Should not fail with proper OIDC config options'
        );

        test.done();
    }


};
