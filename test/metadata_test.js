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

var Metadata = require('../lib/passport-azure-ad/metadata').Metadata;

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

var metadataUrl = 'https://login.windows.net/GraphDir1.OnMicrosoft.com/federationmetadata/2007-06/federationmetadata.xml';
var oidcMetadataUrl = 'https://login.microsoftonline.com/common/.well-known/openid-configuration';
var oidcMetadataUrl2 = 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration';
var options = {};

exports['metadata'] = {

    'has option': function(test) {
        test.expect(1);
        // tests here

        test.doesNotThrow(
            function() {
                new Metadata('http://foo.com/federationmetadata.xml', 'wsfed', options);
            },
            Error,
            'Should not fail with url present'
        );

        test.done();
    },
    'missing option url': function(test) {
        test.expect(1);
        // tests here

        test.throws(
            function() {
                new Metadata();
            },
            Error,
            'Should fail with url missing'
        );

        test.done();
    },
    'missing option auth': function(test) {
        test.expect(1);
        // tests here

        test.throws(
            function() {
                new Metadata('http://foo.com/federationmetadata.xml', options);
            },
            Error,
            'Should fail with auth type missing'
        );

        test.done();
    },
        'missing option options': function(test) {
        test.expect(1);
        // tests here

        test.throws(
            function() {
                new Metadata('http://foo.com/federationmetadata.xml', 'wsfed');
            },
            Error,
            'Should fail with options missing'
        );

        test.done();
    },
    'fetch metadata saml': function(test) {
        test.expect(5);
        // tests here

        test.doesNotThrow(
            function() {
                var m = new Metadata(metadataUrl, 'saml', options);
                m.fetch(function(err) {
                    test.ifError(err);
                    test.ok(m.saml.certs.length > 0, 'fetch should obtain 1 or more saml x509 certificates');
                    test.ok(m.saml.loginEndpoint, 'fetch should obtain saml login endpoint');
                    test.ok(m.saml.logoutEndpoint, 'fetch should obtain saml logout endpoint');
                    test.done();
                });
            },
            Error,
            'Should not fail with url present and auth type saml'
        );

    },
    'fetch metadata wsfed': function(test) {
        test.expect(4);
        // tests here

        test.doesNotThrow(
            function() {
                var m = new Metadata(metadataUrl, 'wsfed', options);
                m.fetch(function(err) {
                    test.ifError(err);
                    test.ok(m.wsfed.certs.length > 0, 'fetch should obtain 1 or more wsfed x509 certificates');
                    test.ok(m.wsfed.loginEndpoint, 'fetch should obtain wsfedlogin endpoint');
                    test.done();
                });
            },
            Error,
            'Should not fail with url present and auth type wsfed'
        );

    },
    'fetch metadata oidc': function(test) {
        test.expect(4);
        // tests here

        test.doesNotThrow(
            function() {
                var m = new Metadata(oidcMetadataUrl, 'oidc', options);
                m.fetch(function(err) {
                    test.ifError(err);
                    test.ok(m.oidc.algorithms, 'fetch algorithms');
                    test.ok(m.oidc.issuer, 'fetch issuer');
                    test.done();
                });
            },
            Error,
            'Should not fail with url present and auth type oidc'
        );

    },
        'fetch metadata oidc v2': function(test) {
        test.expect(4);
        // tests here

        test.doesNotThrow(
            function() {
                var m = new Metadata(oidcMetadataUrl2, 'oidc', options);
                m.fetch(function(err) {
                    test.ifError(err);
                    test.ok(m.oidc.algorithms, 'fetch algorithms');
                    test.ok(m.oidc.issuer, 'fetch issuer');
                    test.done();
                });
            },
            Error,
            'Should not fail with url present and auth type oidc'
        );

    }
};
