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
