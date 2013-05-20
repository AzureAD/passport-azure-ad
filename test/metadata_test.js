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

exports['metadata'] = {

  'has option': function(test) {
    test.expect(1);
    // tests here

    test.doesNotThrow(
      function() {
        new Metadata('http://foo.com/federationmetadata.xml');
      },
      Error,
      'Should not fail with url present'
    );

    test.done();
  },
  'missing option': function(test) {
    test.expect(1);
    // tests here

    test.throws(
      function() {
        new Metadata();
      },
      Error,
      'Should  fail with url missing'
    );

    test.done();
  },
  'fetch metadata': function(test) {
    test.expect(7);
    // tests here

    test.doesNotThrow(
      function() {
        var m = new Metadata(metadataUrl);
        m.fetch(function(err) {
          test.ifError(err);
          test.ok(m.saml.certs.length > 0, 'fetch should obtain 1 or more saml x509 certificates');
          test.ok(m.saml.loginEndpoint, 'fetch should obtain saml login endpoint');
          test.ok(m.saml.logoutEndpoint, 'fetch should obtain saml logout endpoint');
          test.ok(m.wsfed.certs.length > 0, 'fetch should obtain 1 or more wsfed x509 certificates');
          test.ok(m.wsfed.loginEndpoint, 'fetch should obtain wsfedlogin endpoint');
          test.done();
        });
      },
      Error,
      'Should not fail with url present'
    );
  }
};
