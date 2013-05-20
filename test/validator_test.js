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

var Validator = require('../lib/passport-azure-ad/validator').Validator;

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

var   checker =  new Validator({foo: Validator.isNonEmpty});

exports['validator'] = {


  'has option': function(test) {
    test.expect(1);
    // tests here

    test.doesNotThrow(
      function() {
        checker.validate({foo:'test'});
      },
      Error,
      'Should not fail with option present'
    );

    test.done();
  },
  'missing option': function(test) {
      test.expect(1);
      // tests here

      test.throws(
        function() {
          checker.validate({bar:'test'});
        },
        Error,
        'Should  fail with option missing'
      );

    test.done();
  },
  'no options': function(test) {
    test.expect(1);
    // tests here

    test.doesNotThrow(
      function() {
        checker = new Validator({}),
        checker.validate({});
      },
      Error,
      'Should not fail with no options or config'
    );

    test.done();
  }

};
