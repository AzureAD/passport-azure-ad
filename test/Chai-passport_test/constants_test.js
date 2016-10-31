/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

var chai = require('chai');
var expect = chai.expect;
var CONSTANTS = require('../../lib/constants');

CONSTANTS.TENANTNAME_REGEX = /^[0-9a-zA-Z]+.onmicrosoft.com$/;
CONSTANTS.TENANTID_REGEX = /^[0-9a-zA-Z-]+$/;

describe('policy checking', function() {
  it('should pass with good policy name', function(done) {
    expect(CONSTANTS.POLICY_REGEX.test('b2c_1_signin')).to.equal(true);
    expect(CONSTANTS.POLICY_REGEX.test('B2C_1_SIGNIN')).to.equal(true);
    expect(CONSTANTS.POLICY_REGEX.test('B2C_1_My.SIGNIN')).to.equal(true);
    expect(CONSTANTS.POLICY_REGEX.test('B2C_1_My_SIGNIN')).to.equal(true);
    expect(CONSTANTS.POLICY_REGEX.test('B2C_1_My-SIGNIN')).to.equal(true);
    done();
  });

  it('should fail with bad policy name', function(done) {
    expect(CONSTANTS.POLICY_REGEX.test('signin')).to.equal(false);
    expect(CONSTANTS.POLICY_REGEX.test('b2c_SIGNIN')).to.equal(false);
    expect(CONSTANTS.POLICY_REGEX.test('b2c_1_')).to.equal(false);
    expect(CONSTANTS.POLICY_REGEX.test('b2c_1_*SIGNIN')).to.equal(false);
    done();
  });
});

describe('tenant name checking', function() {
  it('should pass with good tenant name', function(done) {
    expect(CONSTANTS.TENANTNAME_REGEX.test('contoso123COMPANY.onmicrosoft.com')).to.equal(true);
    done();
  });

  it('should fail with bad tenant name', function(done) {
    expect(CONSTANTS.TENANTNAME_REGEX.test('contoso.onmicrosoft.comm')).to.equal(false);
    expect(CONSTANTS.TENANTNAME_REGEX.test('contoso123COMPANY')).to.equal(false);
    expect(CONSTANTS.TENANTNAME_REGEX.test('.onmicrosoft.com')).to.equal(false);
    expect(CONSTANTS.TENANTNAME_REGEX.test('contoso123COMPANY.ONMICROSOFT.com')).to.equal(false);
    expect(CONSTANTS.TENANTNAME_REGEX.test('contoso_company.onmicrosoft.com')).to.equal(false);
    done();
  });
});

describe('tenant id checking', function() {
  it('should pass with good tenant id', function(done) {
    expect(CONSTANTS.TENANTID_REGEX.test('683eAd13-3193-43f0-9677-d727c25a588f')).to.equal(true);
    done();
  });

  it('should fail with bad tenant id', function(done) {
    expect(CONSTANTS.TENANTID_REGEX.test('23_12')).to.equal(false);
    done();
  });
});

