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

var test_parameters = {
  v1_params: {
    tenantID: '<fill-in>',
    clientID: '<fill-in>',
    clientSecret: '<fill-in>',
    thumbprint: '<fill-in>',
    privatePEMKey: '<fill-in>',
    username: '<fill-in>',
    password: '<fill-in>',
    oid: '<fill-in>',
  },
  v2_params: {
    tenantID: '<fill-in>',
    clientID: '<fill-in>',
    clientSecret: '<fill-in>',
    thumbprint: '<fill-in>',
    privatePEMKey: '<fill-in>',
    username: '<fill-in>',
    password: '<fill-in>',
    oid: '<fill-in>',
  },
  b2c_params: {
    tenantID: '<fill-in>',
    clientID: '<fill-in>',
    clientSecret: '<fill-in>',
    username: '<fill-in>',
    password: '<fill-in>',
    oid: '<fill-in>',
    scopeForBearer: '<fill-in>',
    scopeForOIDC: '<fill-in>'
  }
};

exports.is_test_parameters_completed = false;

exports.test_parameters = test_parameters;
