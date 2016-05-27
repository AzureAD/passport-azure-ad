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

const setup = require('./oidcsetup');

/**
 * Export configuration functions.
 */
exports.disco = (fn) => {
  setup.discovery(fn);
};

exports.config = (fn) => {
  setup.configuration(fn);
};

/**
 * Expose discovery mechanisms.
 * We most likely won't need this for now for AzureAD but we may implement this in the future!
 *
 */
exports.discovery = {};
exports.discovery.webfinger = require('./discovery/webfinger');
exports.discovery.lrdd = require('./discovery/lrdd');

exports.disco(require('./discovery/webfinger')());

/**
 *  Export modules.
 */

exports.SamlStrategy = require('./samlstrategy');
exports.WsfedStrategy = require('./wsfedstrategy');
exports.BearerStrategy = require('./bearerstrategy');
exports.OIDCStrategy = require('./oidcstrategy');
