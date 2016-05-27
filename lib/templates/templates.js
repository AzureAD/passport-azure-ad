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

const fs = require('fs');
const PATH = require('path');
const _ = require('underscore');

exports.loadSync = (name) => {
  const path = PATH.join(__dirname, name);
  return fs.readFileSync(path, 'utf8');
};

exports.compileSync = (template, params) => {
  return _.template(template, params);
};

exports.load = (name, callback) => {
  const path = PATH.join(__dirname, name);
  fs.readFile(path, 'utf8', (err, data) => {
    callback(err, data);
  });
};

exports.compile = (name, params, callback) => {
  const path = PATH.join(__dirname, name);
  try {
    fs.readFile(path, 'utf8', (err, data) => {
      if (err) {
        callback(err);
      } else {
        try {
          callback(null, _.template(data, params));
        } catch (e) {
          callback(new Error(`Template Error: '${name} ${e.message}`));
        }
      }
    });
  } catch (e) {
    callback(new Error(e.message));
  }
};
