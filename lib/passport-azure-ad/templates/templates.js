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

"use strict";

var fs = require('fs');
var PATH = require('path');
var _ = require('underscore');

exports.loadSync = function (name) {
  var path = PATH.join(__dirname, name);
  return fs.readFileSync(path, 'utf8');
};

exports.compileSync = function (template, params) {
  return _.template(template ,params);
};

exports.load = function (name, callback) {
  var path = PATH.join(__dirname, name);
  fs.readFile(path, 'utf8', function (err, data) {
    callback(err, data);
  });
};

exports.compile = function (name, params, callback) {
  var path = PATH.join(__dirname, name);
  try {
    fs.readFile(path, 'utf8', function (err, data) {
      if(err) {
        callback(err);
      } else {
        try {
          callback(null, _.template(data, params));
        } catch(e) {
          callback(new Error('Template Error: ' + name + " " + e.message));
        }
      }
    });
  } catch(e) {
    callback(new Error(e.message));
  }
};
