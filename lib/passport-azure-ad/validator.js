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

 Validator adapted from JavaScript Patterns by Stoyan Stefanov (O'Reilly), Copyright 2010 Yahoo!, Inc., 9780596806750
 */

'use strict';

var types = {};

var Validator = function (config) {
  this.config = config;
};

Validator.prototype.validate = function (options) {
  var item,
    type,
    checker;

  if (!options) {
    options = {};
  }

  for(item in this.config) {
    if(this.config.hasOwnProperty(item)) {
      type = this.config[item];
      if(!type){
        continue; // no need to validate
      }
      checker = types[type];
      if(!checker) { // missing required checker
        throw {
          name: 'ValidationError',
          message: 'No handler to validate type ' + type + ' for item ' + item
        };
      }

      if(!checker.validate(options[item])) {
        throw new Error('Invalid value for ' + item + '. ' + checker.error);
      }
    } else {
      throw new Error('Missing value for ' + item);

    }
  }
};

Validator.isNonEmpty = 'isNonEmpty';
types.isNonEmpty = {
  validate: function(value) {
    return value !== '' && value !== undefined && value !== null;
  },
  error:'The value cannot be empty'
};



exports.Validator = Validator;