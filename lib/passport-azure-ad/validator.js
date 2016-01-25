/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

  for (item in this.config) {
    if (this.config.hasOwnProperty(item)) {
      type = this.config[item];
      if (!type) {
        continue; // no need to validate
      }
      checker = types[type];
      if (!checker) { // missing required checker
        throw new TypeError('No handler to validate type ' + type + ' for item ' + item);
      }

      if (!checker.validate(options[item])) {
        throw new TypeError('Invalid value for ' + item + '. ' + checker.error);
      }
    } else {
      throw new TypeError('Missing value for ' + item);

    }
  }
};



Validator.isNonEmpty = 'isNonEmpty';
types.isNonEmpty = {
  validate: function (value) {
    return value !== '' && value !== undefined && value !== null;
  },
  error: 'The value cannot be empty'
};

Validator.isTypeLegal = 'isTypeLegal';
types.isTypeLegal = {
  validate: function (value) {
    return value === 'id_token' || value === 'id_token code' || value === 'code';
  },
  error: 'The responseType: must be either id_token, id_token code, or code.'
};

Validator.isModeLegal = 'isModeLegal';
types.isModeLegal = {
  validate: function (value) {
    return value === 'query' || value === 'form_post';
  },
  error: 'The responseMode: must be either query or form_post.'
};

Validator.isURL = 'isURL';
types.isURL = {

  validate: function (value) {
    var pattern = new RegExp('^(https?:\\/\\/)?' + // protocol
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // domain name
      '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
      '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string
      '(\\#[-a-z\\d_]*)?$', 'i'); // fragment locator
    if (!pattern.test(value)) {
      return false;
    } else {
      return true;
    }
  },
  error: 'The URL must be valid and be https://'
};

exports.Validator = Validator;
