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



exports.getElement = function (parentElement, elementName) {
  if (parentElement['saml:' + elementName]) {
    return parentElement['saml:' + elementName];
  } else if (parentElement['samlp:'+elementName]) {
    return parentElement['samlp:'+elementName];
  }
  return parentElement[elementName];
};


exports.getFirstElement = function (parentElement, elementName) {
  var element = null;

  if (parentElement['saml:' + elementName]) {
    element =  parentElement['saml:' + elementName];
  } else if (parentElement['samlp:'+elementName]) {
    element =  parentElement['samlp:'+elementName];
  } else {
    element = parentElement[elementName];
  }
  return Array.isArray(element) ? element[0] : element;
};



