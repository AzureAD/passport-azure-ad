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

var aadutils = require('./aadutils');

var SamlAttributes = exports.SamlAttributes = {
  identityprovider: 'http://schemas.microsoft.com/identity/claims/identityprovider',
  name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  givenname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  surname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  objectidentifier: 'http://schemas.microsoft.com/identity/claims/objectidentifier'
};


exports.validateExpiration = function (samlAssertion, version) {
  var conditions,
    notBefore,
    notOnOrAfter,
    now = new Date();

  if(version !== '2.0') {
    throw new Error('validateExpiration: invalid SAML assertion. Only version 2.0 is supported.');
  }
  try {
    conditions = Array.isArray(samlAssertion.Conditions) ? samlAssertion.Conditions[0].$ : samlAssertion.Conditions;
    notBefore = new Date(conditions.NotBefore);
    notBefore = notBefore.setMinutes(notBefore.getMinutes() - 10); // 10 minutes clock skew

    notOnOrAfter = new Date(conditions.NotOnOrAfter);
    notOnOrAfter = notOnOrAfter.setMinutes(notOnOrAfter.getMinutes() + 10); // 10 minutes clock skew

    if (now < notBefore || now > notOnOrAfter) {
      return false;
    }

    return true;
  } catch (e) {
    // rethrow exceptions
    throw e;
  }
};

exports.validateAudience = function (samlAssertion, realm, version) {
  var conditions,
    restrictions,
    audience;

  if(version !== '2.0') {
    throw new Error('validateAudience: invalid SAML assertion. Only version 2.0 is supported.');
  }

  try {
    conditions = Array.isArray(samlAssertion.Conditions) ? samlAssertion.Conditions[0] : samlAssertion.Conditions;
    restrictions = Array.isArray(conditions.AudienceRestriction) ? conditions.AudienceRestriction[0] : conditions.AudienceRestriction;
    audience = Array.isArray(restrictions.Audience) ? restrictions.Audience[0]: restrictions.Audience;
    return audience === realm;
  } catch (e) {
    // rethrow exceptions
    throw e;
  }
};


exports.getProfile = function (assertion) {
  var profile = {};

  assertion = Array.isArray(assertion) ? assertion[0] : assertion;

  var issuer = aadutils.getFirstElement(assertion, 'Issuer');
  if (issuer) {
    profile.issuer = issuer;
  }

  var subject = aadutils.getFirstElement(assertion, 'Subject');
  if (subject) {
    var nameID = aadutils.getFirstElement(subject, 'NameID');
    if (nameID) {
      profile.nameID = nameID;
      profile.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    }
  }

  var attributeStatement = aadutils.getFirstElement(assertion, 'AttributeStatement');
  if (!attributeStatement) {
    throw new Error('Missing AttributeStatement');
  }

  var attributes = aadutils.getElement(attributeStatement, 'Attribute');

  if (attributes) {
    attributes.forEach(function (attribute) {
      var value = aadutils.getFirstElement(attribute, 'AttributeValue');
      if (typeof value === 'string') {
        profile[attribute.$.Name] = value;
      } else {
        profile[attribute.$.Name] = value._;
      }
    });
  }

  if (!profile.provider && profile[SamlAttributes.identityprovider]) {
    profile.provider = profile[SamlAttributes.identityprovider];
  }

  if (!profile.id && profile[SamlAttributes.objectidentifier]) {
    profile.id = profile[SamlAttributes.objectidentifier];
  }

  if (!profile.mail && profile[SamlAttributes.name]) {
    profile.mail = profile[SamlAttributes.name];
  }

  if (!profile.givenName && profile[SamlAttributes.givenname]) {
    profile.givenName = profile[SamlAttributes.givenname];
  }

  if (!profile.familyName && profile[SamlAttributes.surname]) {
    profile.familyName = profile[SamlAttributes.surname];
  }

  if (!profile.displayName) {
    if(profile[SamlAttributes.givenname]) {
      profile.displayName = profile[SamlAttributes.givenname];
    } else if(profile[SamlAttributes.surname]) {
      profile.displayName = profile[SamlAttributes.surname];
    } else {
      profile.displayName = '';
    }
  }

  if (!profile.email && profile.mail) {
    profile.email = profile.mail;
  }

  return profile;
};

exports.generateUniqueID = function () {
  var chars = "abcdef0123456789";
  var uniqueID = "";
  for (var i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random()*15)), 1);
  }
  return uniqueID;
};

exports.generateInstant = function () {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
};

