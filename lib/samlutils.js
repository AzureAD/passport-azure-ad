/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

const aadutils = require('./aadutils');

const SamlAttributes = exports.SamlAttributes = {
  identityprovider: 'http://schemas.microsoft.com/identity/claims/identityprovider',
  name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  givenname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  surname: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  objectidentifier: 'http://schemas.microsoft.com/identity/claims/objectidentifier',
};

exports.validateExpiration = function validateExpiration(samlAssertion, version) {
  let conditions;
  let notBefore;
  let notOnOrAfter;
  const now = new Date();

  if (version !== '2.0') {
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

exports.validateAudience = function validateAudience(samlAssertion, realm, version) {
  let conditions;
  let restrictions;
  let audience;

  if (version !== '2.0') {
    throw new Error('validateAudience: invalid SAML assertion. Only version 2.0 is supported.');
  }

  try {
    conditions = Array.isArray(samlAssertion.Conditions) ?
      samlAssertion.Conditions[0] :
      samlAssertion.Conditions;
    restrictions = Array.isArray(conditions.AudienceRestriction) ?
      conditions.AudienceRestriction[0] :
      conditions.AudienceRestriction;
    audience = Array.isArray(restrictions.Audience) ?
      restrictions.Audience[0] :
      restrictions.Audience;
    return audience === realm;
  } catch (e) {
    // rethrow exceptions
    throw e;
  }
};

exports.getProfile = function getProfile(samlAssertion) {
  const profile = {};

  const assertion = Array.isArray(samlAssertion) ? samlAssertion[0] : samlAssertion;

  const issuer = aadutils.getFirstElement(assertion, 'Issuer');
  if (issuer) {
    profile.issuer = issuer;
  }

  const subject = aadutils.getFirstElement(assertion, 'Subject');
  if (subject) {
    const nameID = aadutils.getFirstElement(subject, 'NameID');
    if (nameID) {
      profile.nameID = nameID;
      profile.nameIDFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    }
  }

  const attributeStatement = aadutils.getFirstElement(assertion, 'AttributeStatement');
  if (!attributeStatement) {
    throw new Error('Missing AttributeStatement');
  }

  const attributes = aadutils.getElement(attributeStatement, 'Attribute');

  if (attributes) {
    attributes.forEach((attribute) => {
      if (attribute.AttributeValue && attribute.AttributeValue.length > 1) {
        profile[attribute.$.Name] = attribute.AttributeValue;
      } else {
        const value = aadutils.getFirstElement(attribute, 'AttributeValue');
        if (typeof value === 'string') {
          profile[attribute.$.Name] = value;
        } else {
          profile[attribute.$.Name] = value._;
        }
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
    if (profile[SamlAttributes.givenname]) {
      profile.displayName = profile[SamlAttributes.givenname];
    } else if (profile[SamlAttributes.surname]) {
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

exports.generateUniqueID = function generateUniqueID() {
  const chars = 'abcdef0123456789';
  let uniqueID = '';
  for (let i = 0; i < 20; i++) {
    uniqueID += chars.substr(Math.floor((Math.random() * 15)), 1);
  }
  return uniqueID;
};

exports.generateInstant = function generateInstant() {
  const date = new Date();
  const utcFullYear = date.getUTCFullYear();
  const utcMonth = `0${date.getUTCMonth() + 1}`.slice(-2);
  const utcDate = `0${date.getUTCDate()}`.slice(-2);
  const utcHours = `0${date.getUTCHours()}`.slice(-2);
  const utcMinutes = `0${date.getUTCMinutes()}`.slice(-2);
  const utcSeconds = `0${date.getUTCSeconds()}`.slice(-2);

  return `${utcFullYear}-${utcMonth}-${utcDate}T${utcHours}:${utcMinutes}:${utcSeconds}Z`;
};
