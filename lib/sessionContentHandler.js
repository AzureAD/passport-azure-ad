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

'use restrict';

const aadutils = require('./aadutils');

/*
 * the handler for state/nonce
 * @identifier        - such as 'nonce' or 'state'
 * @maxAmout          - the max amout of 'identifier' you want to save in the session, default is 200
 * @maxAge            - when the 'identifier' in session expires in seconds, default is 1800 (seconds)
 */ 
function SessionContentHandler(identifier, maxAmount, maxAge) {
  if (!identifier || identifier === '')
    throw new Error('identifier is required to use sessionContentHandler');
  if (maxAmount && (typeof maxAmount !== 'number' || maxAmount <= 0 || maxAmount % 1 !== 0))
    throw new Error('SessionContentHandler: maxAmount must be a positive integer');
  if (maxAge && (typeof maxAge !== 'number' || maxAge <= 0))
    throw new Error('SessionContentHandler: maxAge must be a positive number');
  this.identifier = identifier;
  this.maxAge = maxAge || 1800;  // seconds
  this.maxAmount = maxAmount || 100;
}

SessionContentHandler.prototype.verify = function(req, sessionKey, itemToVerify) {
  if (!req.session)
    throw new Error('OIDC strategy requires session support. Did you forget to use session middleware such as express-session?');

  // for 'state', it comes from query or body
  if (!itemToVerify && this.identifier === 'state') {
    if (req.query &&req.query.state)
      itemToVerify = req.query.state;
    else if (req.body && req.body.state)
      itemToVerify = req.body.state;
  }

  // the array in session
  var array = req.session[sessionKey] && req.session[sessionKey][this.identifier];
  if (!array)
    array = [];

  // remove the expired ones in array, and check if we have the itemToVerify in array
  aadutils.processArray(array, this.maxAmount, this.maxAge);
  var valid = aadutils.findAndDeleteInArray(array, this.identifier, itemToVerify);

  // clear emptry array, and clear the session if there is nothing inside
  if (req.session[sessionKey] && array.length === 0)
    delete req.session[sessionKey][this.identifier];
  if (req.session[sessionKey] && Object.keys(req.session[sessionKey]).length ===0)
    delete req.session[sessionKey];

  if (valid)
    return {valid: true, errorMessage: ''};
  else
    return {valid: false, errorMessage: 'invalid ' + this.identifier};
};

SessionContentHandler.prototype.add = function(req, sessionKey, itemToAdd) {
  var identifier = this.identifier;

  if (!req.session)
    req.session = {};
  if (!req.session[sessionKey])
    req.session[sessionKey] = {};
  if (!req.session[sessionKey][identifier])
    req.session[sessionKey][identifier] = [];

  var array = req.session[sessionKey][identifier];
  aadutils.processArray(array, this.maxAmount-1, this.maxAge);

  var item = {};
  item[identifier] = itemToAdd;
  item['timeStamp'] = Date.now();
  array.push(item);
};

exports.SessionContentHandler = SessionContentHandler;
