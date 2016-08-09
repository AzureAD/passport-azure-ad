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
 
 /* eslint-disable no-new */

 'use restrict';

var chai = require('chai');
var url = require('url');
var OIDCStrategy = require('../../lib/index').OIDCStrategy;

chai.use(require('chai-passport-strategy'));

// Mock options required to create a OIDC strategy
var options = {
    callbackURL: 'http://returnURL',
    clientID: 'my_client_id',
    clientSecret: 'my_client_secret',
    identityMetadata: 'https://www.example.com/metadataURL',
    skipUserProfile: true,
    responseType: 'id_token',
    responseMode: 'form_post',
    validateIssuer: true,
    passReqToCallback: false,
    sessionKey: 'my_key'    //optional sessionKey
};

var testStrategy = new OIDCStrategy(options, function(profile, done) {});

// Mock `configure`
// `configure` is used to calculate and set the variables required by oauth2, 
// here we just provide the variable values.
testStrategy.configure = function(identifier, done) {
  var opt = {           
    clientID: options.clientID,
    clientSecret: options.clientSecret,
    authorizationURL: 'https://www.example.com/authorizationURL',
    tokenURL: 'https://www.example.com/tokenURL'
  };
  done(null, opt);
};

// Mock `setOptions`
// `setOptions` is used to read and save the metadata, we don't need this in test 
testStrategy.setOptions = function(options, metadata, cachekey, next) { return next();};


describe('OIDCStrategy error handling', function() {
  var challenge;
  var err = {error: 'my_error', error_description: 'my_error_description'};

  var testPrepare = function() {
  	return function(done) {
  		chai.passport
  		  .use(testStrategy)
  		  .fail(function(c) { challenge = c; done(); })
  		  .req(function(req) { req.session = { 'my_key' : {state: 'my_state'}}; req.query = { state: 'my_state'}; req.body = err; })
  		  .authenticate({});
  	};
  };

  describe('error in body', function() {
    before(testPrepare());

    it('should call fail function', function() { chai.expect(challenge).to.equal('my_error'); });
  });
});
