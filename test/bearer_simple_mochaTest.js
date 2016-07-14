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

'use strict';

var chai = require('chai');
chai.use(require('chai-passport-strategy'));
var BearerStrategy = require('../lib/index').BearerStrategy;

// Mock options
var options = {
	certificate: 'my_certificate',  // use certificate to bypass the metadata loading
    validateIssuer: true,
    passReqToCallback: false
};

describe('token mock test', function() {
	var strategy = new BearerStrategy(options, function(token, done) {
		if (token === 'good_token')
			return done(null, {id: 'Mr noname'}, 'authentication successful');
		return done(null, false, 'access token is invalid');
	});

	// Mock jwtVerify
	strategy.jwtVerify = function(req, token, done) { this._verify(token, done); };

	var challenge = '';
	var success_user = '';
	var success_info = '';

	var beforeFunc = function(token, in_header, in_body, in_query) {
		return function(done) {
			chai.passport
			  .use(strategy)
		      .fail(function(c) { 
		      	challenge = c; 
		      	done();
		      })
		      .req(function(req) {
		      	if (token && in_header)
		      		req.headers.authorization = 'Bearer ' + token;
		      	if (token && in_query) {
		      		req.query = {};
		      		req.query.access_token = token;
		      	}
		      	if (token && in_body) {
		      		req.body = {};
		      		req.body.access_token = token;
		      	}
		      })
		      .success(function(user, info) { 
		      	success_user = user.id; 
		      	success_info = info; 
		      	done();
		      })
		      .authenticate();
		  };
	};

	describe('should fail with no token', function() {
		before(beforeFunc());

		it('should fail with challenge', function() {
			chai.expect(challenge).to.be.a.string;
			chai.expect(challenge).to.equal('token is not found');
		})
	});

	describe('should fail with invalid token', function() {
		before(beforeFunc('invalid_token', true));

		it('should fail with challenge', function() {
			chai.expect(challenge).to.be.a.string;
			chai.expect(challenge).to.equal('error: invalid_token, error description: access token is invalid');
		});
	});

	describe('should succeed with good token in header', function() {
		before(beforeFunc('good_token', true));

		it('should succeed', function() {
			chai.expect(success_user).to.equal('Mr noname');
			chai.expect(success_info).to.equal('authentication successful');
		});
	});

	describe('should succeed with good token in body', function() {
		before(beforeFunc('good_token', false, true));

		it('should succeed', function() {
			chai.expect(success_user).to.equal('Mr noname');
			chai.expect(success_info).to.equal('authentication successful');
		});
	});

	describe('should succeed with good token in query', function() {
		before(beforeFunc('good_token', false, false, true));

		it('should succeed', function() {
			chai.expect(success_user).to.equal('Mr noname');
			chai.expect(success_info).to.equal('authentication successful');
		});
	});
});


