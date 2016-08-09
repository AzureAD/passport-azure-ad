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

exports.verifyState = function(req, sessionKey) {
	if (!req.session) {
		return {valid: false, errorMessage: 'OIDC strategy requires session support. Did you forget to use express-session middleware?'};
	}

	// returned state may be in the body or query
	var state_returned = undefined;
	if (req.query && req.query.state)
		state_returned = req.query.state;
	else if (req.body && req.body.state)
		state_returned = req.body.state;

	if (!state_returned) {
		return {valid: false, errorMessage: 'state is not found in the request'};
	}

	// the state we provided before should be in req.session[sessionKey]
	var state_provided = req.session[sessionKey] && req.session[sessionKey].state;
	if (!state_provided)
		return {valid: false, errorMessage: 'state was not provided'};

	// clear the state saved in session, and clear the session if there is nothing inside
	delete req.session[sessionKey].state;
	if (Object.keys(req.session[sessionKey]).length ===0)
		delete req.session[sessionKey];

	// compare the two states
	if (state_returned !== state_provided)
		return {valid:false, errorMessage: 'invalid state in the request'};

	return {valid: true, errorMessage: ''};
};

exports.addStateToSession = function(req, sessionKey, state) {
	if (!req.session) {
		return {valid: false, errorMessage: 'OIDC strategy requires session support. Did you forget to use express-session middleware?'};
	}
	if (!req.session[sessionKey])
		req.session[sessionKey] = {};
	req.session[sessionKey].state = state;
}
