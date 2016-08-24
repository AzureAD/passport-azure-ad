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

exports.verifyNonce = function (req, sessionKey, nonce_in_idtoken) {
    if (!req.session) {
        return { valid: false, errorMessage: 'OIDC strategy requires session support. Did you forget to use session middleware such as express-session?' };
    }

    // the nonce we sent in the authentication request should be in req.session[sessionKey]
    var nonce_from_session = req.session[sessionKey] && req.session[sessionKey].nonce;
    if (!nonce_from_session)
        return { valid: false, errorMessage: 'nonce not found in the session.' };

    // compare the two nonces, this will fail if nonce_in_idtoken is null
    if (nonce_in_idtoken !== nonce_from_session)
        return { valid: false, errorMessage: 'invalid nonce in id_token.' };

    // delete the nonce from session only if there is a match
    delete req.session[sessionKey].nonce;

    // clear the session if there is nothing inside
    if (Object.keys(req.session[sessionKey]).length === 0)
        delete req.session[sessionKey];

    return { valid: true, errorMessage: '' };
};

exports.addNonceToSession = function (req, sessionKey, nonce) {
    if (!req.session) {
        return { valid: false, errorMessage: 'OIDC strategy requires session support. Did you forget to use session middleware such as express-session?' };
    }

    if (!req.session[sessionKey])
        req.session[sessionKey] = {};
    req.session[sessionKey].nonce = nonce;
};
