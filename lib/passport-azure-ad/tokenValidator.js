/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  Apache License 2.0
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
 *
 * Validator adapted from JavaScript Patterns by Stoyan Stefanov (O'Reilly), Copyright 2010 Yahoo!, Inc., 9780596806750
 *
 * @flow
 */

'use strict';

var jwt = require('jsonwebtoken');
var jws = require('jws');
var aadutils = require('./aadutils');
var PEMkey;

// Logging

var bunyan = require('bunyan');
var log = bunyan.createLogger({
    name: 'Microsoft OpenID Connect: Passport Strategy: Token Validator'
});

var TokenValidator = function(metadata, options) {
    if (!metadata) {
        throw new Error("Metadata: metadata object is a required argument");
    }
    if (!options) {
        throw new Error('options is required argument');
    }
    this.metadata = metadata;
    this.options = options;
};



TokenValidator.prototype.generateOidcPEM = function(kid) {

    if (!this.metadata.oidc.keys) {
        return null;
    }
    for (var i = 0; i < this.metadata.oidc.keys.length; i++) {
        if (this.metadata.oidc.keys[i].kid === kid) {
            log.info('Working on key: ', this.metadata.oidc.keys[i]);
            if (!this.metadata.oidc.keys[i].n) {
                log.warn('modulus was empty. Key was corrupt');
                return null;
            } else if (!this.metadata.oidc.keys[i].e) {
                log.warn('exponent was empty. Key was corrupt');
                return null;
            } else {
                var modulus = new Buffer(this.metadata.oidc.keys[i].n, 'base64');
                var exponent = new Buffer(this.metadata.oidc.keys[i].e, 'base64');

                var pubKey = aadutils.rsaPublicKeyPem(modulus, exponent);

                log.info("Received public key of: ", pubKey);

                return pubKey;
            }
        }
    }

    return null;
};

TokenValidator.prototype.jwtVerify = function(token, done) {

       var decoded = jws.decode(token);
        if (decoded == null) {
            log.warn("Invalid JWT token.");
        }

        log.info('token decoded:  ', decoded);

        if (decoded.header.x5t) {
            PEMkey = this.generateOidcPEM(decoded.header.x5t);
        } else if (decoded.header.kid) {
            PEMkey = this.generateOidcPEM(decoded.header.kid);
        } else {
            throw new TypeError('We did not receive a token we know how to validate');
        }



       // if (!options.issuer) {
        //    options.issuer = metadata.oidc.issuer;
        //}
        this.options.algorithms = this.metadata.oidc.algorithms;

        jwt.verify(token, PEMkey, this.options, function(err, token) {
            if (err) {
                if (err instanceof jwt.TokenExpiredError) {
                    log.warn("Access token expired");
                    done(err);
                } else if (err instanceof jwt.JsonWebTokenError) {
                    log.warn("An error was received validating the token", err.message);
                    done(err);
                } else {
                    done(err);
                }
            } else {
                log.info(token, 'was token going out of verification');
                    done(token);
                }
        });
    };

    exports.TokenValidator = TokenValidator;