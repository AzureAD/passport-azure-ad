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
 * @flow
 */

/*jslint node: true */
"use strict";

var bunyan = require('bunyan');
var BearerStrategy = require('passport-http-bearer').Strategy;
var util = require('util');
var jwt = require('jsonwebtoken');
var Metadata = require('./metadata').Metadata;
var jws = require('jws');

var log = bunyan.createLogger({
    name: 'Microsoft OpenID Connect: OAuth Bearer Strategy'
});

var PEMkey = null;
/**
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(token, done) { ... }
 *
 * `token` is the verified and decoded bearer token provided as a credential.
 * The verify callback is responsible for finding the user who posesses the
 * token, and invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `realm`    authentication realm, defaults to "Users"
 *   - `scope`    list of scope values indicating the required scope of the
 *                access token for accessing the requested resource
 *   - `audience` if you want to check JWT audience (aud), provide a value here
 *   - `issuer`   if you want to check JWT issuer (iss), provide a value here
 *
 * Examples:
 *
 *     passport.use(new OIDCBearerStrategy(
 *       secretOrPublicKey
 *       function(token, done) {
 *         User.findById(token.sub, function (err, user) {
 *           if (err) { return done(err); }
 *           if (!user) { return done(null, false); }
 *           return done(null, user, token);
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 * For further details on JSON Web Token, refert to [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
 *
 * @param {object} options - The Options.
 * @param {Function} verify - The verify callback.
 * @constructor
 */

function Strategy(options, verify) {


    // if you want to check JWT issuer that is not in the token (not recommended), provide a value here

    if (options.issuer) {
        log.info('Issuer provided to Strategy was: ', options.issuer);
    }

    // if you want to check JWT audience (aud), provide a value here

    if (options.audience) {
        log.info('Audience provided to Strategy was: ', options.audience);
    }

    if (options.identityMetadata) {

        log.info('Metadata url provided to Strategy was: ', options.identityMetadata);
        this.metadata = new Metadata(options.identityMetadata, "oidc");
    }

    if (!options.certificate && !options.identityMetadata) {
        log.warn("No options was presented to Strategy as required.");
        throw new TypeError('OIDCBearerStrategy requires either a PEM encoded public key or a metadata location that contains cert data for RSA and ECDSA callback.');
    }

    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    // Passport requires a verify function

    if (!verify) {
        throw new TypeError('OIDCBearerStrategy requires a verify callback. Do not cheat!');
    }

    // Token validation settings. Hopefully most of these will be pulled from the metadata and this is not needed


    this.metadata.fetch(function(err) {
        if (err) {
            throw new Error("Unable to fetch metadata: " + err);
        }

    });


    function jwtVerify(req, token, done) {

        if (!options.passReqToCallback) {
            token = arguments[0];
            done = arguments[1];
            req = null;
            log.info('got token - going in to verification');
        }


        var decoded = jws.decode(token);
        if (decoded == null) {
            done(null, false, "Invalid JWT token.");
        }

        log.info('token decoded:  ', decoded);


        // We have two different types of token signatures we have to validate here. One provides x5t and the other a kid.
        // We need to call the right one.

        if (decoded.header.x5t) {
            PEMkey = this.metadata.generateOidcPEM(decoded.header.x5t);
        } else if (decoded.header.kid) {
            PEMkey = this.metadata.generateOidcPEM(decoded.header.kid);
        } else {
            throw new TypeError('We did not reveive a token we know how to validate');
        }



        if (!options.issuer) {
            options.issuer = this.metadata.oidc.issuer;
        }
        options.algorithms = this.metadata.oidc.algorithms;

        jwt.verify(token, PEMkey, options, function(err, token) {
            if (err) {
                if (err instanceof jwt.TokenExpiredError) {
                    log.warn("Access token expired");
                    done(null, false, 'The access token expired');
                } else if (err instanceof jwt.JsonWebTokenError) {
                    log.warn("An error was received validating the token", err.message);
                    done(null, false, util.format('Invalid token (%s)', err.message));
                } else {
                    done(err, false);
                }
            } else {
                log.info(token, 'was token going out of verification');
                if (options.passReqToCallback) {
                    log.info("We did pass Req back to Callback");
                    verify(req, token, done);
                } else {
                    log.info("We did not pass Req back to Callback");
                    verify(token, done);
                }
            }
        });
    }

    var opts = {};
    opts.passReqToCallback = true;

    console.log('Req: ' + options.passReqToCallback);

    BearerStrategy.call(this, options, jwtVerify);

    this.name = 'oauth-bearer'; // Me, a name I call myself.
}

util.inherits(Strategy, BearerStrategy);
/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
