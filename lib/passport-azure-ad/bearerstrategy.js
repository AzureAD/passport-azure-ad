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
"use strict";

var BearerStrategy = require('passport-http-bearer').Strategy,
    util = require('util'),
    jwt = require('jsonwebtoken'),
    aadutils = require('./aadutils'),
    Metadata = require('./metadata').Metadata,
    Log = require('./logging').getLogger,
    jws = require('jws');
var log = new Log("AzureAD: Bearer Strategy");

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
    /*jshint validthis: true */
    if (typeof options === 'function') {
        verify = options;
        options = {};
    }

    // Passport requires a verify function
    if (!verify) {
        throw new TypeError('BearerStrategy requires a verify callback. Do not cheat!');
    }

    // default value of passReqToCallback is true
    if (options.passReqToCallback === undefined || options.passReqToCallback === null) {
        log.warn(`passReqToCallback is not set, setting it to true by default`);
        options.passReqToCallback = true;
    }

    // if logging level specified, switch to it.
    if (options.loggingLevel) { log.levels("console", options.loggingLevel); }

    if (options.identityMetadata) {
        log.info('Metadata url provided to Strategy was: ', options.identityMetadata);
        this.metadata = new Metadata(options.identityMetadata, "oidc", options);
    } else {
        log.warn("No options was presented to Strategy as required.");
        throw new TypeError('OIDCBearerStrategy requires either a PEM encoded public key or a metadata location that contains cert data for RSA and ECDSA callback.');
    }

    if (options.clientID === undefined || options.clientID === null || options.clientID === '') {
        throw new Error('options.clientID cannot be null or empty');
    }

    // check if we are using the common endpoint
    options._isCommonEndpoint = (options.identityMetadata && options.identityMetadata.indexOf('/common/') != -1);

    // the default value of validateIssuer is true
    if (options.validateIssuer == undefined || options.validateIssuer === null)
        options.validateIssuer = true;

    // issuer validation for common endpoint is not supported
    if (options._isCommonEndpoint && options.validateIssuer) {
        throw new Error(`Configuration error. Please either replace 'common' in identity metadata url with your tenant guid (something like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), or set 'validateIssuer' false. Issuer validation is not supported for common endpoint.`);
    }

    // give a warning if user is not validating issuer for non-common endpoint
    if (!options._isCommonEndpoint && !options.validateIssuer) {
        log.warn(`Production environments should always validate the issuer. For multiple issuers custom code will be required.`);
    }

    // if you want to check JWT audience (aud), provide a value here
    if (options.audience) {
        log.info('Audience provided to Strategy was: ', options.audience);
    } else {
        // since the id_token is for itself, so the 'aud' is the clientID by default
        options.audience = options.clientID;
    }

    if (options.policyName) {
        log.info('B2C: We have been instructed that this is a B2C tenant. We will configure as required.');
        if (!options.tenantName) {
            throw new TypeError('BearerStrategy requires you pass the tenant name if using a B2C tenant.');
        } else {
            // We are replacing the common endpoint with the concrete metadata of a B2C tenant.
            options.identityMetadata = options.identityMetadata.replace("common", options.tenantName);
            options.identityMetadata = options.identityMetadata.concat('?p=' + options.policyName)
                .concat(`&${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
                .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);;
        }
    } else {
        options.identityMetadata = options.identityMetadata.concat(`?${aadutils.getLibraryProductParameterName()}=${aadutils.getLibraryProduct()}`)
            .concat(`&${aadutils.getLibraryVersionParameterName()}=${aadutils.getLibraryVersion()}`);
    }

    // Token validation settings. Hopefully most of these will be pulled from the metadata and this is not needed
    this.metadata.fetch(function (err) {
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

        if (options.validateIssuer) {
            options.issuer = this.metadata.oidc.issuer;
        }

        options.algorithms = this.metadata.oidc.algorithms;

        jwt.verify(token, PEMkey, options, function (err, token) {
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

    this._options = options;

    BearerStrategy.call(this, options, jwtVerify);
    this.name = 'oauth-bearer'; // Me, a name I call myself.
}

util.inherits(Strategy, BearerStrategy);
/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
