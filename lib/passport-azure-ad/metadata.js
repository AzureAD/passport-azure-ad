/**
 * Copyright (c) Microsoft Corporationg
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
'use strict';

var xml2js = require('xml2js');
var request = require('request');
var aadutils = require('./aadutils');
var async = require('async');

// Logging

var bunyan = require('bunyan');
var log = bunyan.createLogger({
    name: 'Microsoft OpenID Connect: Passport Strategy: Metadata Parser'
});

var Metadata = function(url, authtype) {
    if (!url) {
        throw new Error("Metadata: url is a required argument");
    }
    if (!authtype) {
        throw new Error('OIDCBearerStrategy requires an authentication type specified to metadata parser. Valid types are saml, wsfed, or odic"');
    }
    this.url = url;
    this.metadata = null;
    this.authtype = authtype;
};

Object.defineProperty(Metadata, 'url', {
    get: function() {
        return this.url;
    }
});

Object.defineProperty(Metadata, 'saml', {
    get: function() {
        return this.saml;
    }
});

Object.defineProperty(Metadata, 'wsfed', {
    get: function() {
        return this.wsfed;
    }
});

Object.defineProperty(Metadata, 'oidc', {
    get: function() {
        return this.oidc;
    }
});

Object.defineProperty(Metadata, 'metadata', {
    get: function() {
        return this.metadata;
    }
});

Metadata.prototype.updateSamlMetadata = function(doc, next) {
    try {
        this.saml = {};

        var entity = aadutils.getElement(doc, 'EntityDescriptor');
        var idp = aadutils.getElement(entity, 'IDPSSODescriptor');
        var signOn = aadutils.getElement(idp[0], 'SingleSignOnService');
        var signOff = aadutils.getElement(idp[0], 'SingleLogoutService');
        var keyDescriptor = aadutils.getElement(idp[0], 'KeyDescriptor');
        this.saml.loginEndpoint = signOn[0].$.Location;
        this.saml.logoutEndpoint = signOff[0].$.Location;

        // copy the x509 certs from the metadata
        this.saml.certs = [];
        for (var j=0;j<keyDescriptor.length;j++) {
     this.saml.certs.push(keyDescriptor[j].KeyInfo[0].X509Data[0].X509Certificate[0]);
     }
        next(null);
    } catch (e) {
        next(new Error('Invalid SAMLP Federation Metadata ' + e.message));
    }
};

Metadata.prototype.updateWsfedMetadata = function(doc, next) {
    try {
        this.wsfed = {};
        var entity = aadutils.getElement(doc, 'EntityDescriptor');
        var roles = aadutils.getElement(entity, 'RoleDescriptor');
        for (var i = 0; i < roles.length; i++) {
            var role = roles[i];
            if (role['fed:SecurityTokenServiceEndpoint']) {
                var endpoint = role['fed:SecurityTokenServiceEndpoint'];
                var endPointReference = aadutils.getFirstElement(endpoint[0], 'EndpointReference');
                this.wsfed.loginEndpoint = aadutils.getFirstElement(endPointReference, 'Address');

                var keyDescriptor = aadutils.getElement(role, 'KeyDescriptor');
                // copy the x509 certs from the metadata
                this.wsfed.certs = [];
                for (var j=0;j<keyDescriptor.length;j++) {
                this.wsfed.certs.push(keyDescriptor[j].KeyInfo[0].X509Data[0].X509Certificate[0]);
                }
                break;
            }
        }

        return next(null);
    } catch (e) {
        next(new Error('Invalid WSFED Federation Metadata ' + e.message));
    }
};

Metadata.prototype.updateOidcMetadata = function(doc, next) {
    log.info('Request to update the Open ID Connect Metadata');
    try {
        this.oidc = {};
        this.oidc.issuer = doc['issuer'];
        this.oidc.algorithms = doc['id_token_signing_alg_values_supported'];
        this.oidc.auth_endpoint = doc['authorization_endpoint'];
        this.oidc.token_endpoint = doc['token_endpoint'];
        this.oidc.userinfo_endpoint = doc['userinfo_endpoint'];
        this.oidc.end_session_endpoint = doc['end_session_endpoint'];
        var jwksUri = doc.jwks_uri;

        log.info('Algorithm retreived was: ', this.oidc.algorithms);
        log.info('Issuer we are using is: ', this.oidc.issuer);
        log.info('Key Endpoint will we use is: ', jwksUri);
        log.info('Authentication endpoint we will use is: ', this.oidc.auth_endpoint);
        log.info('Token endpoint we will use is: ',this.oidc.token_endpoint);
        log.info('User info endpoint we will use is: ',this.oidc.userinfo_endpoint);
        log.info('The logout endpoint we will use is: ',this.oidc.end_session_endpoint);
        log.info();

        var self = this;
        var callback = next;

        async.waterfall([
            // fetch the signing keys
            function(next) {
                request(jwksUri, function(err, response, body) {
                    if (err) {
                        next(err);
                    } else if (response.statusCode !== 200) {
                        next(new Error("Error:" + response.statusCode + " Cannot get AAD Signing Keys"));
                    } else {
                        next(null, body);
                    }
                });
            },

            function(body, next) {
                // parse the AAD Federation metadata xml
                log.info("Parsing JSON retreived from the signing keys endpoint.");
                try {
                    self.oidc.keys = JSON.parse(body).keys;
                    log.info("***** KEYS  ******");
                    log.info("");
                    log.info(self.oidc.keys);
                    log.info("");
                    log.info("***********");
                    next(null);
                } catch (e) {
                    log.info("No keys found at endpoint!");
                    next(new Error(e));
                }
            },

        ], function(err) {
            callback(err);
        });

    } catch (e) {
        next(new Error('Invalid Open ID Connect Federation Metadata ' + e.message));
    }
};

Metadata.prototype.generateOidcPEM = function(kid) {

    if (!this.oidc.keys) {
        return null;
    }
    for (var i = 0; i < this.oidc.keys.length; i++) {
        if (this.oidc.keys[i].kid === kid) {
            log.info('Working on key: ', this.oidc.keys[i]);
            if (!this.oidc.keys[i].n) {
                log.warn('modulus was empty. Key was corrupt');
                return null;
            } else if (!this.oidc.keys[i].e) {
                log.warn('exponent was empty. Key was corrupt');
                return null;
            } else {
                var modulus = new Buffer(this.oidc.keys[i].n, 'base64');
                var exponent = new Buffer(this.oidc.keys[i].e, 'base64');

                var pubKey = aadutils.rsaPublicKeyPem(modulus, exponent);

                log.info("Received public key of: ", pubKey);

                return pubKey;
            }
        }
    }

    return null;
};


Metadata.prototype.fetch = function(callback) {
    var self = this;

    async.waterfall([
        // fetch the Federation metadata for the AAD tenant
        function(next) {
            request(self.url, function(err, response, body) {
                if (err) {
                    next(err);
                } else if (response.statusCode !== 200) {
                    next(new Error("Error:" + response.statusCode + " Cannot get AAD Federation metadata from " + self.url));
                } else {
                    next(null, body);
                }
            });
        },
        function(body, next) {
            if (self.authtype === "saml" || self.authtype === "wsfed") {
                // parse the AAD Federation metadata xml
                var parser = new xml2js.Parser({
                    explicitRoot: true
                });
                // Note: xml responses from Azure AAD have a leading \ufeff which breaks xml2js parser!
                parser.parseString(body.replace("\ufeff", ""), function(err, data) {
                    self.metatdata = data;
                    next(err);

                });
            } else if (self.authtype === "oidc") {
                log.info("Parsing JSON retreived from the endpoint");
                self.metadata = JSON.parse(body);
                next(null);

            } else {
                next(new Error("No Authentication type specified to metadata parser. Valid types are saml, wsfed, or odic"));
            }

        },
        function(next) {

            console.log('updating metadata...');

            if (self.authtype === "saml") {
                self.updateSamlMetadata(self.metatdata, next);
            } else if (self.authtype === "wsfed") {
                self.updateWsfedMetadata(self.metatdata, next);
            } else if (self.authtype === "oidc") {
                self.updateOidcMetadata(self.metadata, next);
            }
        },
    ], function(err) {
        // return err or success (err === null) to callback
        callback(err);
    });
};

exports.Metadata = Metadata;
