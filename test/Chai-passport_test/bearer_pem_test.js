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
var BearerStrategy = require('../../lib/index').BearerStrategy;

var publicKeyPem = "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBCgKCAQEAvbcFrj193Gm6zeo5e2/y54Jx49sIgScv+2JO+n6NxNqQaKVnMkHc\n" +
                "z+S1j2FfpFngotwGMzZIKVCY1SK8SKZMFfRTU3wvToZITwf3W1Qq6n+h+abqpyJT\n" +
                "aqIcfhA0d6kEAM5NsQAKhfvw7fre1QicmU9LWVWUYAayLmiRX6o3tktJq6H58pUz\n" +
                "Ttx/D0Dprnx6z5sW+uiMipLXbrgYmOez7htokJVgDg8w+yDFCxZNo7KVueUkLkxh\n" +
                "NjYGkGfnt18s7ZW036WoTmdaQmW4CChf/o4TLE5VyGpYWm7I/+nV95BBvwlzokVV\n" +
                "KzveKf3l5UU3c6PkGy+BB3E/ChqFm6sPWwIDAQAB\n" +
                "-----END RSA PUBLIC KEY-----";

var expired_access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlliUkFRUll" +
                "jRV9tb3RXVkpLSHJ3TEJiZF85cyIsImtpZCI6IlliUkFRUlljRV9tb3RXVkpLSHJ3T" +
                "EJiZF85cyJ9.eyJhdWQiOiJzcG46NjUxNGE4Y2EtZDllNC00MTU1LWIyOTItNjUyNT" +
                "gzOThmM2FhIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjY4ZGExYTEt" +
                "OWRiNC00OGI5LWIxZmUtNjgzMjUwYmE5MGNjLyIsImlhdCI6MTQ2NzMxMTI0OCwibm" +
                "JmIjoxNDY3MzExMjQ4LCJleHAiOjE0NjczMTUxNDgsImFjciI6IjEiLCJhbXIiOlsi" +
                "cHdkIl0sImFwcGlkIjoiYmViZmFkNTctZWZkNy00MTliLWI3NGItNGI5ZGFiN2JkND" +
                "cwIiwiYXBwaWRhY3IiOiIxIiwiZmFtaWx5X25hbWUiOiJvbmUiLCJnaXZlbl9uYW1l" +
                "Ijoicm9ib3QiLCJpcGFkZHIiOiIxMzEuMTA3LjE2MC4yMjYiLCJuYW1lIjoicm9ib3" +
                "QgMSIsIm9pZCI6Ijc5MTJmZTdiLWI1YWItNDI1Yi1iYjFmLTBlODNiOTlmY2E3ZiIs" +
                "InNjcCI6InVzZXJfaW1wZXJzb25hdGlvbiIsInN1YiI6Ikt1Mi1GdDlsWTlpMkJ2Zm" +
                "htcTQxNjZaSDNrV0g0V1h0bXpHOU0tOE1GYWMiLCJ0aWQiOiIyNjhkYTFhMS05ZGI0" +
                "LTQ4YjktYjFmZS02ODMyNTBiYTkwY2MiLCJ1bmlxdWVfbmFtZSI6InJvYm90QHNpan" +
                "VuLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6InJvYm90QHNpanVuLm9ubWljcm9zb2Z0" +
                "LmNvbSIsInZlciI6IjEuMCJ9.VTg8AqnbSzfC7nUmf3xKnNrS_3BcOSGqz_CBPi6Th" +
                "2piwNc--3Aq_K6SOt2QlbP7yni8IOqeY2ooqDgj0CvcvV3HHHHFatS7X8Kppg4z35l" +
                "B4b67DJuIeHgCYYBR75qMVC1z5n4dgYGoNE-JNvlZZmaeHnrO8FAmQBKJUOrIyCNpo" +
                "BjIsUXgXJKTPdL7HQL9nFz6h9sUmvbvpwqk1NgfmfTsJ0wHuSNHjHmryZ7vGnnjJHU" +
                "C1zQmo9nesF0t7ad2Gk2RdlU93FbcZEW0hFE5Rtu0SbjOZAQdDVsBj_Voi7iQ_Kr-C" +
                "nC14vuZ5kE9ACSMf2VG5wfcg6z4pyQdw-LpjQ";

var options = {
	certificate: publicKeyPem,  // use certificate instead of metadata
    algorithms: ['RS256'],
    clientID: 'spn:6514a8ca-d9e4-4155-b292-65258398f3aa',
    validateIssuer: true,
    issuer: 'https://sts.windows.net/268da1a1-9db4-48b9-b1fe-683250ba90cc/',
    passReqToCallback: false,
};

describe('test expired token using pem', function() {
	var strategy = new BearerStrategy(options, function(token, done) {
		// since we are testing expired token, we won't come here
    });

	var challenge = '';

	before(function(done) {
		chai.passport
		  .use(strategy)
		  .req(function(req) {
		  	req.headers.authorization = 'Bearer ' + expired_access_token;
		  })
		  .fail(function(c) {
		  	challenge = c;
		  	done();
		  })
		  .authenticate();
	});

	it('should fail with token expired message', function() {
		chai.expect(challenge).to.be.a.string;
		chai.expect(challenge).to.equal('jwt is expired');
	});
});
