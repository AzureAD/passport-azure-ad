/**
 * Copyright (c) Microsoft Corporation
 *  All Rights Reserved
 *  MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the 'Software'), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
 * OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

/******************************************************************************
 *  Testing tools setup
 *****************************************************************************/

var chromedriver = require('./driver');
var service = chromedriver.get_service();
var webdriver = chromedriver.webdriver;
var By = webdriver.By;
var until = webdriver.until;

var chai = require('chai');
var expect = chai.expect;

const TEST_TIMEOUT = 500000; // 30 seconds
const LOGIN_WAITING_TIME = 1000; // 1 second

/******************************************************************************
 *  Client configurations
 *****************************************************************************/

// client configuration
var client_config = {
  identityMetadata: 'https://login.microsoftonline.com/passportMiddlewareTest.onmicrosoft.com/.well-known/openid-configuration', 
  clientID: '4e60375b-41f6-4769-9ae1-97b422ac0d4c',
  responseType: 'code id_token', 
  responseMode: 'form_post', 
  redirectUrl: 'http://localhost:3000/auth/openid/return', 
  allowHttpForRedirectUrl: true,
  clientSecret: '668WJN5qvJ1KVVY+An/Ll1Z5sEOeECRTmgMR/x4YVa4=', 
  validateIssuer: true,
  issuer: ['https://sts.windows.net/3bc5b5fb-d689-4886-8f9b-a477b719f741/'],
  passReqToCallback: false,
  scope: null,
  loggingLevel: null,
  nonceLifetime: null,
};

/******************************************************************************
 *  Api server configurations (tenant specific endpoint)
 *****************************************************************************/

// api server configuration
var server_config = {
  identityMetadata: 'https://login.microsoftonline.com/passportMiddlewareTest.onmicrosoft.com/.well-known/openid-configuration',
  clientID: '4e60375b-41f6-4769-9ae1-97b422ac0d4c',
  validateIssuer: true,
  passReqToCallback: false,
  issuer: null,
  audience: 'https://graph.windows.net',
  allowMultiAudiencesInToken: false,
  loggingLevel: null,
};

var server_config_with_req = JSON.parse(JSON.stringify(server_config));
server_config_with_req.passReqToCallback = true;

var server_config_allow_multiAud = JSON.parse(JSON.stringify(server_config));
server_config_allow_multiAud.allowMultiAudiencesInToken = false;

var server_config_wrong_issuer = JSON.parse(JSON.stringify(server_config));
server_config_wrong_issuer.issuer = 'wrong_issuer';

var server_config_wrong_identityMetadata = JSON.parse(JSON.stringify(server_config));
server_config_wrong_identityMetadata.identityMetadata = 'https://login.microsoftonline.com/wrongTenant/.well-known/openid-configuration';

var server_config_wrong_audience = JSON.parse(JSON.stringify(server_config));
server_config_wrong_audience.audience = 'wrong_audience';

var server_config_wrong_issuer_no_validateIssuer = JSON.parse(JSON.stringify(server_config));
server_config_wrong_issuer_no_validateIssuer.issuer = 'wrong_issuer';
server_config_wrong_issuer_no_validateIssuer.validateIssuer = false;

/******************************************************************************
 *  Api server configurations (common endpoint)
 *****************************************************************************/

// api server configuration
var server_config_common_endpoint = {
  identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration',
  clientID: '4e60375b-41f6-4769-9ae1-97b422ac0d4c',
  validateIssuer: true,
  passReqToCallback: false,
  issuer: 'https://sts.windows.net/3bc5b5fb-d689-4886-8f9b-a477b719f741/',
  audience: 'https://graph.windows.net',
  allowMultiAudiencesInToken: false,
  loggingLevel: null,
};

var server_config_common_endpoint_with_req = JSON.parse(JSON.stringify(server_config_common_endpoint));
server_config_common_endpoint_with_req.passReqToCallback = true;

var server_config_common_endpoint_allow_multiAud = JSON.parse(JSON.stringify(server_config_common_endpoint));
server_config_common_endpoint_allow_multiAud.allowMultiAudiencesInToken = false;

var server_config_common_endpoint_wrong_issuer = JSON.parse(JSON.stringify(server_config_common_endpoint));
server_config_common_endpoint_wrong_issuer.issuer = 'wrong_issuer';

var server_config_common_endpoint_wrong_audience = JSON.parse(JSON.stringify(server_config_common_endpoint));
server_config_common_endpoint_wrong_audience.audience = 'wrong_audience';

var server_config_common_endpoint_wrong_issuer_no_validateIssuer = JSON.parse(JSON.stringify(server_config_common_endpoint));
server_config_common_endpoint_wrong_issuer_no_validateIssuer.issuer = 'wrong_issuer';
server_config_common_endpoint_wrong_issuer_no_validateIssuer.validateIssuer = false;

/******************************************************************************
 *  Result checking function
 *****************************************************************************/
var driver;
var client;

var get_token = (done) => {
  driver = chromedriver.get_driver();
  client = require('./app/client_for_api')(client_config, { resourceURL: 'https://graph.windows.net' });

  driver.get('http://localhost:3000')
  .then(() => {
    driver.wait(until.titleIs('Example'), 10000);
    driver.findElement(By.xpath('/html/body/p/a')).click();
  }).then(() => {
    driver.wait(until.titleIs('Sign in to your account'), 10000); 
    var usernamebox = driver.findElement(By.name('login'));
    usernamebox.sendKeys('robot@passportMiddlewareTest.onmicrosoft.com');
    var passwordbox = driver.findElement(By.name('passwd'));
    passwordbox.sendKeys('Tmp123456');
    driver.sleep(LOGIN_WAITING_TIME);
    passwordbox.sendKeys(webdriver.Key.ENTER);
  }).then(() => {
    expect('1').to.equal('1');
    done();
  })
};

var checkResult = (config, result, done) => {
  var server = require('./app/api')(config);
  
  driver.get('http://localhost:3000/callApi')
  .then(() => {
    driver.wait(until.titleIs('result'), 10000);
    driver.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal(result);
      server.shutdown(done);
    });
  });
};

/******************************************************************************
 *  The test cases
 *****************************************************************************/

describe('bearer test', function() {
  this.timeout(TEST_TIMEOUT);

  it('get token for the rest tests', function(done) {
    get_token(done);
  });

  /******************************************************************************
   *  tenant specific endpoint
   *****************************************************************************/

  it('should succeed', function(done) {
    checkResult(server_config, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_with_req, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_allow_multiAud, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_wrong_issuer_no_validateIssuer, 'succeeded', done);
  });

  it('should fail with wrong audience', function(done) {
    checkResult(server_config_wrong_audience, 'Unauthorized', done);
  });

  it('should fail with wrong issuer', function(done) {
    checkResult(server_config_wrong_issuer, 'Unauthorized', done);
  });

  it('should fail with wrong identityMetadata', function(done) {
    checkResult(server_config_wrong_identityMetadata, 'Unauthorized', done);
  });

  /******************************************************************************
   *  common endpoint
   *****************************************************************************/

  it('should succeed', function(done) {
    checkResult(server_config_common_endpoint, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_common_endpoint_with_req, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_common_endpoint_allow_multiAud, 'succeeded', done);
  });

  it('should succeed', function(done) {
    checkResult(server_config_wrong_issuer_no_validateIssuer, 'succeeded', done);
  });

  it('should fail with wrong audience', function(done) {
    checkResult(server_config_common_endpoint_wrong_audience, 'Unauthorized', done);
  });

  it('should fail with wrong issuer', function(done) {
    checkResult(server_config_common_endpoint_wrong_issuer, 'Unauthorized', done);
  });

  it('close service', function(done) {
    expect('1').to.equal('1');
    driver.quit();
    service.stop();
    client.shutdown(done);
  });
});
