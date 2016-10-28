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
const LOGIN_WAITING_TIME = 2000; // 1 second

/******************************************************************************
 *  Client configurations
 *****************************************************************************/

// client configuration
var client_config = {
  identityMetadata: 'https://login.microsoftonline.com/sijun1b2c.onmicrosoft.com/v2.0/.well-known/openid-configuration', 
  clientID: 'f0b6e4eb-2d8c-40b6-b9c6-e26d1074846d',
  responseType: 'code id_token', 
  responseMode: 'form_post', 
  redirectUrl: 'http://localhost:3000/auth/openid/return', 
  allowHttpForRedirectUrl: true,
  clientSecret: '-9m\\Ed*?eb0.\\Iax', 
  validateIssuer: true,
  isB2C: true,
  issuer: ['https://login.microsoftonline.com/22bf40c6-1186-4ea5-b49b-3dc4ec0f54eb/v2.0/'],
  passReqToCallback: false,
  scope: ['offline_access', 'f0b6e4eb-2d8c-40b6-b9c6-e26d1074846d'],
  loggingLevel: null,
  nonceLifetime: null,
};

/******************************************************************************
 *  Api server configurations (tenant specific endpoint)
 *****************************************************************************/

// api server configuration
var server_config = {
  identityMetadata: 'https://login.microsoftonline.com/sijun1b2c.onmicrosoft.com/v2.0/.well-known/openid-configuration',
  clientID: 'f0b6e4eb-2d8c-40b6-b9c6-e26d1074846d',
  validateIssuer: true,
  passReqToCallback: false,
  isB2C: true,
  policyName: 'b2c_1_signin',
  issuer: null,
  audience: null,
  allowMultiAudiencesInToken: false,
  loggingLevel: null,
};

var server_config_with_req = JSON.parse(JSON.stringify(server_config));
server_config_with_req.passReqToCallback = true;

var server_config_allow_multiAud = JSON.parse(JSON.stringify(server_config));
server_config_allow_multiAud.allowMultiAudiencesInToken = false;

var server_config_wrong_issuer = JSON.parse(JSON.stringify(server_config));
server_config_wrong_issuer.issuer = 'wrong_issuer';

var server_config_wrong_policyName = JSON.parse(JSON.stringify(server_config));
server_config_wrong_policyName.policyName = 'b2c_1_wrong_policy';

var server_config_wrong_identityMetadata = JSON.parse(JSON.stringify(server_config));
server_config_wrong_identityMetadata.identityMetadata = 'https://login.microsoftonline.com/wrongTenant/v2.0/.well-known/openid-configuration';

var server_config_wrong_audience = JSON.parse(JSON.stringify(server_config));
server_config_wrong_audience.audience = 'wrong_audience';

var server_config_wrong_issuer_no_validateIssuer = JSON.parse(JSON.stringify(server_config));
server_config_wrong_issuer_no_validateIssuer.issuer = 'wrong_issuer';
server_config_wrong_issuer_no_validateIssuer.validateIssuer = false;

/******************************************************************************
 *  Result checking function
 *****************************************************************************/
var driver;
var client;

var get_token = (done) => {
  driver = chromedriver.get_driver();
  client = require('./app/client_for_api')(client_config, {});

  driver.get('http://localhost:3000/login?p=b2c_1_signin')
  .then(() => {
    driver.wait(until.titleIs('Sign in to your account'), 10000); 
    var usernamebox = driver.findElement(By.name('login'));
    usernamebox.sendKeys('lsj31415926@gmail.com');
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

describe('bearer b2c test', function() {
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

  it('should fail with wrong policyName', function(done) {
    checkResult(server_config_wrong_policyName, 'Unauthorized', done);
  });

  it('should fail with wrong issuer', function(done) {
    checkResult(server_config_wrong_issuer, 'Unauthorized', done);
  });

  it('should fail with wrong identityMetadata', function(done) {
    checkResult(server_config_wrong_identityMetadata, 'Unauthorized', done);
  });

  it('close service', function(done) {
    expect('1').to.equal('1');
    driver.quit();
    service.stop();
    client.shutdown(done);
  });
});
