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

var create_app = require('./app/app');

var chai = require('chai');
var expect = chai.expect;

const TEST_TIMEOUT = 600000; // 600 seconds
const LOGIN_WAITING_TIME = 1000; // 1 second

/******************************************************************************
 *  Tenant specific endpoint configurations
 *****************************************************************************/

// the template config file
var config_template = {
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

// 1. Config with various of response type

// - hybrid flow config with 'code id_token'
var hybrid_config = config_template;

// - hybrid flow config with 'id_token code'
var hybrid_config_alternative = JSON.parse(JSON.stringify(config_template));
hybrid_config_alternative.responseType = 'id_token code';

// - authorization flow config
var code_config = JSON.parse(JSON.stringify(config_template));
code_config.responseType = 'code';

// - implicit flow config with 'id_token'
var implicit_config = JSON.parse(JSON.stringify(config_template));
implicit_config.responseType = 'id_token';

// 2. Config using query as the response mode

// - authorization flow config with query response type
var code_config_query = JSON.parse(JSON.stringify(config_template));
code_config_query.responseType = 'code';
code_config_query.responseMode = 'query';

// 3. Config without issue value

// - hybrid flow with no issue value
var hybrid_config_noIssuer = JSON.parse(JSON.stringify(config_template));
hybrid_config_noIssuer.issuer = null;

// 4. Config with scope values

// - hybrid flow with scope value email and profile
var hybrid_config_with_scope = JSON.parse(JSON.stringify(config_template));
hybrid_config_with_scope.scope = ['email', 'profile'];

// 5. Config with passReqToCallback set to true
var hybrid_config_passReqToCallback = JSON.parse(JSON.stringify(config_template));
hybrid_config_passReqToCallback.passReqToCallback = true;

/******************************************************************************
 *  Common endpoint configurations
 *****************************************************************************/

// the template config file
var config_template_common_endpoint = {
  identityMetadata: 'https://login.microsoftonline.com/common/.well-known/openid-configuration', 
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

// 1. Config with various of response type

// - hybrid flow config with 'code id_token'
var hybrid_config_common_endpoint = config_template;

// - authorization code flow config
var code_config_common_endpoint = JSON.parse(JSON.stringify(config_template_common_endpoint));
code_config_common_endpoint.responseType = 'code';

// - implicit flow config with 'id_token'
var implicit_config_common_endpoint = JSON.parse(JSON.stringify(config_template_common_endpoint));
implicit_config_common_endpoint.responseType = 'id_token';

// 2. Config using query as the response mode

// - authorization code flow config with query response type
var code_config_common_endpoint_query = JSON.parse(JSON.stringify(config_template_common_endpoint));
code_config_common_endpoint_query.responseType = 'code';
code_config_common_endpoint_query.responseMode = 'query';

// 3. Config without issue value

// - hybrid flow with no issue value and no validateIssuer
var hybrid_config_common_endpoint_noIssuer = JSON.parse(JSON.stringify(config_template_common_endpoint));
hybrid_config_common_endpoint_noIssuer.issuer = null;
hybrid_config_common_endpoint_noIssuer.validateIssuer = false;

// 4. Config with scope values

// - hybrid flow with scope value ['email', 'profile']
var hybrid_config_common_endpoint_with_scope = JSON.parse(JSON.stringify(config_template_common_endpoint));
hybrid_config_common_endpoint_with_scope.scope = ['email', 'profile'];

/******************************************************************************
 *  Invalid configurations
 *****************************************************************************/

// 1. common endpoint with no issuer
var hybrid_config_common_endpoint_wrong_issuer = JSON.parse(JSON.stringify(config_template_common_endpoint));
hybrid_config_common_endpoint_wrong_issuer.issuer = ['wrong_issuer'];

// 2. common endpoint with too short nonceLifetime
var hybrid_config_common_endpoint_short_lifetime = JSON.parse(JSON.stringify(config_template_common_endpoint));
hybrid_config_common_endpoint_short_lifetime.nonceLifetime = 0.001; // 1ms

// 2. common endpoint with wrong client secret
var hybrid_config_common_endpoint_wrong_secret = JSON.parse(JSON.stringify(config_template_common_endpoint));
hybrid_config_common_endpoint_wrong_secret.clientSecret = 'wrong_secret';

/******************************************************************************
 *  Result checking function
 *****************************************************************************/
var driver;
var driver1;
var driver2;
var first_time = true;

var checkResult = (config, arity, done) => {
  var server = create_app(config, {}, arity);

  if (!driver)
    driver = chromedriver.get_driver();

  driver.get('http://localhost:3000/login')
  .then(() => {
    if (first_time) {
      driver.wait(until.titleIs('Sign in to your account'), 10000);  
      var usernamebox = driver.findElement(By.name('login'));
      usernamebox.sendKeys('robot@passportMiddlewareTest.onmicrosoft.com');
      var passwordbox = driver.findElement(By.name('passwd'));
      passwordbox.sendKeys('Tmp123456');
      driver.sleep(LOGIN_WAITING_TIME);
      passwordbox.sendKeys(webdriver.Key.ENTER);
      first_time = false;
    }
  }).then(() => {
    driver.wait(until.titleIs('result'), 10000);
    driver.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver.findElement(By.id('sub')).getText().then((text) => { 
      expect(text).to.equal('hKvkTzTTjvDMuxNhh6HBZJzNClZL-64ve_6c6_JjHp0');
    });
    driver.findElement(By.id('upn')).getText().then((text) => {
      // arity 3 means we are using function(iss, sub, done), so there is no profile.displayName
      if (arity !== 3) 
        expect(text).to.equal('robot@passportMiddlewareTest.onmicrosoft.com');
      else
        expect(text).to.equal('none');
    });
    driver.findElement(By.id('access_token')).getText().then((text) => { 
      if (arity >= 6)
        expect(text).to.equal('exists');
      else
        expect(text).to.equal('none');
    });
    driver.findElement(By.id('refresh_token')).getText().then((text) => { 
      if (arity >= 6)
        expect(text).to.equal('exists');
      else
        expect(text).to.equal('none');
      server.shutdown(done); 
    });
  });
};

var checkResultTwoTabs = (config, arity, done) => {
  var server = create_app(config, {}, arity);

  if (!driver1)
    driver1 = chromedriver.get_driver();
  if (!driver2)
    driver2 = chromedriver.get_driver();

  driver1.get('http://localhost:3000/login')
  .then(() => {
    // go to login page at tab1
    driver1.wait(until.titleIs('Sign in to your account'), 10000); 
    driver2.get('http://localhost:3000/login');
  })
  .then(() => {
    // go to login page at tab2
    driver2.wait(until.titleIs('Sign in to your account'), 10000); 
    var usernamebox = driver1.findElement(By.name('login'));
    usernamebox.sendKeys('robot@passportMiddlewareTest.onmicrosoft.com');
    var passwordbox = driver1.findElement(By.name('passwd'));
    passwordbox.sendKeys('Tmp123456');
    driver1.sleep(LOGIN_WAITING_TIME);
    passwordbox.sendKeys(webdriver.Key.ENTER);
  })
  .then(() => {
    // check the result on tab1
    driver1.wait(until.titleIs('result'), 10000);
    driver1.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver1.findElement(By.id('sub')).getText().then((text) => { 
      expect(text).to.equal('hKvkTzTTjvDMuxNhh6HBZJzNClZL-64ve_6c6_JjHp0');
    });
    driver1.findElement(By.id('upn')).getText().then((text) => {
        expect(text).to.equal('robot@passportMiddlewareTest.onmicrosoft.com');
    });
    driver1.findElement(By.id('access_token')).getText().then((text) => { 
        expect(text).to.equal('exists');
    });
    driver1.findElement(By.id('refresh_token')).getText().then((text) => { 
        expect(text).to.equal('exists');
    })
  })
  .then(() => {
    // switch to tab2
    var usernamebox = driver2.findElement(By.name('login'));
    usernamebox.sendKeys('robot@passportMiddlewareTest.onmicrosoft.com');
    var passwordbox = driver2.findElement(By.name('passwd'));
    passwordbox.sendKeys('Tmp123456');
    driver2.sleep(LOGIN_WAITING_TIME);
    passwordbox.sendKeys(webdriver.Key.ENTER);
  })
  .then(() => {
    // check result on tab2
    driver2.wait(until.titleIs('result'), 10000);
    driver2.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver2.findElement(By.id('sub')).getText().then((text) => { 
      expect(text).to.equal('hKvkTzTTjvDMuxNhh6HBZJzNClZL-64ve_6c6_JjHp0');
    });
    driver2.findElement(By.id('upn')).getText().then((text) => {
        expect(text).to.equal('robot@passportMiddlewareTest.onmicrosoft.com');
    });
    driver2.findElement(By.id('access_token')).getText().then((text) => { 
        expect(text).to.equal('exists');
    });
    driver2.findElement(By.id('refresh_token')).getText().then((text) => { 
      expect(text).to.equal('exists');
      driver1.manage().deleteAllCookies();
      driver2.manage().deleteAllCookies();
      driver1.quit(); driver2.quit();
      server.shutdown(done); 
    });
  });
};

var checkInvalidResult = (config, done) => {
  var server = create_app(config, {}, 8);

  if (!driver)
    driver = chromedriver.get_driver();

  driver.get('http://localhost:3000/login')
  .then(() => {
    if (first_time) {
      driver.wait(until.titleIs('Sign in to your account'), 10000);  
      var usernamebox = driver.findElement(By.name('login'));
      usernamebox.sendKeys('robot@passportMiddlewareTest.onmicrosoft.com');
      var passwordbox = driver.findElement(By.name('passwd'));
      passwordbox.sendKeys('Tmp123456');
      driver.sleep(LOGIN_WAITING_TIME);
      passwordbox.sendKeys(webdriver.Key.ENTER);
      first_time = false;
    }
  })
  .then(() => {
    driver.wait(until.titleIs('result'), 10000);
    driver.findElement(By.id('status')).getText().then((text) => {
      expect(text).to.equal('failed');
      server.shutdown(done);
    });
  });
};

/******************************************************************************
 *  The test cases
 *****************************************************************************/
describe('oidc v1 positive arity test', function() {
  this.timeout(TEST_TIMEOUT);

  // In the tests below, we set passReqToCallback to be false

  it('should succeed with arity 8 for verify function', function(done) {
    checkResult(hybrid_config, 8, done);
  });

  it('should succeed with arity 7 for verify function', function(done) {
    checkResult(hybrid_config, 7, done);
  });

  it('should succeed with arity 6 for verify function', function(done) {
    checkResult(hybrid_config, 6, done);
  }); 

  it('should succeed with arity 4 for verify function', function(done) {
    checkResult(hybrid_config, 4, done);
  });

  it('should succeed with arity 3 for verify function', function(done) {
    checkResult(hybrid_config, 3, done);
  });

  it('should succeed with arity 2 for verify function', function(done) {
    checkResult(hybrid_config, 2, done);
  }); 

  // In the tests below, we set passReqToCallback to be true

  it('should succeed with arity 8 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 8, done);
  });

  it('should succeed with arity 7 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 7, done);
  });

  it('should succeed with arity 6 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 6, done);
  }); 

  it('should succeed with arity 4 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 4, done);
  });

  it('should succeed with arity 3 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 3, done);
  });

  it('should succeed with arity 2 for verify function with req parameter', function(done) {
    checkResult(hybrid_config_passReqToCallback, 2, done);
  }); 
});

describe('oidc v1 positive other test', function() {
  this.timeout(TEST_TIMEOUT);

  /****************************************************************************
   *  Test various response types for tenant specific endpoint
   ***************************************************************************/
  
  // hybrid with 'id_token code'
  it('should succeed', function(done) {
    checkResult(hybrid_config_alternative, 8, done);
  }); 

  // authorization code flow
  it('should succeed', function(done) {
    checkResult(code_config, 8, done);
  }); 

  // implicit flow
  it('should succeed', function(done) {
    checkResult(implicit_config, 2, done);
  }); 

  /****************************************************************************
   *  Test various response type for common endpoint
   ***************************************************************************/

  // hybrid flow
  it('should succeed', function(done) {
    checkResult(hybrid_config_common_endpoint, 8, done);
  }); 

  // authorization code flow
  it('should succeed', function(done) {
    checkResult(code_config_common_endpoint, 8, done);
  }); 

  // implicit flow
  it('should succeed', function(done) {
    checkResult(implicit_config_common_endpoint, 2, done);
  }); 

  /***************************************************************************
   *  Test issuer and validateIssuers for both tenant specific and common endpoint
   **************************************************************************/

  // tenant specific endpoint
  it('should succeed', function(done) {
    checkResult(hybrid_config_noIssuer, 2, done);
  });

  // common endpoint with no issuer and no validateIssuer
  it('should succeed', function(done) {
    checkResult(hybrid_config_common_endpoint_noIssuer, 2, done);
  });

  /****************************************************************************
   *  Test scope for both tenant specific and common endpoint
   ***************************************************************************/

  // tenant specific endpoint
  it('should succeed', function(done) {
    checkResult(hybrid_config_with_scope, 2, done);
  });

  // common endpoint
  it('should succeed', function(done) {
    checkResult(hybrid_config_common_endpoint_with_scope, 2, done);
  });

  /****************************************************************************
   *  Test query response type for both tenant specific and common endpoint
   ***************************************************************************/

  // tenant specific endpoint
  it('should succeed', function(done) {
    checkResult(code_config_query, 2, done);
  });

  // common endpoint
  it('should succeed', function(done) {
    checkResult(code_config_common_endpoint_query, 2, done);
  });

  /****************************************************************************
   *  Test login from two tabs
   ***************************************************************************/

  it('should succeed with arity 8 for verify function', function(done) {
    checkResultTwoTabs(hybrid_config, 8, done);
  });
});

describe('oidc v1 negative test', function() {
  this.timeout(TEST_TIMEOUT);

  // Wrong issuer
  it('should fail with wrong issuer', function(done) {
    checkInvalidResult(hybrid_config_common_endpoint_wrong_issuer, done);
  });

  // Nonce lifetime is too short
  it('should fail with short nonce lifetime', function(done) {
    checkInvalidResult(hybrid_config_common_endpoint_short_lifetime, done);
  });

  // Wrong clientSecret
  it('should fail with wrong client secret', function(done) {
    checkInvalidResult(hybrid_config_common_endpoint_wrong_secret, done);
  });

  it('close service', function(done) {
    expect('1').to.equal('1');
    driver.quit();
    service.stop();
    done();
  });
});
