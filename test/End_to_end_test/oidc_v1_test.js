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
var fs = require('fs');

const TEST_TIMEOUT = 1000000; // 1000 seconds
const LOGIN_WAITING_TIME = 3000; // 3 second

/******************************************************************************
 *  Configurations needed
 *****************************************************************************/
// test parameters like clientID, clientSecret, username, password etc
var test_parameters = {};

// tenant specific endpoint configurations
var config_template, hybrid_config, hybrid_config_alternative, code_config,
implicit_config, code_config_query, hybrid_config_noIssuer, hybrid_config_with_scope,
hybrid_config_passReqToCallback, 
hybrid_config_clientAssertion, code_config_clientAssertion = {};

// common endpoint configurations
var config_template_common_endpoint, hybrid_config_common_endpoint, 
code_config_common_endpoint, implicit_config_common_endpoint, 
code_config_common_endpoint_query, hybrid_config_common_endpoint_noIssuer,
hybrid_config_common_endpoint_with_scope = {}; 

// invalid configurations
var hybrid_config_common_endpoint_wrong_issuer, 
hybrid_config_common_endpoint_short_lifetime, 
hybrid_config_common_endpoint_wrong_secret, 
hybrid_config_clientAssertion_invalid_pemKey,
hybrid_config_clientAssertion_unregistered_pemKey,
hybrid_config_clientAssertion_wrong_thumbprint = {};

// drivers needed for the tests
var driver;
var driver1;
var driver2;
var first_time = true;

/******************************************************************************
 *  Untility functions for the tests
 *****************************************************************************/

var get_test_parameters = (apply_test_parameters_callback, done) => {
  var is_test_parameters_completed = require('./test_parameters').is_test_parameters_completed;

  if (is_test_parameters_completed) {
    test_parameters = require('./test_parameters').test_parameters.v1_params;
    apply_test_parameters_callback(done);
  } else {
    require('./script').set_test_parameters((params) => {
      test_parameters = params.v1_params;
      apply_test_parameters_callback(done);
    });
  }
};

var apply_test_parameters = (done) => {

  /****************************************************************************
   *  Tenant specific endpoint configurations
   ***************************************************************************/
  config_template = {
    identityMetadata: 'https://login.microsoftonline.com/' + test_parameters.tenantID + '/.well-known/openid-configuration', 
    clientID: test_parameters.clientID,
    responseType: 'code id_token', 
    responseMode: 'form_post', 
    redirectUrl: 'http://localhost:3000/auth/openid/return', 
    allowHttpForRedirectUrl: true,
    clientSecret: test_parameters.clientSecret,
    validateIssuer: true,
    issuer: ['https://sts.windows.net/' + test_parameters.tenantID + '/'],
    passReqToCallback: false,
    scope: null,
    loggingLevel: null,
    nonceLifetime: null,
  };

  // 1. Config with various of response type
  // - hybrid flow config with 'code id_token'
  hybrid_config = config_template;
  // - hybrid flow config with 'id_token code'
  hybrid_config_alternative = JSON.parse(JSON.stringify(config_template));
  hybrid_config_alternative.responseType = 'id_token code';
  // - authorization flow config
  code_config = JSON.parse(JSON.stringify(config_template));
  code_config.responseType = 'code';
  // - implicit flow config with 'id_token'
  implicit_config = JSON.parse(JSON.stringify(config_template));
  implicit_config.responseType = 'id_token';

  // 2. Config using query as the response mode
  // - authorization flow config with query response type
  code_config_query = JSON.parse(JSON.stringify(config_template));
  code_config_query.responseType = 'code';
  code_config_query.responseMode = 'query';

  // 3. Config without issue value
  // - hybrid flow with no issue value
  hybrid_config_noIssuer = JSON.parse(JSON.stringify(config_template));
  hybrid_config_noIssuer.issuer = null;

  // 4. Config with scope values
  // - hybrid flow with scope value email and profile
  hybrid_config_with_scope = JSON.parse(JSON.stringify(config_template));
  hybrid_config_with_scope.scope = ['email', 'profile'];

  // 5. Config with passReqToCallback set to true
  hybrid_config_passReqToCallback = JSON.parse(JSON.stringify(config_template));
  hybrid_config_passReqToCallback.passReqToCallback = true;

  // 6. Hybird flow using client assertion
  hybrid_config_clientAssertion = JSON.parse(JSON.stringify(hybrid_config));
  hybrid_config_clientAssertion.thumbprint = test_parameters.thumbprint;
  hybrid_config_clientAssertion.privatePEMKey = test_parameters.privatePEMKey;
  hybrid_config_clientAssertion.clientSecret = null;

  // 7. Code flow using client assertion
  code_config_clientAssertion = JSON.parse(JSON.stringify(code_config));
  code_config_clientAssertion.thumbprint = test_parameters.thumbprint;
  code_config_clientAssertion.privatePEMKey = test_parameters.privatePEMKey;
  code_config_clientAssertion.clientSecret = null;  

  /****************************************************************************
   *  Tenant specific endpoint configurations
   ***************************************************************************/
  config_template_common_endpoint = JSON.parse(JSON.stringify(config_template));
  config_template_common_endpoint.identityMetadata = 'https://login.microsoftonline.com/common/.well-known/openid-configuration';

  // 1. Config with various of response type
  // - hybrid flow config with 'code id_token'
  hybrid_config_common_endpoint = config_template;
  // - authorization code flow config
  code_config_common_endpoint = JSON.parse(JSON.stringify(config_template_common_endpoint));
  code_config_common_endpoint.responseType = 'code';
  // - implicit flow config with 'id_token'
  implicit_config_common_endpoint = JSON.parse(JSON.stringify(config_template_common_endpoint));
  implicit_config_common_endpoint.responseType = 'id_token';

  // 2. Config using query as the response mode
  // - authorization code flow config with query response type
  code_config_common_endpoint_query = JSON.parse(JSON.stringify(config_template_common_endpoint));
  code_config_common_endpoint_query.responseType = 'code';
  code_config_common_endpoint_query.responseMode = 'query';

  // 3. Config without issue value
  // - hybrid flow with no issue value and no validateIssuer
  hybrid_config_common_endpoint_noIssuer = JSON.parse(JSON.stringify(config_template_common_endpoint));
  hybrid_config_common_endpoint_noIssuer.issuer = null;
  hybrid_config_common_endpoint_noIssuer.validateIssuer = false;

  // 4. Config with scope values
  // - hybrid flow with scope value ['email', 'profile']
  hybrid_config_common_endpoint_with_scope = JSON.parse(JSON.stringify(config_template_common_endpoint));
  hybrid_config_common_endpoint_with_scope.scope = ['email', 'profile'];

  /****************************************************************************
   *  Invalid configurations
   ***************************************************************************/
  // 1. common endpoint with no issuer
  hybrid_config_common_endpoint_wrong_issuer = JSON.parse(JSON.stringify(config_template_common_endpoint));
  hybrid_config_common_endpoint_wrong_issuer.issuer = ['wrong_issuer'];
  // 2. common endpoint with too short nonceLifetime
  hybrid_config_common_endpoint_short_lifetime = JSON.parse(JSON.stringify(config_template_common_endpoint));
  hybrid_config_common_endpoint_short_lifetime.nonceLifetime = 0.001; // 1ms
  // 2. common endpoint with wrong client secret
  hybrid_config_common_endpoint_wrong_secret = JSON.parse(JSON.stringify(config_template_common_endpoint));
  hybrid_config_common_endpoint_wrong_secret.clientSecret = 'wrong_secret';  
  // 3. Hybird flow using client assertion with invalid privatePEMKey
  hybrid_config_clientAssertion_invalid_pemKey = JSON.parse(JSON.stringify(hybrid_config));
  hybrid_config_clientAssertion_invalid_pemKey.thumbprint = test_parameters.thumbprint;
  hybrid_config_clientAssertion_invalid_pemKey.privatePEMKey = 'invalid private pem key';
  hybrid_config_clientAssertion_invalid_pemKey.clientSecret = null;
  // 4. hybrid flow using client assertion with wrong thumbprint
  hybrid_config_clientAssertion_wrong_thumbprint = JSON.parse(JSON.stringify(hybrid_config));
  hybrid_config_clientAssertion_wrong_thumbprint.thumbprint = 'wrongThumbprint';
  hybrid_config_clientAssertion_wrong_thumbprint.privatePEMKey = test_parameters.privatePEMKey;
  hybrid_config_clientAssertion_wrong_thumbprint.clientSecret = null;
  // 5. hybrid flow using client assertion with unregistered privatePEMKey
  var unregistered_privatePEMKey = fs.readFileSync(__dirname + '/../resource/private.pem', 'utf8');
  hybrid_config_clientAssertion_unregistered_pemKey = JSON.parse(JSON.stringify(hybrid_config));
  hybrid_config_clientAssertion_unregistered_pemKey.thumbprint = test_parameters.thumbprint;
  hybrid_config_clientAssertion_unregistered_pemKey.privatePEMKey = unregistered_privatePEMKey;
  hybrid_config_clientAssertion_unregistered_pemKey.clientSecret = null;
  done();  
};

var checkResult = (test_app_config, arity, done) => {
  var server = create_app(test_app_config, {}, arity);

  if (!driver)
    driver = chromedriver.get_driver();

  driver.get('http://localhost:3000/login')
  .then(() => {
    if (first_time) {
      driver.wait(until.titleIs('Sign in to your account'), 10000);  
      var usernamebox = driver.findElement(By.name('login'));
      usernamebox.sendKeys(test_parameters.username);
      var passwordbox = driver.findElement(By.name('passwd'));
      passwordbox.sendKeys(test_parameters.password);
      driver.sleep(LOGIN_WAITING_TIME);
      passwordbox.sendKeys(webdriver.Key.ENTER);
      first_time = false;
    }
  }).then(() => {
    driver.wait(until.titleIs('result'), 10000);
    driver.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver.findElement(By.id('oid')).getText().then((text) => {
      // arity 3 means we are using function(iss, sub, done), so there is no profile.oid
      if (arity !== 3)  
        expect(text).to.equal(test_parameters.oid);
      else
        expect(text).to.equal('none');
    });
    driver.findElement(By.id('upn')).getText().then((text) => {
      // arity 3 means we are using function(iss, sub, done), so there is no profile.displayName
      if (arity !== 3) 
        expect(text).to.equal(test_parameters.username);
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

var checkResultTwoTabs = (test_app_config, arity, done) => {
  var server = create_app(test_app_config, {}, arity);

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
    usernamebox.sendKeys(test_parameters.username);
    var passwordbox = driver1.findElement(By.name('passwd'));
    passwordbox.sendKeys(test_parameters.password);
    driver1.sleep(LOGIN_WAITING_TIME);
    passwordbox.sendKeys(webdriver.Key.ENTER);
  })
  .then(() => {
    // check the result on tab1
    driver1.wait(until.titleIs('result'), 10000);
    driver1.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver1.findElement(By.id('oid')).getText().then((text) => { 
      expect(text).to.equal(test_parameters.oid);
    });
    driver1.findElement(By.id('upn')).getText().then((text) => {
        expect(text).to.equal(test_parameters.username);
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
    usernamebox.sendKeys(test_parameters.username);
    var passwordbox = driver2.findElement(By.name('passwd'));
    passwordbox.sendKeys(test_parameters.password);
    driver2.sleep(LOGIN_WAITING_TIME);
    passwordbox.sendKeys(webdriver.Key.ENTER);
  })
  .then(() => {
    // check result on tab2
    driver2.wait(until.titleIs('result'), 10000);
    driver2.findElement(By.id('status')).getText().then((text) => { 
      expect(text).to.equal('succeeded');
    });
    driver2.findElement(By.id('oid')).getText().then((text) => { 
      expect(text).to.equal(test_parameters.oid);
    });
    driver2.findElement(By.id('upn')).getText().then((text) => {
        expect(text).to.equal(test_parameters.username);
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

var checkInvalidResult = (test_app_config, done) => {
  var server = create_app(test_app_config, {}, 8);

  if (!driver)
    driver = chromedriver.get_driver();

  driver.get('http://localhost:3000/login')
  .then(() => {
    if (first_time) {
      driver.wait(until.titleIs('Sign in to your account'), 10000);  
      var usernamebox = driver.findElement(By.name('login'));
      usernamebox.sendKeys(test_parameters.username);
      var passwordbox = driver.findElement(By.name('passwd'));
      passwordbox.sendKeys(test_parameters.password);
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

var checkResultForPromptAndHint = (test_app_config, authenticate_opt, done) => {
  var server = create_app(test_app_config, authenticate_opt, 8);

  if (!driver)
    driver = chromedriver.get_driver(); 

  driver.get('http://localhost:3000/login')
  .then(() => {
    if (authenticate_opt.domain_hint === 'live.com') {
      // we should have come to the login page for live.com
      driver.wait(until.titleIs('Sign in to your Microsoft account'), 10000);
    } else if (authenticate_opt.prompt) {
      // without domain_hint, we will come to the generic login page
      driver.wait(until.titleIs('Sign in to your account'), 10000);
      if (!authenticate_opt.login_hint) {
        // if there is no login_hint, then we have to fill the username portion  
        var usernamebox = driver.findElement(By.name('login'));
        usernamebox.sendKeys(test_parameters.username);
      }
      
      var passwordbox = driver.findElement(By.name('passwd'));
      passwordbox.sendKeys(test_parameters.password);
      driver.sleep(LOGIN_WAITING_TIME);
      passwordbox.sendKeys(webdriver.Key.ENTER);
    }
  }).then(() => {
    if (authenticate_opt.domain_hint === 'live.com') {
      server.shutdown(done);
    } else {
      if (authenticate_opt.prompt === 'consent') {
        // consent
        driver.findElement(By.id('cred_accept_button')).click();
      }
      driver.wait(until.titleIs('result'), 10000);
      driver.findElement(By.id('status')).getText().then((text) => { 
        expect(text).to.equal('succeeded');
        server.shutdown(done); 
      });
    }
  });
};

/******************************************************************************
 *  The test cases
 *****************************************************************************/
describe('oidc v1 positive arity test', function() {
  this.timeout(TEST_TIMEOUT);

  it('get and apply config', function(done) {
    get_test_parameters(apply_test_parameters, done);
  });

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
   *  Test client assertion
   ***************************************************************************/
  
  // hybrid flow using client assertion
  it('should succeed', function(done) {
    checkResult(hybrid_config_clientAssertion, 8, done);
  }); 

  // code flow using client assertion
  it('should succeed', function(done) {
    checkResult(code_config_clientAssertion, 8, done);
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

describe('oidc v1 login/domain hint and prompt test', function() {
  this.timeout(TEST_TIMEOUT);

  it('should succeed with login page showing up and username prefilled', function(done) {
    checkResultForPromptAndHint(hybrid_config, { login_hint: test_parameters.username, prompt: 'login' }, done);
  }); 

  it('should succeed with login page showing up and username prefilled and consent page showing up later', function(done) {
    checkResultForPromptAndHint(hybrid_config, { login_hint: test_parameters.username, prompt: 'consent' }, done);
  }); 

  it('should succeed without login page showing up', function(done) {
    checkResultForPromptAndHint(hybrid_config, { login_hint: test_parameters.username }, done);
  }); 

  it('should succeed with live.com login page showing up', function(done) {
    checkResultForPromptAndHint(hybrid_config, { domain_hint: 'live.com' }, done);
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

  // invalid privatePEMKey
  it('should fail with invalid privatePEMKey', function(done) {
    checkInvalidResult(hybrid_config_clientAssertion_invalid_pemKey, done);
  });

  // wrong thumbprint
  it('should fail with wrong thumbprint', function(done) {
    checkInvalidResult(hybrid_config_clientAssertion_wrong_thumbprint, done);
  });

  // unregistered privatePEMKey
  it('should fail with unregistered privatePEMKey', function(done) {
    checkInvalidResult(hybrid_config_clientAssertion_unregistered_pemKey, done);
  });

  it('close service', function(done) {
    expect('1').to.equal('1');
    driver.quit();
    service.stop();
    done();
  });
});
