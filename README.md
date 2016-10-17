
# Microsoft Azure Active Directory Passport.js Plug-In
=============

_passport-azure-ad_ is a collection of [Passport](http://passportjs.org/) Strategies 
to help you integrate with Azure Active Directory. It includes OpenID Connect, 
WS-Federation, and SAML-P authentication and authorization. These providers let you 
integrate your Node app with Microsoft Azure AD so you can use its many features, 
including web single sign-on (WebSSO), Endpoint Protection with OAuth, and JWT token 
issuance and validation.

_passport-azure-ad_ has been tested to work with both [Microsoft Azure Active Directory](https://azure.microsoft.com/en-us/services/active-directory/) 
and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## 1. Security Vulnerability in Versions < 1.4.6 and 2.0.0
_passport-azure-ad_ has a known security vulnerability affecting versions <1.4.6 and 2.0.0. Please update to >=1.4.6 or >=2.0.1 immediately. For more details, see the [security notice](https://github.com/AzureAD/passport-azure-ad/blob/master/SECURITY-NOTICE.MD).

## 2. Versions
Current version - 3.0.1  
Minimum  recommended version - 1.4.6  
You can find the changes for each version in the [change log](https://github.com/AzureAD/passport-azure-ad/blob/master/CHANGELOG.md).

## 3. Contribution History

[![Stories in Ready](https://badge.waffle.io/AzureAD/passport-azure-ad.png?label=ready&title=Ready)](https://waffle.io/AzureAD/passport-azure-ad)

[![Throughput Graph](https://graphs.waffle.io/AzureAD/passport-azure-ad/throughput.svg)](https://waffle.io/AzureAD/passport-azure-ad/metrics)

## 4. Installation

    $ npm install passport-azure-ad

## 5. Usage

This library contains two strategies, OIDCStrategy and BearerStrategy.

OIDCStrategy is for web application login purpose using OpenID connect protocol. It works in the following way:
 If a user is not logged in, passport sends an authentication request to AAD (Azure Active Directory), then AAD returns a login page to let the user enter their credentials. Once the credentials is authenticated by AAD, the web application will eventually get an id_token back (directly from AAD authentication endpoint, or by redeeming a code at AAD token endpoint, depending on the flow you choose). Passport then validates the id_token and propagates the claims in id_token back to the verify callback, and let the passport framework finish the remaining authentication procedures. If the whole process is successful, passport adds the user information into `req.user` and passes it to the next middleware; otherwise, passport sends back an authorized response or redirects the user to the page you specify (such as homepage or login page).

BearerStrategy is for protecting web resource/api purpose using Bearer Token protocol. It works in the following way:
 User sends a request to the protected web api, and the request is supposed to contain an access_token in either authorization header or body. Passport extracts and validates the access_token, and propagates the claims in access_token to the verify callback and let the passport framework finish the remaining authentication procedure. If the whole process is successful, passport adds the user information into `req.user` and passes it to the next middleware, which is usually the business logic of the web resource/api; otherwise, passport sends back an authorized response.

We support AAD v1, v2 and B2C tenants for both strategies. Please check out section 7 for the samples. You can manage v1 tenants and register applications at https://manage.windowsazure.com. For v2 tenants and applications, you should go to https://apps.dev.microsoft.com. For B2C tenants, go to https://manage.windowsazure.com and click 'Manage B2C settings' to register applications and policies. 

### 5.1 OIDCStrategy

#### 5.1.1 Configure strategy and provide callback function

##### 5.1.1.1 Sample using the OIDCStrategy

```javascript
passport.use(new OIDCStrategy({
    identityMetadata: config.creds.identityMetadata,
    clientID: config.creds.clientID,
    responseType: config.creds.responseType,
    responseMode: config.creds.responseMode,
    redirectUrl: config.creds.redirectUrl,
    allowHttpForRedirectUrl: config.creds.allowHttpForRedirectUrl,
    clientSecret: config.creds.clientSecret,
    validateIssuer: config.creds.validateIssuer,
    isB2C: config.creds.isB2C,
    issuer: config.creds.issuer,
    passReqToCallback: config.creds.passReqToCallback,
    scope: config.creds.scope,
    loggingLevel: config.creds.loggingLevel,
    nonceLifetime: config.creds.nonceLifetime,
  },
  function(iss, sub, profile, accessToken, refreshToken, done) {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByOid(profile.oid, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      });
    });
  }
));
```

##### 5.1.1.2 Options

* `identityMetadata` (Required)

  The metadata endpoint provided by the Microsoft Identity Portal that provides the keys and other important information at runtime.    Examples:
  * v1 tenant-specific endpoint
  ```
    https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/.well-known/openid-configuration
    https://login.microsoftonline.com/your_tenant_guid/.well-known/openid-configuration
  ```
  * v1 common endpoint
  ```
    https://login.microsoftonline.com/common/.well-known/openid-configuration
  ```
  * v2 tenant-specific endpoint
  ```
    https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/v2.0/.well-known/openid-configuration 
    https://login.microsoftonline.com/your_tenant_guid/v2.0/.well-known/openid-configuration
  ```
  * v2 common endpoint
  ``` 
    https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
  ```
  
  For B2C, you cannot use v2 common endpoint unless you specify the tenant in `passport.authenticate` using `tenantIdOrName` option. See section 5.1.3 for more details.
  
* `clientID` (Required)

  The client ID of your application in AAD (Azure Active Directory)
  
* `responseType` (Required)
  
  Must be 'code', 'code id_token', 'id_token code' or 'id_token'. For login only flows you can use 'id_token'; if you want access_token, use 'code', 'code id_token' or 'id_token code'.

* `responseMode` (Required)
  
  Must be 'query' or 'form_post'. This is how you get code or id_token back. 'form_post' is recommended for all scenarios.
  
* `redirectUrl`  (Required)
  
  Must be a https url string, unless you set `allowHttpForRedirectUrl` to true. This is the reply URL registered in AAD for your app. Production environment should always use https for `redirectUrl`.

* `passReqToCallback`  (Required)

  Whether you want to use `req` as the first parameter in the verify callback. See section 5.1.1.3 for more details.

* `allowHttpForRedirectUrl`  (Conditional) 
  
  Required to set to true if you want to use http url for redirectUrl like `http://localhost:3000`. 
 
* `clientSecret`  (Conditional)
  
  Required if the `responseType` is not 'id_token'. This is the app key of your app in AAD. For B2C, the app key sometimes contains \, please replace \ with two \'s in the app key, otherwise \ will be treated as the beginning of an escaping character.
  
* `isB2C`  (Conditional)

  Required to set to true if you are using B2C tenant.

* `validateIssuer`  (Conditional)
  
  Required to set to false if you don't want to validate issuer, default value is true. We validate the `iss` claim in id_token against user provided `issuer` values and the issuer value we get from tenant-specific endpoint. If you use common endpoint for `identityMetadata` and you want to validate issuer, then you have to either provide `issuer`, or provide the tenant for each login request using `tenantIdOrName` option in `passport.authenticate` (see section 5.1.3 for more details).
  
* `issuer`  (Conditional)
  
  This can be a string or an array of strings. See `validateIssuer` for the situation that requires `issuer`.

* `scope`  (Optional)

  List of scope values besides `openid` indicating the required scope of the access token for accessing the requested resource. For example, ['email', 'profile']. If you need refresh_token for v2 endpoint, then you have to include the 'offline_access' scope.

* `loggingLevel`  (Optional)

  Logging level. 'info', 'warn' or 'error'.
  
* `nonceLifetime`  (Optional)
  
  The lifetime of nonce in session in seconds. The default value is 3600 seconds.
  
##### 5.1.1.3 Verify callback

If you set `passReqToCallback` option to false, you can use one of the following signatures for the verify callback

```
  function(iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
  function(iss, sub, profile, access_token, refresh_token, params, done)
  function(iss, sub, profile, access_token, refresh_token, done)
  function(iss, sub, profile, done)
  function(iss, sub, done)
  function(profile, done)
```

If you set `passReqToCallback` option to true, you can use one of the following signatures for the verify callback

```
  function(req, iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
  function(req, iss, sub, profile, access_token, refresh_token, params, done)
  function(req, iss, sub, profile, access_token, refresh_token, done)
  function(req, iss, sub, profile, done)
  function(req, iss, sub, done)
  function(req, profile, done)
```

#### 5.1.2 Use `passport.authenticate` to protect routes

To complete the sample, provide a route that corresponds to the path 
configuration parameter that is sent to the strategy:

```javascript

app.get('/login', 
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  function(req, res) {
    log.info('Login was called in the Sample');
    res.redirect('/');
});

// POST /auth/openid/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   home page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.post('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  function(req, res) { 
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

```

#### 5.1.3 Options available for `passport.authenticate`

* `failureRedirect`: the url redirected to when the authentication fails

* `session`: if you don't want a persistent login session, you can use `session: false`

* `customState`: if you want to use a custom state value instead of a random generated one

* `resourceURL`: if you need access_token for some resource. Note this option is only for v1 endpoint and `code`, `code id_token`, `id_token code` flow. For v2 endpoint, resource is considered as a scope, so it should be specified in the `scope` field when you create
the strategy.

* `tenantIdOrName`: if you want to specify the tenant to use for this request. You can use the tenant guid or tenant name (like 'contoso.onmicrosoft.com'). Note: 
  * You must use common endpoint for `identityMetadata`, otherwise this option will be ignored. We will fetch and use the metadata from the tenant you specify for this request.
  * This option only applies to the login request, in other words, the request which is not supposed to contain code or id_token. Passport saves the `tenantIdOrName` value in session before sending the authentication request. When we receive a request containing code or id_token, we retrieve the saved `tenantIdOrName` value from session and use that value.
  * If you are using B2C common endpoint, then `tenantIdOrName` must be used for every login request.

Example:

```
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/', session: false, customState: 'my_state', resourceURL: 'https://graph.microsoft.com/mail.send'});
  
  passport.authenticate('azuread-openidconnect', { tenantIdOrName: 'contoso.onmicrosoft.com' });
```

### 5.2 BearerStrategy

#### 5.2.1 Configure strategy and provide callback function

##### 5.2.1.1 Sample using the BearerStrategy

```javascript

// We pass these options in to the ODICBearerStrategy.

var options = {
  identityMetadata: config.creds.identityMetadata,
  clientID: config.creds.clientID,
  validateIssuer: config.creds.validateIssuer,
  issuer: config.creds.issuer,
  passReqToCallback: config.creds.passReqToCallback,
  isB2C: config.creds.isB2C,
  policyName: config.creds.policyName,
  allowMultiAudiencesInToken: config.creds.allowMultiAudiencesInToken,
  audience: config.creds.audience,
  loggingLevel: config.creds.loggingLevel,
};

var bearerStrategy = new BearerStrategy(options,
  function(token, done) {
    log.info('verifying the user');
    log.info(token, 'was the token retreived');
    findById(token.oid, function(err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        // "Auto-registration"
        log.info('User was added automatically as they were new. Their oid is: ', token.oid);
        users.push(token);
        owner = token.oid;
        return done(null, token);
      }
      owner = token.oid;
      return done(null, user, token);
    });
  }
);
``` 

##### 5.2.1.2 Options

* `identityMetadata` (Required)

  The metadata endpoint provided by the Microsoft Identity Portal that provides the keys and other important information at runtime.    Examples:
  * v1 tenant-specific endpoint
  ```
    https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/.well-known/openid-configuration
    https://login.microsoftonline.com/your_tenant_guid/.well-known/openid-configuration
  ```
  * v1 common endpoint
  ```
    https://login.microsoftonline.com/common/.well-known/openid-configuration
  ```
  * v2 tenant-specific endpoint
  ```
    https://login.microsoftonline.com/your_tenant_name.onmicrosoft.com/v2.0/.well-known/openid-configuration 
    https://login.microsoftonline.com/your_tenant_guid/v2.0/.well-known/openid-configuration
  ```
  * v2 common endpoint
  ``` 
    https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
  ```
  
  For B2C, you can only use v2 tenant-specific endpoint.
  
* `clientID` (Required)

  The client ID of your application in AAD (Azure Active Directory)

* `passReqToCallback`  (Required)

  Whether you want to use `req` as the first parameter in the verify callback. See section 5.2.1.3 for more details.
  
* `isB2C`  (Conditional)

  Required to set to true if you are using B2C tenant.
  
* `policyName`  (Conditional)

  Required if you are using B2C tenant. It is a string starting with 'B2C_1_' (case insensitive).

* `validateIssuer`  (Conditional)
  
  Required to set to false if you don't want to validate issuer, default value is true. We validate the `iss` claim in id_token against user provided `issuer` values and the issuer value we get from tenant-specific endpoint. If you use common endpoint for `identityMetadata` and you want to validate issuer, then you must provide `issuer`.
  
* `issuer`  (Conditional)
  
  This can be a string or an array of strings. See `validateIssuer` for the situation that requires `issuer`.
  
* `allowMultiAudiencesInToken`  (Conditional)

  Required if you allow access_token whose `aud` claim contains multiple values.
  
* `audience`  (Optional)

  Must be a string or an array of strings. We invalidate the `aud` claim in access_token against `audience`. The default value for `audience` is `clientID`.
  
* `loggingLevel`  (Optional)

  Logging level. 'info', 'warn' or 'error'.

##### 5.2.1.3 Verify callback

If you set `passReqToCallback` option to false, you can use the following verify callback

```
  function(token, done)
```

If you set `passReqToCallback` option to true, you can use the following verify callback

```
  function(req, token, done)
```

#### 5.2.2 Use `passport.authenticate` to protect resources or APIs

In the following example, we are using passport to protect '/api/tasks'. User sends a GET request to '/api/tasks' with access_token in authorization header or body. Passport validates the access_token, adds the related claims from access_token to `req.user`, and passes the request to listTasks middleware. The listTasks middleware can then read the user information in `req.user` and list all the tasks related to this user. Note that we do authentication every time, so we don't need to keep this user in session, and this can be achieved  by using `session: false` option.

```javascript
  server.get('/api/tasks', passport.authenticate('oauth-bearer', { session: false }), listTasks);
```

#### 5.2.3 Options available for `passport.authenticate`

* `session`: if you don't want a persistent login session, you can use `session: false`

Example:

```
  passport.authenticate('oauth-bearer', { session: false });
```

## 6. Test

In the library root folder, type the following command to install the dependency packages:

```
    $ npm install
```

Then type the following command to run tests:

```
    $ npm test
```

Tests will run automatically and in the terminal you can see how many tests are passing/failing. More details can be found [here](https://github.com/AzureAD/passport-azure-ad/blob/master/contributing.md).

## 7. Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://azure.microsoft.com/en-us/documentation/samples/?service=active-directory) 
to help you get started with learning the Azure Identity system. This includes 
tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, 
and Linux. We also provide full walkthroughs for authentication flows such as 
OAuth2, OpenID Connect, Graph API, and other awesome features. 

Azure Identity samples for this plug-in can be found in the following links:

### 7.1 Samples for [OpenID connect strategy](https://github.com/AzureAD/passport-azure-ad/blob/master/lib/oidcstrategy.js)

* [sample using v1 endpoint](https://github.com/AzureADQuickStarts/WebApp-OpenIDConnect-NodeJS)

* [sample using v2 endpoint](https://github.com/AzureADQuickStarts/AppModelv2-WebApp-OpenIDConnect-nodejs)

* [sample using B2C tenant](https://github.com/AzureADQuickStarts/B2C-WebApp-OpenIDConnect-NodeJS)

### 7.2 Samples for [Bearer strategy](https://github.com/AzureAD/passport-azure-ad/blob/master/lib/bearerstrategy.js)

* [sample using v1 endpoint](https://github.com/AzureADQuickStarts/WebAPI-Bearer-NodeJS)

* [sample using v2 endpoint](https://github.com/AzureADQuickStarts/AppModelv2-WebAPI-nodejs)

* [sample using B2C tenant](https://github.com/AzureADQuickStarts/B2C-WebApi-Nodejs)

## 8. Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one. We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## 9. Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## 10. Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

More details [about contribution](https://github.com/AzureAD/passport-azure-ad/blob/master/contributing.md) 

## 11. Releases

Please check the [releases](https://github.com/AzureAD/passport-azure-ad/releases) for updates.

## 12. Acknowledgements

The code is based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library and Matias Woloski's [passport-wsfed-saml2](https://github.com/auth0/passport-wsfed-saml2) library as well as Kiyofumi Kondoh's [passport-openid-google](https://github.com/kkkon/passport-google-openidconnect).

## 13. License
Copyright (c) Microsoft Corp.  All rights reserved. Licensed under the MIT License;

## 14. Microsoft Open Source Code of Conduct

We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
