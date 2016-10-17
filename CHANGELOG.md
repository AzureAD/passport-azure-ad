<a name="3.0.1"></a>
# 3.0.1

## OIDCStrategy

### New features

* specify tenant per request 

  Now you can specify the tenant per request, using the `tenantIdOrName` option in `passport.authenticate`. More details on the usage can be found in README.md. This brings us two additional benefits:

  * B2C common endpoint support

    Now you can use B2C common endpoint, if you specify the tenant for each login request (in other words, a request that doesn't contain code or id_token) using the `tenantIdOrName` option.

  * extensive issuer validation on common endpoint
    
    If you want to validate issuer on common endpoint, previously you have to provide `issuer`in configuration. Now you can either provide `issuer`, or specify the tenant for each login request.

# 3.0.0

## OIDCStrategy

### Breaking changes

#### SAML and WSFED

* We no longer support SAML and WSFED starting from version 3.0.0, please use release 2.0.3 instead.

#### Options

* `skipUserProfile` option: this option is no longer provided. We will load 'userinfo' if we can get an access_token for 'userinfo'. More specifically, if you are using AAD v1 with 'code', 'code id_token' or 'id_token code' flow, and the resource is not specified. For all other scenarios, we do an 'id_token' fallback.

* `returnURL`/`callbackURL` option: this option is renamed to `redirectUrl`. `redirectUrl` can only be a https url now unless you set the `allowHttpForRedirectUrl` option to true.

#### Claims in the returned profile

* removed `email` claim.

* added `oid`, `upn` and `emails` claim. `emails` claim is always an array. You might get `upn` claim from non B2C tenants, and you might
get `emails` claim from B2C tenants.

#### B2C only

* `identityMetadata` option: common endpoint is no longer allowed for B2C. Tenant-specific endpoint should be used, for instance:
`https://login.microsoftonline.com/your_B2C_tenant_name.onmicrosoft.com/v2.0/.well-known/openid-configuration` or 
`https://login.microsoftonline.com/your_B2C_tenant_guid/v2.0/.well-known/openid-configuration`.

* `isB2C` option: this is a new option. If you are using a B2C tenant, set this option to true. 

* `tenantName`: this option is no longer used.

### New features

* multiple nonce and state support in OIDCStrategy. Provided `nonceLifetime` option to configure the lifetime of nonce saved in session.

* enabled `issuer` validation against common endpoint. To validate issuer on common endpoint, user must
specify the allowed issuer(s) in `issuer` option, and set `validateIssuer` option to true. 

* user-provided state support. The usage is as follows:

```
  passport.authenticate('azuread-openidconnect', { customState : 'the_state_you_want_to_use' });
```

## BearerStrategy

### Breaking changes

#### General

* We no longer accept access_token sent by request query. access_token should either be put in the request header or request body.

* We no longer support the `certificate` option. Now we always fetch the keys from the metadata url and generate the pem key.

#### B2C only

* `identityMetadata`: common endpoint is no longer allowed for B2C. Tenant-specific endpoint should be used, for instance:
`https://login.microsoftonline.com/your_B2C_tenant_name.onmicrosoft.com/v2.0/.well-known/openid-configuration` or 
`https://login.microsoftonline.com/your_B2C_tenant_guid/v2.0/.well-known/openid-configuration`.

* `isB2C` option: this is a new option. If you are using a B2C tenant, set this option to true. 

* `tenantName`: this option is no longer used.

#### New features

* enabled `issuer` validation against common endpoint. To validate issuer on common endpoint, user must
specify the allowed issuer or array of issuers in `issuer` option, and set `validateIssuer` option to true. 


## Bug fixes

* [#218](https://github.com/AzureAD/passport-azure-ad/issues/218) Missing email claim for B2C

* [#195](https://github.com/AzureAD/passport-azure-ad/issues/195) Remove default query support for access_token in bearerStrategy

* [#194](https://github.com/AzureAD/passport-azure-ad/issues/194) Error message for 'sub' mismatch is incorrect after redeeming 'code'

* [#189](https://github.com/AzureAD/passport-azure-ad/issues/189) Extensibility to allow issuer validation when going against common endpoint

* [#188](https://github.com/AzureAD/passport-azure-ad/issues/188) Mocha tests for B2C to prevent regressions

* [#187](https://github.com/AzureAD/passport-azure-ad/issues/187) p parameter is not being passed in each flow through the passport.js library

* [#171](https://github.com/AzureAD/passport-azure-ad/issues/171) multiple nonce and state handling

* [#165](https://github.com/AzureAD/passport-azure-ad/issues/165) validationConfiguration.callbackUrl should be named redirectUrl

* [#164](https://github.com/AzureAD/passport-azure-ad/issues/164) By default redirect URL should be https

# 2.0.3

* Updated telemetry version.

# 2.0.2

* Increased the size of nonce and state in OIDCStrategy.

# 2.0.1

## Major changes from 2.0.0

### Security Fix
* Version 2.0.1 fixes a known security vulnerability affecting versions <1.4.6 and 2.0.0. All users should upgrade to 2.0.1 or greater immediately. For more details, see the [Security-Notice](https://github.com/AzureAD/passport-azure-ad/blob/master/SECURITY-NOTICE.MD) for more details.

### BearerStrategy
* Metadata is loaded only once in 2.0.0, which happens at the creation time of the strategy. In 2.0.1 we load metadata for each request that requires authentication. We keep the metadata in memory cache for 30 minutes. Whenever we need to load the metadata, we check the memory cache first. If we don't find it we then load the metadata from AAD and save it in memory cache. This way BearerStrategy can automatically handle the key rolling of Azure Active Directory. 
* The default value of validateIssuer is true.

### OIDCStrategy
* For OIDCStrategy, we now support 'code id_token' as the response_type, in addition to 'code', 'id_token code' and 'id_token'.
* The default value of validateIssuer is true.

### Miscellaneous
* For non-server-related errors, in 2.0.1 we call Strategy.fail function instead of throwing an error, so the user can do the failure redirection.
* Added chai-passport-strategy testing tool and more unit tests.
* Fixed some bugs in examples.
* Added telemetry parameters in both OIDCStrategy and BearerStrategy when sending requests to Azure Active Directory.

### Upgrade Notes

1. This patch updates the library that your application runs, but does not change the current state of your users, including any sessions they had open. This applies to malicious users who could have exploited this vulnerability to gain access to your system. If your application has users with existing sessions open, after applying the patch, ensure all these sessions are terminated and users are required to sign in again. 


2. In previous versions of the Passport-Azure-AD for NodeJS library, the issuer wasn't validated, even if you had set validateIssuer to true in your configuration. This is fixed in versions 1.4.6 and 2.0.1. However, this may mean you get 401s if you are using the common endpoint in the identityMetadata config setting and have validateIssuer to true. If you are using the common endpoint (which looks like "https://login.microsoftonline.com/common/.well-known/openid-configuration"), issuers cannot be validated. You can fix this in two ways: 

 - If you are a single-tenant app, you can replace 'common' with your tenantId in the endpoint address. The issuer will be validated. IdentityMetadata set to support a single tenant should look like "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011dddd/.well-known/openid-configuration" with your tenant GUID replaced in the path or "https://login.microsoftonline.com/your-tenant-name.onmicrosoft.com/.well-known/openid-configuration" with your tenant name replaced in the path.

 - If you are a multi-tenant app and need to go against the common endpoint, you must set validateIssuer to false. Be aware that the issuer field of the token will not be validated and all issuers will be accepted. 
 
## Bug fixes in 2.0.1
* [#71](https://github.com/AzureAD/passport-azure-ad/issues/71) Cryptic error message when the client ID is null/undefined
* [#90](https://github.com/AzureAD/passport-azure-ad/issues/90) Cannot read property 'keys' of undefined
* [#117](https://github.com/AzureAD/passport-azure-ad/issues/117) TypeError: Invalid hex string in aadutils.js
* [#112](https://github.com/AzureAD/passport-azure-ad/issues/112) done is not a function. bearerstrategy.js:149
* [#121](https://github.com/AzureAD/passport-azure-ad/issues/121) Error with regex into pem.js

# 1.4.8

* Updated telemetry version.

# 1.4.7

* Increased the size of nonce and state in OIDCStrategy.

# 1.4.6

### Security Fix
* Version 1.4.6 fixes a known security vulnerability affecting versions <1.4.6. All users should upgrade to 1.4.6 or greater immediately. For more details, see the [Security-Notice](https://github.com/AzureAD/passport-azure-ad/blob/master/SECURITY-NOTICE.MD).

### BearerStrategy
* The default value of validateIssuer is true.

### OIDCStrategy
* For OIDCStrategy, we now support 'code id_token' as the response_type, in addition to 'code', 'id_token code' and 'id_token'.
* The default value of validateIssuer is true.
* Validating options at the time of creating strategy, instead of when authenticate method is called.

### Miscellaneous
* For non-server-related errors, in 1.4.6 we call Strategy.fail function instead of throwing error, so user can do the failure redirection.
* Added chai-passport-strategy testing tool and more unit tests.
* Added telemetry in both OIDC and Bearer strategy when sending requests to AAD.
* Fixed some bugs in examples.

### Upgrade Notes

1. This patch updates the library that your application runs, but does not change the current state of your users, including any sessions they had open. This applies to malicious users who could have exploited this vulnerability to gain access to your system. If your application has users with existing sessions open, after applying the patch, ensure all these sessions are terminated and users are required to sign in again. 


2. In previous versions of the Passport-Azure-AD for NodeJS library, the issuer wasn't validated, even if you had set validateIssuer to true in your configuration. This is fixed in versions 1.4.6 and 2.0.1. However, this may mean you get 401s if you are using the common endpoint in the identityMetadata config setting and have validateIssuer to true. If you are using the common endpoint (which looks like "https://login.microsoftonline.com/common/.well-known/openid-configuration"), issuers cannot be validated. You can fix this in two ways: 

 - If you are a single-tenant app, you can replace 'common' with your tenantId in the endpoint address. The issuer will be validated. IdentityMetadata set to support a single tenant should look like "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011dddd/.well-known/openid-configuration" with your tenant GUID replaced in the path or "https://login.microsoftonline.com/your-tenant-name.onmicrosoft.com/.well-known/openid-configuration" with your tenant name replaced in the path.

 - If you are a multi-tenant app and need to go against the common endpoint, you must set validateIssuer to false. Be aware that the issuer field of the token will not be validated and all issuers will be accepted. 
 
