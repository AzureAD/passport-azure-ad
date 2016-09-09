<a name="2.0.2"></a>
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
