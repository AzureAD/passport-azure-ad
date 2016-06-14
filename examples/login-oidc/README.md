-------------------------------------------------------------------------------
            OIDC strategy Example  for Azure Active Directory
-------------------------------------------------------------------------------

[Passport](http://passportjs.org/) strategy for authenticating with Azure 
Active Directory using OIDC. 


-------------------------------------------------------------------------------
Step 1. Register this example app with your Azure Active Directory tenant
-------------------------------------------------------------------------------
(1) Sign in to the Azure management portal.
(2) Click on Active Directory in the left hand nav.
(3) Click the directory tenant where you wish to register the example app.
(4) Click the Applications tab.
(5) In the drawer, click Add.
(6) Click "Add an application my organization is developing".
(7) Enter a friendly name for the app, for example "passportAppOIDC", select 
    "Web Application and/or Web API", and click next.
(8) For the sign-on URL, enter http://localhost:3000/login
(9) For the App ID URI, enter https://<your_tenant_name>/passportAppOIDC, then 
    replace <your_tenant_name> with the name of your Azure AD tenant. Now click
    next, and click the CONFIGURE tab.
(10) Copy the CLIENT ID value, and paste this value to the 'ClientId' field in
    your client_config_*.js file in this folder.
(10) For REPLY URL, enter http://localhost:3000/auth/openid/return
     This value goes into the 'returnURL' field in your client_config_*.js.
(11) Click the dropdown 'Select duration' menu in the keys section, pick '1 year'
    then click 'save' at the bottom of the page. This creates a app key value,
    copy and paste it into the ClientSecret field in your client_config_*.js

-------------------------------------------------------------------------------
Step 2. Install
-------------------------------------------------------------------------------
Open a cmd window, type 

	npm install

in the passport-azure-ad directory and then in this example directory.

-------------------------------------------------------------------------------
Step 3. Run the app
-------------------------------------------------------------------------------
Type 

    node app.js

Then open your browser, and go to "http://localhost:3000".


-------------------------------------------------------------------------------
License
-------------------------------------------------------------------------------
Copyright (c) Microsoft.  All rights reserved. Licensed under the MIT License. 
