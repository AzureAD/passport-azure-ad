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

var url = require('url'), 
  https = require('https');


function configuration(issuer, cb) {
  var parsed = url.parse(issuer),
  path,
  headers = {};
    
  path = parsed.pathname;
  // Check if path already ends in "/"
  path += '/.well-known/openid-configuration';
    
  headers['Host'] = parsed.host;
  headers['Accept'] = 'application/json';
  
  var options = {
    host: parsed.hostname,
    port: parsed.port,
    path: path,
    method: 'GET',
    headers: headers
  };
  
  var req = https.request(options, function(res) {
    var data = '';
    
    res.on('data', function(chunk) {
      data += chunk;
    });
    res.on('end', function() {
      if (res.statusCode !== 200) {
        return cb(new Error("OpenID provider configuration request failed: " + res.statusCode));
      }
      
      var config = {};
      try {
        var json = JSON.parse(data);
        
        config.issuer = json.issuer;
        config.authorizationURL = json.authorization_endpoint;
        config.tokenURL = json.token_endpoint;
        config.userInfoURL = json.userinfo_endpoint;
        config.registrationURL = json.registration_endpoint;
        
        config._raw = json;
        
        cb(null, config);
      } catch(ex) {
        return cb(ex);
      }
    });
  });
  req.on('error', function(err) {
    cb(err);
  });
  req.end();
}


exports = module.exports = configuration;
exports.configuration = configuration;
