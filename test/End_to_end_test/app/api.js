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

module.exports = function(strategyOptions) {
  var express = require('express');
  var cookieParser = require('cookie-parser');
  var bodyParser = require('body-parser');
  var methodOverride = require('method-override');
  var passport = require('passport');
  var enableGracefulShutdown = require('server-graceful-shutdown');
  var BearerStrategy = require('../../../lib/index').BearerStrategy;
  var hasReq = strategyOptions.passReqToCallback;

  // the verify function 
  var verifyFunc = (profile, done) => { done(null, profile); };
  var verifyFuncWithReq = (req, profile, done) => { done(null, profile); };

  var strategy;
  if (hasReq)
    strategy = new BearerStrategy(strategyOptions, verifyFuncWithReq);
  else
    strategy = new BearerStrategy(strategyOptions, verifyFunc);
  passport.use(strategy);

  var app = express();
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(methodOverride());
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({ extended : true }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);

  app.get('/api', passport.authenticate('oauth-bearer', { session: false }),
    function(req, res) {
      res.send('succeeded');
    }
  );

  var server = app.listen(4000);
  enableGracefulShutdown(server);
  return server;
};


