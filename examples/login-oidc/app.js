/**
* Copyright (c) Microsoft Corporation
*  All Rights Reserved
*  Apache License 2.0
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* @flow
*/



 'use strict';

    /**
    * Module dependencies.
    */

    var util = require('util');
    var assert = require('assert-plus');
    var mongoose = require('mongoose/');
    var bunyan = require('bunyan');
    var restify = require('restify');
    var config = require('./config');
    var passport = require('passport');
    var OIDCBearerStrategy = require('../../lib/passport-azure-ad/index').OIDCStrategy;


    // We pass these options in to the ODICBearerStrategy.

    var options = {
   // The URL of the metadata document for your app. We will put the keys for token validation from the URL found in the jwks_uri tag of the in the metadata.
  identityMetadata: config.creds.identityMetadata,
  issuer: config.creds.issuer,
  audience: config.creds.audience

};

    // array to hold logged in users
    var users = [];

    // Our logger
    var log = bunyan.createLogger({name: 'Windows Azure Active Directory Sample'});

// MongoDB setup
// Setup some configuration
var serverPort = process.env.PORT || 8888;
var serverURI = (process.env.PORT) ? config.creds.mongoose_auth_mongohq : config.creds.mongoose_auth_local;

// Connect to MongoDB
global.db = mongoose.connect(serverURI);
var Schema = mongoose.Schema;
log.info('MongoDB Schema loaded');

// Here we create a schema to store our tasks and users. Pretty simple schema for now.
var TaskSchema = new Schema({
  owner: String,
  task: String,
  completed: Boolean,
  date: Date
});

// Use the schema to register a model
mongoose.model('Task', TaskSchema);
var Task = mongoose.model('Task');



/**
 *
 * APIs for our REST Task server
 */

 // Create a task

function createTask(req, res, next) {

    // Resitify currently has a bug which doesn't allow you to set default headers
    // This headers comply with CORS and allow us to mongodbServer our response to any origin

  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");

    // Create a new task model, fill it up and save it to Mongodb
  var _task = new Task();

  if (!req.params.task) {
          req.log.warn({params: p}, 'createTodo: missing task');
          next(new MissingTaskError());
          return;
      }

  _task.owner = req.params.owner;
   _task.task = req.params.task;
   _task.date = new Date();

  _task.save(function (err) {
    if (err) {
        req.log.warn(err, 'createTask: unable to save');
        next(err);
    } else {
    res.send(201, _task);

            }
  });

  return next();

}


 // Delete a task by name

function removeTask(req, res, next) {

        Task.remove( { task:req.params.task }, function (err) {
                if (err) {
                        req.log.warn(err,
                                     'removeTask: unable to delete %s',
                                     req.params.task);
                        next(err);
                } else {
                        res.send(204);
                        next();
                }
        });
}

 // Delete all tasks

function removeAll(req, res, next) {
        Task.remove();
        res.send(204);
        return next();
}


// Get a specific task based on name

function getTask(req, res, next) {

  log.info('getTask was called');
        Task.find(req.params.owner, function (err, data) {
                if (err) {
                        req.log.warn(err, 'get: unable to read %s', req.params.owner);
                        next(err);
                        return;
                }

                res.json(data);
        });

        return next();
}

 /// Simple returns the list of TODOs that were loaded.

function listTasks(req, res, next) {
  // Resitify currently has a bug which doesn't allow you to set default headers
  // This headers comply with CORS and allow us to mongodbServer our response to any origin

  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");

  log.info("listTasks was called");

  Task.find().limit(20).sort('date').exec(function (err,data) {

    if (err) {
      return next(err);
    }

    if (data.length > 0) {
            log.info(data);
        }

    if (!data.length) {
            log.warn(err, "There is no tasks in the database. Did you initalize the database as stated in the README?");
        }

    else {

        res.json(data);

        }
  });

  return next();
}

///--- Errors for communicating something interesting back to the client

function MissingTaskError() {
        restify.RestError.call(this, {
                statusCode: 409,
                restCode: 'MissingTask',
                message: '"task" is a required parameter',
                constructorOpt: MissingTaskError
        });

        this.name = 'MissingTaskError';
}
util.inherits(MissingTaskError, restify.RestError);


function TaskExistsError(owner) {
        assert.string(owner, 'owner');

        restify.RestError.call(this, {
                statusCode: 409,
                restCode: 'TaskExists',
                message: owner + ' already exists',
                constructorOpt: TaskExistsError
        });

        this.name = 'TaskExistsError';
}
util.inherits(TaskExistsError, restify.RestError);


function TaskNotFoundError(owner) {
        assert.string(owner, 'owner');

        restify.RestError.call(this, {
                statusCode: 404,
                restCode: 'TaskNotFound',
                message: owner + ' was not found',
                constructorOpt: TaskNotFoundError
        });

        this.name = 'TaskNotFoundError';
}

util.inherits(TaskNotFoundError, restify.RestError);

/**
 * Our Server
 */


var server = restify.createServer({
        name: "Windows Azure Active Directroy TODO Server",
    version: "2.0.1"
});

        // Ensure we don't drop data on uploads
        server.pre(restify.pre.pause());

        // Clean up sloppy paths like //todo//////1//
        server.pre(restify.pre.sanitizePath());

        // Handles annoying user agents (curl)
        server.pre(restify.pre.userAgentConnection());

        // Set a per request bunyan logger (with requestid filled in)
        server.use(restify.requestLogger());

        // Allow 5 requests/second by IP, and burst to 10
        server.use(restify.throttle({
                burst: 10,
                rate: 5,
                ip: true,
        }));

        // Use the common stuff you probably want
        server.use(restify.acceptParser(server.acceptable));
        server.use(restify.dateParser());
        server.use(restify.queryParser());
        server.use(restify.gzipResponse());
        server.use(restify.bodyParser({ mapParams: true})); // Allows for JSON mapping to REST
        server.use(restify.authorizationParser()); // Looks for authorization headers

        // Let's start using Passport.js

         server.use(passport.initialize()); // Starts passport
         server.use(passport.session()); // Provides session support

        /**
        /*
        /* Calling the OIDCBearerStrategy and managing users
        /*
        /* Passport pattern provides the need to manage users and info tokens
        /* with a FindorCreate() method that must be provided by the implementor.
        /* Here we just autoregister any user and implement a FindById().
        /* You'll want to do something smarter.
        **/

        var findById = function (id, fn) {
          for (var i = 0, len = users.length; i < len; i++) {
            var user = users[i];
            if (user.id === id) {
              return fn(null, user);
            }
          }
          return fn(null, null);
        };


        var oidcStrategy = new OIDCBearerStrategy(options,
                     function(token, done) {
                      log.info('verifying the user');
                       log.info(token, 'was the token retreived');
             findById(token.sub, function (err, user) {
               if (err) { return done(err); }

                 if (!user) {
          // "Auto-registration"
          log.info('User was added automatically as they were new. Their sub is: ', token.sub);
          users.push(token);
          return done(null, token);
        }
               return done(null, user, token);
             });
          }
                 );

        passport.use(oidcStrategy);

        /// Now the real handlers. Here we just CRUD

        /**
        /*
        /* Each of these handlers are protected by our OIDCBearerStrategy by invoking 'oidc-bearer'
        /* in the pasport.authenticate() method. We set 'session: false' as REST is stateless and
        /* we don't need to maintain session state. You can experiement removing API protection
        /* by removing the passport.authenticate() method like so:
        /*
        /* server.get('/tasks', listTasks);
        /*
        **/

        server.get('/tasks', passport.authenticate('oidc-bearer', { session: false }), listTasks);
        server.get('/tasks', passport.authenticate('oidc-bearer', { session: false }), listTasks);
        server.get('/tasks/:owner', passport.authenticate('oidc-bearer', { session: false }), getTask);
        server.head('/tasks/:owner', passport.authenticate('oidc-bearer', { session: false }), getTask);
        server.post('/tasks/:owner/:task', passport.authenticate('oidc-bearer', { session: false }), createTask);
        server.post('/tasks', passport.authenticate('oidc-bearer', { session: false }), createTask);
        server.del('/tasks/:owner/:task', passport.authenticate('oidc-bearer', { session: false }), removeTask);
        server.del('/tasks/:owner', passport.authenticate('oidc-bearer', { session: false }), removeTask);
        server.del('/tasks', passport.authenticate('oidc-bearer', { session: false }), removeTask);
        server.del('/tasks', passport.authenticate('oidc-bearer', { session: false }), removeAll, function respond(req, res, next) { res.send(204); next(); });


        // Register a default '/' handler

        server.get('/', function root(req, res, next) {
                var routes = [
                        'GET     /',
                        'POST    /tasks/:owner/:task',
                        'POST    /tasks (for JSON body)',
                        'GET     /tasks',
                        'PUT     /tasks/:owner',
                        'GET     /tasks/:owner',
                        'DELETE  /tasks/:owner/:task'
                ];
                res.send(200, routes);
                next();
        });


  server.listen(serverPort, function() {

  var consoleMessage = '\n Windows Azure Active Directory Tutorial';
  consoleMessage += '\n +++++++++++++++++++++++++++++++++++++++++++++++++++++';
  consoleMessage += '\n %s server is listening at %s';
  consoleMessage += '\n Open your browser to %s/tasks\n';
  consoleMessage += '+++++++++++++++++++++++++++++++++++++++++++++++++++++ \n';
  consoleMessage += '\n !!! why not try a $curl -isS %s | json to get some ideas? \n';
  consoleMessage += '+++++++++++++++++++++++++++++++++++++++++++++++++++++ \n\n';

  //log.info(consoleMessage, server.name, server.url, server.url, server.url);

});
