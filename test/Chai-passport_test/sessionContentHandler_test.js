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
 
 /* eslint-disable no-new */

'use restrict';

const chai = require('chai');
const expect = chai.expect;
const SessionContentHandler = require('../../lib/sessionContentHandler').SessionContentHandler; 

describe('checking constructor', function() {
  it('should throw without identifier', function(done) {
    expect(SessionContentHandler.bind(SessionContentHandler)).
      to.throw('identifier is required to use sessionContentHandler');
    done();
  });

  it('should throw with non-integer maxAmount', function(done) {
    expect(SessionContentHandler.bind(SessionContentHandler, 'state', 1.1)).
      to.throw('SessionContentHandler: maxAmount must be a positive integer');
    done();
  });

  it('should throw with negative maxAmount', function(done) {
    expect(SessionContentHandler.bind(SessionContentHandler, 'state', -1)).
      to.throw('SessionContentHandler: maxAmount must be a positive integer');
    done();
  });

  it('should throw with invalid maxAge', function(done) {
    expect(SessionContentHandler.bind(SessionContentHandler, 'state', 1, -1)).
      to.throw('SessionContentHandler: maxAge must be a positive number');
    done();
  });
});

describe('checking add function', function() {
  var req = {};
  var handler = new SessionContentHandler('state', 2, 0.1);

  it('should have the items we push in', function(done) {
    handler.add(req, 'key', 'state1');
    handler.add(req, 'key', 'state2');
    expect(req.session['key']['state'].length).to.equal(2);
    expect(req.session['key']['state'][0]['state']).to.equal('state1');
    expect(req.session['key']['state'][1]['state']).to.equal('state2');
    done();
  });

  it('should not exceed the maxAmount of items', function(done) {
    // we add a third item, but the maxAmount allowed is 2, so the first
    // state should be removed automatically
    handler.add(req, 'key', 'state3');
    expect(req.session['key']['state'].length).to.equal(2);
    expect(req.session['key']['state'][0]['state']).to.equal('state2');
    expect(req.session['key']['state'][1]['state']).to.equal('state3');
    done();
  });

  it('should removed expired items', function(done) {
    // if we call 'add' function after the maxAge, all the expired ones should be
    // removed when we can 'add' function  
    setTimeout(function() {
      handler.add(req, 'key', 'state4');
      expect(req.session['key']['state'].length).to.equal(1);
      expect(req.session['key']['state'][0]['state']).to.equal('state4');
      done();
    }, 100);  // maxAge is 0.1 second = 100 ms 
  });
});

describe('checking verify function', function() {
  var req = {};
  var handler = new SessionContentHandler('state', 2, 0.1);

  it('should throw without session', function(done) {
    expect(handler.verify.bind(handler, req, 'key', 'test')).
      to.throw('OIDC strategy requires session support. Did you forget to use session middleware such as express-session?');
    done();
  });

  it('should find the item we added, item should be deleted after verify', function(done) {
    handler.add(req, 'key', 'state1');

    // should have the items we added
    var result = handler.verify(req, 'key', 'state1');
    expect(result.valid).to.equal(true);
    expect(result.errorMessage).to.equal('');

    // should be deleted after verify
    var result = handler.verify(req, 'key', 'state1');
    expect(result.valid).to.equal(false);
    expect(result.errorMessage).to.equal('invalid state');    
    done();
  });

  it('should be able to find the state in req', function(done) {
    // should be able to find the state in query
    handler.add(req, 'key', 'state1');
    req.query = {state: 'state1'};
    var result = handler.verify(req, 'key', 'state1');
    expect(result.valid).to.equal(true);
    expect(result.errorMessage).to.equal('');
    delete req.query;

    // should be able to find the state in body
    handler.add(req, 'key', 'state1');
    req.body = {state: 'state1'};
    var result = handler.verify(req, 'key', 'state1');
    expect(result.valid).to.equal(true);
    expect(result.errorMessage).to.equal('');
    delete req.body; 

    done();
  });

  it('should not find the expired item', function(done) {
    handler.add(req, 'key', 'state1');

    setTimeout(function() {
      var result = handler.verify(req, 'key', 'state1');
      expect(result.valid).to.equal(false);
      expect(result.errorMessage).to.equal('invalid state');
      done();
    }, 100); // expire after 0.1 second = 100ms
  });
});
