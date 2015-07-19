/**
 * Module dependencies.
 */
var webfinger = require('webfinger').webfinger;


/**
 * Discover OpenID Connect provider configuration using WebFinger.
 *
 * This discovery mechanism uses WebFinger to discover the issuer for a
 * user-supplied identifier.  Once the issuer is known, it's configuration is
 * loaded.
 *
 * Note: Prior to draft 12, OpenID Connect Discovery used Simple Web Discovery
 *       rather than WebFinger.  At the time of writing, many provider
 *       implementations continue to implement SWD.
 *
 * References:
 *   - [OpenID Connect Discovery 1.0 - draft 12](http://openid.net/specs/openid-connect-discovery-1_0.html)
 *   - [WebFinger](http://tools.ietf.org/html/draft-ietf-appsawg-webfinger-08)
 *
 * @return {Function}
 * @api public
 */
module.exports = function() {
  
  return function(identifier, done) {
    if (!identifier) { return done(); }
    
    webfinger(identifier, 'http://openid.net/specs/connect/1.0/issuer', { webfingerOnly: true }, function(err, jrd) {
      if (err) { return done(err); };
      if (!jrd.links) { return done(new Error('No links in resource descriptor')); }
      
      var issuer;
      for (var i = 0; i < jrd.links.length; i++) {
        var link = jrd.links[i];
        if (link.rel == 'http://openid.net/specs/connect/1.0/issuer') {
          issuer = link.href;
          break;
        }
      }
      
      if (!issuer) { return done(new Error('No OpenID Connect issuer in resource descriptor')); }
      return done(null, issuer);
    });
  }
}
