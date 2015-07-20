/**
 * Module dependencies.
 */
var lrdd = require('webfinger').lrdd;


/**
 * Discover OpenID Connect provider configuration using Web Host Metadata and
 * LRDD.
 *
 * This discovery mechanism uses Web Host Metadata and LRDD to discover the
 * issuer for a user-supplied identifier.  Once the issuer is known, it's
 * configuration is loaded.
 *
 * LRDD-based discovery was specified in the original, community-drafted version
 * of WebFinger, and was also adopted through the second draft of the IETF
 * standardization process.  Beginning at the third draft, the IETF
 * specification of WebFinger no longer builds on RFC 6415.
 *
 * This results in some degree of confusion, as there are now two fundamentally
 * different protocols both referred to as "WebFinger".  This module implements
 * the "community" version of WebFinger.  This method of discovery is not
 * officially recognized by OpenID Connect, but can be as a fallback for relying
 * parties who wish to implement broad coverage using a variety of discovery
 * protocols:
 *
 *     var oidc = require('passport-openidconnect');
 *     oidc.disco(oidc.discovery.lrdd());
 *
 * References:
 *   - [Web Host Metadata](http://tools.ietf.org/html/rfc6415)
 *   - [WebFinger](http://code.google.com/p/webfinger/wiki/WebFingerProtocol)
 *   - [webfinger-02](http://tools.ietf.org/html/draft-ietf-appsawg-webfinger-02)
 *
 * @return {Function}
 * @api public
 */
module.exports = function() {
  
  return function(identifier, done) {
    if (!identifier) { return done(); }
    
    lrdd(identifier, function(err, jrd) {
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
