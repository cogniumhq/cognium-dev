/**
 * Safe mirror — issuer comes from server configuration.
 */
'use strict';

function discovery() {
  const host = 'gitlab.example.com';
  const doc = {
    issuer: 'https://' + host,
    authorization_endpoint: 'https://' + host + '/oauth/authorize',
  };
  cache.set('oidc-discovery', doc);
  return doc;
}

module.exports = { discovery };
