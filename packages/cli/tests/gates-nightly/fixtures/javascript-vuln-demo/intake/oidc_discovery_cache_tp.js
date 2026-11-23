/**
 * TP — caller host is stored in the shared OIDC discovery document (CWE-524).
 * CVE-2026-112212 class: poisoned discovery endpoint URLs.
 */
'use strict';

function discovery(host) {
  const doc = {
    issuer: 'https://' + host,
    authorization_endpoint: 'https://' + host + '/oauth/authorize',
  };
  cache.set('oidc-discovery', doc); // SINK CWE-524
  return doc;
}

module.exports = { discovery };
