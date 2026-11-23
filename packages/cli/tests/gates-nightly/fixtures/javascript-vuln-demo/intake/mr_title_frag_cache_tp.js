/**
 * TP — rendered title is cached without the viewer (CWE-524).
 * CVE-2026-105711 class: confidential title shared across users.
 */
'use strict';

function titleHtml(mergeRequest) {
  return cache.fetch('mr-title-' + mergeRequest.id, () => mergeRequest.title); // SINK CWE-524
}

module.exports = { titleHtml };
