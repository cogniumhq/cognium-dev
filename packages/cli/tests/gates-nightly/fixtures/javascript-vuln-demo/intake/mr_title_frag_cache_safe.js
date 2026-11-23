/**
 * Safe mirror — cache key includes the viewer, and the title is redacted first.
 */
'use strict';

function titleHtml(mergeRequest, viewer) {
  const shown = redact(mergeRequest.title, viewer);
  return cache.fetch('mr-title-' + mergeRequest.id + '-' + viewer.id, () => shown);
}

module.exports = { titleHtml };
