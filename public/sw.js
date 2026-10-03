// Lafiya emergency-card offline protocol (envelope v1, encrypted at rest v2).
//
// We intentionally cache a structured, versioned projection rather than the
// rendered HTML. Offline presentation therefore cannot accidentally inherit a
// live-looking verification badge, stale scripts, or an old route layout.
// Envelopes are AES-GCM encrypted under a key derived from the card URL's
// secret segment and stored under an opaque hashed key (issue #630, ADR-004).

import {
  CARD_CACHE_LIMITS,
  cardSecretFromUrl,
  createOfflineEnvelope,
  decryptOfflineEnvelope,
  encryptOfflineEnvelope,
  enforceCacheBudget,
  offlineCacheKey,
  offlineEnvelopeResponse,
  renderOfflineEnvelope,
  validateOfflineEnvelope,
  withEntryMetaHeaders,
} from "./offline-cache-helpers.js";

// v2: encrypted envelopes. Activation deletes the v1 plaintext cache.
const CARD_CACHE = "lafiya-emergency-envelopes-v2";
const CARD_PATH_PREFIX = "/card/";

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      // Remove legacy rendered-card caches: they bypass envelope expiry and
      // cannot state the three freshness dimensions honestly.
      await Promise.all(
        keys
          .filter((key) => key !== CARD_CACHE)
          .map((key) => caches.delete(key)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET" || request.mode !== "navigate") return;
  const url = new URL(request.url);
  if (
    url.origin !== self.location.origin ||
    !url.pathname.startsWith(CARD_PATH_PREFIX)
  )
    return;
  event.respondWith(handleCardNavigation(event));
});

async function withCacheLock(name, fn) {
  const locks = self.navigator && self.navigator.locks;
  if (locks && typeof locks.request === "function") {
    return locks.request(`lafiya-cache:${name}`, fn);
  }
  return fn();
}

async function storeEnvelope(cacheKey, envelope, secret) {
  const record = await encryptOfflineEnvelope(envelope, secret, cacheKey);
  if (!record) return false;
  const request = new Request(new URL(cacheKey, self.location.origin));
  const response = offlineEnvelopeResponse(record);
  const bytes = new Uint8Array(await response.clone().arrayBuffer());
  return withCacheLock(CARD_CACHE, async () => {
    const cache = await caches.open(CARD_CACHE);
    const { admit } = await enforceCacheBudget({
      cache,
      incomingRequest: request,
      incomingSize: bytes.byteLength,
      maxEntries: CARD_CACHE_LIMITS.maxEntries,
      maxBytes: CARD_CACHE_LIMITS.maxBytes,
    });
    if (!admit) return false;
    const headers = withEntryMetaHeaders(response.headers, {
      cachedAt: envelope.cachedAt,
      lastAccessed: Date.now(),
      size: bytes.byteLength,
    });
    await cache.put(request, new Response(bytes, { headers }));
    return true;
  });
}

async function handleCardNavigation(event) {
  const request = event.request;
  const secret = cardSecretFromUrl(request.url);
  const cacheKey = secret ? await offlineCacheKey(request.url) : null;
  const cacheRequest = cacheKey
    ? new Request(new URL(cacheKey, self.location.origin))
    : null;
  try {
    const networkResponse = await fetch(request);
    if (!networkResponse.ok) return networkResponse;

    const envelope = await createOfflineEnvelope(
      await networkResponse.clone().text(),
      new Date().toISOString(),
    );
    if (!cacheRequest) return networkResponse;
    const cache = await caches.open(CARD_CACHE);
    if (envelope) {
      await storeEnvelope(cacheKey, envelope, secret);
    } else {
      // Consent withdrawal, malformed source, unsupported envelope version,
      // and unavailable cards remove any prior local copy at next contact.
      await cache.delete(cacheRequest);
    }
    return networkResponse;
  } catch {
    const cache = await caches.open(CARD_CACHE);
    const cached = cacheRequest ? await cache.match(cacheRequest) : undefined;
    const record = cached ? await cached.json().catch(() => null) : null;
    const envelope = await decryptOfflineEnvelope(record, secret, cacheKey);
    const validation = await validateOfflineEnvelope(
      envelope,
      new Date().toISOString(),
    );
    if (!validation.valid) {
      if (cached) event.waitUntil(cache.delete(cacheRequest));
      return new Response(renderOfflineEnvelope(null, validation.reason), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response(renderOfflineEnvelope(envelope), {
      status: 200,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
}
