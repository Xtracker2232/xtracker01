const CACHE_NAME = 'xtracker-v2';
const STATIC_FILES = [
  '/index.html',
  '/login.html',
  '/dashboard.html',
  '/manifest.json'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(STATIC_FILES);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE_NAME; })
            .map(function(k) { return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', function(e) {
  // Toujours réseau pour les API, POST, et ressources externes
  if (
    e.request.url.includes('/api/') ||
    e.request.method !== 'GET' ||
    e.request.url.includes('googleapis.com') ||
    e.request.url.includes('discord') ||
    e.request.url.includes('railway.app')
  ) {
    e.respondWith(fetch(e.request));
    return;
  }
  // Pages HTML - réseau d'abord, cache en fallback
  e.respondWith(
    fetch(e.request).then(function(response) {
      if (response.ok) {
        var clone = response.clone();
        caches.open(CACHE_NAME).then(function(cache) {
          cache.put(e.request, clone);
        });
      }
      return response;
    }).catch(function() {
      return caches.match(e.request);
    })
  );
});