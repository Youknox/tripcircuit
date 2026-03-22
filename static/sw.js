const CACHE = 'goandtrip-v1';
const PRECACHE = [
  '/',
  '/organiser',
  '/static/logo.svg',
  '/static/favicon.svg',
  '/static/manifest.json',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(PRECACHE))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Network-first pour les routes Flask, cache-first pour les assets statiques
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Assets statiques → cache-first
  if (url.pathname.startsWith('/static/')) {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request))
    );
    return;
  }

  // Pages / API → network-first (pas de cache pour les données utilisateur)
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
