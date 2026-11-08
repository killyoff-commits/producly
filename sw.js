// Garde l'app disponible sans réseau. Tant qu'il y a du réseau, la dernière version mise en ligne est servie.
const CACHE = 'objectifs-xp-v1';
const FILES = ['./', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];
const FONT_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com'];
// Le SDK Firebase est chargé à une version figée : une fois gardé, il ne change plus, et le classement démarre hors ligne.
const isFirebaseSdk = (url) => (url.hostname === 'www.gstatic.com' && url.pathname.startsWith('/firebasejs/'))
  || (url.hostname === 'cdn.jsdelivr.net' && url.pathname.startsWith('/npm/firebase@'));

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);

  // Les polices ne changent pas : la copie gardée suffit.
  if (FONT_HOSTS.includes(url.hostname) || isFirebaseSdk(url)) {
    event.respondWith(
      caches.match(request).then((cached) => cached || fetch(request).then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(request, copy));
        }
        return response;
      }))
    );
    return;
  }

  if (url.origin !== self.location.origin) return;
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(request, copy));
        }
        return response;
      })
      .catch(() => caches.match(request).then((cached) => cached || caches.match('./')))
  );
});
