/* Manifest version: smwkGrXJ */
// Caution! Be sure you understand the caveats before publishing an application with
// offline support. See https://aka.ms/blazor-offline-considerations

self.importScripts('service-worker-assets.js');
self.addEventListener('install', event => event.waitUntil(onInstall(event)));
self.addEventListener('activate', event => event.waitUntil(onActivate(event)));
self.addEventListener('fetch', event => event.respondWith(onFetch(event)));

const cacheNamePrefix = 'offline-cache-';
const cacheName = `${cacheNamePrefix}${self.assetsManifest.version}`;
const offlineAssetsInclude = [ /\.dll$/, /\.pdb$/, /\.wasm/, /\.html/, /\.js$/, /\.json$/, /\.css$/, /\.woff$/, /\.png$/, /\.jpe?g$/, /\.gif$/, /\.ico$/, /\.blat$/, /\.dat$/, /\.webmanifest$/ ];
const offlineAssetsExclude = [ /^service-worker\.js$/ ];

// Replace with your base path if you are hosting on a subfolder. Ensure there is a trailing '/'.
const base = "/KalVault/";
const baseUrl = new URL(base, self.origin);
const manifestUrlList = self.assetsManifest.assets.map(asset => new URL(asset.url, baseUrl).href);

async function onInstallOLD(event) {
    console.info('Service worker: Install');

    // Fetch and cache all matching items from the assets manifest
    const assetsRequests = self.assetsManifest.assets
        .filter(asset => offlineAssetsInclude.some(pattern => pattern.test(asset.url)))
        .filter(asset => !offlineAssetsExclude.some(pattern => pattern.test(asset.url)))
        //.map(asset => new Request(asset.url, { cache: 'no-cache' }));
        .map(asset => new Request(new URL(asset.url, baseUrl).href, { cache: 'no-cache' }));
    //await caches.open(cacheName).then(cache => cache.addAll(assetsRequests));
    
for (const asset of assetsRequests) {
    try {
        await cache.add(new Request(asset.url));
    } catch (err) {
        console.warn('Failed to cache:', asset.url);
    }
}
    
     console.info('Service worker: Install Complete');
}

async function onInstall(event) {
    console.info('Service worker: Install');
    const cache = await caches.open(cacheName);
    
    // Ensure this matches your <base href> EXACTLY
    const base = "/KalVault/"; 
    const baseUrl = new URL(base, self.origin);

    const assetsToCache = self.assetsManifest.assets
        .filter(asset => offlineAssetsInclude.some(pattern => pattern.test(asset.url)))
        .filter(asset => !offlineAssetsExclude.some(pattern => pattern.test(asset.url)));

    // Fetch files one by one to isolate which one is failing
    for (const asset of assetsToCache) {
        const assetUrl = new URL(asset.url, baseUrl).href;
        try {
            // We use 'no-cache' to ensure we get the fresh version from GitHub
            const response = await fetch(assetUrl, { cache: 'no-cache' });
            if (!response.ok) throw new Error(`Status: ${response.status}`);
            
            await cache.put(assetUrl, response);
        } catch (error) {
            console.error(`Failed to cache: ${assetUrl}`, error);
        }
    }
}


async function onInstallNEW(event) {
    console.info('Service worker: Install');

    const cache = await caches.open(cacheName);
    
try {
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) throw new Error(response.status);
    await cache.put(url, response.clone());
} catch (err) {
    console.warn("Skipping missing file:", url);
}
    
   // for (const asset of self.assetsManifest.assets) {
      //  if (!offlineAssetsInclude.some(pattern => pattern.test(asset.url))) continue;
      //  if (offlineAssetsExclude.some(pattern => pattern.test(asset.url))) continue;

      //  const url = new URL(asset.url, baseUrl).href;

     //   try {
          //  console.log("Caching:", url);
         //   await cache.add(new Request(url, { cache: 'no-cache' }));
       // } catch (err) {
           // console.error("FAILED:", url, err);
       // }
    //}

    console.info('Service worker: Install Complete');
}



async function onActivate(event) {
    console.info('Service worker: Activate');

    // Delete unused caches
    const cacheKeys = await caches.keys();
    await Promise.all(cacheKeys
        .filter(key => key.startsWith(cacheNamePrefix) && key !== cacheName)
        .map(key => caches.delete(key)));
}

async function onFetch(event) {
    let cachedResponse = null;
    if (event.request.method === 'GET') {
        // For all navigation requests, try to serve index.html from cache,
        // unless that request is for an offline resource.
        // If you need some URLs to be server-rendered, edit the following check to exclude those URLs
        const shouldServeIndexHtml = event.request.mode === 'navigate'
            && !manifestUrlList.some(url => url === event.request.url);

        //const request = shouldServeIndexHtml ? 'index.html' : event.request;
        const request = shouldServeIndexHtml ? new Request(base + 'index.html') : event.request;
        const cache = await caches.open(cacheName);
        cachedResponse = await cache.match(request);
    }

    return cachedResponse || fetch(event.request);
}
