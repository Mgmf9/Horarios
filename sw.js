// Abre na hora com a cópia salva e busca a versão nova por trás.
const C="rovigo-badia-v2";
const CORE=["./","./index.html","./manifest.webmanifest","./icon-192.png","./icon-512.png","./apple-touch-icon.png"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()))});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener("fetch",e=>{
  const r=e.request; if(r.method!=="GET")return;
  if(new URL(r.url).origin!==location.origin&&!/fonts\.(googleapis|gstatic)\.com$/.test(new URL(r.url).hostname))return; // servidor de avisos: sem cache
  e.respondWith(caches.open(C).then(async c=>{
    const hit=await c.match(r,{ignoreSearch:true})||(r.mode==="navigate"?await c.match("./index.html"):null);
    const net=fetch(r).then(res=>{if(res&&(res.ok||res.type==="opaque"))c.put(r,res.clone());return res}).catch(()=>hit);
    if(hit){e.waitUntil(net);return hit}
    return net;
  }));
});
// Aviso que chega do servidor, mesmo com o app fechado
self.addEventListener("push",e=>{
  let d={title:"Sai em 10 min",body:"Sua viagem está chegando."};
  try{d=Object.assign(d,e.data.json())}catch(_){}
  e.waitUntil(self.registration.showNotification(d.title,{body:d.body,tag:d.tag,icon:"icon-192.png",badge:"icon-192.png"}));
});
self.addEventListener("notificationclick",e=>{e.notification.close();e.waitUntil(clients.matchAll({type:"window",includeUncontrolled:true}).then(l=>l.length?l[0].focus():clients.openWindow("./")))});
