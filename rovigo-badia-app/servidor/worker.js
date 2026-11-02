// Avisos do app Rovigo e Badia Polesine
// Cloudflare Worker: guarda os avisos marcados no sino e, a cada minuto,
// manda uma notificação push para os que já chegaram na hora.
//
// Precisa de: um banco D1 ligado com o nome DB e um gatilho cron "* * * * *".
// As chaves de notificação (VAPID) são criadas sozinhas no primeiro acesso.

// Troque pelo seu e-mail. A Apple usa isso como contato do remetente dos avisos.
const CONTATO = "mailto:seu-email@exemplo.com";

// Só aceita assinaturas dos serviços de push oficiais
const PUSH_HOSTS = [/\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /\.push\.services\.mozilla\.com$/, /\.notify\.windows\.com$/];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...CORS } });

// ---------- base64url ----------
const enc = new TextEncoder();
const b64u = (buf) => {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = (str) => {
  const s = atob(str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4));
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
};
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// ---------- banco ----------
async function setup(db) {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS cfg (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS alarms (id TEXT NOT NULL, endpoint TEXT NOT NULL, sub TEXT NOT NULL, at INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY (id, endpoint))"),
    db.prepare("CREATE INDEX IF NOT EXISTS alarms_at ON alarms (at)"),
  ]);
}

// Chaves VAPID: criadas uma vez e guardadas no banco
async function vapid(db) {
  const row = await db.prepare("SELECT v FROM cfg WHERE k = 'vapid'").first();
  if (row) return JSON.parse(row.v);
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = b64u(await crypto.subtle.exportKey("raw", kp.publicKey));
  const v = { jwk, pub };
  await db.prepare("INSERT OR IGNORE INTO cfg (k, v) VALUES ('vapid', ?)").bind(JSON.stringify(v)).run();
  const again = await db.prepare("SELECT v FROM cfg WHERE k = 'vapid'").first();
  return JSON.parse(again.v);
}

// ---------- push (RFC 8291 + VAPID RFC 8292) ----------
async function vapidHeader(endpoint, keys) {
  const aud = new URL(endpoint).origin;
  const header = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: CONTATO })));
  const key = await crypto.subtle.importKey("jwk", keys.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${claims}`));
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${keys.pub}`;
}

async function hkdf(salt, ikm, info, bits) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, bits));
}

export async function encryptPayload(sub, text) {
  const uaPublic = unb64u(sub.keys.p256dh);
  const auth = unb64u(sub.keys.auth);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 128);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 96);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plain = concat(enc.encode(text), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, plain));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export async function sendPush(sub, payload, keys) {
  const body = await encryptPayload(sub, JSON.stringify(payload));
  return fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: await vapidHeader(sub.endpoint, keys),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "900",
      Urgency: "high",
    },
    body,
  });
}

// ---------- validação ----------
function validSub(s) {
  try {
    if (!s || typeof s.endpoint !== "string" || !s.keys || typeof s.keys.p256dh !== "string" || typeof s.keys.auth !== "string") return false;
    const u = new URL(s.endpoint);
    return u.protocol === "https:" && PUSH_HOSTS.some((r) => r.test(u.hostname));
  } catch { return false; }
}
const short = (v, n) => typeof v === "string" && v.length > 0 && v.length <= n;

// ---------- rotas ----------
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    await setup(env.DB);

    if (req.method === "GET" && url.pathname === "/key") {
      const keys = await vapid(env.DB);
      return new Response(keys.pub, { headers: { "Content-Type": "text/plain", ...CORS } });
    }

    if (req.method === "POST" && url.pathname === "/alarm") {
      let b; try { b = await req.json(); } catch { return json({ error: "corpo inválido" }, 400); }
      const now = Date.now();
      if (!validSub(b.sub) || !short(b.id, 120) || !short(b.title, 80) || !short(b.body, 200) ||
          typeof b.at !== "number" || b.at < now - 60000 || b.at > now + 9 * 86400000)
        return json({ error: "dados inválidos" }, 400);
      const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM alarms WHERE endpoint = ?").bind(b.sub.endpoint).first();
      if (n && n.n >= 30) return json({ error: "avisos demais para este aparelho" }, 429);
      await env.DB.prepare("INSERT OR REPLACE INTO alarms (id, endpoint, sub, at, title, body) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(b.id, b.sub.endpoint, JSON.stringify(b.sub), Math.round(b.at), b.title, b.body).run();
      return json({ ok: true });
    }

    if (req.method === "POST" && url.pathname === "/alarm/delete") {
      let b; try { b = await req.json(); } catch { return json({ error: "corpo inválido" }, 400); }
      if (!short(b.id, 120) || !short(b.endpoint, 1000)) return json({ error: "dados inválidos" }, 400);
      await env.DB.prepare("DELETE FROM alarms WHERE id = ? AND endpoint = ?").bind(b.id, b.endpoint).run();
      return json({ ok: true });
    }

    if (req.method === "GET" && url.pathname === "/") return new Response("Avisos Rovigo Badia: funcionando.", { headers: CORS });
    return json({ error: "não encontrado" }, 404);
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(run(env));
  },
};

export async function run(env) {
  await setup(env.DB);
  const now = Date.now();
  const { results } = await env.DB.prepare("SELECT * FROM alarms WHERE at <= ? LIMIT 200").bind(now + 20000).all();
  if (!results || !results.length) return 0;
  const keys = await vapid(env.DB);
  let sent = 0;
  for (const a of results) {
    let gone = false, ok = false;
    try {
      const res = await sendPush(JSON.parse(a.sub), { title: a.title, body: a.body, tag: a.id }, keys);
      ok = res.ok;
      if (ok) sent++;
      if (res.status === 404 || res.status === 410) gone = true; // aparelho saiu do app
    } catch (_) { /* tenta de novo no próximo minuto se ainda estiver no prazo */ }
    if (gone) await env.DB.prepare("DELETE FROM alarms WHERE endpoint = ?").bind(a.endpoint).run();
    else if (ok || a.at < now - 5 * 60000) await env.DB.prepare("DELETE FROM alarms WHERE id = ? AND endpoint = ?").bind(a.id, a.endpoint).run();
  }
  return sent;
}
