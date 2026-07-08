const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ── Web Push helpers ────────────────────────────────────

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDec(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - s.length % 4) % 4));
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
}

function concat(...bufs) {
  const len = bufs.reduce((s, b) => s + b.length, 0);
  const r = new Uint8Array(len);
  let off = 0;
  for (const b of bufs) { r.set(b, off); off += b.length; }
  return r;
}

async function hmacSha256(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

async function hkdfExtract(salt, ikm) {
  return hmacSha256(salt.length ? salt : new Uint8Array(32), ikm);
}

async function hkdfExpand(prk, info, len) {
  const out = await hmacSha256(prk, concat(info, new Uint8Array([1])));
  return out.slice(0, len);
}

async function encryptPayload(plaintext, sub) {
  const clientPub = b64urlDec(sub.keys.p256dh);
  const clientAuth = b64urlDec(sub.keys.auth);

  const localKP = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const localPub = new Uint8Array(await crypto.subtle.exportKey('raw', localKP.publicKey));

  const clientKey = await crypto.subtle.importKey('raw', clientPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: clientKey }, localKP.privateKey, 256));

  const prkKey = await hkdfExtract(clientAuth, shared);
  const keyInfo = concat(new TextEncoder().encode('WebPush: info\0'), clientPub, localPub);
  const ikm = await hkdfExpand(prkKey, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hkdfExtract(salt, ikm);
  const cek = await hkdfExpand(prk, new TextEncoder().encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdfExpand(prk, new TextEncoder().encode('Content-Encoding: nonce\0'), 12);

  const padded = concat(new TextEncoder().encode(plaintext), new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, padded));

  const header = new Uint8Array(86);
  header.set(salt, 0);
  const rs = 4096;
  header[16] = (rs >> 24) & 0xff;
  header[17] = (rs >> 16) & 0xff;
  header[18] = (rs >> 8) & 0xff;
  header[19] = rs & 0xff;
  header[20] = 65;
  header.set(localPub, 21);

  return concat(header, encrypted);
}

async function createVapidAuth(endpoint, env) {
  const pubRaw = b64urlDec(env.VAPID_PUBLIC_KEY);
  const url = new URL(endpoint);
  const aud = `${url.protocol}//${url.host}`;
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600;

  const hdr = b64url(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const pay = b64url(new TextEncoder().encode(JSON.stringify({ aud, exp, sub: 'mailto:chaletdrouin@noreply.github.com' })));
  const input = `${hdr}.${pay}`;

  const privRaw = b64urlDec(env.VAPID_PRIVATE_KEY);
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: b64url(pubRaw.slice(1, 33)),
    y: b64url(pubRaw.slice(33, 65)),
    d: b64url(privRaw),
  };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(input)));

  return `vapid t=${input}.${b64url(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

async function sendPush(sub, payload, env) {
  try {
    const body = await encryptPayload(JSON.stringify(payload), sub);
    const auth = await createVapidAuth(sub.endpoint, env);
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': auth,
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'TTL': '86400',
      },
      body,
    });
    return res.status < 400;
  } catch {
    return false;
  }
}

async function notifyAll(payload, env) {
  const subs = (await env.BOOKINGS.get('push_subs', 'json')) || [];
  if (!subs.length) return;
  const alive = [];
  await Promise.allSettled(subs.map(async sub => {
    const ok = await sendPush(sub, payload, env);
    if (ok) alive.push(sub);
  }));
  if (alive.length !== subs.length) {
    await env.BOOKINGS.put('push_subs', JSON.stringify(alive));
  }
}

// ── Main handler ────────────────────────────────────────

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // GET /vapid-public-key
    if (req.method === 'GET' && path === '/vapid-public-key') {
      return json({ key: env.VAPID_PUBLIC_KEY });
    }

    // POST /subscribe
    if (req.method === 'POST' && path === '/subscribe') {
      let sub;
      try { sub = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (!sub.endpoint || !sub.keys) return json({ error: 'Invalid subscription' }, 400);
      const subs = (await env.BOOKINGS.get('push_subs', 'json')) || [];
      if (!subs.find(s => s.endpoint === sub.endpoint)) {
        subs.push({ endpoint: sub.endpoint, keys: sub.keys });
        await env.BOOKINGS.put('push_subs', JSON.stringify(subs));
      }
      return json({ ok: true }, 201);
    }

    // DELETE /subscribe
    if (req.method === 'POST' && path === '/unsubscribe') {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const subs = (await env.BOOKINGS.get('push_subs', 'json')) || [];
      await env.BOOKINGS.put('push_subs', JSON.stringify(subs.filter(s => s.endpoint !== body.endpoint)));
      return json({ ok: true });
    }

    // GET /bookings
    if (req.method === 'GET' && path === '/bookings') {
      const all = (await env.BOOKINGS.get('all', 'json')) || [];
      return json(all);
    }

    // POST /bookings
    if (req.method === 'POST' && path === '/bookings') {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (!body.start || !body.end || !body.description) {
        return json({ error: 'start, end, description required' }, 400);
      }
      const all = (await env.BOOKINGS.get('all', 'json')) || [];
      const booking = {
        id: crypto.randomUUID(),
        start: body.start,
        end: body.end,
        description: String(body.description).slice(0, 100),
        color: /^#[0-9a-f]{6}$/i.test(body.color) ? body.color : '#4f8ef7',
        createdAt: new Date().toISOString(),
      };
      all.push(booking);
      await env.BOOKINGS.put('all', JSON.stringify(all));

      ctx.waitUntil
        ? ctx.waitUntil(notifyAll({ title: 'Nouvelle r\u00e9servation', body: booking.description }, env))
        : await notifyAll({ title: 'Nouvelle r\u00e9servation', body: booking.description }, env);

      return json(booking, 201);
    }

    // PUT /bookings/:id
    const mPut = path.match(/^\/bookings\/([0-9a-f-]+)$/i);
    if (req.method === 'PUT' && mPut) {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const all = (await env.BOOKINGS.get('all', 'json')) || [];
      const idx = all.findIndex(b => b.id === mPut[1]);
      if (idx === -1) return json({ error: 'Not found' }, 404);
      const old = all[idx];
      all[idx] = {
        ...old,
        start: body.start || old.start,
        end: body.end || old.end,
        description: body.description ? String(body.description).slice(0, 100) : old.description,
        color: /^#[0-9a-f]{6}$/i.test(body.color) ? body.color : old.color,
      };
      await env.BOOKINGS.put('all', JSON.stringify(all));

      const notify = notifyAll({ title: 'R\u00e9servation modifi\u00e9e', body: all[idx].description }, env);
      ctx.waitUntil ? ctx.waitUntil(notify) : await notify;

      return json(all[idx]);
    }

    // DELETE /bookings/:id
    const mDel = path.match(/^\/bookings\/([0-9a-f-]+)$/i);
    if (req.method === 'DELETE' && mDel) {
      const id = mDel[1];
      const all = (await env.BOOKINGS.get('all', 'json')) || [];
      const booking = all.find(b => b.id === id);
      const desc = booking ? booking.description : 'Réservation';
      await env.BOOKINGS.put('all', JSON.stringify(all.filter(b => b.id !== id)));

      const notify = notifyAll({ title: 'R\u00e9servation supprim\u00e9e', body: desc }, env);
      ctx.waitUntil ? ctx.waitUntil(notify) : await notify;

      return new Response(null, { status: 204, headers: CORS });
    }

    // ── Inventory ──

    const DEFAULT_INVENTORY = [
      { name: 'Pâtes', cat: 'Épicerie' },
      { name: 'Riz', cat: 'Épicerie' },
      { name: 'Farine', cat: 'Épicerie' },
      { name: 'Sucre', cat: 'Épicerie' },
      { name: 'Céréales', cat: 'Épicerie' },
      { name: 'Conserves', cat: 'Épicerie' },
      { name: 'Sel', cat: 'Condiments' },
      { name: 'Poivre', cat: 'Condiments' },
      { name: 'Huile d\'olive', cat: 'Condiments' },
      { name: 'Vinaigre', cat: 'Condiments' },
      { name: 'Moutarde', cat: 'Condiments' },
      { name: 'Ketchup', cat: 'Condiments' },
      { name: 'Herbes de Provence', cat: 'Condiments' },
      { name: 'Papier toilette', cat: 'Entretien' },
      { name: 'Savon', cat: 'Entretien' },
      { name: 'Liquide vaisselle', cat: 'Entretien' },
      { name: 'Éponges', cat: 'Entretien' },
      { name: 'Sacs poubelle', cat: 'Entretien' },
      { name: 'Produit multi-surfaces', cat: 'Entretien' },
    ];

    async function getInventory() {
      let items = await env.BOOKINGS.get('inventory', 'json');
      if (!items) {
        items = DEFAULT_INVENTORY.map(d => ({
          id: crypto.randomUUID(), name: d.name, cat: d.cat, qty: 1,
        }));
        await env.BOOKINGS.put('inventory', JSON.stringify(items));
      }
      return items;
    }

    // GET /inventory
    if (req.method === 'GET' && path === '/inventory') {
      const items = await getInventory();
      const updated = await env.BOOKINGS.get('inventory_updated');
      return json({ items, updatedAt: updated || null });
    }

    // POST /inventory
    if (req.method === 'POST' && path === '/inventory') {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (!body.name) return json({ error: 'name required' }, 400);
      const items = await getInventory();
      const item = { id: crypto.randomUUID(), name: String(body.name).slice(0, 80), cat: String(body.cat || 'Épicerie').slice(0, 40), qty: Number(body.qty) || 1 };
      items.push(item);
      await env.BOOKINGS.put('inventory', JSON.stringify(items));
      await env.BOOKINGS.put('inventory_updated', new Date().toISOString());
      return json(item, 201);
    }

    // PUT /inventory/reorder
    if (req.method === 'PUT' && path === '/inventory/reorder') {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (!Array.isArray(body.ids)) return json({ error: 'ids required' }, 400);
      const items = await getInventory();
      const byId = new Map(items.map(i => [i.id, i]));
      const newItems = body.ids.map(id => byId.get(id)).filter(Boolean);
      items.forEach(i => { if (!body.ids.includes(i.id)) newItems.push(i); });
      await env.BOOKINGS.put('inventory', JSON.stringify(newItems));
      await env.BOOKINGS.put('inventory_updated', new Date().toISOString());
      return json({ items: newItems });
    }

    // PUT /inventory/:id
    const mInvPut = path.match(/^\/inventory\/([0-9a-f-]+)$/i);
    if (req.method === 'PUT' && mInvPut) {
      let body;
      try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      const items = await getInventory();
      const idx = items.findIndex(i => i.id === mInvPut[1]);
      if (idx === -1) return json({ error: 'Not found' }, 404);
      if (body.name !== undefined) items[idx].name = String(body.name).slice(0, 80);
      if (body.qty !== undefined) items[idx].qty = Math.max(0, Number(body.qty));
      await env.BOOKINGS.put('inventory', JSON.stringify(items));
      await env.BOOKINGS.put('inventory_updated', new Date().toISOString());
      return json(items[idx]);
    }

    // DELETE /inventory/:id
    const mInvDel = path.match(/^\/inventory\/([0-9a-f-]+)$/i);
    if (req.method === 'DELETE' && mInvDel) {
      const items = await getInventory();
      await env.BOOKINGS.put('inventory', JSON.stringify(items.filter(i => i.id !== mInvDel[1])));
      await env.BOOKINGS.put('inventory_updated', new Date().toISOString());
      return new Response(null, { status: 204, headers: CORS });
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};
