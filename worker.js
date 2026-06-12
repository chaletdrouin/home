const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
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
      return json(booking, 201);
    }

    // DELETE /bookings/:id
    const m = path.match(/^\/bookings\/([0-9a-f-]+)$/i);
    if (req.method === 'DELETE' && m) {
      const id = m[1];
      const all = (await env.BOOKINGS.get('all', 'json')) || [];
      await env.BOOKINGS.put('all', JSON.stringify(all.filter(b => b.id !== id)));
      return new Response(null, { status: 204, headers: CORS });
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};
