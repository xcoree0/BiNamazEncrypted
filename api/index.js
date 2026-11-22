// BiNamaz - Vercel API. Yalnızca ŞİFRELİ veriyi Upstash Redis'te saklar.
// Gizli bilgi kodda yok; Redis bağlantısı Vercel ortam değişkenlerinden gelir.
const crypto = require('crypto');

// Upstash/Vercel entegrasyonu değişken adına önek ekleyebilir (ör. STORAGE_KV_REST_API_URL); hepsini yakala.
const envFind = re => { const k = Object.keys(process.env).find(k => re.test(k)); return k ? process.env[k] : undefined; };
const URL_ = (envFind(/(^|_)(KV_REST_API_URL|UPSTASH_REDIS_REST_URL)$/) || '').replace(/\/$/, '');
const TOKEN = envFind(/(^|_)(KV_REST_API_TOKEN|UPSTASH_REDIS_REST_TOKEN)$/);

async function R(...cmds) {                       // Upstash REST pipeline
  const r = await fetch(URL_ + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds),
  });
  if (!r.ok) throw new Error('redis ' + r.status);
  return (await r.json()).map(x => { if (x.error) throw new Error(x.error); return x.result; });
}
const one = async c => (await R(c))[0];

const okId = s => typeof s === 'string' && /^[A-Za-z0-9_-]{3,40}$/.test(s);
const okDay = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
const okCode = s => typeof s === 'string' && /^BN-[A-Z0-9]{6}$/.test(s);
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const same = (a, b) => {
  a = Buffer.from(String(a)); b = Buffer.from(String(b));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const getG = async id => { const v = await one(['GET', 'g:' + id]); return v ? JSON.parse(v) : null; };
const authed = (g, tok) => !!g && typeof tok === 'string' && tok.length >= 32 && same(g.ah, sha(tok));

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.query && req.query.a === 'ping') {    // teşhis: /api?a=ping
      let redis = 'bağlı değil';
      if (URL_ && TOKEN) { try { redis = String(await one(['PING'])); } catch (e) { redis = 'hata: ' + e.message; } }
      return res.json({ ok: 1, env: !!(URL_ && TOKEN), redis });
    }
    if (!URL_ || !TOKEN) return res.status(500).json({ err: 'redis ayarlı değil' });
    const b = req.body && typeof req.body === 'object' ? req.body : {};
    const q = req.query || {};
    const a = q.a || b.a;
    const post = req.method === 'POST';

    if (a === 'groups') {                         // üyesi olduğum (şifreli) gruplar
      if (!okCode(q.code)) return res.status(400).json([]);
      const ids = await one(['SMEMBERS', 'm:' + q.code]);
      if (!ids || !ids.length) return res.json([]);
      const vals = await R(...ids.map(i => ['GET', 'g:' + i]));
      return res.json(vals.filter(Boolean).map(v => JSON.parse(v))
        .filter(g => g.memberCodes.includes(q.code))
        .map(g => ({ id: g.id, salt: g.salt, memberCodes: g.memberCodes, enc: g.enc })));
    }

    if (a === 'ticks') {                          // bir günün şifreli tikleri
      if (!okId(q.g) || !okDay(q.day)) return res.status(400).json({ err: 'bad' });
      if (!authed(await getG(q.g), q.tok)) return res.status(403).json({ err: 'auth' });
      const h = (await one(['HGETALL', 't:' + q.g + ':' + q.day])) || [];
      const out = [];
      for (let i = 0; i < h.length; i += 2) out.push({ code: h[i], enc: h[i + 1] });
      return res.json(out);
    }

    if (a === 'setgroup' && post) {               // grup kur / güncelle (jeton ister)
      const { id, data, tok } = b;
      if (!okId(id) || !data || typeof data.enc !== 'string' || data.enc.length > 8000 ||
          typeof data.salt !== 'string' || data.salt.length > 100 ||
          !Array.isArray(data.memberCodes) || typeof tok !== 'string' || tok.length < 32)
        return res.status(400).json({ err: 'bad' });
      const mc = [...new Set(data.memberCodes.filter(okCode))].slice(0, 100);
      const ex = await getG(id);
      if (ex && !authed(ex, tok)) return res.status(403).json({ err: 'auth' });
      const g = { id, salt: data.salt, memberCodes: mc, enc: data.enc, ah: ex ? ex.ah : sha(tok) };
      await R(['SET', 'g:' + id, JSON.stringify(g)], ...mc.map(c => ['SADD', 'm:' + c, id]));
      return res.json({ ok: 1 });
    }

    if (a === 'tick' && post) {                   // kendi satırımın tiki
      const { g, day, code, enc, tok } = b;
      if (!okId(g) || !okDay(day) || !okCode(code) || typeof enc !== 'string' || enc.length > 2000)
        return res.status(400).json({ err: 'bad' });
      const gr = await getG(g);
      if (!authed(gr, tok)) return res.status(403).json({ err: 'auth' });
      if (!gr.memberCodes.includes(code)) return res.status(403).json({ err: 'member' });
      const key = 't:' + g + ':' + day;
      await R(['HSET', key, code, enc], ['EXPIRE', key, 432000]);   // 5 gün sonra otomatik silinir
      return res.json({ ok: 1 });
    }

    if (a === 'delgroup' && post) {               // grubu ve tüm tiklerini sil (jeton ister)
      const { id, tok } = b;
      if (!okId(id)) return res.status(400).json({ err: 'bad' });
      const g = await getG(id);
      if (!authed(g, tok)) return res.status(403).json({ err: 'auth' });
      const tk = (await one(['KEYS', 't:' + id + ':*'])) || [];
      await R(['DEL', 'g:' + id], ...g.memberCodes.map(c => ['SREM', 'm:' + c, id]), ...tk.map(k => ['DEL', k]));
      return res.json({ ok: 1 });
    }

    return res.status(404).json({ err: 'unknown' });
  } catch (e) {
    return res.status(500).json({ err: 'server' });
  }
};
