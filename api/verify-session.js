// api/verify-session.js
// Called by admin.html on load to verify the session cookie is valid and unexpired.

const ALLOWED_IDS = ['849599398043844619', '964672784829648946'];

export default async function handler(req, res) {
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) return res.status(500).json({ ok: false, error: 'misconfigured' });

  const cookie = req.headers.cookie || '';
  const match = cookie.match(/usmp_session=([^;]+)/);
  if (!match) return res.status(401).json({ ok: false, error: 'no_session' });

  const [payloadB64, sigHex] = match[1].split('.');
  if (!payloadB64 || !sigHex) return res.status(401).json({ ok: false, error: 'malformed' });

  try {
    // Verify HMAC signature
    const encoder = new TextEncoder();
    const keyData = encoder.encode(sessionSecret);
    const msgData = encoder.encode(payloadB64);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const valid = await crypto.subtle.verify('HMAC', cryptoKey, sigBytes, msgData);

    if (!valid) return res.status(401).json({ ok: false, error: 'invalid_signature' });

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());

    // Check expiry
    if (Date.now() > payload.exp) return res.status(401).json({ ok: false, error: 'expired' });

    // Re-check allowed list (in case it changed)
    if (!ALLOWED_IDS.includes(payload.id)) return res.status(403).json({ ok: false, error: 'unauthorized' });

    return res.status(200).json({ ok: true, user: { id: payload.id, username: payload.username, avatar: payload.avatar } });
  } catch (err) {
    console.error('Verify session error:', err);
    return res.status(401).json({ ok: false, error: 'invalid' });
  }
}
