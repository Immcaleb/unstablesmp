// api/discord-callback.js
// Vercel serverless function — exchanges Discord OAuth code for user info,
// checks against the approved user ID list, and sets a session cookie.

const ALLOWED_IDS = ['849599398043844619', '964672784829648946'];

export default async function handler(req, res) {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send('Missing code');
  }

  const clientId = process.env.DISCORD_CLIENT_ID;
  const clientSecret = process.env.DISCORD_CLIENT_SECRET;
  const redirectUri = process.env.DISCORD_REDIRECT_URI;
  const sessionSecret = process.env.SESSION_SECRET;

  if (!clientId || !clientSecret || !redirectUri || !sessionSecret) {
    return res.status(500).send('Server misconfigured — check environment variables.');
  }

  try {
    // Exchange code for access token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
      }),
    });

    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      console.error('Token exchange failed:', err);
      return res.redirect('/admin?error=token_exchange_failed');
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // Fetch Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userRes.ok) {
      return res.redirect('/admin?error=user_fetch_failed');
    }

    const user = await userRes.json();

    // Check if user is allowed
    if (!ALLOWED_IDS.includes(user.id)) {
      return res.redirect('/admin?error=unauthorized');
    }

    // Build a simple signed session token: base64(payload).signature
    const payload = JSON.stringify({
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      exp: Date.now() + 1000 * 60 * 60 * 24, // 24h
    });
    const payloadB64 = Buffer.from(payload).toString('base64');

    // HMAC-SHA256 signature
    const encoder = new TextEncoder();
    const keyData = encoder.encode(sessionSecret);
    const msgData = encoder.encode(payloadB64);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

    const sessionToken = `${payloadB64}.${sigHex}`;

    // Set cookie and redirect to admin
    res.setHeader('Set-Cookie', `usmp_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
    return res.redirect('/admin');
  } catch (err) {
    console.error('Discord callback error:', err);
    return res.redirect('/admin?error=server_error');
  }
}
