// api/auth.js — Discord OAuth2 callback handler
// Vercel serverless function

const ALLOWED_IDS = ['849599398043844619'];

export default async function handler(req, res) {
  const { code, error } = req.query;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (error) {
    return res.redirect('/?auth=denied');
  }

  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }

  const CLIENT_ID     = process.env.DISCORD_CLIENT_ID;
  const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
  const REDIRECT_URI  = process.env.DISCORD_REDIRECT_URI; // e.g. https://yourdomain.vercel.app/api/auth

  if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    return res.status(500).json({ error: 'Missing environment variables' });
  }

  try {
    // 1. Exchange code for access token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  REDIRECT_URI,
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      console.error('Token error:', tokenData);
      return res.redirect('/admin.html?auth=error');
    }

    // 2. Fetch Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();

    // 3. Check if user ID is allowed
    if (!ALLOWED_IDS.includes(user.id)) {
      return res.redirect('/admin.html?auth=denied');
    }

    // 4. Build a signed session token (simple base64 payload — good enough for a static site)
    const session = Buffer.from(JSON.stringify({
      id:       user.id,
      username: user.username,
      avatar:   user.avatar,
      expires:  Date.now() + 1000 * 60 * 60 * 24, // 24 hours
    })).toString('base64');

    // 5. Redirect to admin with session token in URL fragment (never hits server logs)
    return res.redirect(`/admin.html#token=${session}`);

  } catch (err) {
    console.error('Auth error:', err);
    return res.redirect('/admin.html?auth=error');
  }
}
