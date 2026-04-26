// api/logout.js
export default function handler(req, res) {
  res.setHeader('Set-Cookie', 'usmp_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.redirect('/admin');
}
