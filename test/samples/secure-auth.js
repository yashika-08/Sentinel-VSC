// test/samples/secure-auth.js
// ✅ Secure version — Sentinel should grade this A

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ✅ SECURE: Parameterized query
async function loginUser(username, password) {
  const [rows] = await db.execute(
    'SELECT id, username, email, password_hash FROM users WHERE username = ?',
    [username]  // parameterized — injection safe
  );
  if (rows.length === 0) return null;
  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  return match ? { id: user.id, username: user.username, email: user.email } : null;
}

// ✅ SECURE: JWT properly verified
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'myapp'
    });
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ✅ SECURE: Config from environment
const config = {
  db: {
    host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD,
  },
  stripe: {
    secretKey: process.env.STRIPE_SECRET_KEY,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiry: '24h'
  }
};

// ✅ SECURE: XSS-safe comment rendering
const DOMPurify = require('dompurify');

function renderUserComment(comment) {
  const container = document.getElementById('comments');
  const clean = DOMPurify.sanitize(comment.text, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
  const div = document.createElement('div');
  div.innerHTML = clean;
  container.appendChild(div);
}

// ✅ SECURE: Path traversal prevention
const path = require('path');

async function downloadFile(req, res) {
  const filename = path.basename(req.params.filename); // strip traversal
  const allowedDir = path.resolve('/uploads');
  const filePath = path.resolve(allowedDir, filename);
  if (!filePath.startsWith(allowedDir)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.sendFile(filePath);
}
