// test/samples/vulnerable-auth.js
// Sample file with intentional vulnerabilities for testing Sentinel-VSC

// ❌ VULNERABLE: SQL Injection
async function loginUser(username, password) {
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  const [rows] = await db.query(query);
  return rows.length > 0 ? rows[0] : null;
}

// ❌ VULNERABLE: JWT not verified
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Unauthorized');
  const decoded = jwt.decode(token);  // BUG: should be jwt.verify()
  req.user = decoded;
  next();
}

// ❌ VULNERABLE: Hardcoded credentials
const config = {
  db: {
    host: 'prod-db.internal.example.com',
    password: 'SuperSecret123!',          // hardcoded password
  },
  stripe: {
    secretKey: 'REPLACE_WITH STRIPE_KEY',  // live key!
  },
  jwt: {
    secret: 'my-very-secret-jwt-key-do-not-share',
  }
};

// ❌ VULNERABLE: XSS
function renderUserComment(comment) {
  const container = document.getElementById('comments');
  container.innerHTML += comment.text;  // XSS: unsanitized
}

// ❌ VULNERABLE: Path traversal
async function downloadFile(req, res) {
  const filename = req.params.filename;
  const filePath = path.join('/uploads', filename);  // traversal: ../../etc/passwd
  res.sendFile(filePath);
}

// ❌ VULNERABLE: Command injection
const { exec } = require('child_process');
function processImage(req, res) {
  const filename = req.body.filename;
  exec(`convert ${filename} -resize 200x200 output.jpg`, (err, stdout) => {
    res.send(stdout);
  });
}
