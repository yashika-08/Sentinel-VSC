import { SecurityIssue } from '../utils/types';

interface SASTRule {
  id: string;
  name: string;
  description: string;
  pattern: RegExp;
  severity: 'critical' | 'warning' | 'info';
  owaspCategory: string;
  languages: string[];
  fix?: string;
  negativePattern?: RegExp; // if matched, skip this rule (reduce false positives)
}

const SAST_RULES: SASTRule[] = [
  // ── SQL Injection ────────────────────────────────────────────────────────
  {
    id: 'sqli-001',
    name: 'SQL Injection via String Concatenation',
    description: 'User input directly concatenated into SQL query string. Allows attacker to manipulate queries.',
    pattern: /(?:query|sql|statement)\s*[+=]\s*[`'"]\s*SELECT.*?\$\{|\+\s*(?:req\.|request\.|params\.|body\.|query\.)/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript'],
    fix: "Use parameterized queries: db.execute('SELECT * FROM t WHERE id = ?', [userInput])"
  },
  {
    id: 'sqli-002',
    name: 'SQL Injection via Template Literal',
    description: 'Template literal interpolation in SQL allows injection attacks.',
    pattern: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE).*?\$\{[^}]+\}/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript'],
    fix: "Replace with parameterized queries or an ORM like Prisma/Sequelize"
  },
  {
    id: 'sqli-003',
    name: 'SQL Injection — Python f-string',
    description: 'Python f-string interpolation in SQL cursor.execute() call.',
    pattern: /cursor\.execute\s*\(\s*f["']/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['python'],
    fix: "Use cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))"
  },

  // ── XSS ────────────────────────────────────────────────────────────────
  {
    id: 'xss-001',
    name: 'Cross-Site Scripting (XSS) — innerHTML',
    description: 'Assigning user-controlled data to innerHTML executes embedded scripts.',
    pattern: /\.innerHTML\s*[+]?=\s*(?!`[^$]*`)[^;'"`]+(?:req\.|params\.|body\.|user\.|comment\.|input\.)/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript'],
    fix: "Use DOMPurify.sanitize() or el.textContent for plain text"
  },
  {
    id: 'xss-002',
    name: 'Cross-Site Scripting — document.write',
    description: 'document.write() with user data enables XSS attacks.',
    pattern: /document\.write\s*\([^)]*(?:location|search|hash|referrer|\breq\b|\bparams\b)/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript'],
    fix: "Never use document.write() with user input. Use safe DOM APIs instead."
  },
  {
    id: 'xss-003',
    name: 'Unsafe URL in href/src',
    description: 'Unvalidated URL in href attribute can accept javascript: protocol.',
    pattern: /\.href\s*=\s*(?!['"`]https?:\/\/)[^;]+(?:params\.|req\.|user\.|comment\.)/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript'],
    fix: "Validate URL protocol: const url = new URL(input); if (!['http:','https:'].includes(url.protocol)) return;"
  },

  // ── Broken Authentication ───────────────────────────────────────────────
  {
    id: 'auth-001',
    name: 'JWT Signature Not Verified',
    description: 'jwt.decode() does NOT verify the signature. Use jwt.verify() instead.',
    pattern: /jwt\.decode\s*\(/gi,
    severity: 'critical',
    owaspCategory: 'A07',
    languages: ['javascript', 'typescript'],
    fix: "Use jwt.verify(token, secret, { algorithms: ['HS256'] }) — never jwt.decode()"
  },
  {
    id: 'auth-002',
    name: 'Weak JWT Algorithm',
    description: '"none" algorithm allows forged tokens without any signature.',
    pattern: /algorithms?\s*:\s*\[\s*['"]none['"]\s*\]/gi,
    severity: 'critical',
    owaspCategory: 'A07',
    languages: ['javascript', 'typescript', 'python'],
    fix: "Use algorithms: ['HS256'] or ['RS256'] — never 'none'"
  },
  {
    id: 'auth-003',
    name: 'Hardcoded Credentials in Code',
    description: 'Password or secret hardcoded directly in source — anyone with repo access has them.',
    pattern: /(?:password|passwd|pwd|secret|api_?key|auth_?token)\s*[=:]\s*['"`][^'"`\s]{6,}['"`]/gi,
    negativePattern: /process\.env\.|os\.environ|getenv|config\[/gi,
    severity: 'critical',
    owaspCategory: 'A02',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby'],
    fix: "Move to environment variable: process.env.SECRET_KEY or use a secrets manager"
  },
  {
    id: 'auth-004',
    name: 'MD5 / SHA1 Password Hashing',
    description: 'MD5 and SHA1 are cryptographically broken for password storage. Use bcrypt or argon2.',
    pattern: /(?:md5|sha1|sha-1)\s*\(/gi,
    severity: 'warning',
    owaspCategory: 'A02',
    languages: ['javascript', 'typescript', 'python', 'php'],
    fix: "Use bcrypt.hash(password, 12) or argon2.hash(password)"
  },

  // ── Path Traversal ─────────────────────────────────────────────────────
  {
    id: 'path-001',
    name: 'Path Traversal — Unsanitized File Path',
    description: 'User input passed to fs.readFile/writeFile without sanitization allows directory traversal.',
    pattern: /fs\.(?:readFile|writeFile|readFileSync|writeFileSync|unlink|rmdir)\s*\([^)]*(?:params\.|req\.|body\.|query\.)/gi,
    severity: 'critical',
    owaspCategory: 'A01',
    languages: ['javascript', 'typescript'],
    fix: "Use path.basename() and validate against an allowlist of safe directories"
  },

  // ── Command Injection ──────────────────────────────────────────────────
  {
    id: 'cmdi-001',
    name: 'Command Injection — exec() with User Input',
    description: 'User input passed to exec()/system() allows arbitrary command execution.',
    pattern: /(?:exec|execSync|spawn|system|popen)\s*\([^)]*(?:\$\{|\+\s*(?:req\.|params\.|body\.))/gi,
    severity: 'critical',
    owaspCategory: 'A03',
    languages: ['javascript', 'typescript', 'python'],
    fix: "Use execFile() with argument arrays, never pass user input to shell commands"
  },

  // ── Insecure Deserialization ────────────────────────────────────────────
  {
    id: 'deser-001',
    name: 'Unsafe Deserialization — eval()',
    description: 'eval() with user input executes arbitrary JavaScript code.',
    pattern: /eval\s*\([^)]*(?:req\.|params\.|body\.|user\.|input\.)/gi,
    severity: 'critical',
    owaspCategory: 'A08',
    languages: ['javascript', 'typescript'],
    fix: "Never use eval() with user data. Use JSON.parse() for data, or a safe expression evaluator."
  },
  {
    id: 'deser-002',
    name: 'Insecure pickle.loads()',
    description: 'pickle.loads() with untrusted data allows arbitrary code execution.',
    pattern: /pickle\.loads?\s*\(/gi,
    severity: 'critical',
    owaspCategory: 'A08',
    languages: ['python'],
    fix: "Use JSON or a safe serialization format. Never deserialize untrusted pickle data."
  },

  // ── Security Misconfiguration ──────────────────────────────────────────
  {
    id: 'misconfig-001',
    name: 'Debug Mode Enabled in Production',
    description: 'DEBUG=True or debug:true exposes stack traces and internal details.',
    pattern: /(?:DEBUG\s*=\s*True|debug\s*:\s*true|app\.run\s*\([^)]*debug\s*=\s*True)/gi,
    severity: 'warning',
    owaspCategory: 'A05',
    languages: ['javascript', 'typescript', 'python'],
    fix: "Set DEBUG=False in production. Use environment variables to control debug mode."
  },
  {
    id: 'misconfig-002',
    name: 'CORS Wildcard Origin',
    description: 'Access-Control-Allow-Origin: * allows any website to make credentialed requests.',
    pattern: /(?:Access-Control-Allow-Origin['"]\s*:\s*['"]?\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*)/gi,
    severity: 'warning',
    owaspCategory: 'A05',
    languages: ['javascript', 'typescript'],
    fix: "Restrict CORS to specific trusted origins: origin: ['https://yourdomain.com']"
  },
  {
    id: 'misconfig-003',
    name: 'Disabled SSL/TLS Verification',
    description: 'Disabling certificate verification allows man-in-the-middle attacks.',
    pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl_verify\s*=\s*False|insecure\s*:\s*true)/gi,
    severity: 'critical',
    owaspCategory: 'A05',
    languages: ['javascript', 'typescript', 'python'],
    fix: "Never disable TLS verification. Fix certificate issues properly."
  },

  // ── Sensitive Data Exposure ────────────────────────────────────────────
  {
    id: 'data-001',
    name: 'Sensitive Data in Console Log',
    description: 'Logging passwords, tokens, or PII to console may expose them in log files.',
    pattern: /console\.(?:log|info|warn|error)\s*\([^)]*(?:password|token|secret|ssn|credit.?card|cvv)/gi,
    severity: 'warning',
    owaspCategory: 'A09',
    languages: ['javascript', 'typescript'],
    fix: "Sanitize log output: console.log('[AUTH]', 'Login attempt for user:', username) — never log secrets."
  },

  // ── SSRF ───────────────────────────────────────────────────────────────
  {
    id: 'ssrf-001',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Making HTTP requests to user-controlled URLs allows internal network access.',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get|request\s*\()\s*\([^)]*(?:\$\{|\+\s*(?:req\.|params\.|body\.|user\.))/gi,
    severity: 'warning',
    owaspCategory: 'A10',
    languages: ['javascript', 'typescript'],
    fix: "Validate and allowlist URLs before making server-side requests. Block private IP ranges."
  },
];

export class SASTEngine {
  analyze(code: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = code.split('\n');

    const applicableRules = SAST_RULES.filter(rule =>
      rule.languages.includes(language) || rule.languages.includes('*')
    );

    for (const rule of applicableRules) {
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];

        // Skip commented lines
        if (this.isCommentLine(line, language)) continue;

        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(line);
        if (!match) continue;

        // Check negative pattern (reduces false positives)
        if (rule.negativePattern) {
          rule.negativePattern.lastIndex = 0;
          if (rule.negativePattern.test(line)) continue;
        }

        issues.push({
          id: `${rule.id}-L${lineIndex + 1}-${Date.now()}`,
          ruleId: rule.id,
          title: rule.name,
          description: rule.description,
          severity: rule.severity,
          owaspCategory: rule.owaspCategory,
          line: lineIndex + 1,
          column: match.index,
          matchedText: match[0].trim(),
          source: 'sast',
          fix: rule.fix
        });
      }
    }

    return issues;
  }

  private isCommentLine(line: string, language: string): boolean {
    const trimmed = line.trim();
    if (['javascript', 'typescript', 'java', 'go'].includes(language)) {
      return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*');
    }
    if (language === 'python' || language === 'ruby') {
      return trimmed.startsWith('#');
    }
    return false;
  }
}
