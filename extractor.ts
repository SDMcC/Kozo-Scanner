'use client'

import { unzipSync } from 'fflate'

// ---------- Types ----------

export interface FileEntry {
  path: string
  lines: number
  size: number
  ext: string
  isTest: boolean
}

export interface SecretFinding {
  file: string
  line: number
  type: string
  severity: 'critical' | 'high' | 'medium'
  preview: string // always redacted — value is never included
}

export interface Vitals {
  totalFiles: number
  totalLines: number
  totalSize: number
  avgFileLines: number
  maxDepth: number
  avgDepth: number
  testFileCount: number
  sourceFileCount: number
  testRatio: number
  depCount: number | null
  depNames: string[] // package names only — never values or lock file data
  hasExistingCursorRules: boolean
  hasExistingMdc: boolean
  hasEnvExample: boolean
  languageBreakdown: Record<string, { files: number; lines: number }>
  files: FileEntry[] // metadata only — paths, line counts, no content
  secretFindings: SecretFinding[] // redacted previews only — no raw values
  repoName: string
}

// ---------- Constants ----------

const EXT_LANG: Record<string, string> = {
  ts: 'TypeScript', tsx: 'TypeScript', js: 'JavaScript', jsx: 'JavaScript',
  py: 'Python', rb: 'Ruby', go: 'Go', rs: 'Rust', java: 'Java',
  cs: 'C#', cpp: 'C++', c: 'C', php: 'PHP', swift: 'Swift',
  kt: 'Kotlin', vue: 'Vue', svelte: 'Svelte', css: 'CSS', scss: 'CSS',
  html: 'HTML', json: 'JSON', md: 'Markdown', yaml: 'YAML', yml: 'YAML',
  toml: 'TOML', sh: 'Shell', bash: 'Shell',
}

const SOURCE_EXTS = new Set(['ts','tsx','js','jsx','py','rb','go','rs','java','cs','cpp','c','php','swift','kt','vue','svelte'])
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', '__pycache__', '.cache', 'coverage', '.turbo'])
const BINARY_EXTS = new Set(['png','jpg','jpeg','gif','ico','woff','woff2','ttf','otf','eot','mp4','webm','mp3','pdf','zip','gz','tar'])
const SKIP_SECRET_EXTS = new Set(['md', 'txt', 'lock', 'sum', 'png', 'jpg', 'svg', 'ico', 'woff', 'woff2'])
const SKIP_SECRET_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'])

// Placeholder emails and domains that are safe to use and should not trigger false positives
const PLACEHOLDER_PATTERNS = [
  /user@example\.com/i,
  /test@example\.com/i,
  /admin@example\.com/i,
  /demo@example\.com/i,
  /placeholder@example\.com/i,
  /noreply@example\.com/i,
  /contact@example\.com/i,
  /support@example\.com/i,
  /info@example\.com/i,
  /test@test\./i,
  /admin@localhost/i,
  /test@localhost/i,
  /@example\./i, // catch-all for any @example.* domain
]

// ---------- Secret patterns ----------
// IMPORTANT: patterns match on the line to detect the *presence* of a secret type.
// The preview is always redacted before being added to Vitals — raw values never leave the browser.

const SECRET_PATTERNS: Array<{ name: string; severity: 'critical' | 'high' | 'medium'; regex: RegExp }> = [
  { name: 'Ethereum Private Key',   severity: 'critical', regex: /\b(0x[a-fA-F0-9]{64})\b/ },
  { name: 'Bitcoin WIF Key',        severity: 'critical', regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/ },
  { name: 'AWS Access Key',         severity: 'critical', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS Secret Key',         severity: 'critical', regex: /aws[_\-.]?secret[_\-.]?access[_\-.]?key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i },
  { name: 'GCP Service Account',    severity: 'critical', regex: /"type"\s*:\s*"service_account"/ },
  { name: 'Azure Connection String',severity: 'critical', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/ },
  { name: 'GitHub Token',           severity: 'critical', regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Stripe Secret Key',      severity: 'critical', regex: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/ },
  { name: 'OpenAI API Key',         severity: 'critical', regex: /\bsk-[A-Za-z0-9]{32,}\b/ },
  { name: 'Anthropic API Key',      severity: 'critical', regex: /\bsk-ant-[A-Za-z0-9\-_]{32,}\b/ },
  { name: 'Private Key Block',      severity: 'critical', regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'Stripe Publishable Key', severity: 'medium',   regex: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/ },
  { name: 'Slack Bot Token',        severity: 'high',     regex: /\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/ },
  { name: 'Slack Webhook',          severity: 'high',     regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/ },
  { name: 'Twilio Account SID',     severity: 'high',     regex: /\bAC[a-f0-9]{32}\b/ },
  { name: 'Sendgrid API Key',       severity: 'high',     regex: /\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b/ },
  { name: 'Hardcoded Password',     severity: 'high',     regex: /\b(password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}['"]/i },
  { name: 'Hardcoded Secret',       severity: 'high',     regex: /\b(secret|secret_key|api_secret)\s*[=:]\s*['"][^'"]{8,}['"]/i },
  { name: 'JWT Token',              severity: 'medium',   regex: /\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/ },
  { name: 'Email Address (hardcoded)', severity: 'medium', regex: /['"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['"]/ },
  { name: 'IP Address (hardcoded)', severity: 'medium',   regex: /['"](\d{1,3}\.){3}\d{1,3}['"]/ },
]

// Max line length to scan — prevents ReDoS on minified files with 50k+ char single lines
const MAX_LINE_LENGTH = 1000

function scanLineForSecrets(filePath: string, lines: string[]): SecretFinding[] {
  const filename = filePath.split('/').pop() ?? ''
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  if (SKIP_SECRET_EXTS.has(ext) || SKIP_SECRET_FILES.has(filename)) return []
  if (filename.includes('.example') || filename.includes('.sample')) return []

  const isEnvFile = filename.startsWith('.env') || filename.includes('.env.')
  const findings: SecretFinding[] = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // Skip very long lines (minified JS/CSS) to prevent regex catastrophic backtracking
    if (line.length > MAX_LINE_LENGTH) continue

    if (/^\s*(\/\/|#|\/\*)/.test(line) && !isEnvFile) continue

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.severity === 'medium' && !isEnvFile && !line.toLowerCase().includes('=')) continue
      if (pattern.regex.test(line)) {
        // Special handling for email addresses: skip if it matches a placeholder pattern
        if (pattern.name === 'Email Address (hardcoded)') {
          if (PLACEHOLDER_PATTERNS.some(p => p.test(line))) continue
        }

        // Redact: replace any quoted string 6+ chars with [REDACTED] before storing
        const redacted = line.trim().slice(0, 80)
          .replace(/['"][^'"]{6,}['"]/g, '"[REDACTED]"')
          .replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA[REDACTED]')
          .replace(/\bsk[-_][A-Za-z0-9\-_]{8,}/g, 'sk-[REDACTED]')
          .replace(/\bgh[pousr]_[A-Za-z0-9]{6,}/g, 'gh_[REDACTED]')
        findings.push({ file: filePath, line: i + 1, type: pattern.name, severity: pattern.severity, preview: redacted })
        break
      }
    }
  }
  return findings
}

// ---------- Main extractor ----------

export async function extractVitals(file: File): Promise<Vitals> {
  const arrayBuffer = await file.arrayBuffer()
  const uint8 = new Uint8Array(arrayBuffer)

  // All decompression happens in-browser. The raw content is read, analysed,
  // and then discarded. Only the derived metadata (Vitals) is returned.
  const decompressed = unzipSync(uint8)

  const files: FileEntry[] = []
  const secretFindings: SecretFinding[] = []
  const allFilePaths: string[] = []
  let depCount: number | null = null
  let depNames: string[] = []
  let hasExistingCursorRules = false
  let hasExistingMdc = false
  const langBreakdown: Record<string, { files: number; lines: number }> = {}

  for (const [filePath, content] of Object.entries(decompressed)) {
    // Skip directory entries and system dirs
    if (filePath.endsWith('/')) continue
    const pathParts = filePath.split('/')
    if (pathParts.some(p => SKIP_DIRS.has(p))) continue

    const filename = pathParts[pathParts.length - 1]
    if (!filename) continue
    const ext = filename.includes('.') ? filename.split('.').pop()!.toLowerCase() : ''

    allFilePaths.push(filePath)

    if (filename === '.cursorrules') hasExistingCursorRules = true
    if (ext === 'mdc') hasExistingMdc = true

    // Parse package.json for dep count (metadata only — we read dep keys, not values)
    if (filename === 'package.json' && depCount === null) {
      try {
        const pkg = JSON.parse(new TextDecoder().decode(content))
        const allDeps = [
          ...Object.keys(pkg.dependencies ?? {}),
          ...Object.keys(pkg.devDependencies ?? {}),
        ]
        depCount = allDeps.length
        // Store package names only — never versions or resolved URLs
        depNames = allDeps
      } catch { /* skip malformed */ }
    }

    // Skip known binaries
    if (BINARY_EXTS.has(ext) || content.length > 500_000) continue

    // Decode text — skip non-UTF8 binary files silently
    let text: string
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(content)
    } catch {
      continue
    }

    const lines = text.split('\n')

    // Secret scan — preview is redacted before storing, raw text is never sent
    const findings = scanLineForSecrets(filePath, lines)
    secretFindings.push(...findings)

    // Source file metrics
    const isMeasurable = SOURCE_EXTS.has(ext) || ['css','scss','html','vue','svelte'].includes(ext)
    if (!isMeasurable) continue

    const lang = EXT_LANG[ext] ?? 'Other'
    if (!langBreakdown[lang]) langBreakdown[lang] = { files: 0, lines: 0 }
    langBreakdown[lang].files++
    langBreakdown[lang].lines += lines.length

    files.push({
      path: filePath,
      lines: lines.length,
      size: content.length,
      ext,
      isTest: /\.(test|spec)\.[jt]sx?$/.test(filename) || pathParts.some(p => ['__tests__','tests','test','spec'].includes(p)),
    })

    // text is a local variable — it goes out of scope here and is GC'd.
    // It is never assigned to any object that leaves this function.
  }

  const hasEnvExample = allFilePaths.some(p => {
    const f = p.split('/').pop() ?? ''
    return ['.env.example', '.env.sample', '.env.template'].includes(f)
  })

  const sourceFiles = files.filter(f => SOURCE_EXTS.has(f.ext))
  const testFiles = files.filter(f => f.isTest)
  const depths = files.map(f => f.path.split('/').length - 1)
  const maxDepth = depths.length ? Math.max(...depths) : 0
  const avgDepth = depths.length ? depths.reduce((a, b) => a + b, 0) / depths.length : 0
  const totalLines = files.reduce((a, f) => a + f.lines, 0)

  return {
    totalFiles: files.length,
    totalLines,
    totalSize: files.reduce((a, f) => a + f.size, 0),
    avgFileLines: files.length ? Math.round(totalLines / files.length) : 0,
    maxDepth,
    avgDepth: Math.round(avgDepth * 10) / 10,
    testFileCount: testFiles.length,
    sourceFileCount: sourceFiles.length,
    testRatio: sourceFiles.length ? testFiles.length / sourceFiles.length : 0,
    depCount,
    depNames,
    hasExistingCursorRules,
    hasExistingMdc,
    hasEnvExample,
    languageBreakdown: langBreakdown,
    files, // paths + line counts only — no content
    secretFindings, // type + severity + file path + line number + redacted preview only
    repoName: file.name.replace(/\.zip$/i, ''),
  }
}
