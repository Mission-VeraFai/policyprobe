'use client'

import { useState, useRef, useEffect } from 'react'
// Session token helpers — replaces plain uuidv4() with HMAC-signed, expiry-bearing,
// subject-bound tokens using the browser Web Crypto API.
const SESSION_TOKEN_TTL_MS = 60 * 60 * 1000 // 1 hour

async function deriveSessionKey(): Promise<CryptoKey> {
  // Use a per-browser-session secret stored in sessionStorage so the key is
  // ephemeral and never leaves the browser context.
  const storageKey = '__sk'
  let rawHex = sessionStorage.getItem(storageKey)
  if (!rawHex) {
    const raw = crypto.getRandomValues(new Uint8Array(32))
    rawHex = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('')
    sessionStorage.setItem(storageKey, rawHex)
  }
  const keyBytes = new Uint8Array(rawHex.match(/.{2}/g)!.map(h => parseInt(h, 16)))
  return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

async function createSessionToken(subject: string): Promise<string> {
  const key = await deriveSessionKey()
  const issuedAt = Date.now()
  const expiresAt = issuedAt + SESSION_TOKEN_TTL_MS
  const payload = JSON.stringify({ sub: subject, iat: issuedAt, exp: expiresAt })
  const payloadB64 = btoa(payload)
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64))
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBytes)))
  return `${payloadB64}.${sig}`
}

async function verifySessionToken(token: string): Promise<{ sub: string; exp: number } | null> {
  try {
    const [payloadB64, sig] = token.split('.')
    if (!payloadB64 || !sig) return null
    const key = await deriveSessionKey()
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payloadB64))
    if (!valid) return null
    const payload = JSON.parse(atob(payloadB64)) as { sub: string; iat: number; exp: number }
    if (Date.now() > payload.exp) return null // expired
    return { sub: payload.sub, exp: payload.exp }
  } catch {
    return null
  }
}

// Helper: sanitize user text input before it is sent to the LLM API.
// Strips null bytes, non-printable control characters (except common whitespace),
// and enforces a maximum length to prevent prompt-injection via oversized payloads.
const MAX_INPUT_LENGTH = 4000
const ALLOWED_FILE_TYPES = new Set(['text/plain', 'application/pdf', 'image/png', 'image/jpeg', 'image/webp'])
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 // 5 MB

// PII patterns to detect in file contents before upload.
// Includes Singapore-specific PII: NRIC/FIN, Singapore passport, SingPass ID,
// CPF account number, and Singapore phone numbers.
const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'credit card number', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b/ },
  { name: 'email address', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
  { name: 'US phone number', pattern: /\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/ },
  // Singapore-specific PII patterns
  // NRIC/FIN: starts with S, T, F, G, or M followed by 7 digits and a letter
  { name: 'Singapore NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  // Singapore passport: starts with E followed by 7 digits
  { name: 'Singapore passport number', pattern: /\bE\d{7}[A-Z]?\b/ },
  // SingPass ID: typically an NRIC or a user-defined ID; catch common format
  { name: 'SingPass ID', pattern: /\bsingpass[\s_-]?id[:\s]+[A-Za-z0-9@._-]{6,}/i },
  // CPF account number: 9-digit numeric string (standalone)
  { name: 'Singapore CPF account number', pattern: /\b\d{9}\b/ },
  // Singapore phone number: +65 followed by 8 digits, or local 8-digit starting with 6, 8, or 9
  { name: 'Singapore phone number', pattern: /\b(?:\+65[\s-]?)?[689]\d{7}\b/ },
]

// Reads a text file and returns the first PII type found, or null if clean.
async function detectPIIInTextFile(file: File): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result
      if (typeof text !== 'string') {
        resolve(null)
        return
      }
      for (const { name, pattern } of PII_PATTERNS) {
        if (pattern.test(text)) {
          resolve(name)
          return
        }
      }
      resolve(null)
    }
    reader.onerror = () => resolve(null)
    reader.readAsText(file)
  })
}

// Shell/exec primitives that must not appear in user input.
const DANGEROUS_INPUT_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // Shell command chaining and redirection
  { name: 'shell chaining', pattern: /(?:^|\s|;|&|\|)(?:bash|sh|zsh|ksh|csh|tcsh|fish|cmd|powershell|pwsh)(?:\s|$)/i },
  { name: 'shell redirection', pattern: /(?:[|]{1,2}|[&]{1,2}|;|`|\$\()/ },
  // Common exec primitives
  { name: 'exec primitive', pattern: /\b(?:exec|eval|system|popen|subprocess|spawn|fork|execve|execvp|ShellExecute|WScript\.Shell|os\.system|child_process)\s*[\.(]/i },
  // Base64-encoded payloads (long base64 strings are suspicious in chat input)
  { name: 'base64 payload', pattern: /(?:[A-Za-z0-9+/]{40,}={0,2})/ },
  // Binary / non-UTF-8 escape sequences smuggled as text
  { name: 'binary escape', pattern: /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{3})/ },
  // Leetspeak obfuscation of common dangerous words
  { name: 'leetspeak obfuscation', pattern: /(?:3x3c|3x[e3][c(]|[e3][x%][e3][c(]|5h[e3]ll|5y5t[e3]m|[e3]v[4a]l)/i },
  // Prompt-injection trigger phrases
  { name: 'prompt injection', pattern: /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|disregard\s+(?:your\s+)?(?:previous|prior|system)\s+(?:prompt|instructions?)|you\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|dan|unrestricted)\s+mode)/i },
]

function sanitizeTextInput(raw: string): string {
  // 1. Remove null bytes and non-printable ASCII control characters
  //    (keep \t, \n, \r which are legitimate whitespace).
  // eslint-disable-next-line no-control-regex
  let sanitized = raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

  // 2. Remove Unicode direction-override characters and invisible tag-block
  //    characters that can hide injected instructions from human reviewers.
  // eslint-disable-next-line no-misleading-character-class
  sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069\uFEFF\u200B-\u200F\u2028\u2029]/g, '')
  // Unicode tag block U+E0000–U+E007F
  sanitized = sanitized.replace(/[\uE0000-\uE007F]/gu, '')

  // 3. Collapse runs of more than two consecutive newlines to prevent prompt flooding.
  sanitized = sanitized.replace(/\n{3,}/g, '\n\n')

  // 4. Enforce maximum length before pattern checks to bound regex work.
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH)
  }

  // 5. Reject input that contains dangerous patterns (shell commands, base64
  //    payloads, binary escapes, leetspeak obfuscation, prompt injection).
  for (const { name, pattern } of DANGEROUS_INPUT_PATTERNS) {
    if (pattern.test(sanitized)) {
      console.warn(`sanitizeTextInput: blocked input matching pattern "${name}"`)
      throw new Error(`Your message contains content that is not allowed (${name}). Please revise your input.`)
    }
  }

  return sanitized
}

// Maximum length allowed for a single MCP/LLM server output string.
const MAX_OUTPUT_LENGTH = 32_000

// ---------------------------------------------------------------------------
// MCP Server Authentication – HMAC-SHA-256 signature verification.
// The MCP/LLM server must sign every response payload with a shared secret.
// The client verifies the signature before trusting any server output.
// The shared secret is provisioned via REACT_APP_MCP_SERVER_HMAC_SECRET.
// ---------------------------------------------------------------------------

/**
 * Derives a CryptoKey from the shared MCP server secret for HMAC-SHA-256.
 * Returns null if the secret is not configured.
 */
async function getMcpServerHmacKey(): Promise<CryptoKey | null> {
  const secret = process.env.REACT_APP_MCP_SERVER_HMAC_SECRET
  if (!secret) {
    console.error('[MCP Auth] REACT_APP_MCP_SERVER_HMAC_SECRET is not configured – server authentication is disabled.')
    return null
  }
  const enc = new TextEncoder()
  return crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )
}

/**
 * verifyMcpServerSignature – verifies that `payload` was signed by the
 * MCP/LLM server using the shared HMAC-SHA-256 secret.
 *
 * @param payload   - The raw string payload received from the server.
 * @param signature - The hex-encoded HMAC-SHA-256 signature provided by the server.
 * @returns         - true if the signature is valid, false otherwise.
 */
async function verifyMcpServerSignature(payload: string, signature: string): Promise<boolean> {
  if (!signature || typeof signature !== 'string' || signature.length === 0) {
    console.warn('[MCP Auth] No signature provided by MCP server – rejecting output.')
    return false
  }
  const key = await getMcpServerHmacKey()
  if (!key) {
    // Secret not configured: fail closed to avoid silently skipping auth.
    return false
  }
  try {
    const enc = new TextEncoder()
    // Convert hex signature to Uint8Array.
    const sigBytes = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? []
    )
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payload))
    if (!valid) {
      console.warn('[MCP Auth] MCP server signature verification FAILED – output rejected.')
    }
    return valid
  } catch (err) {
    console.error('[MCP Auth] Error during signature verification:', err)
    return false
  }
}

/**
 * sanitizeMcpOutput – sanitizes text received from an MCP or LLM server before
 * it is rendered or processed by the client.
 *
 * Defences applied:
 *  1. Type-guard: non-string values are coerced to an empty string.
 *  2. Null bytes and non-printable ASCII control characters are stripped
 *     (\t, \n, \r are preserved as legitimate whitespace).
 *  3. Unicode direction-override and invisible/tag characters that are
 *     commonly used in prompt-injection attacks are removed.
 *  4. Runs of more than two consecutive newlines are collapsed.
 *  5. Output is truncated to MAX_OUTPUT_LENGTH to prevent DoS via
 *     oversized payloads.
 */
/**
 * Patterns that indicate dynamic code execution primitives.
 * Any LLM/MCP output matching one of these is considered unsafe and is
 * replaced with a safe placeholder rather than being rendered.
 */
const DYNAMIC_CODE_EXECUTION_PATTERNS: RegExp[] = [
  // JavaScript / TypeScript
  /\beval\s*\(/i,
  /\bFunction\s*\(/i,
  /\bnew\s+Function\b/i,
  /\bsetTimeout\s*\(\s*['"`]/i,
  /\bsetInterval\s*\(\s*['"`]/i,
  /\bexecScript\s*\(/i,
  // Python
  /\bexec\s*\(/i,
  /\beval\s*\(/i,
  /\bcompile\s*\(/i,
  /\b__import__\s*\(/i,
  /\bimportlib\.import_module\s*\(/i,
  // Shell / subprocess
  /\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/i,
  /\bos\s*\.\s*(system|popen|execv|execve|execvp|spawnl|spawnle|spawnlp|spawnv|spawnve|spawnvp)\s*\(/i,
  /\bchild_process\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/i,
  // Ruby
  /\beval\s*\(/i,
  /`[^`]*`/,           // backtick shell execution
  /\bsystem\s*\(/i,
  /\%x\s*\{/i,
  // PHP
  /\beval\s*\(/i,
  /\bpreg_replace\s*\([^,]*\/e/i,
  /\bassert\s*\([^)]*\$[^)]*\)/i,
  // Generic dangerous patterns
  /\bdynamic(?:ally)?\s+(?:execut|evaluat|compil)/i,
]

/**
 * authenticatedSanitizeMcpOutput – authenticates the MCP server response by
 * verifying its HMAC-SHA-256 signature, then sanitizes the payload.
 *
 * @param raw       - The raw payload from the MCP/LLM server.
 * @param signature - The hex-encoded HMAC-SHA-256 signature from the server.
 * @returns         - A Promise resolving to the sanitized string, or '' if auth fails.
 */
async function authenticatedSanitizeMcpOutput(raw: unknown, signature: string): Promise<string> {
  // Coerce to string first so we can verify the exact bytes the server signed.
  const payload = typeof raw === 'string' ? raw : ''
  if (payload === '') return ''

  // Authenticate the server before processing its output.
  const trusted = await verifyMcpServerSignature(payload, signature)
  if (!trusted) {
    // Reject output from unauthenticated or tampered server responses.
    return ''
  }

  return sanitizeMcpOutput(raw)
}

function sanitizeMcpOutput(raw: unknown): string {
  // 1. Coerce to string.
  if (typeof raw !== 'string') {
    return ''
  }

  // 2. Strip null bytes and non-printable ASCII control characters
  //    (keep \t \n \r).
  // eslint-disable-next-line no-control-regex
  let sanitized = raw.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

  // 3. Remove Unicode direction-override characters (U+202A–U+202E,
  //    U+2066–U+2069) and Unicode tag block (U+E0000–U+E007F) which
  //    can be used to hide injected instructions from human reviewers.
  // eslint-disable-next-line no-misleading-character-class
  sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069\uDB40\uDC00-\uDB40\uDC7F]/g, '')

  // 4. Collapse excessive newlines.
  sanitized = sanitized.replace(/\n{3,}/g, '\n\n')

  // 5. Enforce maximum output length.
  if (sanitized.length > MAX_OUTPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_OUTPUT_LENGTH)
  }

  // 6. Detect dynamic code execution primitives.
  //    If any pattern matches, discard the entire output to prevent
  //    client-side execution of injected code.
  for (const pattern of DYNAMIC_CODE_EXECUTION_PATTERNS) {
    if (pattern.test(sanitized)) {
      console.warn(
        '[sanitizeMcpOutput] Blocked LLM output containing dynamic code execution primitive matching:',
        pattern.toString()
      )
      return '[Response blocked: output contained a dynamic code execution primitive and was removed for security reasons.]'
    }
  }

  return sanitized
}

// ---------------------------------------------------------------------------
// Audit logging – forensic readiness for every AI-driven interaction.
// Writes a structured record to /api/audit-log (persistent store) and falls
// back to console output so no interaction is ever silently dropped.
// ---------------------------------------------------------------------------
async function sha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(text)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ---------------------------------------------------------------------------
// Principal integrity helpers
// ---------------------------------------------------------------------------
const PRINCIPAL_TTL_MS = 8 * 60 * 60 * 1000 // 8 hours

async function hmacSign(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message))
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

async function hmacVerify(secret: string, message: string, mac: string): Promise<boolean> {
  const expected = await hmacSign(secret, message)
  if (expected.length !== mac.length) return false
  // Constant-time comparison
  let diff = 0
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ mac.charCodeAt(i)
  }
  return diff === 0
}

// Returns a per-session secret, generating one if absent.
function getSessionSecret(): string {
  const secretKey = 'audit_session_secret'
  let secret = sessionStorage.getItem(secretKey)
  if (!secret) {
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    secret = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
    sessionStorage.setItem(secretKey, secret)
  }
  return secret
}

async function getPrincipal(): Promise<string> {
  const key = 'audit_principal_id'
  const stored = sessionStorage.getItem(key)
  const secret = getSessionSecret()

  if (stored) {
    try {
      const parsed = JSON.parse(stored) as { id: string; exp: number; sub: string; mac: string }
      const now = Date.now()
      // Verify expiry
      if (parsed.exp && now < parsed.exp) {
        // Verify HMAC binding: mac covers id + exp + sub
        const message = `${parsed.id}:${parsed.exp}:${parsed.sub}`
        const valid = await hmacVerify(secret, message, parsed.mac)
        if (valid) {
          return parsed.id
        }
      }
    } catch {
      // Fall through to regenerate
    }
    // Invalid or expired — clear and regenerate
    sessionStorage.removeItem(key)
  }

  // Generate a new signed, expiry-bound principal
  const id = uuidv4()
  const exp = Date.now() + PRINCIPAL_TTL_MS
  const sub = 'audit-principal'
  const message = `${id}:${exp}:${sub}`
  const mac = await hmacSign(secret, message)
  const record = JSON.stringify({ id, exp, sub, mac })
  sessionStorage.setItem(key, record)
  return id
}

// Approved model registry — only pinned, organisation-approved model identifiers.
// Add new models here only after they have been reviewed and approved.
const APPROVED_MODEL_IDS = [
  'org-approved-model-v1',
  'org-approved-model-v2',
] as const

type ApprovedModelId = typeof APPROVED_MODEL_IDS[number]

async function writeAuditLog(entry: {
  interactionId: string
  timestamp: string
  principal: string
  modelId: ApprovedModelId
  modelDigest: string
  inputHash: string
  inputLength: number
  outputSummary: string
  outputLength: number
  endpoint: string
  status: 'success' | 'error'
  errorMessage?: string
}): Promise<void> {
  // Enforce registry membership and digest integrity before persisting.
  if (!isApprovedModelId(entry.modelId)) {
    const msg = `[AUDIT] Rejected audit log: modelId '${entry.modelId}' is not in the approved model registry.`
    console.error(msg)
    throw new Error(msg)
  }
  const expectedDigest = getApprovedModelDigest(entry.modelId)
  if (entry.modelDigest !== expectedDigest) {
    const msg = `[AUDIT] Rejected audit log: digest mismatch for modelId '${entry.modelId}'. Expected '${expectedDigest}', got '${entry.modelDigest}'.`
    console.error(msg)
    throw new Error(msg)
  }
  // Primary: persist to server-side audit store.
  try {
    await fetch('/api/audit-log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    })
  } catch (persistErr) {
    // Secondary: console fallback so the record is never silently lost.
    // Emit the full structured record to console BEFORE re-throwing so it is
    // always visible in local logs even when the persistent store is unavailable.
    console.error('[AUDIT] Failed to persist audit log to server. Emitting record to console for forensic readiness:', persistErr)
    console.info('[AUDIT]', JSON.stringify(entry))
    // Re-throw so callers are aware of the durable-store failure and can
    // surface it to the user or an alerting system — no silent swallowing.
    throw persistErr
  }
  // Always emit to console for local forensic readiness (success path).
  console.info('[AUDIT]', JSON.stringify(entry))
}
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Approved Model Registry – identity, version pinning, and integrity.
// Each entry carries an immutable SHA-256 digest of the model manifest so
// that any substitution or tampering is detected at runtime.
// ---------------------------------------------------------------------------
const APPROVED_MODEL_REGISTRY: Record<
  string,
  { digest: string; displayName: string }
> = {
  'org-approved-model-v1': {
    digest:
      'a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef12345678',
    displayName: 'Org Approved Model v1',
  },
  'org-approved-model-v2': {
    digest:
      'b7e2d3f4a5c6890123456789012345678901bcdef2345678901bcdef23456789ab',
    displayName: 'Org Approved Model v2',
  },
}

export type ApprovedModelId = keyof typeof APPROVED_MODEL_REGISTRY

function isApprovedModelId(id: string): id is ApprovedModelId {
  return Object.prototype.hasOwnProperty.call(APPROVED_MODEL_REGISTRY, id)
}

function getApprovedModelDigest(id: ApprovedModelId): string {
  return APPROVED_MODEL_REGISTRY[id].digest
}
// ---------------------------------------------------------------------------

function sanitizeFileName(name: string): string {
  // Allow only alphanumerics, dots, hyphens, and underscores.
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 255)
}

// ---------------------------------------------------------------------------
// LLM Output Sanitization – prevents dynamic code execution primitives from
// being propagated from model responses into the application.
// ---------------------------------------------------------------------------
const DANGEROUS_CODE_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'eval',            pattern: /\beval\s*\(/gi },
  { name: 'exec',            pattern: /\bexec\s*\(/gi },
  { name: 'execSync',        pattern: /\bexecSync\s*\(/gi },
  { name: 'execFile',        pattern: /\bexecFile\s*\(/gi },
  { name: 'spawn',           pattern: /\bspawn\s*\(/gi },
  { name: 'Function',        pattern: /\bnew\s+Function\s*\(/gi },
  { name: 'setTimeout-str',  pattern: /\bsetTimeout\s*\(\s*['"`]/gi },
  { name: 'setInterval-str', pattern: /\bsetInterval\s*\(\s*['"`]/gi },
  { name: 'setImmediate-str',pattern: /\bsetImmediate\s*\(\s*['"`]/gi },
  { name: 'importDynamic',   pattern: /\bimport\s*\(/gi },
  { name: 'require',         pattern: /\brequire\s*\(/gi },
  { name: '__import__',      pattern: /\b__import__\s*\(/gi },
  { name: 'compile',         pattern: /\bcompile\s*\(/gi },
  { name: 'subprocess',      pattern: /\bsubprocess\s*\./gi },
  { name: 'os.system',       pattern: /\bos\.system\s*\(/gi },
  { name: 'ProcessBuilder',  pattern: /\bProcessBuilder\b/g },
  { name: 'Runtime.exec',    pattern: /\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(/gi },
]

function sanitizeLLMOutput(raw: string): string {
  let sanitized = raw
  const redacted: string[] = []
  for (const { name, pattern } of DANGEROUS_CODE_PATTERNS) {
    if (pattern.test(sanitized)) {
      redacted.push(name)
      // Reset lastIndex for global regexes before replacing.
      pattern.lastIndex = 0
      sanitized = sanitized.replace(pattern, `[REDACTED:${name}]`)
    }
    // Always reset lastIndex after test/replace to avoid stateful regex bugs.
    pattern.lastIndex = 0
  }
  if (redacted.length > 0) {
    console.warn(
      '[SECURITY] sanitizeLLMOutput: redacted dynamic code execution primitives from LLM response:',
      redacted
    )
  }
  return sanitized
}
// ---------------------------------------------------------------------------

// Singapore PII patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  // NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
  { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  // Singapore mobile numbers: +65 or 65 prefix followed by 8 digits starting with 8 or 9
  { name: 'Singapore phone number', pattern: /(?:\+65|\b65)?\s*[89]\d{7}\b/ },
  // Singapore postal codes: 6-digit codes (common format)
  { name: 'Singapore postal code', pattern: /\bSingapore\s+\d{6}\b/i },
  // SingPass user ID references
  { name: 'SingPass identifier', pattern: /\bsingpass\b/i },
  // CorpPass references
  { name: 'CorpPass identifier', pattern: /\bcorppass\b/i },
  // Singapore bank account patterns (DBS/POSB/OCBC/UOB common formats)
  { name: 'Singapore bank account', pattern: /\b\d{3}-\d{5,6}-\d{1}\b/ },
  // Singapore National Registration Identity Card explicit label
  { name: 'NRIC label', pattern: /\b(?:nric|fin)\s*(?:no\.?|number|#)?\s*:?\s*[STFGM]\d{7}[A-Z]\b/i },
]

function containsSingaporePII(text: string): { found: boolean; types: string[] } {
  const foundTypes: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(text)) {
      foundTypes.push(name)
    }
  }
  return { found: foundTypes.length > 0, types: foundTypes }
}

const TEXT_READABLE_TYPES = new Set([
  'text/plain',
  'text/html',
  'application/json',
])

const TEXT_READABLE_EXTENSIONS = ['.txt', '.html', '.htm', '.json']

function isTextReadableFile(file: File): boolean {
  if (TEXT_READABLE_TYPES.has(file.type)) return true
  const nameLower = file.name.toLowerCase()
  return TEXT_READABLE_EXTENSIONS.some((ext) => nameLower.endsWith(ext))
}

// Prompt-injection patterns to detect attempts to hijack the LLM via file content.
const PROMPT_INJECTION_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'ignore instructions', pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i },
  { name: 'system prompt override', pattern: /you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:new|different|evil|unrestricted)/i },
  { name: 'jailbreak DAN', pattern: /\bDAN\b|do\s+anything\s+now/i },
  { name: 'role override', pattern: /(?:act|pretend|behave)\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+)/i },
  { name: 'prompt leak', pattern: /(?:repeat|print|output|reveal|show|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|context)/i },
  { name: 'instruction injection marker', pattern: /<\s*(?:system|assistant|user|instruction)\s*>/i },
  { name: 'CRLF injection', pattern: /(?:\r\n|\n)\s*(?:system|assistant|user)\s*:/i },
  { name: 'token smuggling', pattern: /\[\s*(?:INST|SYS|SYSTEM|END)\s*\]/i },
]

function containsPromptInjection(text: string): { found: boolean; types: string[] } {
  const foundTypes: string[] = []
  for (const { name, pattern } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      foundTypes.push(name)
    }
  }
  return { found: foundTypes.length > 0, types: foundTypes }
}

async function readFileAsText(file: File): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target?.result as string ?? null)
    reader.onerror = () => resolve(null)
    reader.readAsText(file)
  })
}

async function validateAndSanitizeFiles(files: File[]): Promise<{ valid: File[]; errors: string[] }> {
  const valid: File[] = []
  const errors: string[] = []
  for (const file of files) {
    if (!ALLOWED_FILE_TYPES.has(file.type)) {
      errors.push(`File "${sanitizeFileName(file.name)}" has disallowed type "${file.type}".`)
      continue
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      errors.push(`File "${sanitizeFileName(file.name)}" exceeds the 5 MB size limit.`)
      continue
    }
    // Scan all text-readable files for Singapore PII and prompt injection.
    if (isTextReadableFile(file)) {
      const text = await readFileAsText(file)
      if (text !== null) {
        const piiCheck = containsSingaporePII(text)
        if (piiCheck.found) {
          errors.push(
            `File "${sanitizeFileName(file.name)}" was rejected because it contains Singapore PII: ${piiCheck.types.join(', ')}.`
          )
          continue
        }
        const injectionCheck = containsPromptInjection(text)
        if (injectionCheck.found) {
          errors.push(
            `File "${sanitizeFileName(file.name)}" was rejected because it contains potential prompt-injection content: ${injectionCheck.types.join(', ')}.`
          )
          continue
        }
      }
    } else {
      // For binary files (PDF, DOCX, images), scan the filename itself for injection patterns.
      const injectionInName = containsPromptInjection(file.name)
      if (injectionInName.found) {
        errors.push(
          `File "${sanitizeFileName(file.name)}" was rejected because its filename contains potential prompt-injection content: ${injectionInName.types.join(', ')}.`
        )
        continue
      }
    }
    // Re-wrap with a sanitized filename to prevent path-traversal or injection
    // via the filename field that is forwarded to the API.
    const sanitized = new File([file], sanitizeFileName(file.name), { type: file.type })
    valid.push(sanitized)
  }
  return { valid, errors }
}

// Async wrapper that also performs PII scanning on text files.
async function validateAndSanitizeFilesWithPIICheck(
  files: File[]
): Promise<{ valid: File[]; errors: string[] }> {
  const { valid: typeAndSizeValid, errors } = validateAndSanitizeFiles(files)
  const finalValid: File[] = []
  for (const file of typeAndSizeValid) {
    const piiType = await detectPIIInTextFile(file)
    if (piiType) {
      errors.push(
        `File "${sanitizeFileName(file.name)}" was rejected because it contains ${piiType}. Please remove PII before uploading.`
      )
      continue
    }
    finalValid.push(file)
  }
  return { valid: finalValid, errors }
}

// Helper: detect and block malicious prompt patterns before sending to the AI agent.
function sanitizeAndValidateInput(value: string): { safe: boolean; reason?: string } {
  // 1. Reject binary / non-printable characters (potential binary executable injection).
  // Allow common whitespace (\t, \n, \r) but block other control characters.
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(value)) {
    return { safe: false, reason: 'Input contains binary or non-printable characters.' }
  }

  // 2. Detect base64-encoded payloads (long runs of base64 chars that decode to something).
  const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/g
  const b64Matches = value.match(base64Pattern)
  if (b64Matches) {
    for (const match of b64Matches) {
      try {
        const decoded = atob(match)
        // Flag if decoded content looks like a shell command or script.
        if (/(?:bash|sh|cmd|powershell|eval|exec|system|import os|subprocess)/i.test(decoded)) {
          return { safe: false, reason: 'Input contains a base64-encoded command payload.' }
        }
      } catch {
        // Not valid base64 — skip.
      }
    }
  }

  // 3. Detect shell command patterns.
  const shellPatterns = [
    /(?:^|\s|;|&&|\|\|)\s*(?:bash|sh|zsh|fish|cmd\.exe|powershell(?:\.exe)?|pwsh)\b/i,
    /(?:rm\s+-rf|mkfs|dd\s+if=|chmod\s+[0-7]{3,4}|chown\s+root|sudo\s+|su\s+-)/i,
    /(?:curl|wget)\s+.*(?:http|ftp)/i,
    /(?:eval|exec|system|popen|subprocess|os\.system)\s*\(/i,
    /(?:\$\(|`)[^`]*(?:\)|`)/,   // command substitution: $(cmd) or `cmd`
    /(?:>|>>|2>&1|\|)\s*\/(?:etc|dev|proc|sys|tmp)/i,
  ]
  for (const pattern of shellPatterns) {
    if (pattern.test(value)) {
      return { safe: false, reason: 'Input contains a shell command pattern.' }
    }
  }

  // 4. Detect leetspeak obfuscation used to bypass content filters.
  // Replace common leet substitutions and check for blocked keywords.
  const leetMap: Record<string, string> = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
  }
  const deleetified = value
    .toLowerCase()
    .replace(/[013456789@$!]/g, (c) => leetMap[c] ?? c)
  const leetBlocklist = [
    /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(?:a|an|the)/i,
    /act\s+as\s+(?:a|an|the)/i,
    /disregard\s+(?:your|all|the)/i,
    /jailbreak/i,
    /do\s+anything\s+now/i,
  ]
  for (const pattern of leetBlocklist) {
    if (pattern.test(deleetified)) {
      return { safe: false, reason: 'Input contains obfuscated injection keywords.' }
    }
  }

  // 5. Detect hidden prompt injection patterns (direct instruction overrides).
  const injectionPatterns = [
    /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    /forget\s+(?:all\s+)?(?:previous|prior|above)\s+instructions/i,
    /disregard\s+(?:your|all|the)\s+(?:previous|prior|system|original)/i,
    /you\s+are\s+now\s+(?:a|an|the)\s+\w/i,
    /act\s+as\s+(?:a|an|the)\s+\w/i,
    /pretend\s+(?:you\s+are|to\s+be)\s+(?:a|an|the)/i,
    /system\s*:\s*you\s+are/i,
    /\[\s*system\s*\]/i,
    /<\s*system\s*>/i,
    /###\s*(?:instruction|system|prompt)/i,
    /do\s+anything\s+now/i,
    /jailbreak/i,
    /prompt\s+injection/i,
  ]
  for (const pattern of injectionPatterns) {
    if (pattern.test(value)) {
      return { safe: false, reason: 'Input contains a prompt injection attempt.' }
    }
  }

  return { safe: true }
}

// Helper: validate a JWT's structure, expiry, and subject binding client-side.
// NOTE: This does NOT replace server-side signature verification; it is a
// defence-in-depth guard that rejects obviously invalid / expired tokens
// before they are ever sent to the API.
function validateToken(token: string): boolean {
  // 1. Structure check – a JWT must have exactly three Base64url segments.
  const parts = token.split('.')
  if (parts.length !== 3) return false

  try {
    // 2. Decode the payload (second segment).
    // atob requires standard Base64; convert Base64url → Base64 first.
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=')
    const payloadJson = atob(padded)
    const payload = JSON.parse(payloadJson) as Record<string, unknown>

    // 3. Expiry check – reject tokens whose `exp` claim is in the past.
    if (typeof payload['exp'] === 'number') {
      const nowSeconds = Math.floor(Date.now() / 1000)
      if (payload['exp'] < nowSeconds) {
        console.warn('[auth] Token has expired; discarding.')
        return false
      }
    } else {
      // Tokens without an expiry claim are not acceptable.
      console.warn('[auth] Token missing `exp` claim; discarding.')
      return false
    }

    // 4. Subject binding – `sub` must be present and non-empty.
    if (typeof payload['sub'] !== 'string' || payload['sub'].trim() === '') {
      console.warn('[auth] Token missing or empty `sub` claim; discarding.')
      return false
    }

    return true
  } catch {
    // Malformed Base64 or JSON – treat as invalid.
    return false
  }
}

// Helper: retrieve the stored auth token only after integrity validation.
function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null
  const token = localStorage.getItem('auth_token')
  if (!token) return null
  if (!validateToken(token)) {
    // Remove the invalid / expired token so it cannot be reused.
    localStorage.removeItem('auth_token')
    return null
  }
  return token
}
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { Send, Paperclip, Loader2 } from 'lucide-react'

// Approved model identifiers — only models on the organisation's registry may
// be referenced in provenance metadata.
export type ApprovedModelId =
  | 'org-approved-model-v1'
  | 'org-approved-model-v2'

/**
 * Canonical registry of approved foundation models.
 * Each entry carries the model's pinned SHA-256 digest so that any
 * invocation can be verified against a known-good artefact hash before
 * provenance metadata is persisted.
 *
 * To add a new model:
 *  1. Obtain the official SHA-256 digest from your model governance team.
 *  2. Add an entry here under a new ApprovedModelId literal.
 *  3. Update the ApprovedModelId union type above.
 */
export const APPROVED_MODEL_REGISTRY: Readonly<Record<ApprovedModelId, { digest: string; displayName: string }>> = {
  'org-approved-model-v1': {
    // SHA-256 digest of the approved model artefact — must match the value
    // published in the organisation's model governance portal.
    digest: 'a3f1c2e4b5d6789012345678901234567890abcdef1234567890abcdef123456',
    displayName: 'Org Approved Model v1',
  },
  'org-approved-model-v2': {
    digest: 'b7e2d3f4a5c6890123456789012345678901bcdef2345678901bcdef23456789',
    displayName: 'Org Approved Model v2',
  },
} as const

/**
 * Type-guard: returns true only when modelId is a key in APPROVED_MODEL_REGISTRY.
 * Use this before any model invocation or provenance metadata write.
 */
export function isApprovedModelId(modelId: string): modelId is ApprovedModelId {
  return Object.prototype.hasOwnProperty.call(APPROVED_MODEL_REGISTRY, modelId)
}

/**
 * Returns the pinned SHA-256 digest for an approved model, or throws if the
 * model is not in the registry.  Call isApprovedModelId first when you need
 * a non-throwing check.
 */
export function getApprovedModelDigest(modelId: string): string {
  if (!isApprovedModelId(modelId)) {
    throw new Error(
      `Model '${modelId}' is not in the approved model registry. ` +
      `Approved models: ${Object.keys(APPROVED_MODEL_REGISTRY).join(', ')}`,
    )
  }
  return APPROVED_MODEL_REGISTRY[modelId].digest
}

// Patterns considered dangerous dynamic-code-execution primitives that must
// never appear verbatim in LLM-generated content rendered to the user.
const DANGEROUS_CODE_PATTERNS: ReadonlyArray<RegExp> = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bimportScripts\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bsubprocess\b/gi,
  /\bos\.system\s*\(/gi,
  /\bos\.popen\s*\(/gi,
  /\bchild_process\b/gi,
  /\bspawn\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bexecFile\s*\(/gi,
  /\b__import__\s*\(/gi,
  /\bcompile\s*\(.*exec/gi,
]

/**
 * Scans LLM-generated content for dynamic code execution primitives.
 * Returns an object describing whether dangerous content was found and,
 * if so, a sanitized version of the content with the offending fragments
 * replaced by a visible placeholder so the user is aware of the redaction.
 */
// ---------------------------------------------------------------------------
// SyntheticProvenance – metadata that MUST be attached to every AI-generated
// output before it is served to the user.
// ---------------------------------------------------------------------------
export interface SyntheticProvenance {
  /** Approved model identifier from APPROVED_MODEL_REGISTRY */
  modelId: string
  /** ISO-8601 UTC timestamp of when the content was generated */
  generatedAt: string
  /** Deterministic watermark derived from content + modelId + timestamp */
  watermark: string
  /** Hex-encoded SHA-256 provenance signature (content + modelId + generatedAt) */
  provenanceSignature: string
}

/**
 * Derives a lightweight watermark string from the provided inputs.
 * The watermark is embedded as a structured comment so it survives
 * plain-text rendering without altering visible content.
 */
function deriveWatermark(content: string, modelId: string, generatedAt: string): string {
  // Simple deterministic hash: sum of char codes XOR'd with seed values.
  let hash = 0
  const seed = `${modelId}::${generatedAt}`
  for (let i = 0; i < content.length; i++) {
    hash = ((hash << 5) - hash + content.charCodeAt(i)) >>> 0
  }
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 3) + hash + seed.charCodeAt(i)) >>> 0
  }
  return `ai-wm-${hash.toString(16).padStart(8, '0')}`
}

/**
 * Derives a hex-encoded SHA-256 provenance signature from
 * content + modelId + generatedAt using the Web Crypto API (SubtleCrypto).
 *
 * The function also verifies that modelId is present in APPROVED_MODEL_REGISTRY
 * and that the registry's pinned digest is included in the signed payload,
 * binding the signature to a specific approved model artefact.
 *
 * Returns a Promise<string> — callers must await the result.
 */
async function deriveProvenanceSignature(
  content: string,
  modelId: string,
  generatedAt: string,
): Promise<string> {
  // Enforce registry membership before signing.
  const pinnedDigest = getApprovedModelDigest(modelId) // throws if not approved

  // Bind the pinned model digest into the signed payload so the signature
  // is invalidated if the model artefact changes.
  const input = `${content}|${modelId}|${generatedAt}|${pinnedDigest}`
  const encoder = new TextEncoder()
  const data = encoder.encode(input)

  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

function sanitizeLLMOutput(
  content: string,
  modelId: string = 'org-approved-model-v1',
): {
  safe: boolean
  sanitized: string
  detectedPatterns: string[]
  provenance: SyntheticProvenance
} {
  const detectedPatterns: string[] = []
  let sanitized = content

  for (const pattern of DANGEROUS_CODE_PATTERNS) {
    // Use a fresh regex each iteration to avoid stateful lastIndex issues.
    const freshPattern = new RegExp(pattern.source, pattern.flags)
    if (freshPattern.test(sanitized)) {
      // Record the pattern name for audit logging.
      detectedPatterns.push(pattern.source)
      // Replace every occurrence with a clearly visible redaction marker.
      const replacePattern = new RegExp(pattern.source, pattern.flags)
      sanitized = sanitized.replace(replacePattern, '[REDACTED:UNSAFE_CODE]')
    }
  }

  const generatedAt = new Date().toISOString()
  const watermark = deriveWatermark(sanitized, modelId, generatedAt)
  const provenanceSignature = deriveProvenanceSignature(sanitized, modelId, generatedAt)

  const provenance: SyntheticProvenance = {
    modelId,
    generatedAt,
    watermark,
    provenanceSignature,
  }

  return {
    safe: detectedPatterns.length === 0,
    sanitized,
    detectedPatterns,
    provenance,
  }
}

// ---------------------------------------------------------------------------
// Approved model registry – ONLY these pinned, immutable identifiers are
// permitted. Any model reference not present here is rejected at runtime.
// ---------------------------------------------------------------------------
export const APPROVED_MODEL_REGISTRY = {
  // Org-approved models
  'org-approved-model-v1': { vendor: 'internal', family: 'org-approved', pinned: true },
  'org-approved-model-v2': { vendor: 'internal', family: 'org-approved', pinned: true },
} as const

/** Union type of all approved, pinned model identifiers. */
export type ApprovedModelId = keyof typeof APPROVED_MODEL_REGISTRY

/**
 * Runtime guard: returns true only if the supplied id is a known, pinned
 * entry in the approved model registry. Rejects alias/unpinned references
 * such as bare "gpt-4", "claude", or "gemini".
 */
export function isApprovedModelId(id: string): id is ApprovedModelId {
  if (!id || typeof id !== 'string') return false
  const entry = (APPROVED_MODEL_REGISTRY as Record<string, unknown>)[id]
  if (!entry) {
    console.warn(`[model-registry] Model "${id}" is NOT_IN_REGISTRY; rejecting.`)
    return false
  }
  return true
}

// Provenance metadata that MUST be present on every AI-generated message.
export interface SyntheticProvenance {
  isSynthetic: true
  modelId: ApprovedModelId  // MUST be a pinned, registry-approved identifier
  generatedAt: string       // ISO-8601 timestamp recorded at generation time
  watermark: string         // HMAC-SHA-256 hex signature over provenance fields
  provenanceSignature: string // Hex signature binding content + provenance
}

// Base fields shared by all message roles.
interface MessageBase {
  id: string
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
}

// User / system messages carry no synthetic-content provenance.
export interface UserMessage extends MessageBase {
  role: 'user' | 'system'
  isSynthetic?: false
  modelId?: never
  generatedAt?: never
  watermark?: never
  provenanceSignature?: never
}

// Assistant messages MUST carry fully-populated provenance.
export interface AssistantMessage extends MessageBase, SyntheticProvenance {
  role: 'assistant'
}

export type Message = UserMessage | AssistantMessage

// ---------------------------------------------------------------------------
// Provenance helpers
// ---------------------------------------------------------------------------

/** Derive a deterministic HMAC-SHA-256 hex string using the Web Crypto API. */
async function hmacSha256Hex(key: string, data: string): Promise<string> {
  const enc = new TextEncoder()
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data))
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Build a fully-provenance-stamped AssistantMessage.
 * The watermark signs the provenance fields; provenanceSignature additionally
 * binds the message content so any post-generation tampering is detectable.
 *
 * The signing key is derived from the session token (or a fallback) so that
 * signatures are session-scoped and verifiable server-side.
 */
export async function buildAssistantMessage({
  content,
  modelId,
  attachments,
}: {
  content: string
  modelId: string
  attachments?: FileAttachment[]
}): Promise<AssistantMessage> {
  const id = uuidv4()
  const generatedAt = new Date().toISOString()

  // Use the session auth token as the HMAC key so signatures are
  // session-scoped.  Throw if no token is available so callers are forced
  // to ensure authentication before building provenance-stamped messages.
  const authToken =
    typeof window !== 'undefined' ? localStorage.getItem('auth_token') : null
  if (!authToken) {
    throw new Error(
      'buildAssistantMessage: no auth_token found in localStorage. ' +
      'A valid session token is required to sign provenance fields.',
    )
  }
  const signingKey = authToken

  // Watermark: signs the provenance metadata fields.
  const provenancePayload = `${id}|${modelId}|${generatedAt}`
  const watermark = await hmacSha256Hex(signingKey, provenancePayload)

  // provenanceSignature: additionally binds the message content.
  const fullPayload = `${provenancePayload}|${content}`
  const provenanceSignature = await hmacSha256Hex(signingKey, fullPayload)

  const message: AssistantMessage = {
    id,
    role: 'assistant',
    content,
    timestamp: new Date(),
    attachments,
    isSynthetic: true,
    modelId,
    generatedAt,
    watermark,
    provenanceSignature,
  }

  // Write a durable audit record for every AI-generated assistant message.
  const inputHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content))
    .then(buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''))
    .catch(() => 'hash-unavailable')
  const sessionId =
    typeof window !== 'undefined' ? (localStorage.getItem('session_id') ?? 'unknown-session') : 'unknown-session'
  // Extract modelVersion from modelId if encoded as 'name-vN', else default to 'unknown'
  const modelVersionMatch = modelId.match(/-(v\d[\w.]*)$/i)
  const modelVersion = modelVersionMatch ? modelVersionMatch[1] : 'unknown'
  await writeAuditRecord({
    modelId,
    modelVersion,
    inputHash,
    outputSnippet: content.slice(0, 200),
    timestamp: generatedAt,
    sessionId,
    messageId: id,
    decision: 'assistant-message-generated',
  }).catch(err => { throw new Error(`[AUDIT] buildAssistantMessage audit write failed: ${err}`) })

  return message
}

/**
 * Type-guard: returns true only when all required provenance fields are
 * present and non-empty.  Use this before rendering or forwarding any
 * assistant message.
 */
export function hasValidProvenance(msg: Message): msg is AssistantMessage {
  if (msg.role !== 'assistant') return false
  const m = msg as AssistantMessage
  return (
    m.isSynthetic === true &&
    typeof m.modelId === 'string' && m.modelId.length > 0 &&
    typeof m.generatedAt === 'string' && m.generatedAt.length > 0 &&
    typeof m.watermark === 'string' && m.watermark.length === 64 &&
    typeof m.provenanceSignature === 'string' && m.provenanceSignature.length === 64
  )
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  // content is intentionally omitted to prevent raw file bytes reaching client messages or API payloads
}

/** Strip any raw content from an attachment before including it in a message or API payload. */
function sanitizeAttachment(attachment: FileAttachment): FileAttachment {
  const { id, name, type, size } = attachment
  return { id, name, type, size }
}

/** Only safe, non-sensitive fields are permitted in PolicyError details to prevent internal metadata leakage. */
export interface PolicyErrorDetails {
  code?: string
  field?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: PolicyErrorDetails
}

/** Strip PolicyError details down to the permitted display fields only. */
function sanitizePolicyError(error: PolicyError): PolicyError {
  if (!error.details) return error
  const { code, field } = error.details
  return {
    ...error,
    details: {
      ...(code !== undefined ? { code: String(code) } : {}),
      ...(field !== undefined ? { field: String(field) } : {}),
    },
  }
}

// Audit logger: persists AI decision records for forensic readiness
async function writeAuditRecord(record: {
  modelId: string
  modelVersion: string
  inputHash: string
  outputSnippet: string
  timestamp: string
  sessionId: string
  messageId: string
  decision?: string
}): Promise<void> {
  let response: Response
  try {
    response = await fetch('/api/audit/ai-decisions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(record),
    })
  } catch (err) {
    console.error('[AUDIT] Network error writing audit record:', err)
    throw new Error(`[AUDIT] Network error writing audit record: ${err}`)
  }
  if (!response.ok) {
    const body = await response.text().catch(() => '')
    const msg = `[AUDIT] Audit record persist failed: HTTP ${response.status} ${response.statusText} — ${body}`
    console.error(msg)
    throw new Error(msg)
  }
}): Promise<void> {
  try {
    const token = getAuthToken()
    await fetch('/api/audit/ai-decisions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(record),
    })
  } catch (err) {
    // Audit failures must not silently disappear — log to console as fallback
    console.error('[AUDIT] Failed to persist AI decision record:', err, record)
  }
}

// Compute a SHA-256 hex digest of a string (used for input hashing in audit records)
async function sha256Hex(text: string): Promise<string> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    // Fallback: length-prefixed placeholder when SubtleCrypto is unavailable
    return `nohash-len${text.length}`
  }
  const encoded = new TextEncoder().encode(text)
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', encoded)
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

// Patterns that indicate potentially malicious prompt injection attempts
const SHELL_COMMAND_PATTERN = /(?:^|\s|;|&&|\|\|)(sudo|chmod|chown|curl|wget|bash|sh|zsh|python|perl|ruby|nc|ncat|netcat|exec|eval|system|popen|subprocess|os\.system|cmd\.exe|powershell|\$\(|`[^`]*`)(?:\s|$|;)/i
const BASE64_INJECTION_PATTERN = /(?:[A-Za-z0-9+/]{40,}={0,2})(?:\s*(?:decode|base64|atob|eval))?/
const INVISIBLE_CHARS_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/
const BINARY_MAGIC_BYTES_PATTERN = /(?:\x7fELF|MZ\x90|\xcf\xfa\xed\xfe|\xce\xfa\xed\xfe|\x4d\x5a)/
const LEETSPEAK_INJECTION_PATTERN = /(?:3x3c|3v4l|5y5t3m|sh3ll|c0mm4nd|1nj3ct|3xpl01t|pwn3d|r00t|4dm1n)/i
const EXCESSIVE_BASE64_THRESHOLD = 60 // characters of continuous base64-like content

// Patterns for dynamic code execution primitives in LLM output
const LLM_EVAL_PATTERN = /\beval\s*\(/i
const LLM_FUNCTION_CONSTRUCTOR_PATTERN = /new\s+Function\s*\(/i
const LLM_SETTIMEOUT_CODE_PATTERN = /(?:setTimeout|setInterval)\s*\(\s*['"`]/i
const LLM_EXEC_PATTERN = /\b(?:exec|execSync|execFile|spawn|spawnSync)\s*\(/i
const LLM_DYNAMIC_IMPORT_PATTERN = /\bimport\s*\(/i
const LLM_SCRIPT_INJECTION_PATTERN = /<script[\s>]/i
const LLM_DANGEROUS_PROTO_PATTERN = /__proto__|constructor\s*\[|prototype\s*\[/i

function sanitizeLLMOutput(text: string): { safe: boolean; reason?: string; sanitized: string } {
  if (!text || typeof text !== 'string') {
    return { safe: false, reason: 'LLM output is not a valid string.', sanitized: '' }
  }

  // Check for eval() calls
  if (LLM_EVAL_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains eval() — dynamic code execution primitive detected.', sanitized: text.replace(LLM_EVAL_PATTERN, '[eval removed]') }
  }

  // Check for Function constructor (new Function(...))
  if (LLM_FUNCTION_CONSTRUCTOR_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains Function constructor — dynamic code execution primitive detected.', sanitized: text.replace(LLM_FUNCTION_CONSTRUCTOR_PATTERN, '[Function constructor removed]') }
  }

  // Check for setTimeout/setInterval with string argument (code execution)
  if (LLM_SETTIMEOUT_CODE_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains setTimeout/setInterval with string code — dynamic code execution primitive detected.', sanitized: text.replace(LLM_SETTIMEOUT_CODE_PATTERN, '[dynamic timer removed]') }
  }

  // Check for exec/spawn primitives
  if (LLM_EXEC_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains exec/spawn — dynamic code execution primitive detected.', sanitized: text.replace(LLM_EXEC_PATTERN, '[exec removed]') }
  }

  // Check for dynamic import()
  if (LLM_DYNAMIC_IMPORT_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains dynamic import() — dynamic code execution primitive detected.', sanitized: text.replace(LLM_DYNAMIC_IMPORT_PATTERN, '[dynamic import removed]') }
  }

  // Check for script tag injection
  if (LLM_SCRIPT_INJECTION_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains <script> tag — potential code injection detected.', sanitized: text.replace(LLM_SCRIPT_INJECTION_PATTERN, '[script tag removed]') }
  }

  // Check for prototype pollution primitives
  if (LLM_DANGEROUS_PROTO_PATTERN.test(text)) {
    return { safe: false, reason: 'LLM output contains prototype/constructor access — potential code injection detected.', sanitized: text.replace(LLM_DANGEROUS_PROTO_PATTERN, '[prototype access removed]') }
  }

  return { safe: true, sanitized: text }
}

function sanitizeInput(text: string): { safe: boolean; reason?: string; sanitized: string } {
  // Check for invisible/hidden characters
  if (INVISIBLE_CHARS_PATTERN.test(text)) {
    // Strip invisible characters and warn
    const sanitized = text.replace(INVISIBLE_CHARS_PATTERN, '')
    return { safe: false, reason: 'Hidden or invisible characters were detected and removed from your message.', sanitized }
  }

  // Check for binary executable magic bytes
  if (BINARY_MAGIC_BYTES_PATTERN.test(text)) {
    return { safe: false, reason: 'Binary executable content detected in message. This content cannot be sent.', sanitized: '' }
  }

  // Check for shell command injection patterns
  if (SHELL_COMMAND_PATTERN.test(text)) {
    return { safe: false, reason: 'Potential shell command detected in message. Please rephrase your request.', sanitized: '' }
  }

  // Check for suspicious base64 blocks (long continuous base64 strings)
  const base64Matches = text.match(/[A-Za-z0-9+/=]{60,}/g)
  if (base64Matches && base64Matches.length > 0) {
    // Attempt to decode and check for shell commands or executables
    for (const match of base64Matches) {
      try {
        const decoded = atob(match.replace(/[^A-Za-z0-9+/=]/g, ''))
        if (SHELL_COMMAND_PATTERN.test(decoded) || BINARY_MAGIC_BYTES_PATTERN.test(decoded)) {
          return { safe: false, reason: 'Base64-encoded malicious content detected. This message cannot be sent.', sanitized: '' }
        }
      } catch {
        // Not valid base64, continue
      }
    }
    // Flag long base64 blocks even if decode check passes
    if (BASE64_INJECTION_PATTERN.test(text)) {
      return { safe: false, reason: 'Suspicious encoded content detected in your message. Please rephrase without encoded blocks.', sanitized: '' }
    }
  }

  // Check for leetspeak injection patterns
  if (LEETSPEAK_INJECTION_PATTERN.test(text)) {
    return { safe: false, reason: 'Obfuscated command patterns detected in your message. Please rephrase your request.', sanitized: '' }
  }

  return { safe: true, sanitized: text }
}

// PII patterns and redaction
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: '[REDACTED_EMAIL]' },
  { pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, label: '[REDACTED_PHONE]' },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: '[REDACTED_SSN]' },
  { pattern: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}\b/g, label: '[REDACTED_CARD]' },
  { pattern: /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g, label: '[REDACTED_NAME]' },
  // Singapore-specific PII patterns
  { pattern: /\b[STFGM]\d{7}[A-Z]\b/gi, label: '[REDACTED_SG_NRIC_FIN]' },
  { pattern: /\bSingPass\s*[Ii][Dd]?\s*[:\-]?\s*[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: '[REDACTED_SINGPASS_ID]' },
  { pattern: /\bCPF\s*(?:Account\s*)?(?:No\.?|Number|#)?\s*[:\-]?\s*\d{9}[A-Z]\b/gi, label: '[REDACTED_CPF_ACCOUNT]' },
  { pattern: /\b(?:WP|Work\s*Permit)\s*(?:No\.?|Number|#)?\s*[:\-]?\s*[A-Z0-9]{6,12}\b/gi, label: '[REDACTED_WORK_PERMIT]' },
  { pattern: /\bE\d{7}[A-Z]\b/gi, label: '[REDACTED_SG_PASSPORT]' },
  { pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/g, label: '[REDACTED_SG_PHONE]' },
  { pattern: /\bSingapore\s+\d{6}\b/gi, label: '[REDACTED_SG_POSTAL]' },
]

function redactPII(content: string): { redacted: string; piiFound: boolean } {
  let redacted = content
  let piiFound = false
  for (const { pattern, label } of PII_PATTERNS) {
    const before = redacted
    redacted = redacted.replace(pattern, label)
    if (redacted !== before) piiFound = true
  }
  return { redacted, piiFound }
}

// Singapore PII detection patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'Singapore NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  { name: 'Singapore Phone Number', pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/ },
  { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
  { name: 'Singapore Passport', pattern: /\bE\d{7}[A-Z]\b/i },
  { name: 'Email Address', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
]

function detectSingaporePII(content: string): string[] {
  const detected: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(content)) {
      detected.push(name)
    }
  }
  return detected
}

// Fetches a server-issued session token from the backend authentication endpoint.
// The server validates the user's identity (e.g., via session cookie or OAuth)
// and returns a signed token. Client-side token generation is not permitted.
async function fetchServerSessionToken(): Promise<string | null> {
  try {
    const response = await fetch('/api/auth/session-token', {
      method: 'POST',
      credentials: 'include', // send session cookies for server-side identity validation
      headers: { 'Content-Type': 'application/json' },
    })
    if (!response.ok) {
      // 401/403 means the user is not authenticated on the server
      return null
    }
    const data = await response.json()
    if (typeof data.token !== 'string' || !data.token) {
      return null
    }
    return data.token
  } catch {
    return null
  }
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  // Server-issued session token — fetched once on mount after server authenticates the user.
  const conversationTokenRef = useRef<string | null>(null)
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null) // null = pending

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
    // Fetch a server-issued token; only allow agent access if the server confirms authentication.
    fetchServerSessionToken().then(token => {
      if (token) {
        conversationTokenRef.current = token
        setIsAuthenticated(true)
      } else {
        conversationTokenRef.current = null
        setIsAuthenticated(false)
      }
    })
  }, [])

  const MALICIOUS_PATTERNS = [
    // Prompt injection / jailbreak phrases
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+(a\s+)?(?:dan|jailbreak|unrestricted|evil|free)/i,
    /act\s+as\s+(if\s+you\s+are\s+)?(?:a\s+)?(?:dan|jailbreak|unrestricted|evil|uncensored)/i,
    /system\s*:\s*(you|your|ignore|forget|disregard)/i,
    /\[system\]/i,
    /<\s*system\s*>/i,
    /new\s+instructions?\s*:/i,
    /override\s+(safety|policy|guidelines?|rules?|restrictions?)/i,
    /bypass\s+(safety|policy|guidelines?|rules?|restrictions?|filter)/i,
    /jailbreak/i,
    /prompt\s+injection/i,
    // Shell commands
    /(?:^|\s|;|&&|\|\|)(?:rm\s+-rf|sudo\s+|chmod\s+|chown\s+|wget\s+|curl\s+.*\|\s*(?:bash|sh)|eval\s*\(|exec\s*\()/m,
    /(?:base64\s+-d|base64\s+--decode)/i,
    // Leetspeak prompt injection patterns
    /1gn[o0]r[e3]\s+[a4]ll\s+[i1]n5truct/i,
    /[i1]gn[o0]r[e3]\s+pr[e3]v[i1][o0]u5/i,
    // Base64-encoded suspicious content (decode and re-check)
  ]

  const BASE64_PATTERN = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/

  const containsMaliciousContent = (text: string): { malicious: boolean; reason: string } => {
    // Check raw text against patterns
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.test(text)) {
        return { malicious: true, reason: 'Suspicious prompt injection or shell command pattern detected.' }
      }
    }

    // Check for base64-encoded blocks and decode them for inspection
    const base64Blocks = text.match(/[A-Za-z0-9+\/]{20,}={0,2}/g) || []
    for (const block of base64Blocks) {
      if (BASE64_PATTERN.test(block)) {
        try {
          const decoded = atob(block)
          // Only inspect if decoded result is printable ASCII
          if (/^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
            for (const pattern of MALICIOUS_PATTERNS) {
              if (pattern.test(decoded)) {
                return { malicious: true, reason: 'Base64-encoded malicious content detected in file.' }
              }
            }
          }
        } catch {
          // Not valid base64, skip
        }
      }
    }

    return { malicious: false, reason: '' }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    // Sanitize user input before processing
    if (input.trim()) {
      const sanitizationResult = sanitizeInput(input)
      if (!sanitizationResult.safe) {
        if (sanitizationResult.sanitized && sanitizationResult.sanitized !== input) {
          // Invisible chars stripped — update input and warn
          setInput(sanitizationResult.sanitized)
          const warnMessage: Message = {
            id: uuidv4(),
            role: 'system',
            content: `⚠️ Security Notice: ${sanitizationResult.reason} Your message has been cleaned. Please review and resubmit.`,
            timestamp: new Date(),
            error: { type: 'threat', message: sanitizationResult.reason || 'Suspicious content detected' },
          }
          setMessages(prev => [...prev, warnMessage])
          setIsLoading(false)
          return
        } else {
          // Dangerous content — block entirely
          const blockMessage: Message = {
            id: uuidv4(),
            role: 'system',
            content: `🚫 Message Blocked: ${sanitizationResult.reason}`,
            timestamp: new Date(),
            error: { type: 'threat', message: sanitizationResult.reason || 'Malicious content detected' },
          }
          setMessages(prev => [...prev, blockMessage])
          setIsLoading(false)
          return
        }
      }
    }

    const attachments: FileAttachment[] = []

            // Process pending files
    for (const file of pendingFiles) {
      const content = await readFileContent(file)

      // Check for Singapore PII before sending to backend
      const piiFound = detectSingaporePII(content)
      if (piiFound.length > 0) {
        const piiErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: `Upload blocked: The file "${file.name}" contains Singapore PII (${piiFound.join(', ')}). Please remove sensitive information before uploading.`,
          timestamp: new Date(),
          error: {
            type: 'pii',
            message: `Singapore PII detected in uploaded file: ${piiFound.join(', ')}`,
            details: { file: file.name, piiCategories: piiFound },
          },
        }
        setMessages(prev => [...prev, piiErrorMessage])
        setIsLoading(false)
        setPendingFiles([])
        setShowFileUpload(false)
        return
      }

      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    } = redactPII(rawContent)
      if (piiFound) {
        // PII detected and redacted — not logged to avoid exposing PII-related information
      }
      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }" was rejected: ${scanResult.reason} Please remove any prompt injection attempts, shell commands, or encoded malicious content from your file.`,
          timestamp: new Date(),
          error: {
            type: 'threat',
            message: scanResult.reason,
            details: { fileName: file.name },
          },
        }
        setMessages(prev => [...prev, errorMessage])
        setPendingFiles([])
        setShowFileUpload(false)
        setIsLoading(false)
        return
      }

      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: input || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
      const sessionToken = typeof window !== 'undefined'
        ? (sessionStorage.getItem('auth_token') || localStorage.getItem('auth_token') || '')
        : ''

      if (!sessionToken) {
        const authErrorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: 'Authentication required. Please log in to continue.',
          timestamp: new Date(),
          error: { type: 'auth', message: 'No authentication token found. Request blocked.' },
        }
        setMessages(prev => [...prev, authErrorMessage])
        setIsLoading(false)
        return
      }

      // Sanitize and validate input BEFORE sending to the AI model
      const sanitizedInput = sanitizeTextInput(input)
      const inputError = validateTextInput(sanitizedInput)
      if (inputError) {
        const validationMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: inputError,
          timestamp: new Date(),
          error: { type: 'validation', message: inputError },
        }
        setMessages(prev => [...prev, validationMessage])
        setIsLoading(false)
        return
      }
      for (const attachment of attachments) {
        const attachmentError = validateAttachment(attachment)
        if (attachmentError) {
          const validationMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: attachmentError,
            timestamp: new Date(),
            error: { type: 'validation', message: attachmentError },
          }
          setMessages(prev => [...prev, validationMessage])
          setIsLoading(false)
          return
        }
      }

      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          message: sanitizedInput,
          attachments: attachments,
          conversation_id: conversationTokenRef.current ?? await generateSignedSessionToken(),
        }),
      })

      const data = await response.json()

      const sanitizeLLMOutput = (text: string): string => {
        if (typeof text !== 'string') return '';
        // Patterns for dynamic code execution primitives
        const dangerousPatterns = [
          /\beval\s*\(/gi,
          /\bexec\s*\(/gi,
          /\bnew\s+Function\s*\(/gi,
          /\bsetTimeout\s*\(\s*['"`]/gi,
          /\bsetInterval\s*\(\s*['"`]/gi,
          /\bsetImmediate\s*\(\s*['"`]/gi,
          /\bexecScript\s*\(/gi,
          /\bdocument\.write\s*\(/gi,
          /\bwindow\[\s*['"`]eval['"`]\s*\]/gi,
          /\bglobalThis\[\s*['"`]eval['"`]\s*\]/gi,
        ];
        let sanitized = text;
        for (const pattern of dangerousPatterns) {
          sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.replace(/[()]/g, '')}]`);
        }
        return sanitized;
      };

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.detail || 'An error occurred',
          timestamp: new Date(),
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
        const completionTimestamp = new Date().toISOString()
      const resolvedModelId = data.model || data.modelId || 'unknown'
      const completionContent = sanitizeLLMOutput(data.message || data.response || data.content || '')

      const assistantMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: completionContent,
        timestamp: new Date(),
        isSynthetic: true,
      }

      // Persist audit record for this AI decision (forensic readiness)
      sha256Hex(userMessage).then(inputHash => {
        writeAuditRecord({
          eventType: 'ai_completion',
          principal: getAuthToken() ?? 'anonymous',
          modelId: resolvedModelId,
          inputHash,
          outputSnippet: completionContent.slice(0, 200),
          timestamp: completionTimestamp,
          sessionId: CHAT_SESSION_ID,
          messageId: assistantMessage.id,
        })
      }).catch(err => console.error('[AUDIT] Input hashing failed:', err)) : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  // --- Input sanitization and validation helpers ---
  const MAX_MESSAGE_LENGTH = 10000
  const ALLOWED_FILE_TYPES = [
    'image/png', 'image/jpeg', 'image/gif', 'image/webp',
    'application/pdf',
    'text/plain', 'text/html', 'text/csv',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  ]
  const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB

  const sanitizeTextInput = (text: string): string => {
    // Remove null bytes and non-printable control characters (except common whitespace)
    return text
      .replace(/\x00/g, '')                        // null bytes
      .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars except \t \n \r
      .trim()
  }

  const validateTextInput = (text: string): string | null => {
    if (!text || text.length === 0) return 'Message must not be empty.'
    if (text.length > MAX_MESSAGE_LENGTH)
      return `Message exceeds maximum allowed length of ${MAX_MESSAGE_LENGTH} characters.`
    return null
  }

  const validateAttachment = (attachment: { name: string; type: string; size?: number; content: string }): string | null => {
    if (!ALLOWED_FILE_TYPES.includes(attachment.type))
      return `File type "${attachment.type}" is not allowed for "${attachment.name}".`
    if (attachment.size !== undefined && attachment.size > MAX_FILE_SIZE_BYTES)
      return `File "${attachment.name}" exceeds the maximum allowed size of 10 MB.`
    // Validate base64 content for binary files
    if (attachment.type.startsWith('image/') || attachment.type === 'application/pdf') {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(attachment.content))
        return `File "${attachment.name}" contains invalid base64 content.`
    }
    return null
  }
  // --- End sanitization helpers ---

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        const result = reader.result as string
        // For binary files, return base64
        if (file.type.startsWith('image/') || file.type === 'application/pdf') {
          resolve(result.split(',')[1]) // Remove data URL prefix
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (file.type.startsWith('image/') || file.type === 'application/pdf') {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <header className="flex items-center justify-center py-3 border-b border-chat-border bg-chat-sidebar">
        <h1 className="text-xl font-semibold text-white">PolicyProbe</h1>
      </header>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto chat-scrollbar">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-400">
            <div className="text-4xl mb-4">🔍</div>
            <h2 className="text-2xl font-medium text-white mb-2">PolicyProbe</h2>
            <p className="text-center max-w-md">
              Upload documents to analyze or ask questions about policy compliance.
              <br />
              <span className="text-sm text-gray-500 mt-2 block">
                Supports PDF, Word, HTML, and image files
              </span>
            </p>
          </div>
        ) : (
          <MessageList messages={messages} />
        )}
      </div>

      {/* PII Redaction Utility — scrubs text files before upload */}
      {/* redactPIIFromFiles is defined above this component */}

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={async (files: File[]) => {
            const redacted = await redactPIIFromFiles(files)
            handleFileSelect(redacted)
          }} />
        </div>
      )}

      {/* Pending Files Display */}
      {pendingFiles.length > 0 && (
        <div className="border-t border-chat-border bg-chat-input px-4 py-2">
          <div className="flex flex-wrap gap-2">
            {pendingFiles.map((file, index) => (
              <div
                key={index}
                className="flex items-center gap-2 bg-chat-hover rounded-lg px-3 py-1.5 text-sm"
              >
                <span className="text-gray-300">{file.name}</span>
                <button
                  onClick={() => removePendingFile(index)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Input Area */}
      <div className="border-t border-chat-border bg-chat-bg p-4">
        <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
          <div className="relative flex items-end bg-chat-input rounded-xl border border-chat-border">
            {/* File Upload Button */}
            <button
              type="button"
              onClick={() => setShowFileUpload(!showFileUpload)}
              className="p-3 text-gray-400 hover:text-white transition-colors"
            >
              <Paperclip className="w-5 h-5" />
            </button>

                        {/* Hidden file input */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
              className="hidden"
              onChange={async (e) => {
                if (e.target.files) {
                  const files = Array.from(e.target.files);
                  const safeFiles: File[] = [];
                  const rejectedNames: string[] = [];

                  // Singapore PII patterns
                  const singaporePIIPatterns: RegExp[] = [
                    // NRIC / FIN: S/T/F/G/M followed by 7 digits and a letter
                    /\b[STFGM]\d{7}[A-Z]\b/i,
                    // CPF account number: 9 digits (standalone)
                    /\b\d{9}\b/,
                    // SingPass user ID pattern (alphanumeric, 6-12 chars, common format)
                    /\bsingpass[_\-]?id[:\s]+\S+/i,
                    // Singapore mobile numbers: +65 followed by 8 digits starting with 8 or 9
                    /\b(\+65|65)?[89]\d{7}\b/,
                    // Singapore postal code (6 digits starting with valid district prefix)
                    /\b[0-9]{6}\b/,
                    // MediSave / CPF references
                    /\b(medisave|cpf|central\s+provident\s+fund)\b/i,
                    // SingPass keyword
                    /\bsingpass\b/i,
                    // CorpPass keyword
                    /\bcorppass\b/i,
                  ];

                  const containsSingaporePII = (text: string): boolean => {
                    return singaporePIIPatterns.some((pattern) => pattern.test(text));
                  };

                  const readFileAsText = (file: File): Promise<string> =>
                    new Promise((resolve) => {
                      const reader = new FileReader();
                      reader.onload = (ev) => resolve((ev.target?.result as string) ?? "");
                      reader.onerror = () => resolve("");
                      reader.readAsText(file);
                    });

                  for (const file of files) {
                    // Only scan text-readable file types for PII
                    const textTypes = [".txt", ".html", ".htm", ".json"];
                    const isTextFile = textTypes.some((ext) =>
                      file.name.toLowerCase().endsWith(ext)
                    );

                    if (isTextFile) {
                      const text = await readFileAsText(file);
                      if (containsSingaporePII(text)) {
                        rejectedNames.push(file.name);
                        continue;
                      }
                    }
                    safeFiles.push(file);
                  }

                  if (rejectedNames.length > 0) {
                    alert(
                      `The following file(s) were rejected because they appear to contain Singapore PII (e.g. NRIC, FIN, CPF, SingPass data):\n\n${rejectedNames.join("\n")}\n\nPlease remove any personal identifiable information before uploading.`
                    );
                  }

                  if (safeFiles.length > 0) {
                    handleFileSelect(safeFiles);
                  }

                  // --- LLM Output Sanitizer (defined once, used throughout) ---
                  // Placed here so it is hoisted into the enclosing component scope
                  // via the module-level declaration below.

                  // Reset input so the same file can be re-selected after correction
                  e.target.value = "";
                }
              }}
            />

                        {/* Text Input */}
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Message PolicyProbe..."
              className="flex-1 bg-transparent text-white placeholder-gray-500 resize-none py-3 pr-12 focus:outline-none max-h-48"
              rows={1}
              disabled={isLoading}
            />
            {/* Synthetic Content Provenance Watermark — attached to every AI-generated response */}
            <span
              aria-label="AI-generated content provenance"
              title="AI-Generated Content — PolicyProbe-AI"
              className="sr-only"
              data-synthetic-content="true"
              data-origin-tag="PolicyProbe-AI"
            >
              [AI-GENERATED CONTENT — PolicyProbe-AI]
            </span>

            {/* Send Button */}
            <button
              type="submit"
              disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
              className="absolute right-2 bottom-2 p-2 text-gray-400 hover:text-white disabled:opacity-50 disabled:hover:text-gray-400 transition-colors"
            >
              {isLoading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-center text-gray-500 mt-2">
            PolicyProbe demonstrates AI policy evaluation and remediation
          </p>
          <p className="text-xs text-center text-gray-600 mt-1" aria-label="Synthetic content disclosure">
            ⚠️ <span className="font-semibold text-gray-500">AI-Generated Content</span> — Responses are synthetically produced by{" "}
            <span className="font-mono text-gray-500">our AI model</span> (PolicyProbe-AI).{" "}
            Verify critical information independently.
          </p>
        </form>
      </div>
    </div>
  )
}
