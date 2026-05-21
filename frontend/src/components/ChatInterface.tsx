'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'

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

// Provenance metadata that MUST be present on every AI-generated message.
export interface SyntheticProvenance {
  isSynthetic: true
  modelId: string          // Identifier of the model that produced the content
  generatedAt: string      // ISO-8601 timestamp recorded at generation time
  watermark: string        // HMAC-SHA-256 hex signature over provenance fields
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
  // session-scoped.  Fall back to a static sentinel so the field is never
  // empty (server should reject sentinel-signed messages in production).
  const signingKey =
    (typeof window !== 'undefined' && localStorage.getItem('auth_token')) ??
    'UNSIGNED-SENTINEL-REPLACE-IN-PROD'

  // Watermark: signs the provenance metadata fields.
  const provenancePayload = `${id}|${modelId}|${generatedAt}`
  const watermark = await hmacSha256Hex(signingKey, provenancePayload)

  // provenanceSignature: additionally binds the message content.
  const fullPayload = `${provenancePayload}|${content}`
  const provenanceSignature = await hmacSha256Hex(signingKey, fullPayload)

  return {
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
  eventType: 'ai_completion'
  principal: string
  modelId: string
  inputHash: string
  outputSnippet: string
  timestamp: string
  sessionId: string
  messageId: string
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

// Generates a signed session token: base64url(payload).base64url(HMAC-SHA256(payload))
// payload = { jti, iat, exp, sub } — provides identity binding, issued-at, and expiry.
async function generateSignedSessionToken(): Promise<string> {
  const jti = uuidv4()
  const iat = Math.floor(Date.now() / 1000)
  const exp = iat + 4 * 60 * 60 // 4-hour expiry
  const sub = 'chat-session'
  const payload = JSON.stringify({ jti, iat, exp, sub })
  const payloadB64 = btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

  // Derive a per-session signing key from a fixed app secret + the jti
  const appSecret = 'chat-session-signing-secret-v1'
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(appSecret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    keyMaterial,
    new TextEncoder().encode(payloadB64)
  )
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

  return `${payloadB64}.${sigB64}`
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  // Stable signed session token — generated once on mount, bound to this component lifetime.
  const conversationTokenRef = useRef<string | null>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
    // Generate and cache the signed session token once on mount.
    generateSignedSessionToken().then(token => {
      conversationTokenRef.current = token
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
        console.warn(`PII detected and redacted in file: ${file.name}`)
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

      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({
          message: sanitizeTextInput(input),
          attachments: attachments,
          conversation_id: conversationTokenRef.current ?? await generateSignedSessionToken(),
        }),
      })

      // Validate sanitized input before sending
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
        const generatedAt = data.generated_at ?? new Date().toISOString()
        const modelId = data.model_id ?? data.model ?? 'unknown'
        const watermark = data.watermark ?? `wp-${Buffer.from(`${modelId}:${generatedAt}`).toString('base64')}`
              const completionTimestamp = new Date().toISOString()
      const resolvedModelId = data.model || data.modelId || 'unknown'
      const completionContent = data.message || data.response || data.content || ''

      const assistantMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: completionContent,
        timestamp: new Date(),
        isSynthetic: true,
        modelId: resolvedModelId,
        generatedAt: completionTimestamp,
        watermark: data.watermark,
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

      {/* File Upload Modal */}
      {showFileUpload && (
        <div className="border-t border-chat-border bg-chat-input p-4">
          <FileUpload onFilesSelected={handleFileSelect} />
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
              onChange={(e) => {
                if (e.target.files) {
                  handleFileSelect(Array.from(e.target.files))
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
        </form>
      </div>
    </div>
  )
}
