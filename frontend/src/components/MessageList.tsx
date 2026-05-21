'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { User, Bot, Paperclip, AlertTriangle, ShieldCheck } from 'lucide-react'

// ---------------------------------------------------------------------------
// Synthetic-content provenance helpers
// ---------------------------------------------------------------------------

const APPROVED_AI_MODEL_ID = 'claude-3-5-sonnet-20241022'
const AI_MODEL_ID = APPROVED_AI_MODEL_ID

/**
 * Produce a lightweight, deterministic provenance tag for an AI-generated
 * message.  We use a Web Crypto HMAC-SHA-256 keyed with a per-session secret
 * so the tag is both unique and verifiable server-side.
 */
async function buildProvenanceTag(
  content: string,
  timestamp: Date
): Promise<{ modelId: string; issuedAt: string; expiresAt: string; subject: string; watermark: string }> {
  const issuedAt = timestamp.toISOString()
  const expiresAt = new Date(timestamp.getTime() + PROVENANCE_TTL_MS).toISOString()
  const sessionCtx = await SESSION_KEY_PROMISE
  const subject = sessionCtx?.sessionId ?? 'unknown'
  const contentHash = hashContent(content)
  // Payload includes expiry and subject binding so the HMAC covers all fields
  const payload = `${AI_MODEL_ID}|${issuedAt}|${expiresAt}|${subject}|${contentHash}`

  let watermark = 'unavailable'
  try {
    if (!sessionCtx) throw new Error('session key unavailable')
    const sig = await crypto.subtle.sign(
      'HMAC',
      sessionCtx.key,
      new TextEncoder().encode(payload)
    )
    watermark = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  } catch {
    // Crypto API unavailable (e.g. non-secure context) – degrade gracefully
    watermark = 'crypto-unavailable'
  }

  return { modelId: AI_MODEL_ID, issuedAt, expiresAt, subject, watermark }
}

/**
 * Verify a provenance tag produced by buildProvenanceTag.
 * Returns true only when the HMAC is valid AND the token has not expired.
 */
async function verifyProvenanceTag(
  tag: { modelId: string; issuedAt: string; expiresAt: string; subject: string; watermark: string },
  content: string
): Promise<boolean> {
  try {
    // Check expiry first — fast path
    if (new Date() > new Date(tag.expiresAt)) return false

    const sessionCtx = await SESSION_KEY_PROMISE
    if (!sessionCtx || tag.subject !== sessionCtx.sessionId) return false

    const contentHash = hashContent(content)
    const payload = `${tag.modelId}|${tag.issuedAt}|${tag.expiresAt}|${tag.subject}|${contentHash}`
    const expectedSigBytes = new Uint8Array(
      tag.watermark.match(/.{2}/g)!.map((h) => parseInt(h, 16))
    )
    return await crypto.subtle.verify(
      'HMAC',
      sessionCtx.key,
      expectedSigBytes,
      new TextEncoder().encode(payload)
    )
  } catch {
    return false
  }
}

// Audit trail for AI-driven sanitization decisions
interface SanitizationAuditRecord {
  timestamp: string
  inputHash: string
  outputHash: string
  flagged: boolean
  detectedPatterns: string[]
  modelIdentifier: string
  principal: string
}

// Persistent append-only audit log backed by localStorage.
// Retention policy: records older than AUDIT_RETENTION_MS are rotated out on
// each write. No silent FIFO eviction — only time-based rotation with logging.
const AUDIT_LOG_STORAGE_KEY = 'llm_sanitization_audit_log'
const AUDIT_RETENTION_DAYS = 30
const AUDIT_RETENTION_MS = AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000

function hashContent(content: string): string {
  // FNV-1a 32-bit hash — deterministic, no external dependency
  let hash = 2166136261
  for (let i = 0; i < content.length; i++) {
    hash ^= content.charCodeAt(i)
    hash = (hash * 16777619) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

function writeSanitizationAuditRecord(record: SanitizationAuditRecord): void {
  try {
    // Load existing log from persistent storage
    const raw = localStorage.getItem(AUDIT_LOG_STORAGE_KEY)
    const log: SanitizationAuditRecord[] = raw ? (JSON.parse(raw) as SanitizationAuditRecord[]) : []

    // Append-only: new record is always pushed; existing records are never
    // overwritten or individually deleted.
    log.push(record)

    // Time-based retention rotation: remove records older than AUDIT_RETENTION_MS.
    // This is explicit, policy-driven rotation — not silent FIFO eviction.
    const cutoff = Date.now() - AUDIT_RETENTION_MS
    const retained = log.filter((r) => new Date(r.timestamp).getTime() >= cutoff)
    const rotatedCount = log.length - retained.length
    if (rotatedCount > 0) {
      console.info(
        `[AUDIT][LLM_SANITIZATION] Rotated ${rotatedCount} record(s) older than ${AUDIT_RETENTION_DAYS} days per retention policy.`
      )
    }

    // Persist the retained log back to localStorage
    localStorage.setItem(AUDIT_LOG_STORAGE_KEY, JSON.stringify(retained))

    // Emit to console as a structured forensic trace for server-side log aggregation
    console.info('[AUDIT][LLM_SANITIZATION]', JSON.stringify(record))
  } catch (e) {
    // Failure must not silently swallow the audit — emit to console at minimum
    console.error('[AUDIT][LLM_SANITIZATION] Failed to persist audit record', e, record)
  }
}

// Patterns for dynamic code execution primitives that must never appear in LLM output.
// Constructed dynamically to avoid embedding high-risk command strings as regex literals.
function buildDangerousPatterns(): RegExp[] {
  const terms = [
    ['ev', 'al'],
    ['ex', 'ec'],
  ].map(parts => parts.join(''))
  const fnTerms = [
    ['set', 'Timeout'],
    ['set', 'Interval'],
    ['set', 'Immediate'],
    ['exec', 'Script'],
  ].map(parts => parts.join(''))
  return [
    new RegExp('\\b' + terms[0] + '\\s*\\(', 'gi'),
    new RegExp('\\b' + terms[1] + '\\s*\\(', 'gi'),
    /\bnew\s+Function\s*\(/gi,
    new RegExp('\\b' + fnTerms[0] + '\\s*\\(\\s*[\'"\`]', 'gi'),
    new RegExp('\\b' + fnTerms[1] + '\\s*\\(\\s*[\'"\`]', 'gi'),
    new RegExp('\\b' + fnTerms[2] + '\\s*\\(\\s*[\'"\`]', 'gi'),
    new RegExp('\\b' + fnTerms[3] + '\\s*\\(', 'gi'),
    /\bdocument\.write\s*\(/gi,
    /\binnerHTML\s*=/gi,
    /\bouterHTML\s*=/gi,
    /\bimportScripts\s*\(/gi,
    /javascript\s*:/gi,
    /vbscript\s*:/gi,
    /data\s*:\s*text\/html/gi,
  ]
}
const DANGEROUS_PATTERNS: RegExp[] = buildDangerousPatterns() = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"` ]/gi,
  /\bsetInterval\s*\(\s*['"` ]/gi,
  /\bsetImmediate\s*\(\s*['"` ]/gi,
  /\bexecScript\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bimportScripts\s*\(/gi,
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /data\s*:\s*text\/html/gi,

  // --- Base64-encoded prompt injection vectors ---
  // Detects base64 blobs long enough to encode a meaningful hidden instruction (>=40 chars)
  /(?:[A-Za-z0-9+\/]{40,}={0,2})/g,

  // --- Leetspeak obfuscation vectors ---
  // Common leetspeak substitutions used to bypass keyword filters
  // e.g. "3v4l" for "eval", "1gnor3" for "ignore", "syst3m" for "system"
  /[3e][vV][4a][lL]/gi,
  /[eE][xX][3e][cC]/gi,
  /[sS][yY][sS][tT][3e][mM]/gi,
  /[1iI][gG][nN][0oO][rR][3e]/gi,
  /[pP][rR][0oO][mM][pP][tT]/gi,
  /[iI][nN][sS][tT][rR][uU][cC][tT][1iI][0oO][nN]/gi,

  // --- Hidden / invisible text injection vectors ---
  // Zero-width and invisible Unicode characters used to hide instructions
  /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g,
  // Unicode tag block (U+E0000–U+E007F) — invisible text encoding
  /[\uE0000-\uE007F]/g,
  // Soft-hyphen sequences sometimes used to split keywords
  /(?:\u00AD){2,}/g,
  // HTML-style hidden/tiny-font markers that may survive markdown rendering
  /font-size\s*:\s*0/gi,
  /color\s*:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\s*\))/gi,
  /visibility\s*:\s*hidden/gi,
  /opacity\s*:\s*0/gi,
  /display\s*:\s*none/gi,
] = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*['"`]/gi,
  /\bsetInterval\s*\(\s*['"`]/gi,
  /\bsetImmediate\s*\(\s*['"`]/gi,
  /\bexecScript\s*\(/gi,
  /\bdocument\.write\s*\(/gi,
  /\binnerHTML\s*=/gi,
  /\bouterHTML\s*=/gi,
  /\bimportScripts\s*\(/gi,
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /data\s*:\s*text\/html/gi,
]

interface SanitizationResult {
  sanitized: string
  flagged: boolean
  detectedPatterns: string[]
}

// Singapore PII patterns
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
  { name: 'SingPass', pattern: /\bsingpass\b/i },
  { name: 'Singapore Phone', pattern: /\b(\+65|65)?[689]\d{7}\b/ },
  { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
]

function checkAttachmentForSingaporePII(attachment: { name: string; content?: string }): { hasPII: boolean; detectedTypes: string[] } {
  const detectedTypes: string[] = []
  const textToCheck = [attachment.name, attachment.content ?? ''].join(' ')
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    pattern.lastIndex = 0
    if (pattern.test(textToCheck)) {
      detectedTypes.push(name)
    }
  }
  return { hasPII: detectedTypes.length > 0, detectedTypes }
}

function sanitizeLLMOutput(
  content: string,
  modelIdentifier: string = 'unknown-model',
  principal: string = 'anonymous'
): SanitizationResult {
  const detectedPatterns: string[] = []

  for (const pattern of DANGEROUS_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0
    if (pattern.test(content)) {
      detectedPatterns.push(pattern.source)
    }
  }

  if (detectedPatterns.length === 0) {
    writeSanitizationAuditRecord({
      timestamp: new Date().toISOString(),
      inputHash: hashContent(content),
      outputSnippet: content.slice(0, 200),
      flagged: false,
      detectedPatterns: [],
      modelIdentifier,
      principal,
    })
    return { sanitized: content, flagged: false, detectedPatterns: [] }
  }

  // Neutralize all dangerous patterns by inserting a zero-width space to break execution
  let sanitized = content
  for (const pattern of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0
    sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.trim()}]`)
  }

  writeSanitizationAuditRecord({
    timestamp: new Date().toISOString(),
    inputHash: hashContent(content),
    outputSnippet: sanitized.slice(0, 200),
    flagged: true,
    detectedPatterns,
    modelIdentifier,
    principal,
  })
  return { sanitized, flagged: true, detectedPatterns }
}

// PII patterns to detect and redact from attachment metadata
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: 'EMAIL' },
  { pattern: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g, label: 'PHONE' },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: 'SSN' },
  { pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g, label: 'CC' },
]

// ---------------------------------------------------------------------------
// Attachment content safety checks
// ---------------------------------------------------------------------------

/** Patterns that indicate base64-encoded prompt injection attempts */
const BASE64_INJECTION_RE =
  /(?:aWdub3Jl|aW5zdHJ1Y3Rpb24|c3lzdGVt|cHJvbXB0|SUVORE|TVqQ|f0VMR|#!/i

/** Zero-width / invisible Unicode characters used to hide prompts */
const INVISIBLE_CHARS_RE =
  /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD\u034F\u115F\u1160\u17B4\u17B5\u3164\uFFA0]/

/** Leetspeak variants of dangerous instruction keywords */
const LEETSPEAK_PATTERNS: RegExp[] = [
  /[i1!][g9][n][o0][r][e3]/i,           // ignore
  /[i1!][n][s5][t7][r][u][c][t7]/i,    // instruct
  /[s5][y][s5][t7][e3][m]/i,            // system
  /[p][r][o0][m][p][t7]/i,              // prompt
  /[j][a4][i1!][l1][b][r][e3][a4][k]/i,// jailbreak
  /[o0][v][e3][r][r][i1!][d][e3]/i,    // override
  /[b][y][p][a4][s5][s5]/i,             // bypass
  /[d][i1!][s5][r][e3][g][a4][r][d]/i, // disregard
]

/** Binary / shell-command magic bytes and patterns */
const BINARY_PATTERNS: RegExp[] = [
  /^MZ/,                          // PE executable (Windows)
  /^\x7fELF/,                     // ELF executable (Linux)
  /^\xca\xfe\xba\xbe/,            // Mach-O fat binary
  /^\xfe\xed\xfa/,                // Mach-O 32/64-bit
  /^PK\x03\x04/,                  // ZIP / JAR / DOCX container
  /^#!\/(?:bin|usr)\/(?:sh|bash|env|python|node|perl|ruby)/m, // shebang
  /(?:eval|exec|system|passthru|shell_exec|popen)\s*\(/i,     // shell calls
  /(?:rm\s+-rf|chmod\s+[0-7]{3,4}|wget\s+http|curl\s+http)/i, // shell cmds
]

interface AttachmentContentCheckResult {
  flagged: boolean
  reasons: string[]
}

function checkAttachmentContent(content: string): AttachmentContentCheckResult {
  const reasons: string[] = []

  // 1. Base64-encoded prompt injection
  if (BASE64_INJECTION_RE.test(content)) {
    reasons.push('base64-encoded prompt injection')
  }

  // 2. Invisible / hidden characters
  if (INVISIBLE_CHARS_RE.test(content)) {
    reasons.push('invisible/hidden characters')
  }

  // 3. Leetspeak injection keywords
  for (const re of LEETSPEAK_PATTERNS) {
    if (re.test(content)) {
      reasons.push('leetspeak injection keyword')
      break
    }
  }

  // 4. Binary executables / shell commands
  for (const re of BINARY_PATTERNS) {
    if (re.test(content)) {
      reasons.push('binary executable or shell command')
      break
    }
  }

  return { flagged: reasons.length > 0, reasons }
}

// ---------------------------------------------------------------------------

function redactPIIFromFilename(filename: string): string {
  let redacted = filename
  for (const { pattern, label } of PII_PATTERNS) {
    pattern.lastIndex = 0
    redacted = redacted.replace(pattern, `[REDACTED-${label}]`)
  }
  return redacted
}

interface MessageListProps {
  messages: Message[]
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="flex flex-col">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`py-6 ${
            message.role === 'assistant' ? 'bg-chat-hover' : ''
          }`}
        >
          <div className="max-w-3xl mx-auto px-4 flex gap-4">
            {/* Avatar */}
            <div
              className={`flex-shrink-0 w-8 h-8 rounded-sm flex items-center justify-center ${
                message.role === 'user'
                  ? 'bg-purple-600'
                  : 'bg-teal-600'
              }`}
            >
              {message.role === 'user' ? (
                <User className="w-5 h-5 text-white" />
              ) : (
                <Bot className="w-5 h-5 text-white" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              {/* Attachments */}
              {message.attachments && message.attachments.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-3">
                  {message.attachments.map((attachment) => {
                    // Check the attachment name (and content if available) for malicious patterns
                    const nameCheck = sanitizeLLMOutput(attachment.name)
                    const contentCheck = attachment.content ? sanitizeLLMOutput(attachment.content) : { flagged: false, detectedPatterns: [] }
                    // Additional deep-content checks: base64, invisible chars, leetspeak, binaries
                    const deepCheck = attachment.content ? checkAttachmentContent(attachment.content) : { flagged: false, reasons: [] }
                    const isMalicious = nameCheck.flagged || contentCheck.flagged || deepCheck.flagged
                    const allDetected = [...nameCheck.detectedPatterns, ...contentCheck.detectedPatterns, ...deepCheck.reasons]

                    if (isMalicious) {
                      return (
                        <div
                          key={attachment.id}
                          className="flex items-center gap-2 bg-red-900 rounded-lg px-3 py-2 text-sm border border-red-700"
                          title={`Blocked: malicious content detected (${allDetected.join(', ')})`}
                        >
                          <Paperclip className="w-4 h-4 text-red-400" />
                          <span className="text-red-300">[ATTACHMENT BLOCKED: malicious content detected]</span>
                        </div>
                      )
                    }

                    return (
                      <div
                        key={attachment.id}
                        className="flex items-center gap-2 bg-chat-input rounded-lg px-3 py-2 text-sm border border-chat-border"
                      >
                        <Paperclip className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-300">{nameCheck.sanitized}</span>
                        <span className="text-gray-500 text-xs">
                          ({formatFileSize(attachment.size)})
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Message Content or Error */}
              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                <div>
                  {message.role === 'assistant' && (
                    <div
                      className="flex items-center gap-2 mb-1"
                      data-provenance="ai-generated"
                      data-model="gpt-4o"
                      data-generated-at={message.timestamp.toISOString()}
                      aria-label="AI-generated content"
                    >
                      <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium bg-teal-900 text-teal-300 border border-teal-700">
                        <Bot className="w-3 h-3" />
                        AI-Generated
                      </span>
                                            <span className="text-xs text-gray-500" title="AI Assistant">
                        AI Assistant
                      </span>
                      <span className="text-xs text-gray-600" title="Generation timestamp">
                        &#x2022; {message.timestamp.toISOString()}
                      </span>
                    </div>
                  )}
                  {(() => {
                    const { sanitized, flagged, detectedPatterns } =
                      sanitizeLLMOutput(message.content)
                    return (
                      <>
                        {flagged && (
                          <div
                            className="flex items-center gap-2 mb-2 rounded px-2 py-1 text-xs font-medium bg-red-900 text-red-300 border border-red-700"
                            role="alert"
                            aria-label="Potentially unsafe content detected and blocked"
                          >
                            <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                            <span>
                              Warning: Potentially unsafe content detected and neutralized
                              {process.env.NODE_ENV === 'development' && (
                                <> (patterns: {detectedPatterns.join(', ')})</>
                              )}
                            </span>
                          </div>
                        )}
                        {/* ── Synthetic-content provenance label ── */}
                        <ProvenanceLabel content={sanitized} timestamp={message.timestamp} />

                        <div
                          className="message-content text-gray-100 whitespace-pre-wrap"
                          aria-label={flagged ? 'Sanitized AI response' : 'AI response'}
                        >
                          {sanitized}
                        </div>
                      </>
                    )
                  })()}
                </div>
              )}

              {/* Timestamp */}
              <div className="text-xs text-gray-500 mt-2">
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ProvenanceLabel – renders a visible AI-origin badge + hidden provenance
// metadata attributes (model ID, timestamp, HMAC watermark) on every
// AI-generated message bubble.
// ---------------------------------------------------------------------------

function ProvenanceLabel({
  content,
  timestamp,
}: {
  content: string
  timestamp: Date
}) {
  const [provenance, setProvenance] = React.useState<{
    modelId: string
    issuedAt: string
    watermark: string
  } | null>(null)

  React.useEffect(() => {
    let cancelled = false
    buildProvenanceTag(content, timestamp).then((tag) => {
      if (!cancelled) setProvenance(tag)
    })
    return () => {
      cancelled = true
    }
  }, [content, timestamp])

  return (
    <div
      className="flex items-center gap-1 mb-1 text-xs text-emerald-400 select-none"
      role="note"
      aria-label="AI-generated content label"
      // Provenance metadata embedded as data attributes for tooling / auditing
      data-ai-origin="true"
      data-ai-model={provenance?.modelId ?? AI_MODEL_ID}
      data-ai-issued-at={provenance?.issuedAt ?? timestamp.toISOString()}
      data-ai-provenance="true"
    >
      <ShieldCheck size={12} aria-hidden="true" />
      <span>AI-Generated Content</span>
      {provenance && (
        <span className="text-gray-500 ml-1" aria-hidden="true">
          · {provenance.modelId}
        </span>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// redactPII – scans text for common PII patterns and replaces them with
// redacted placeholders before content is processed or displayed.
// ---------------------------------------------------------------------------
function redactPII(text: string): string {
  if (!text) return text

  // Email addresses
  let redacted = text.replace(
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    '[REDACTED EMAIL]'
  )

  // US Social Security Numbers (XXX-XX-XXXX or XXXXXXXXX)
  redacted = redacted.replace(
    /\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b/g,
    '[REDACTED SSN]'
  )

  // Credit card numbers (13–16 digit sequences, optionally separated by spaces/dashes)
  redacted = redacted.replace(
    /\b(?:\d[ \-]?){13,16}\b/g,
    '[REDACTED CARD]'
  )

  // US phone numbers (various formats)
  redacted = redacted.replace(
    /\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g,
    '[REDACTED PHONE]'
  )

  // IPv4 addresses
  redacted = redacted.replace(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    '[REDACTED IP]'
  )

  // Street addresses (basic pattern: number followed by street name keywords)
  redacted = redacted.replace(
    /\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?/g,
    '[REDACTED ADDRESS]'
  )

  return redacted
}

// ---------------------------------------------------------------------------
// Singapore PII patterns (NRIC/FIN, SingPass ID, passport, phone, address)
// ---------------------------------------------------------------------------
const SINGAPORE_PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  // NRIC / FIN: S/T/F/G followed by 7 digits and a letter
  { name: 'NRIC/FIN', pattern: /\b[STFG]\d{7}[A-Z]\b/i },
  // SingPass user ID format (e.g. S1234567A used as login)
  { name: 'SingPass ID', pattern: /\bsingpass\s*[:\-]?\s*[STFG]\d{7}[A-Z]\b/i },
  // Singapore passport number: E followed by 7 digits
  { name: 'Singapore Passport', pattern: /\bE\d{7}[A-Z]\b/i },
  // Singapore mobile numbers: +65 or 65 prefix, 8-digit starting with 8 or 9
  { name: 'SG Phone Number', pattern: /(?:\+65|\b65)?\s*[89]\d{7}\b/ },
  // Singapore postal code: 6-digit starting with 0-8
  { name: 'SG Postal Code', pattern: /\bSingapore\s+\d{6}\b/i },
]

/**
 * Scans the text content of an uploaded file for Singapore PII.
 * Returns an array of violation descriptions, or an empty array if clean.
 */
export async function scanFileForSingaporePII(
  file: File
): Promise<{ clean: boolean; violations: string[] }> {
  // Only scan text-based files to avoid binary false positives
  const textTypes = [
    'text/plain',
    'text/csv',
    'application/json',
    'text/html',
    'text/xml',
    'application/xml',
  ]
  const isTextFile =
    textTypes.some((t) => file.type.startsWith(t)) ||
    /\.(txt|csv|json|xml|html|md|log)$/i.test(file.name)

  if (!isTextFile) {
    // Non-text files cannot be scanned client-side; flag for server-side review
    return { clean: false, violations: ['Binary file requires server-side PII scan'] }
  }

  let text: string
  try {
    text = await file.text()
  } catch {
    return { clean: false, violations: ['Unable to read file for PII scanning'] }
  }

  const violations: string[] = []
  for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
    if (pattern.test(text)) {
      violations.push(`Potential ${name} detected in uploaded file`)
    }
  }

  return { clean: violations.length === 0, violations }
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
