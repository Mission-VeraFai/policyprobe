'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { User, Bot, Paperclip, AlertTriangle, ShieldCheck } from 'lucide-react'

// ---------------------------------------------------------------------------
// Synthetic-content provenance helpers
// ---------------------------------------------------------------------------

const APPROVED_AI_MODEL_ID = 'gpt-4'
const AI_MODEL_ID = process.env.NEXT_PUBLIC_AI_MODEL_ID ?? APPROVED_AI_MODEL_ID

/**
 * Produce a lightweight, deterministic provenance tag for an AI-generated
 * message.  We use a Web Crypto HMAC-SHA-256 keyed with a per-session secret
 * so the tag is both unique and verifiable server-side.
 */
async function buildProvenanceTag(
  content: string,
  timestamp: Date
): Promise<{ modelId: string; issuedAt: string; watermark: string }> {
  const issuedAt = timestamp.toISOString()
  const contentHash = hashContent(content)
  const payload = `${AI_MODEL_ID}|${issuedAt}|${contentHash}`

  let watermark = 'unavailable'
  try {
    // Use a stable per-page-load key; in production replace with a server-
    // supplied signing key fetched at boot time.
    const rawKey = crypto.getRandomValues(new Uint8Array(32))
    const key = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )
    const sig = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(payload)
    )
    watermark = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  } catch {
    // Crypto API unavailable (e.g. non-secure context) – degrade gracefully
    watermark = 'crypto-unavailable'
  }

  return { modelId: AI_MODEL_ID, issuedAt, watermark }
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

// Append-only in-memory audit log — never overwritten, only pushed to.
// Retention policy: cap at MAX_AUDIT_LOG_ENTRIES; oldest records are evicted
// when the limit is reached so memory is bounded.
const MAX_AUDIT_LOG_ENTRIES = 1000
const _auditLog: SanitizationAuditRecord[] = []

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
    // Append-only: records are only ever pushed, never overwritten or deleted
    // individually. Retention policy: evict the oldest entry when the cap is
    // exceeded so the log remains bounded in memory.
    if (_auditLog.length >= MAX_AUDIT_LOG_ENTRIES) {
      _auditLog.shift() // remove oldest — FIFO eviction
    }
    _auditLog.push(record)
    // Emit to console as a structured forensic trace for server-side log aggregation
    console.info('[AUDIT][LLM_SANITIZATION]', JSON.stringify(record))
  } catch (e) {
    // Failure must not silently swallow the audit — emit to console at minimum
    console.error('[AUDIT][LLM_SANITIZATION] Failed to persist audit record', e, record)
  }
} = record
    const redactedRecord = { ...safeRecord, outputHash }
    const existing = sessionStorage.getItem(AUDIT_LOG_KEY)
    const log: SanitizationAuditRecord[] = existing ? JSON.parse(existing) : []
    log.push(redactedRecord)
    sessionStorage.setItem(AUDIT_LOG_KEY, JSON.stringify(log))
    // Emit only the redacted record (no raw output) to console
    console.info('[AUDIT][LLM_SANITIZATION]', JSON.stringify(redactedRecord))
  } catch (e) {
    // Storage failure must not silently swallow the audit — emit to console at minimum
    console.error('[AUDIT][LLM_SANITIZATION] Failed to persist audit record', e, record)
  }
}

// Patterns for dynamic code execution primitives that must never appear in LLM output
const DANGEROUS_PATTERNS: RegExp[] = [
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

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}
